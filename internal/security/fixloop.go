package security

import (
	"context"
	"errors"
	"fmt"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/fixer"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/logger"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
	"go.uber.org/zap"
)

// DefaultFixRounds bounds how many repair passes a single fix loop may run.
//
// The cap exists so a repair that oscillates — one that removes a violation but
// creates another, forever — terminates instead of looping. In practice the loop
// converges in one or two rounds because every repair is narrow and idempotent;
// the cap is a backstop, not a budget.
const DefaultFixRounds = 5

// Stop reasons recorded on a FixLoopSummary. Every one is a deliberate terminal
// state; none of them means the code is safe.
const (
	StopConverged      = "converged: verdict is APPROVED"
	StopBlocked        = "blocked: a blocking condition could not be repaired"
	StopIncomplete     = "analysis incomplete: a mandatory check could not run, so repairs would be unsound"
	StopNoRepair       = "no repair applies to the remaining findings"
	StopRoundCap       = "round cap reached without converging"
	StopScoreRegressed = "patch made the deterministic score worse and was rolled back"
	StopPatchInvalid   = "patch failed validation and was rolled back"
	StopNoSemantic     = "remaining findings need human judgement; enable --fix-semantic to ask the model for a patch"
)

// SemanticPatcher proposes a patch for findings no mechanical rule can fix.
//
// Implementations must return complete code, never a diff or an instruction: the
// full pipeline re-verifies whatever comes back, so a patch that is not valid
// source is caught by the same checks the rest of the loop relies on.
type SemanticPatcher interface {
	Patch(ctx context.Context, code, language string, report *sec.Report) (string, error)
}

// FixLoopOptions configures one fix-loop run.
type FixLoopOptions struct {
	// MaxRounds caps repair passes. Zero selects DefaultFixRounds.
	MaxRounds int
	// Semantic enables LLM-proposed patches for findings the mechanical rules
	// could not repair.
	Semantic bool
	// Patch is the semantic patcher. Required only when Semantic is true.
	Patch SemanticPatcher
}

// FixLoop runs rule-driven repairs and re-verifies each one through the full
// pipeline before keeping it.
//
// The loop is fail-closed in three separate ways:
//
//   - Nothing is trusted. A patch is accepted only after the complete pipeline
//     has re-run on it, so no repair reaches the output without passing the same
//     gates as the original code.
//   - Nothing regresses. A patch whose deterministic score drops is rolled back
//     and the loop stops, so a "fix" can never make the report worse.
//   - Nothing is guessed. A finding no rule covers is reported as unrepairable
//     rather than silently skipped, so the loop stops with an accurate account
//     instead of a falsely clean result.
//
// The verdict is always the one the pipeline computed on the final code. The loop
// chooses which code to verify next; it never synthesises a verdict.
type FixLoop struct {
	pipeline PipelineRunner
	fixer    *fixer.Fixer
	opts     FixLoopOptions
}

// PipelineRunner is the verification pipeline as the fix loop needs it. It is an
// interface so the loop can be driven by a pipeline whose stages respond to the
// code being verified, which is what the rollback tests need.
type PipelineRunner interface {
	Run(ctx context.Context, prompt, code, language, aiProvider, aiModel string) (*sec.Report, error)
}

// NewFixLoop wires a fix loop onto an existing pipeline.
func NewFixLoop(p PipelineRunner, f *fixer.Fixer, opts FixLoopOptions) *FixLoop {
	if opts.MaxRounds <= 0 {
		opts.MaxRounds = DefaultFixRounds
	}
	return &FixLoop{pipeline: p, fixer: f, opts: opts}
}

// loopState carries the code and report the loop is currently working on. The
// first repair produces a candidate; it replaces this state only after the
// pipeline has re-verified it.
type loopState struct {
	code   string
	report *sec.Report
}

// Run executes the fix loop and returns the report for the final code, with the
// fix-loop audit trail attached.
//
// baseReport is the first verification of the original code. It is passed in
// rather than recomputed so the pre-fix score recorded in the report is the same
// number the user was shown, and so the original is analysed exactly once.
//
// The input report is not modified: a fresh report is returned, and the caller's
// copy still describes the original code.
func (l *FixLoop) Run(ctx context.Context, baseReport *sec.Report, language string) (*sec.Report, error) {
	if baseReport == nil {
		return nil, errors.New("fix loop requires the initial verification report")
	}

	log := logger.WithStage("fixloop")

	state := &loopState{code: baseReport.GeneratedCode, report: cloneReport(baseReport)}

	summary := &sec.FixLoopSummary{
		PreFixScore:   baseReport.FinalScore,
		PreFixVerdict: baseReport.Verdict,
	}

	finish := func(reason string) (*sec.Report, error) {
		summary.StoppedCleanly = true
		summary.StopReason = reason
		summary.PostFixScore = state.report.FinalScore
		summary.PostFixVerdict = state.report.Verdict
		state.report.Fix = summary
		log.Info("fix loop stopped",
			zap.String("reason", reason),
			zap.Int("rounds", len(summary.FixRounds)),
			zap.Int("score", state.report.FinalScore),
			zap.String("verdict", string(state.report.Verdict)),
		)
		return state.report, nil
	}

	// Terminal states of the first pass are all handled before any repair runs:
	// there is no point rewriting code whose verdict can no longer change.
	if !state.report.AnalysisComplete {
		return finish(StopIncomplete)
	}
	if state.report.Verdict == sec.VerdictApproved {
		return finish(StopConverged)
	}
	if state.report.Verdict == sec.VerdictBlocked {
		return finish(StopBlocked)
	}

	for round := 1; round <= l.opts.MaxRounds; round++ {
		result := l.fixer.Apply(state.code, language, state.report.Violations, state.report.Findings)

		// Adopt the next state before checking the stop reason: when a round
		// converged, the state it produced is the very code that reached
		// APPROVED, and that code is what the report must describe.
		next, rec, stopReason := l.advance(ctx, state, result, language, round)
		summary.FixRounds = append(summary.FixRounds, *rec)

		if next != nil {
			state = next
		}
		if stopReason != "" {
			return finish(stopReason)
		}
	}

	return finish(StopRoundCap)
}

// advance applies a repair pass, re-verifies it, and decides whether to adopt it.
//
// It returns the next loop state (a new value, never a mutation of state) plus
// the round record and a stop reason. An empty stop reason means the patch was
// accepted and the loop should continue from the returned state.
func (l *FixLoop) advance(
	ctx context.Context,
	state *loopState,
	result fixer.Result,
	language string,
	round int,
) (*loopState, *sec.FixRound, string) {
	log := logger.WithStage("fixloop")

	rec := &sec.FixRound{
		Round:         round,
		Strategy:      sec.FixStrategyMechanical,
		Repairs:       result.Summary(),
		PreFixScore:   state.report.FinalScore,
		PreFixVerdict: state.report.Verdict,
	}

	rollback := func(reason string) (*loopState, *sec.FixRound, string) {
		rec.PostFixScore = state.report.FinalScore
		rec.PostFixVerdict = state.report.Verdict
		return state, rec, reason
	}

	// ── No mechanical repair was produced ───────────────────────────────────
	if len(result.Repairs) == 0 {
		rec.Unrepairable = result.Unrepairable

		if len(result.Unrepairable) == 0 {
			// Nothing left to repair and nothing outstanding. This is a
			// terminal state even when the verdict is only WARNING, because
			// another round would find exactly the same thing.
			if reason := stopFor(state.report.Verdict); reason != "" {
				return rollback(reason)
			}
			return rollback(StopNoRepair)
		}

		// Remaining findings need judgement. Hand them to the semantic patcher
		// only when the caller explicitly opted in.
		if !l.opts.Semantic || l.opts.Patch == nil {
			return rollback(StopNoSemantic)
		}
		return l.advanceSemantic(ctx, state, rec, language)
	}

	// ── A mechanical patch was produced ─────────────────────────────────────
	verified, err := l.pipeline.Run(ctx, state.report.Prompt, result.Code, language,
		state.report.AIProvider, state.report.AIModel)
	if err != nil {
		rec.Unrepairable = append(rec.Unrepairable,
			fmt.Sprintf("patch could not be re-verified: %v", err))
		return rollback(StopPatchInvalid)
	}

	rec.Diff = fixer.Diff(state.code, result.Code, "generated_code")
	rec.PostFixScore = verified.FinalScore
	rec.PostFixVerdict = verified.Verdict

	if verified.FinalScore < state.report.FinalScore {
		rec.Unrepairable = append(rec.Unrepairable,
			fmt.Sprintf("patch regressed the score from %d to %d and was rolled back",
				state.report.FinalScore, verified.FinalScore))
		return rollback(StopScoreRegressed)
	}

	rec.Accepted = true
	log.Info("round accepted",
		zap.Int("round", round),
		zap.Int("repairs", len(result.Repairs)),
		zap.Int("score", verified.FinalScore),
		zap.String("verdict", string(verified.Verdict)),
	)

	next := &loopState{code: result.Code, report: verified}
	return next, rec, stopFor(verified.Verdict)
}

// advanceSemantic asks the patcher for a patch and re-verifies it exactly as a
// mechanical patch is re-verified.
//
// The patch is never treated as approved on the strength of the model that wrote
// it. It is recorded as Accepted only because the pipeline re-scored it, and the
// caller is required to surface its diff for human review.
func (l *FixLoop) advanceSemantic(
	ctx context.Context,
	state *loopState,
	rec *sec.FixRound,
	language string,
) (*loopState, *sec.FixRound, string) {
	log := logger.WithStage("fixloop")
	rollback := func(reason string) (*loopState, *sec.FixRound, string) {
		rec.PostFixScore = state.report.FinalScore
		rec.PostFixVerdict = state.report.Verdict
		return state, rec, reason
	}

	patched, err := l.opts.Patch.Patch(ctx, state.code, language, state.report)
	if err != nil {
		rec.Unrepairable = append(rec.Unrepairable,
			fmt.Sprintf("semantic patch failed: %v", err))
		return rollback(StopPatchInvalid)
	}
	if patched == "" || patched == state.code {
		rec.Unrepairable = append(rec.Unrepairable,
			"semantic patcher returned no change")
		return rollback(StopNoRepair)
	}

	verified, err := l.pipeline.Run(ctx, state.report.Prompt, patched, language,
		state.report.AIProvider, state.report.AIModel)
	if err != nil {
		rec.Unrepairable = append(rec.Unrepairable,
			fmt.Sprintf("semantic patch could not be re-verified: %v", err))
		return rollback(StopPatchInvalid)
	}

	rec.Strategy = sec.FixStrategySemantic
	rec.Diff = fixer.Diff(state.code, patched, "generated_code")
	rec.PostFixScore = verified.FinalScore
	rec.PostFixVerdict = verified.Verdict

	if verified.FinalScore < state.report.FinalScore {
		rec.Unrepairable = append(rec.Unrepairable,
			fmt.Sprintf("semantic patch regressed the score from %d to %d and was rolled back",
				state.report.FinalScore, verified.FinalScore))
		return rollback(StopScoreRegressed)
	}

	rec.Accepted = true
	log.Info("semantic patch re-verified — human review of the diff is still required",
		zap.Int("round", rec.Round),
		zap.Int("score", verified.FinalScore),
		zap.String("verdict", string(verified.Verdict)),
	)

	return &loopState{code: patched, report: verified}, rec, stopFor(verified.Verdict)
}

// stopFor maps a verdict to the stop reason that describes it. An empty result
// means the loop should keep going.
func stopFor(v sec.Verdict) string {
	switch v {
	case sec.VerdictApproved:
		return StopConverged
	case sec.VerdictBlocked:
		return StopBlocked
	case sec.VerdictAnalysisIncomplete:
		return StopIncomplete
	default:
		return ""
	}
}

// cloneReport copies a report so the loop can replace its state without
// mutating the caller's copy of the original result.
func cloneReport(r *sec.Report) *sec.Report {
	if r == nil {
		return nil
	}
	out := *r
	out.Findings = append([]sec.Finding(nil), r.Findings...)
	out.Vulns = append([]sec.Vulnerability(nil), r.Vulns...)
	out.Violations = append([]sec.PolicyViolation(nil), r.Violations...)
	return &out
}

// LastDiff returns the diff of the most recent round that produced one, or an
// empty string when none did. It backs `--review`.
func LastDiff(summary *sec.FixLoopSummary) string {
	if summary == nil {
		return ""
	}
	for i := len(summary.FixRounds) - 1; i >= 0; i-- {
		if summary.FixRounds[i].Diff != "" {
			return summary.FixRounds[i].Diff
		}
	}
	return ""
}
