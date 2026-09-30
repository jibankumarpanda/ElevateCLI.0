package security

import (
	"context"
	"strings"
	"testing"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/fixer"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// livePolicyEngine is a real PolicyEngineImpl so the loop exercises the same
// rule matching the production path uses, rather than canned violations.
func livePolicyEngine(policy config.PolicyConfig) PolicyEngine {
	return NewPolicyEngine(policy)
}

func fixLoopConfig() config.Config {
	return config.Config{
		Sandbox: config.SandboxConfig{Mode: "skip", TimeoutSec: 5, MaxMemoryMB: 256},
		Scoring: config.ScoringConfig{},
		Policy:  config.PolicyConfig{},
	}
}

func fixPolicy(blockedImports, blockedFuncs []string, maxComplexity int) config.PolicyConfig {
	var p config.PolicyConfig
	p.Rules.BlockedImports = blockedImports
	p.Rules.BlockedFunctions = blockedFuncs
	p.Rules.MaxCyclomaticComplexity = maxComplexity
	return p
}

// newFixLoopTest wires a fix loop over a pipeline whose SAST stage is empty and
// whose sandbox is opted out, so the loop's behaviour is driven purely by the
// policy stage — which is what the mechanical repairs act on.
//
// A single policy violation costs 20 points of the policy sub-score, which is
// only 20% of the total weight. That is not enough on its own to pull a clean
// report below the passing threshold, so tests that need the loop to do real
// work also seed a finding. See blockingFindings for the arithmetic.
func newFixLoopTest(t *testing.T, policy config.PolicyConfig, opts FixLoopOptions) *FixLoop {
	t.Helper()
	cfg := fixLoopConfig()
	cfg.Policy = policy
	p := New(cfg,
		&stubStaticAnalyzer{},
		&stubDependencyAuditor{},
		livePolicyEngine(policy),
		&stubSandboxRunner{result: sec.SandboxResult{Skipped: true, Mode: "none"}},
	)
	return NewFixLoop(p, fixer.New(policy), opts)
}

// blockingFindings returns nine MEDIUM SAST findings, which is enough to hold the
// pre-fix verdict below the passing threshold while still leaving room for a
// repair to lift it back over.
//
// The weights are SAST 0.40 / deps 0.30 / policy 0.20 / sandbox 0.10, and the
// passing threshold defaults to 70. With a clean dependency stage (30) and an
// opted-out sandbox (10), 40 points are fixed and the SAST and policy stages
// must supply the rest. Nine MEDIUM findings deduct 72 SAST points, leaving a
// sub-score of 28 that contributes 11.2. A single policy violation drops the
// policy sub-score to 80, contributing 16, for a total of about 67 — below the
// threshold. Removing that violation restores the full 20 points and the report
// converges to APPROVED at about 71, which is the transition these tests assert.
func blockingFindings() []sec.Finding {
	rules := []string{
		"G101", "G102", "G103", "G104", "G106",
		"G107", "G201", "G202", "G304",
	}
	out := make([]sec.Finding, 0, len(rules))
	for i, rule := range rules {
		out = append(out, sec.Finding{
			ID:       "f" + string(rune('1'+i)),
			RuleID:   rule,
			Title:    "seeded finding " + rule,
			Severity: sec.SeverityMedium,
		})
	}
	return out
}

// newFixLoopWithFindings is newFixLoopTest plus seeded SAST findings, for tests
// that need the pre-fix verdict to be below the passing threshold.
func newFixLoopWithFindings(
	t *testing.T,
	policy config.PolicyConfig,
	findings []sec.Finding,
	opts FixLoopOptions,
) *FixLoop {
	t.Helper()
	cfg := fixLoopConfig()
	cfg.Policy = policy
	p := New(cfg,
		&stubStaticAnalyzer{findings: findings},
		&stubDependencyAuditor{},
		livePolicyEngine(policy),
		&stubSandboxRunner{result: sec.SandboxResult{Skipped: true, Mode: "none"}},
	)
	return NewFixLoop(p, fixer.New(policy), opts)
}

func TestFixLoopConvergesOnRepairableViolation(t *testing.T) {
	code := `package main

import (
	"fmt"
	"os/exec"
)

func main() {
	fmt.Println("hello")
}
`
	policy := fixPolicy([]string{"os/exec"}, nil, 0)
	l := newFixLoopWithFindings(t, policy, blockingFindings(), FixLoopOptions{})

	base, err := l.pipeline.Run(context.Background(), "p", code, "go", "x", "y")
	if err != nil {
		t.Fatalf("base run: %v", err)
	}
	if len(base.Violations) == 0 {
		t.Fatal("test setup: expected a blocked-import violation before the loop")
	}
	if base.Verdict == sec.VerdictApproved {
		t.Fatalf("test setup: pre-fix verdict must be below APPROVED, got %d/%d",
			base.FinalScore, sec.ExitCodeOK)
	}

	got, err := l.Run(context.Background(), base, "go")
	if err != nil {
		t.Fatalf("fix loop: %v", err)
	}

	if got.Fix == nil {
		t.Fatal("report must carry the fix-loop summary")
	}
	if len(got.Fix.FixRounds) != 1 {
		t.Fatalf("expected exactly one round, got %d", len(got.Fix.FixRounds))
	}
	round := got.Fix.FixRounds[0]
	if !round.Accepted {
		t.Errorf("round should be accepted: %+v", round)
	}
	if round.Strategy != sec.FixStrategyMechanical {
		t.Errorf("strategy = %q, want mechanical", round.Strategy)
	}
	if round.Diff == "" {
		t.Error("accepted round must record a diff for human review")
	}
	if strings.Contains(got.GeneratedCode, "os/exec") {
		t.Errorf("blocked import survived the loop:\n%s", got.GeneratedCode)
	}
	if got.Verdict != sec.VerdictApproved {
		t.Errorf("verdict = %q, want APPROVED after a clean repair", got.Verdict)
	}
	if got.Fix.StopReason != StopConverged {
		t.Errorf("stop reason = %q, want converged", got.Fix.StopReason)
	}
}

func TestFixLoopRecordsPreAndPostScores(t *testing.T) {
	code := `package main

import (
	"fmt"
	"os/exec"
)

func main() {
	fmt.Println("hello")
}
`
	policy := fixPolicy([]string{"os/exec"}, nil, 0)
	l := newFixLoopWithFindings(t, policy, blockingFindings(), FixLoopOptions{})

	base, err := l.pipeline.Run(context.Background(), "p", code, "go", "x", "y")
	if err != nil {
		t.Fatalf("base run: %v", err)
	}

	got, err := l.Run(context.Background(), base, "go")
	if err != nil {
		t.Fatalf("fix loop: %v", err)
	}

	if got.Fix.PreFixScore != base.FinalScore {
		t.Errorf("pre-fix score = %d, want the original score %d",
			got.Fix.PreFixScore, base.FinalScore)
	}
	if got.Fix.PostFixScore != got.FinalScore {
		t.Errorf("post-fix score = %d, must equal the final report score %d",
			got.Fix.PostFixScore, got.FinalScore)
	}
	if got.Fix.PostFixVerdict != got.Verdict {
		t.Errorf("post-fix verdict = %q, must equal the final verdict %q",
			got.Fix.PostFixVerdict, got.Verdict)
	}
	if got.Fix.PreFixScore >= got.Fix.PostFixScore {
		t.Errorf("expected the fix to raise the score, got %d -> %d",
			got.Fix.PreFixScore, got.Fix.PostFixScore)
	}
}

func TestFixLoopDoesNotMutateInputReport(t *testing.T) {
	code := `package main

import (
	"fmt"
	"os/exec"
)

func main() {
	fmt.Println("hello")
}
`
	policy := fixPolicy([]string{"os/exec"}, nil, 0)
	l := newFixLoopWithFindings(t, policy, blockingFindings(), FixLoopOptions{})

	base, err := l.pipeline.Run(context.Background(), "p", code, "go", "x", "y")
	if err != nil {
		t.Fatalf("base run: %v", err)
	}
	originalScore := base.FinalScore
	originalCode := base.GeneratedCode

	if _, err := l.Run(context.Background(), base, "go"); err != nil {
		t.Fatalf("fix loop: %v", err)
	}

	if base.FinalScore != originalScore {
		t.Errorf("input report score was mutated: %d -> %d", originalScore, base.FinalScore)
	}
	if base.GeneratedCode != originalCode {
		t.Error("input report code was mutated; the loop must return a new report")
	}
	if base.Fix != nil {
		t.Error("input report must not receive a fix summary")
	}
}

func TestFixLoopStopsOnUnrepairableViolation(t *testing.T) {
	// os/exec is still referenced, so the import cannot be removed safely. The
	// loop must stop and say so rather than emit code that does not compile.
	code := `package main

import "os/exec"

func main() {
	_ = exec.Command("ls")
}
`
	policy := fixPolicy([]string{"os/exec"}, nil, 0)
	l := newFixLoopWithFindings(t, policy, blockingFindings(), FixLoopOptions{})

	base, err := l.pipeline.Run(context.Background(), "p", code, "go", "x", "y")
	if err != nil {
		t.Fatalf("base run: %v", err)
	}

	got, err := l.Run(context.Background(), base, "go")
	if err != nil {
		t.Fatalf("fix loop: %v", err)
	}

	if got.Fix.StopReason != StopNoSemantic {
		t.Errorf("stop reason = %q, want %q", got.Fix.StopReason, StopNoSemantic)
	}
	if len(got.Fix.FixRounds) != 1 {
		t.Fatalf("expected one recorded round, got %d", len(got.Fix.FixRounds))
	}
	if len(got.Fix.FixRounds[0].Unrepairable) == 0 {
		t.Error("the refusal must be recorded so the user knows why nothing changed")
	}
	if got.GeneratedCode != code {
		t.Errorf("code must be left untouched:\n%s", got.GeneratedCode)
	}
}

func TestFixLoopRefusesToRunOnIncompleteAnalysis(t *testing.T) {
	// A stage error means the finding list is missing entries, so repairing
	// against it would be unsound. The loop must refuse and keep the verdict.
	policy := fixPolicy([]string{"os/exec"}, nil, 0)
	cfg := fixLoopConfig()
	cfg.Policy = policy
	p := New(cfg,
		&stubStaticAnalyzer{err: context.DeadlineExceeded},
		&stubDependencyAuditor{},
		livePolicyEngine(policy),
		&stubSandboxRunner{result: sec.SandboxResult{Skipped: true, Mode: "none"}},
	)
	l := NewFixLoop(p, fixer.New(policy), FixLoopOptions{})

	base, err := p.Run(context.Background(), "p", "package main", "go", "x", "y")
	if err != nil {
		t.Fatalf("base run: %v", err)
	}

	got, err := l.Run(context.Background(), base, "go")
	if err != nil {
		t.Fatalf("fix loop: %v", err)
	}

	if got.Fix.StopReason != StopIncomplete {
		t.Errorf("stop reason = %q, want %q", got.Fix.StopReason, StopIncomplete)
	}
	if len(got.Fix.FixRounds) != 0 {
		t.Errorf("no repair round may run on incomplete analysis, got %d", len(got.Fix.FixRounds))
	}
	if got.Verdict != sec.VerdictAnalysisIncomplete {
		t.Errorf("verdict = %q, want ANALYSIS_INCOMPLETE", got.Verdict)
	}
}

func TestFixLoopShortCircuitsOnApprovedCode(t *testing.T) {
	l := newFixLoopTest(t, fixPolicy([]string{"os/exec"}, nil, 0), FixLoopOptions{})

	base, err := l.pipeline.Run(context.Background(), "p", "package main", "go", "x", "y")
	if err != nil {
		t.Fatalf("base run: %v", err)
	}
	if base.Verdict != sec.VerdictApproved {
		t.Fatalf("test setup: want an APPROVED base report, got %q", base.Verdict)
	}

	got, err := l.Run(context.Background(), base, "go")
	if err != nil {
		t.Fatalf("fix loop: %v", err)
	}

	if got.Fix.StopReason != StopConverged {
		t.Errorf("stop reason = %q, want converged", got.Fix.StopReason)
	}
	if len(got.Fix.FixRounds) != 0 {
		t.Errorf("already-approved code needs no rounds, got %d", len(got.Fix.FixRounds))
	}
}

func TestFixLoopStopsOnBlocked(t *testing.T) {
	// A CRITICAL finding is a hard stop: the loop must not keep trying to
	// repair around it, and must report BLOCKED.
	policy := fixPolicy(nil, nil, 0)
	cfg := fixLoopConfig()
	cfg.Policy = policy
	p := New(cfg,
		&stubStaticAnalyzer{findings: []sec.Finding{{ID: "f", RuleID: "G105", Severity: sec.SeverityCritical}}},
		&stubDependencyAuditor{},
		livePolicyEngine(policy),
		&stubSandboxRunner{result: sec.SandboxResult{Skipped: true, Mode: "none"}},
	)
	l := NewFixLoop(p, fixer.New(policy), FixLoopOptions{})

	base, err := p.Run(context.Background(), "p", "package main", "go", "x", "y")
	if err != nil {
		t.Fatalf("base run: %v", err)
	}
	if base.Verdict != sec.VerdictBlocked {
		t.Fatalf("test setup: want BLOCKED, got %q", base.Verdict)
	}

	got, err := l.Run(context.Background(), base, "go")
	if err != nil {
		t.Fatalf("fix loop: %v", err)
	}

	if got.Fix.StopReason != StopBlocked {
		t.Errorf("stop reason = %q, want %q", got.Fix.StopReason, StopBlocked)
	}
	if got.Verdict != sec.VerdictBlocked {
		t.Errorf("verdict = %q, want BLOCKED preserved", got.Verdict)
	}
}

func TestFixLoopStopsWhenNoRuleCoversTheFindings(t *testing.T) {
	// None of the seeded findings maps to a mechanical rule, so the loop must
	// terminate after one round rather than spinning to the cap. This guards the
	// "nothing repairable and something unrepairable" path, which previously
	// returned an empty stop reason and let the loop run to the cap.
	policy := fixPolicy(nil, nil, 0)
	cfg := fixLoopConfig()
	cfg.Policy = policy
	p := New(cfg,
		&stubStaticAnalyzer{findings: nonConvergingFindings()},
		&stubDependencyAuditor{},
		livePolicyEngine(policy),
		&stubSandboxRunner{result: sec.SandboxResult{Skipped: true, Mode: "none"}},
	)

	l := NewFixLoop(p, fixer.New(policy), FixLoopOptions{MaxRounds: 5})
	base, err := p.Run(context.Background(), "p", "package main", "go", "x", "y")
	if err != nil {
		t.Fatalf("base run: %v", err)
	}
	if base.Verdict == sec.VerdictApproved {
		t.Fatalf("test setup: want a non-approved base report, got %d", base.FinalScore)
	}

	got, err := l.Run(context.Background(), base, "go")
	if err != nil {
		t.Fatalf("fix loop: %v", err)
	}

	if got.Fix.StopReason != StopNoSemantic {
		t.Errorf("stop reason = %q, want %q", got.Fix.StopReason, StopNoSemantic)
	}
	if len(got.Fix.FixRounds) != 1 {
		t.Errorf("expected one round before stopping, got %d", len(got.Fix.FixRounds))
	}
}

// nonConvergingFindings returns ten MEDIUM findings, which keeps the verdict
// below APPROVED even after the policy stage is clean.
//
// With ten findings the SAST sub-score is 20, contributing 8 against the fixed
// 30 (deps) and 10 (sandbox), so even a perfect policy stage of 100 only reaches
// about 68 — still under the threshold of 70. Tests that need the loop to keep
// going after a successful repair use these so convergence cannot mask them.
func nonConvergingFindings() []sec.Finding {
	out := blockingFindings()
	out = append(out, sec.Finding{
		ID: "f10", RuleID: "G401", Title: "seeded finding G401", Severity: sec.SeverityMedium,
	})
	return out
}

func TestFixLoopRoundCapStopsOscillatingRepairs(t *testing.T) {
	// A patcher that alternates between two bodies keeps producing accepted
	// rounds, so only the cap terminates the loop.
	policy := fixPolicy(nil, nil, 0)
	cfg := fixLoopConfig()
	cfg.Policy = policy
	p := New(cfg,
		&stubStaticAnalyzer{
			findings: nonConvergingFindings(),
		},
		&stubDependencyAuditor{},
		livePolicyEngine(policy),
		&stubSandboxRunner{result: sec.SandboxResult{Skipped: true, Mode: "none"}},
	)

	calls := 0
	patcher := &stubPatcher{fn: func(code, lang string) string {
		calls++
		if calls%2 == 1 {
			return code + "\n// variant A\n"
		}
		return code + "\n// variant B\n"
	}}

	l := NewFixLoop(p, fixer.New(policy), FixLoopOptions{MaxRounds: 4, Semantic: true, Patch: patcher})
	base, err := p.Run(context.Background(), "p", "package main", "go", "x", "y")
	if err != nil {
		t.Fatalf("base run: %v", err)
	}

	got, err := l.Run(context.Background(), base, "go")
	if err != nil {
		t.Fatalf("fix loop: %v", err)
	}

	if got.Fix.StopReason != StopRoundCap {
		t.Errorf("stop reason = %q, want %q", got.Fix.StopReason, StopRoundCap)
	}
	if len(got.Fix.FixRounds) != 4 {
		t.Errorf("expected exactly 4 rounds, got %d", len(got.Fix.FixRounds))
	}
}

func TestFixLoopRollsBackScoreRegression(t *testing.T) {
	// The repair raises the policy score but the SAST stage gets worse, so the
	// overall score must drop and the patch must be discarded.
	policy := fixPolicy([]string{"os/exec"}, nil, 0)
	cfg := fixLoopConfig()
	cfg.Policy = policy

	// Stage results depend on the code so the pipeline can be made to regress.
	regressing := &codeAwarePipeline{ //nolint:staticcheck
		Pipeline: New(cfg,
			&stubStaticAnalyzer{},
			&stubDependencyAuditor{},
			livePolicyEngine(policy),
			&stubSandboxRunner{result: sec.SandboxResult{Skipped: true, Mode: "none"}},
		),
		regressOn: "os/exec",
	}
	l := NewFixLoop(regressing, fixer.New(policy), FixLoopOptions{})

	code := `package main

import (
	"fmt"
	"os/exec"
)

func main() {
	fmt.Println("hello")
}
`
	base, err := regressing.Run(context.Background(), "p", code, "go", "x", "y")
	if err != nil {
		t.Fatalf("base run: %v", err)
	}

	got, err := l.Run(context.Background(), base, "go")
	if err != nil {
		t.Fatalf("fix loop: %v", err)
	}

	if got.Fix.StopReason != StopScoreRegressed {
		t.Errorf("stop reason = %q, want %q", got.Fix.StopReason, StopScoreRegressed)
	}
	if got.GeneratedCode != code {
		t.Errorf("a regressing patch must be rolled back:\n%s", got.GeneratedCode)
	}
	if got.Fix.FixRounds[0].Accepted {
		t.Error("a rolled-back round must not be marked accepted")
	}
}

// codeAwarePipeline degrades the SAST stage once the blocked import is gone, so
// a repair that removes the policy violation still lowers the overall score.
type codeAwarePipeline struct {
	*Pipeline
	regressOn string
}

func (c *codeAwarePipeline) Run(ctx context.Context, prompt, code, language, provider, model string) (*sec.Report, error) {
	if !strings.Contains(code, c.regressOn) {
		// Four CRITICAL findings zero out the SAST sub-score, so the total drops
		// from 64 to 60 even though removing the policy violation gained 20
		// policy points. That is exactly the shape of a repair that trades one
		// problem for a worse one, and it must be rejected on score.
		findings := []sec.Finding{
			{ID: "x1", RuleID: "G105", Severity: sec.SeverityCritical},
			{ID: "x2", RuleID: "G106", Severity: sec.SeverityCritical},
			{ID: "x3", RuleID: "G107", Severity: sec.SeverityCritical},
			{ID: "x4", RuleID: "G307", Severity: sec.SeverityCritical},
		}
		c.static = &stubStaticAnalyzer{findings: findings}
	} else {
		c.static = &stubStaticAnalyzer{findings: nonConvergingFindings()}
	}
	return c.Pipeline.Run(ctx, prompt, code, language, provider, model)
}

// stubPatcher returns code from a caller-supplied function.
type stubPatcher struct {
	fn func(code, language string) string
}

func (s *stubPatcher) Patch(_ context.Context, code, language string, _ *sec.Report) (string, error) {
	return s.fn(code, language), nil
}

func TestFixLoopRejectsNilBaseReport(t *testing.T) {
	l := newFixLoopTest(t, fixPolicy(nil, nil, 0), FixLoopOptions{})
	if _, err := l.Run(context.Background(), nil, "go"); err == nil {
		t.Error("a nil base report must be an error, not a silent pass-through")
	}
}

func TestFixLoopSemanticPatchIsReVerified(t *testing.T) {
	// A semantic patch that reintroduces a blocked import must be caught by the
	// re-verification, not waved through because the model proposed it.
	policy := fixPolicy([]string{"os/exec"}, nil, 0)
	cfg := fixLoopConfig()
	cfg.Policy = policy
	p := New(cfg,
		&stubStaticAnalyzer{findings: nonConvergingFindings()},
		&stubDependencyAuditor{},
		livePolicyEngine(policy),
		&stubSandboxRunner{result: sec.SandboxResult{Skipped: true, Mode: "none"}},
	)

	patcher := &stubPatcher{fn: func(code, _ string) string {
		return "package main\n\nimport \"os/exec\"\n\nfunc main() { _ = exec.Command(\"ls\") }\n"
	}}

	l := NewFixLoop(p, fixer.New(policy), FixLoopOptions{Semantic: true, Patch: patcher})
	base, err := p.Run(context.Background(), "p", "package main", "go", "x", "y")
	if err != nil {
		t.Fatalf("base run: %v", err)
	}

	got, err := l.Run(context.Background(), base, "go")
	if err != nil {
		t.Fatalf("fix loop: %v", err)
	}

	round := got.Fix.FixRounds[0]
	if round.Strategy != sec.FixStrategySemantic {
		t.Errorf("strategy = %q, want semantic", round.Strategy)
	}
	if round.Diff == "" {
		t.Error("a semantic patch must record its diff for human review")
	}
	// The patch reintroduces a policy violation, so its score must be lower than
	// the clean original and the patch must be rolled back.
	if got.Fix.StopReason != StopScoreRegressed {
		t.Errorf("stop reason = %q, want %q", got.Fix.StopReason, StopScoreRegressed)
	}
	if round.Accepted {
		t.Error("a regressive semantic patch must not be accepted")
	}
}

func TestFixLoopSemanticRequiresOptIn(t *testing.T) {
	// Without Semantic enabled the patcher must never be consulted, even though
	// unrepairable findings exist.
	policy := fixPolicy(nil, nil, 0)
	cfg := fixLoopConfig()
	cfg.Policy = policy
	p := New(cfg,
		&stubStaticAnalyzer{findings: nonConvergingFindings()},
		&stubDependencyAuditor{},
		livePolicyEngine(policy),
		&stubSandboxRunner{result: sec.SandboxResult{Skipped: true, Mode: "none"}},
	)

	called := false
	patcher := &stubPatcher{fn: func(code, _ string) string {
		called = true
		return code + "// patched\n"
	}}

	l := NewFixLoop(p, fixer.New(policy), FixLoopOptions{Patch: patcher})
	base, err := p.Run(context.Background(), "p", "package main", "go", "x", "y")
	if err != nil {
		t.Fatalf("base run: %v", err)
	}

	got, err := l.Run(context.Background(), base, "go")
	if err != nil {
		t.Fatalf("fix loop: %v", err)
	}

	if called {
		t.Error("patcher must not be called without the Semantic opt-in")
	}
	if got.Fix.StopReason != StopNoSemantic {
		t.Errorf("stop reason = %q, want %q", got.Fix.StopReason, StopNoSemantic)
	}
}

func TestLastDiffReturnsLatestRound(t *testing.T) {
	summary := &sec.FixLoopSummary{
		FixRounds: []sec.FixRound{
			{Round: 1, Diff: "diff-one"},
			{Round: 2, Diff: "diff-two"},
		},
	}
	if got := LastDiff(summary); got != "diff-two" {
		t.Errorf("LastDiff = %q, want the latest round's diff", got)
	}

	// A trailing round with no diff must not hide an earlier accepted one.
	summary.FixRounds = append(summary.FixRounds, sec.FixRound{Round: 3})
	if got := LastDiff(summary); got != "diff-two" {
		t.Errorf("LastDiff = %q, want the latest available diff", got)
	}

	if got := LastDiff(nil); got != "" {
		t.Errorf("LastDiff(nil) = %q, want empty", got)
	}
	if got := LastDiff(&sec.FixLoopSummary{}); got != "" {
		t.Errorf("LastDiff with no rounds = %q, want empty", got)
	}
}

func TestFixLoopIsDeterministic(t *testing.T) {
	code := `package main

import (
	"fmt"
	"os/exec"
)

func main() {
	fmt.Println("hello")
}
`
	policy := fixPolicy([]string{"os/exec"}, nil, 0)

	var first string
	for i := 0; i < 4; i++ {
		l := newFixLoopTest(t, policy, FixLoopOptions{})
		base, err := l.pipeline.Run(context.Background(), "p", code, "go", "x", "y")
		if err != nil {
			t.Fatalf("base run: %v", err)
		}
		got, err := l.Run(context.Background(), base, "go")
		if err != nil {
			t.Fatalf("fix loop: %v", err)
		}
		if i == 0 {
			first = got.GeneratedCode
			continue
		}
		if got.GeneratedCode != first {
			t.Fatalf("fix loop output is not deterministic on iteration %d", i)
		}
	}
}
