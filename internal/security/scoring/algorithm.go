// Package scoring implements the deterministic, fail-closed security scoring
// algorithm used to decide whether AI-generated code may be used or executed.
//
// Scoring formula (documented contract, do not change silently):
//
//	final = SAST*sast_weight + Deps*dep_weight + Policy*policy_weight + Sandbox*sandbox_weight
//
// where each stage sub-score is 0–100 and the weights default to
// 0.40/0.30/0.20/0.10 (normalised if they do not sum to 1.0).
//
// The numeric score is advisory. The final verdict is authoritative and
// fail-closed:
//
//   - execution that was attempted and failed  -> EXECUTION_FAILED
//   - a mandatory check could not complete     -> ANALYSIS_INCOMPLETE (fail-closed)
//   - any CRITICAL finding or vulnerability    -> BLOCKED
//   - otherwise                                -> APPROVED / WARNING / REJECTED by threshold
//
// A score must never override a critical finding, a sandbox failure, or
// incomplete analysis. No verdict is a security guarantee.
package scoring

import (
	"math"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// Calculator computes the final security score and verdict from pipeline results.
type Calculator struct {
	cfg config.ScoringConfig
}

// New returns a Calculator using the provided scoring configuration.
func New(cfg config.ScoringConfig) *Calculator {
	return &Calculator{cfg: cfg}
}

// passThreshold returns the score at or above which a result is APPROVED,
// defaulting to 70 when the configured value is out of range.
func (c *Calculator) passThreshold() int {
	if c.cfg.PassThreshold <= 0 || c.cfg.PassThreshold > 100 {
		return 70
	}
	return c.cfg.PassThreshold
}

// effectiveWeights returns the stage weights, normalised so they sum to 1.0.
// If the configured weights are all zero, the documented defaults are used.
func (c *Calculator) effectiveWeights() (sast, deps, policy, sandbox float64) {
	sast = c.cfg.SASTWeight
	deps = c.cfg.DepWeight
	policy = c.cfg.PolicyWeight
	sandbox = c.cfg.SandboxWeight

	total := sast + deps + policy + sandbox
	if total <= 0 {
		return 0.40, 0.30, 0.20, 0.10
	}
	return sast / total, deps / total, policy / total, sandbox / total
}

// Compute takes the results of all pipeline stages and returns the per-stage
// sub-scores, the weighted final score (0–100), and the final verdict.
//
// analysisComplete must be false when any mandatory check (static analysis,
// dependency audit, policy check, or a required sandbox run) could not be
// performed. In fail-closed mode an incomplete analysis is never scored as
// safe. The result is deterministic: identical inputs always produce the
// identical score and verdict.
func (c *Calculator) Compute(
	findings []sec.Finding,
	vulns []sec.Vulnerability,
	violations []sec.PolicyViolation,
	sandbox sec.SandboxResult,
	analysisComplete bool,
) (sec.StageScores, int, sec.Verdict) {

	stages := sec.StageScores{
		SAST:    c.scoreSAST(findings),
		Deps:    c.scoreDeps(vulns),
		Policy:  c.scorePolicy(violations),
		Sandbox: c.scoreSandbox(sandbox),
	}

	wSAST, wDeps, wPolicy, wSandbox := c.effectiveWeights()
	final := int(math.Round(
		float64(stages.SAST)*wSAST +
			float64(stages.Deps)*wDeps +
			float64(stages.Policy)*wPolicy +
			float64(stages.Sandbox)*wSandbox,
	))
	final = clamp(final, 0, 100)

	hasCritical := hasCriticalFindings(findings) || hasCriticalVulns(vulns)

	verdict := c.verdict(final, sandbox, hasCritical, analysisComplete)
	return stages, final, verdict
}

// verdict implements the fail-closed decision order. Hard conditions are
// evaluated first and cannot be overridden by a high numeric score.
func (c *Calculator) verdict(final int, sandbox sec.SandboxResult, hasCritical, analysisComplete bool) sec.Verdict {
	// 1. The sandbox attempted to run the code and the run failed. This is a
	//    hard stop: execution was attempted, so the code demonstrably failed
	//    at runtime, regardless of the static score.
	if sandbox.Executed && !sandbox.Success {
		return sec.VerdictExecutionFailed
	}

	// 2. A mandatory check could not be completed. Fail closed by default so
	//    a partial result is never presented as safe. In fail-open mode the
	//    score is still computed but the verdict can never be APPROVED.
	if !analysisComplete {
		if c.cfg.FailClosed {
			return sec.VerdictAnalysisIncomplete
		}
		if final >= c.passThreshold() {
			return sec.VerdictWarning
		}
		return sec.VerdictRejected
	}

	// 3. A critical finding or critical vulnerability is present. BLOCKED is a
	//    hard stop and overrides the numeric score: one CRITICAL issue is not
	//    cancelled out by clean results in other stages.
	if hasCritical {
		return sec.VerdictBlocked
	}

	// 4. Threshold verdicts on the deterministic score.
	if final >= c.passThreshold() {
		return sec.VerdictApproved
	}
	if final >= 40 {
		return sec.VerdictWarning
	}
	return sec.VerdictRejected
}

// ─── Stage sub-scores ─────────────────────────────────────────────────────────

// scoreSAST subtracts severity points per finding, starting from 100.
func (c *Calculator) scoreSAST(findings []sec.Finding) int {
	score := 100
	for _, f := range findings {
		score -= f.Severity.SeverityScore()
	}
	return clamp(score, 0, 100)
}

// scoreDeps subtracts severity points per known vulnerability, starting from 100.
func (c *Calculator) scoreDeps(vulns []sec.Vulnerability) int {
	score := 100
	for _, v := range vulns {
		score -= v.Severity.SeverityScore()
	}
	return clamp(score, 0, 100)
}

// scorePolicy deducts 20 points per policy violation, starting from 100.
func (c *Calculator) scorePolicy(violations []sec.PolicyViolation) int {
	score := 100 - (len(violations) * 20)
	return clamp(score, 0, 100)
}

// scoreSandbox awards points based on the sandbox result.
//   - deliberately skipped (user opted out via --no-sandbox): no penalty
//   - execution was required but could not run: partial credit only
//   - executed and failed: zero
//   - executed and succeeded: full marks
//
// Note: a required sandbox that could not run also sets analysisComplete=false
// in the pipeline, so the verdict is governed by fail-closed logic rather than
// this sub-score alone.
func (c *Calculator) scoreSandbox(result sec.SandboxResult) int {
	switch {
	case result.Skipped:
		return 100 // deliberate opt-out, not penalised
	case !result.Executed:
		return 50 // required but could not run
	case !result.Success:
		return 0 // executed and failed — hard zero
	default:
		return 100
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func hasCriticalFindings(findings []sec.Finding) bool {
	for _, f := range findings {
		if f.Severity == sec.SeverityCritical {
			return true
		}
	}
	return false
}

func hasCriticalVulns(vulns []sec.Vulnerability) bool {
	for _, v := range vulns {
		if v.Severity == sec.SeverityCritical {
			return true
		}
	}
	return false
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
