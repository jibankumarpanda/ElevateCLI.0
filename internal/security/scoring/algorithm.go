// Package scoring implements the weighted security scoring algorithm.
// Score = (SAST × 0.40) + (Deps × 0.30) + (Policy × 0.20) + (Sandbox × 0.10)
package scoring

import (
	// Package scoring implements the weighted security scoring algorithm.
// Score = (SAST × 0.40) + (Deps × 0.30) + (Policy × 0.20) + (Sandbox × 0.10)
package scoring

import (
	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// Calculator computes the final security score from pipeline results.
type Calculator struct {
	cfg config.ScoringConfig
}

// New returns a Calculator using the provided scoring weights.
func New(cfg config.ScoringConfig) *Calculator {
	return &Calculator{cfg: cfg}
}

// Compute takes the results of all 4 pipeline stages and returns
// per-stage scores, a weighted final score (0–100), and the verdict.
func (c *Calculator) Compute(
	findings []sec.Finding,
	vulns []sec.Vulnerability,
	violations []sec.PolicyViolation,
	sandbox sec.SandboxResult,
) (sec.StageScores, int, sec.Verdict) {

	stages := sec.StageScores{
		SAST:    c.scoreSAST(findings),
		Deps:    c.scoreDeps(vulns),
		Policy:  c.scorePolicy(violations),
		Sandbox: c.scoreSandbox(sandbox),
	}

	final := int(
		float64(stages.SAST)*c.cfg.SASTWeight +
			float64(stages.Deps)*c.cfg.DepWeight +
			float64(stages.Policy)*c.cfg.PolicyWeight +
			float64(stages.Sandbox)*c.cfg.SandboxWeight,
	)

	if final < 0 {
		final = 0
	}
	if final > 100 {
		final = 100
	}

	return stages, final, verdict(final, c.cfg.PassThreshold, sandbox)
}

// ─── Stage scorers ────────────────────────────────────────────────────────────

func (c *Calculator) scoreSAST(findings []sec.Finding) int {
	score := 100
	for _, f := range findings {
		score -= f.Severity.SeverityScore()
	}
	return clamp(score)
}

func (c *Calculator) scoreDeps(vulns []sec.Vulnerability) int {
	score := 100
	for _, v := range vulns {
		score -= v.Severity.SeverityScore()
	}
	return clamp(score)
}

func (c *Calculator) scorePolicy(violations []sec.PolicyViolation) int {
	score := 100 - (len(violations) * 20)
	return clamp(score)
}

func (c *Calculator) scoreSandbox(result sec.SandboxResult) int {
	if result.Skipped {
		return 100 // not penalised if intentionally skipped
	}
	if !result.Executed {
		return 50 // partial penalty if we couldn't execute
	}
	if !result.Success {
		return 0 // sandbox failure is a hard zero for this stage
	}
	return 100
}

// ─── Verdict ─────────────────────────────────────────────────────────────────

func verdict(score, threshold int, sandbox sec.SandboxResult) sec.Verdict {
	// Sandbox failure always rejects regardless of score
	if sandbox.Executed && !sandbox.Success {
		return sec.VerdictRejected
	}
	if score >= threshold {
		return sec.VerdictApproved
	}
	if score >= 40 {
		return sec.VerdictWarning
	}
	return sec.VerdictRejected
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func clamp(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// Calculator computes the final security score from pipeline results.
type Calculator struct {
	cfg config.ScoringConfig
}

// New returns a Calculator using the provided scoring weights.
func New(cfg config.ScoringConfig) *Calculator {
	return &Calculator{cfg: cfg}
}

// Compute takes the results of all 4 pipeline stages and returns
// per-stage scores, a weighted final score (0–100), and the verdict.
func (c *Calculator) Compute(
	findings []sec.Finding,
	vulns []sec.Vulnerability,
	violations []sec.PolicyViolation,
	sandbox sec.SandboxResult,
) (sec.StageScores, int, sec.Verdict) {

	stages := sec.StageScores{
		SAST:    c.scoreSAST(findings),
		Deps:    c.scoreDeps(vulns),
		Policy:  c.scorePolicy(violations),
		Sandbox: c.scoreSandbox(sandbox),
	}

	final := int(
		float64(stages.SAST)*c.cfg.SASTWeight +
			float64(stages.Deps)*c.cfg.DepWeight +
			float64(stages.Policy)*c.cfg.PolicyWeight +
			float64(stages.Sandbox)*c.cfg.SandboxWeight,
	)

	if final < 0 {
		final = 0
	}
	if final > 100 {
		final = 100
	}

	return stages, final, verdict(final, c.cfg.PassThreshold, sandbox)
}

// ─── Stage scorers ────────────────────────────────────────────────────────────

func (c *Calculator) scoreSAST(findings []sec.Finding) int {
	score := 100
	for _, f := range findings {
		score -= f.Severity.SeverityScore()
	}
	return clamp(score)
}

func (c *Calculator) scoreDeps(vulns []sec.Vulnerability) int {
	score := 100
	for _, v := range vulns {
		score -= v.Severity.SeverityScore()
	}
	return clamp(score)
}

func (c *Calculator) scorePolicy(violations []sec.PolicyViolation) int {
	score := 100 - (len(violations) * 20)
	return clamp(score)
}

func (c *Calculator) scoreSandbox(result sec.SandboxResult) int {
	if result.Skipped {
		return 100 // not penalised if intentionally skipped
	}
	if !result.Executed {
		return 50 // partial penalty if we couldn't execute
	}
	if !result.Success {
		return 0 // sandbox failure is a hard zero for this stage
	}
	return 100
}

// ─── Verdict ─────────────────────────────────────────────────────────────────

func verdict(score, threshold int, sandbox sec.SandboxResult) sec.Verdict {
	// Sandbox failure always rejects regardless of score
	if sandbox.Executed && !sandbox.Success {
		return sec.VerdictRejected
	}
	if score >= threshold {
		return sec.VerdictApproved
	}
	if score >= 40 {
		return sec.VerdictWarning
	}
	return sec.VerdictRejected
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func clamp(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
