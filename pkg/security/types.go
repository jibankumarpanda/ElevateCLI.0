// Package security provides shared types used across the entire ElevateCLI
// security pipeline. Every other package imports from here — define once, use everywhere.
package security

import "time"

// ─── Severity levels ────────────────────────────────────────────────────────

// Severity represents how dangerous a finding is.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// SeverityScore returns the point deduction for a given severity.
func (s Severity) SeverityScore() int {
	switch s {
	case SeverityCritical:
		return 25
	case SeverityHigh:
		return 15
	case SeverityMedium:
		return 8
	case SeverityLow:
		return 3
	default:
		return 0
	}
}

// ─── Verdict ────────────────────────────────────────────────────────────────

// Verdict is the final decision on a piece of generated code.
//
// The verdict is the authoritative decision point of the pipeline. It is
// deterministic: identical inputs always produce the identical verdict.
// Verdicts are ordered by strictness for callers that need to compare them.
type Verdict string

const (
	// VerdictApproved means no blocking issues and a score at or above the
	// configured passing threshold.
	VerdictApproved Verdict = "APPROVED"

	// VerdictWarning means the score is below the passing threshold but not
	// critically low, or that analysis could not fully complete in fail-open
	// mode. The code should be reviewed before use.
	VerdictWarning Verdict = "WARNING"

	// VerdictRejected means the score is too low to be used.
	VerdictRejected Verdict = "REJECTED"

	// VerdictBlocked means a critical finding or critical vulnerability is
	// present. Blocked is a hard stop: it overrides the numeric score.
	VerdictBlocked Verdict = "BLOCKED"

	// VerdictAnalysisIncomplete means one or more mandatory security checks
	// could not be completed (e.g. a scanner binary is missing or a stage
	// errored) while fail-closed mode is enabled. It is a hard stop: a result
	// from incomplete analysis must never be treated as safe.
	VerdictAnalysisIncomplete Verdict = "ANALYSIS_INCOMPLETE"

	// VerdictExecutionFailed means the sandbox attempted to execute the code
	// and the execution failed (non-zero exit, timeout, or resource limit).
	// It is a hard stop regardless of the static score.
	VerdictExecutionFailed Verdict = "EXECUTION_FAILED"
)

// ─── Finding (SAST result) ───────────────────────────────────────────────────

// Finding represents a single static analysis result.
type Finding struct {
	ID          string   `json:"id"`
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Column      int      `json:"column"`
	Code        string   `json:"code"`       // snippet of offending code
	Suggestion  string   `json:"suggestion"` // how to fix it
	Source      string   `json:"source"`     // "gosec" | "semgrep" | "custom-ast"
}

// ─── Vulnerability (dependency audit result) ─────────────────────────────────

// Vulnerability represents a known CVE in a dependency.
type Vulnerability struct {
	ID           string   `json:"id"` // e.g. "CVE-2024-12345"
	Package      string   `json:"package"`
	Version      string   `json:"version"`
	FixedVersion string   `json:"fixed_version"` // empty if no fix yet
	Severity     Severity `json:"severity"`
	Description  string   `json:"description"`
	CVSS         float64  `json:"cvss"`
	Source       string   `json:"source"` // "govulncheck" | "osv-scanner"
}

// ─── Policy violation ────────────────────────────────────────────────────────

// Policy action values. A rule's action decides whether a violation blocks
// approval outright ("block") or is only advisory ("warn"). Blocking is the
// default so an unconfigured rule fails safe.
const (
	PolicyActionBlock = "block"
	PolicyActionWarn  = "warn"
)

// IsBlocking reports whether the action prevents an approving verdict.
// An empty action is treated as blocking for backward compatibility.
func (v PolicyViolation) IsBlocking() bool {
	return v.Action != PolicyActionWarn
}

// PolicyViolation represents a rule broken by the generated code.
type PolicyViolation struct {
	Rule        string   `json:"rule"`
	Description string   `json:"description"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Value       string   `json:"value"`    // the blocked import/function found
	Severity    Severity `json:"severity"` // severity assigned by the policy
	Action      string   `json:"action"`   // "block" | "warn"
}

// ─── Sandbox result ──────────────────────────────────────────────────────────

// SandboxResult captures what happened when the code was executed in isolation.
type SandboxResult struct {
	Executed      bool          `json:"executed"`
	Success       bool          `json:"success"`
	ExitCode      int           `json:"exit_code"`
	Stdout        string        `json:"stdout"`
	Stderr        string        `json:"stderr"`
	RuntimeErrors []string      `json:"runtime_errors"`
	Duration      time.Duration `json:"duration"`
	MemoryUsedMB  int           `json:"memory_used_mb"`
	CPUPercent    float64       `json:"cpu_percent"`
	Mode          string        `json:"mode"` // "firecracker" | "process" | "docker"
	Skipped       bool          `json:"skipped"`
	SkipReason    string        `json:"skip_reason"`
}

// ─── Stage scores ────────────────────────────────────────────────────────────

// StageScores holds the 0–100 sub-score for each pipeline stage.
type StageScores struct {
	SAST    int `json:"sast"`
	Deps    int `json:"deps"`
	Policy  int `json:"policy"`
	Sandbox int `json:"sandbox"`
}

// ─── Fix loop ────────────────────────────────────────────────────────────────

// FixStrategy identifies how the patch for a fix round was produced.
//
// The two strategies have different trust properties. FixStrategyMechanical
// patches come from deterministic rules with no LLM involvement, so they are
// reproducible from the findings alone. FixStrategySemantic patches were
// proposed by the same model class that produced the code under review, so
// they are never trusted: they must be re-verified by the full pipeline and
// reviewed by a human before use.
const (
	FixStrategyMechanical = "mechanical"
	FixStrategySemantic   = "semantic"
)

// FixRound records one pass of the fail-closed fix loop: what was changed,
// what the deterministic score and verdict were before and after, and the
// diff a human needs in order to review the change.
type FixRound struct {
	// Round is the 1-based round number within the loop.
	Round int `json:"round"`
	// Strategy is FixStrategyMechanical or FixStrategySemantic.
	Strategy string `json:"strategy"`
	// Repairs describes each mechanical repair that was applied in this
	// round, in application order. Empty means nothing was repairable.
	Repairs []string `json:"repairs,omitempty"`
	// PreFixScore and PostFixScore are the deterministic 0–100 scores
	// before and after the patch was re-verified.
	PreFixScore  int `json:"pre_fix_score"`
	PostFixScore int `json:"post_fix_score"`
	// PreFixVerdict and PostFixVerdict are the fail-closed verdicts before
	// and after. A round is only Accepted when the verdict did not regress.
	PreFixVerdict  Verdict `json:"pre_fix_verdict"`
	PostFixVerdict Verdict `json:"post_fix_verdict"`
	// Unrepairable lists violations that no mechanical rule could fix. They
	// are the reason a loop stops without going green.
	Unrepairable []string `json:"unrepairable,omitempty"`
	// Diff is the unified diff from the round's input code to its output.
	Diff string `json:"diff,omitempty"`
	// Accepted reports whether the patch was kept. It is false when no
	// repair applied, when the patched code failed to parse, or when the
	// deterministic score regressed — in which case the previous code is
	// kept and the loop stops.
	Accepted bool `json:"accepted"`
}

// FixLoopSummary is the aggregate outcome of the fix loop, embedded in Report.
type FixLoopSummary struct {
	// PreFixScore is the deterministic score of the original, unpatched code.
	PreFixScore int `json:"pre_fix_score"`
	// PreFixVerdict is the fail-closed verdict for the original code.
	PreFixVerdict Verdict `json:"pre_fix_verdict"`
	// PostFixScore is the deterministic score of the final code, recomputed
	// by re-running the full pipeline. It equals Report.FinalScore.
	PostFixScore int `json:"post_fix_score"`
	// PostFixVerdict is the fail-closed verdict for the final code. It
	// equals Report.Verdict.
	PostFixVerdict Verdict `json:"post_fix_verdict"`
	// FixRounds is the ordered per-round audit trail, including rounds that
	// were rolled back.
	FixRounds []FixRound `json:"fix_rounds"`
	// StoppedCleanly reports that the loop reached a terminal state
	// deliberately: either every rule-driven repair converged, or a blocking
	// condition was reached, or the round cap was hit. It never means the code
	// is safe — only that the loop is no longer running.
	StoppedCleanly bool `json:"stopped_cleanly"`
	// StopReason explains which terminal state was reached, for example
	// "converged" or "round cap reached".
	StopReason string `json:"stop_reason"`
}

// ─── Final security report ───────────────────────────────────────────────────

// Report is the complete result of the 4-stage pipeline for one piece of code.
type Report struct {
	ID            string            `json:"id"` // UUID
	Timestamp     time.Time         `json:"timestamp"`
	Prompt        string            `json:"prompt"`
	Language      string            `json:"language"`
	GeneratedCode string            `json:"generated_code"`
	CodeHash      string            `json:"code_hash"` // SHA-256, never store raw keys
	Findings      []Finding         `json:"findings"`
	Vulns         []Vulnerability   `json:"vulnerabilities"`
	Violations    []PolicyViolation `json:"policy_violations"`
	Sandbox       SandboxResult     `json:"sandbox"`
	StageScores   StageScores       `json:"stage_scores"`
	FinalScore    int               `json:"final_score"` // 0–100
	Verdict       Verdict           `json:"verdict"`
	// AnalysisComplete is false when a mandatory check could not run (missing
	// scanner binary, stage error, sandbox setup failure). In fail-closed mode
	// this forces VerdictAnalysisIncomplete so a partial result is never
	// presented as safe.
	AnalysisComplete bool          `json:"analysis_complete"`
	Duration         time.Duration `json:"total_duration"`
	AIProvider       string        `json:"ai_provider"`
	AIModel          string        `json:"ai_model"`
	// Fix is the fail-closed fix loop outcome. It is nil when no fix loop ran,
	// so a plain scan report is unchanged from the pre-fix-loop schema.
	Fix *FixLoopSummary `json:"fix,omitempty"`
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// FindingsBySeverity returns findings filtered to a specific severity.
func (r *Report) FindingsBySeverity(s Severity) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == s {
			out = append(out, f)
		}
	}
	return out
}

// CriticalCount returns the number of critical findings.
func (r *Report) CriticalCount() int {
	return len(r.FindingsBySeverity(SeverityCritical))
}

// HasBlockers returns true if there are any critical findings or sandbox failures.
func (r *Report) HasBlockers() bool {
	return r.CriticalCount() > 0 || (!r.Sandbox.Skipped && !r.Sandbox.Success)
}
