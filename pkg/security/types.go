// Package security provides shared types used across the entire ElevatedCLI
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

// PolicyViolation represents a rule broken by the generated code.
type PolicyViolation struct {
	Rule        string `json:"rule"`
	Description string `json:"description"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Value       string `json:"value"` // the blocked import/function found
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
