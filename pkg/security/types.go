package security

import "time"

// Severity represents the security impact level.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Finding represents a single security issue found during analysis.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Line        int      `json:"line"`
	File        string   `json:"file"`
	Tool        string   `json:"tool"`
	Suggestion  string   `json:"suggestion"`
}

// Vulnerability represents a dependency-related security issue.
type Vulnerability struct {
	ID             string   `json:"id"`
	Package        string   `json:"package"`
	CurrentVersion string   `json:"current_version"`
	FixedVersion   string   `json:"fixed_version"`
	Description    string   `json:"description"`
	CVEs           []string `json:"cves"`
	Severity       Severity `json:"severity"`
}

// Report aggregates all findings and scores for a specific piece of code.
type Report struct {
	Prompt         string          `json:"prompt"`
	GeneratedCode  string          `json:"generated_code"`
	Language       string          `json:"language"`
	Timestamp      time.Time       `json:"timestamp"`
	Findings       []Finding       `json:"findings"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	PolicyViolations []Finding      `json:"policy_violations"`
	SandboxResult  SandboxResult   `json:"sandbox_result"`
	Score          int             `json:"score"`
	Verdict        Verdict         `json:"verdict"`
}

// SandboxResult contains the outcome of the code execution.
type SandboxResult struct {
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exit_code"`
	Duration   time.Duration `json:"duration"`
	Suspicious bool   `json:"suspicious"`
	Error      string `json:"error,omitempty"`
}

// Verdict represents the final security decision.
type Verdict string

const (
	VerdictApproved Verdict = "APPROVED"
	VerdictWarning  Verdict = "WARNING"
	VerdictRejected Verdict = "REJECTED"
)
