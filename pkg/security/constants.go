package security

// Process exit codes used to signal a verdict to callers (e.g. CI/CD).
// A non-zero code means the generated/audited code must not be used as-is.
//
//	0  — non-blocking outcome (APPROVED / WARNING)
//	2  — REJECTED or BLOCKED: code failed verification or hit a hard stop
//	3  — ANALYSIS_INCOMPLETE: a required check could not complete (fail-closed)
//	4  — EXECUTION_FAILED: the sandbox ran the code and it failed at runtime
const (
	ExitCodeOK              = 0
	ExitCodeRejected        = 2
	ExitCodeAnalysisFailed  = 3
	ExitCodeExecutionFailed = 4
)

// ExitCodeFor maps a verdict to its process exit code. Non-blocking verdicts
// (APPROVED, WARNING) return ExitCodeOK so a clean scan does not gate a build.
// Every hard-stop verdict returns a distinct non-zero code so CI can both
// detect the failure and reason about its cause.
func ExitCodeFor(v Verdict) int {
	switch v {
	case VerdictRejected, VerdictBlocked:
		return ExitCodeRejected
	case VerdictAnalysisIncomplete:
		return ExitCodeAnalysisFailed
	case VerdictExecutionFailed:
		return ExitCodeExecutionFailed
	default: // APPROVED, WARNING
		return ExitCodeOK
	}
}
