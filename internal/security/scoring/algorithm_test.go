package scoring

import (
	"testing"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// ─── Fixtures ─────────────────────────────────────────────────────────────────

func defaultCalc() *Calculator {
	// Zero-value config: weights 0.4/0.3/0.2/0.1, threshold 70, fail-closed.
	return New(config.ScoringConfig{})
}

func boolPtr(b bool) *bool { return &b }

func finding(sev sec.Severity) sec.Finding {
	return sec.Finding{ID: "test", Severity: sev}
}

func vuln(sev sec.Severity) sec.Vulnerability {
	return sec.Vulnerability{ID: "CVE-0000-0000", Severity: sev}
}

func violations(n int) []sec.PolicyViolation {
	out := make([]sec.PolicyViolation, n)
	for i := range out {
		out[i] = sec.PolicyViolation{Rule: "TEST", Value: "x"}
	}
	return out
}

var sandboxOK = sec.SandboxResult{Executed: true, Success: true, Mode: "process"}

var sandboxFailed = sec.SandboxResult{Executed: true, Success: false, ExitCode: 1, Mode: "process"}

var sandboxSkipped = sec.SandboxResult{Skipped: true, SkipReason: "opt-out", Mode: "none"}

var sandboxNotRun = sec.SandboxResult{Executed: false, Mode: "process"}

// ─── Clean result ─────────────────────────────────────────────────────────────

func TestCleanResultApproved(t *testing.T) {
	stages, final, verdict := defaultCalc().Compute(nil, nil, nil, sandboxOK, true)
	if stages.SAST != 100 || stages.Deps != 100 || stages.Policy != 100 || stages.Sandbox != 100 {
		t.Fatalf("unexpected stage scores: %+v", stages)
	}
	if final != 100 {
		t.Fatalf("final score = %d, want 100", final)
	}
	if verdict != sec.VerdictApproved {
		t.Fatalf("verdict = %q, want %q", verdict, sec.VerdictApproved)
	}
}

// ─── Critical findings/vulns hard-block ──────────────────────────────────────

func TestCriticalFindingBlocksHighScore(t *testing.T) {
	// One CRITICAL finding (25 pts) with everything else clean still scores 90,
	// but a numeric score must never override a critical issue.
	stages, final, verdict := defaultCalc().Compute(
		[]sec.Finding{finding(sec.SeverityCritical)},
		nil, nil, sandboxOK, true,
	)
	if stages.SAST != 75 {
		t.Fatalf("SAST = %d, want 75", stages.SAST)
	}
	if final != 90 {
		t.Fatalf("final = %d, want 90", final)
	}
	if verdict != sec.VerdictBlocked {
		t.Fatalf("verdict = %q, want %q", verdict, sec.VerdictBlocked)
	}
}

func TestCriticalVulnBlocksHighScore(t *testing.T) {
	_, final, verdict := defaultCalc().Compute(
		nil,
		[]sec.Vulnerability{vuln(sec.SeverityCritical)},
		nil, sandboxOK, true,
	)
	if final != 93 { // Deps = 75 → 40 + 22.5 + 20 + 10 = 92.5 → 93
		t.Fatalf("final = %d, want 93", final)
	}
	if verdict != sec.VerdictBlocked {
		t.Fatalf("verdict = %q, want %q", verdict, sec.VerdictBlocked)
	}
}

// ─── Sandbox execution failure hard-blocks ───────────────────────────────────

func TestSandboxExecutedFailedHardBlocks(t *testing.T) {
	// Code ran and crashed in the sandbox: hard stop, even with a perfect
	// static picture and even if the analysis was otherwise incomplete.
	stages, final, verdict := defaultCalc().Compute(nil, nil, nil, sandboxFailed, false)
	if stages.Sandbox != 0 {
		t.Fatalf("sandbox stage = %d, want 0", stages.Sandbox)
	}
	if final != 90 {
		t.Fatalf("final = %d, want 90", final)
	}
	if verdict != sec.VerdictExecutionFailed {
		t.Fatalf("verdict = %q, want %q", verdict, sec.VerdictExecutionFailed)
	}
}

// ─── Fail-closed incomplete analysis ─────────────────────────────────────────

func TestIncompleteAnalysisFailClosedByDefault(t *testing.T) {
	// Zero-value config (FailClosed == nil) must fail closed: a clean-looking
	// result with an incomplete analysis is never APPROVED.
	_, final, verdict := defaultCalc().Compute(nil, nil, nil, sandboxOK, false)
	if final != 100 {
		t.Fatalf("final = %d, want 100", final)
	}
	if verdict != sec.VerdictAnalysisIncomplete {
		t.Fatalf("verdict = %q, want %q", verdict, sec.VerdictAnalysisIncomplete)
	}
}

func TestIncompleteAnalysisExplicitFailOpenHighScore(t *testing.T) {
	calc := New(config.ScoringConfig{FailClosed: boolPtr(false)})
	_, final, verdict := calc.Compute(nil, nil, nil, sandboxOK, false)
	if final != 100 {
		t.Fatalf("final = %d, want 100", final)
	}
	if verdict != sec.VerdictWarning { // would be APPROVED, capped at WARNING
		t.Fatalf("verdict = %q, want %q", verdict, sec.VerdictWarning)
	}
}

func TestIncompleteAnalysisExplicitFailOpenLowScore(t *testing.T) {
	calc := New(config.ScoringConfig{FailClosed: boolPtr(false)})
	lowFindings := []sec.Finding{
		finding(sec.SeverityHigh), finding(sec.SeverityHigh), finding(sec.SeverityHigh),
		finding(sec.SeverityHigh), finding(sec.SeverityHigh), finding(sec.SeverityHigh),
		finding(sec.SeverityMedium),
	}
	_, final, verdict := calc.Compute(
		lowFindings,
		[]sec.Vulnerability{
			vuln(sec.SeverityHigh), vuln(sec.SeverityHigh),
			vuln(sec.SeverityHigh), vuln(sec.SeverityHigh),
		},
		violations(5), sandboxOK, false,
	)
	if final != 23 {
		t.Fatalf("final = %d, want 23", final)
	}
	if verdict != sec.VerdictRejected {
		t.Fatalf("verdict = %q, want %q", verdict, sec.VerdictRejected)
	}
}

func TestIncompleteBeatsCriticalFinding(t *testing.T) {
	// Verdict order: incomplete analysis is evaluated before critical findings,
	// because with a missing scanner we cannot even determine the full picture.
	_, _, verdict := defaultCalc().Compute(
		[]sec.Finding{finding(sec.SeverityCritical)},
		nil, nil, sandboxOK, false,
	)
	if verdict != sec.VerdictAnalysisIncomplete {
		t.Fatalf("verdict = %q, want %q", verdict, sec.VerdictAnalysisIncomplete)
	}
}

// ─── Threshold verdicts ──────────────────────────────────────────────────────

func TestWarningScore(t *testing.T) {
	// SAST = 21 (4 High + 2 Medium + 1 Low = 79 pts) → 0.4*21+30+20+10 = 68.4 → 68.
	findings := []sec.Finding{
		finding(sec.SeverityHigh), finding(sec.SeverityHigh),
		finding(sec.SeverityHigh), finding(sec.SeverityHigh),
		finding(sec.SeverityMedium), finding(sec.SeverityMedium),
		finding(sec.SeverityLow),
	}
	_, final, verdict := defaultCalc().Compute(findings, nil, nil, sandboxOK, true)
	if final != 68 {
		t.Fatalf("final = %d, want 68", final)
	}
	if verdict != sec.VerdictWarning {
		t.Fatalf("verdict = %q, want %q", verdict, sec.VerdictWarning)
	}
}

func TestRejectedScore(t *testing.T) {
	// SAST = 2, Deps = 40, Policy = 0, Sandbox = 100 →
	// 0.4*2 + 0.3*40 + 0.2*0 + 0.1*100 = 22.8 → 23. No critical present.
	findings := []sec.Finding{
		finding(sec.SeverityHigh), finding(sec.SeverityHigh), finding(sec.SeverityHigh),
		finding(sec.SeverityHigh), finding(sec.SeverityHigh), finding(sec.SeverityHigh),
		finding(sec.SeverityMedium),
	}
	vulns := []sec.Vulnerability{
		vuln(sec.SeverityHigh), vuln(sec.SeverityHigh),
		vuln(sec.SeverityHigh), vuln(sec.SeverityHigh),
	}
	_, final, verdict := defaultCalc().Compute(findings, vulns, violations(5), sandboxOK, true)
	if final != 23 {
		t.Fatalf("final = %d, want 23", final)
	}
	if verdict != sec.VerdictRejected {
		t.Fatalf("verdict = %q, want %q", verdict, sec.VerdictRejected)
	}
}

// ─── Determinism ─────────────────────────────────────────────────────────────

func TestDeterministic(t *testing.T) {
	findings := []sec.Finding{
		finding(sec.SeverityHigh), finding(sec.SeverityHigh),
		finding(sec.SeverityMedium), finding(sec.SeverityMedium),
		finding(sec.SeverityLow),
	}
	in := func() ([]sec.Finding, []sec.Vulnerability, []sec.PolicyViolation, sec.SandboxResult, bool) {
		// Rebuild the inputs each call to prove no internal mutation leaks.
		return append([]sec.Finding{}, findings...),
			[]sec.Vulnerability{vuln(sec.SeverityMedium)},
			violations(1), sandboxOK, true
	}

	s1, f1, v1 := defaultCalc().Compute(in())
	s2, f2, v2 := defaultCalc().Compute(in())
	if s1 != s2 || f1 != f2 || v1 != v2 {
		t.Fatalf("nondeterministic: first=%+v %d %q second=%+v %d %q", s1, f1, v1, s2, f2, v2)
	}
}

// ─── Weight handling ─────────────────────────────────────────────────────────

func TestWeightsNormalised(t *testing.T) {
	// All weights equal (sum 4 → normalised to 0.25 each).
	calc := New(config.ScoringConfig{
		SASTWeight: 1, DepWeight: 1, PolicyWeight: 1, SandboxWeight: 1,
	})
	// SAST = 52 (3 High + 1 Low = 48 pts) → 0.25*52 + 0.25*300 = 88.
	findings := []sec.Finding{
		finding(sec.SeverityHigh), finding(sec.SeverityHigh), finding(sec.SeverityHigh),
		finding(sec.SeverityLow),
	}
	_, final, _ := calc.Compute(findings, nil, nil, sandboxOK, true)
	if final != 88 {
		t.Fatalf("final = %d, want 88", final)
	}
}

func TestZeroWeightsUseDefaults(t *testing.T) {
	// Same input as TestWeightsNormalised, but zero weights must fall back to
	// the documented defaults (0.4/0.3/0.2/0.1): 0.4*52+30+20+10 = 80.8 → 81.
	findings := []sec.Finding{
		finding(sec.SeverityHigh), finding(sec.SeverityHigh), finding(sec.SeverityHigh),
		finding(sec.SeverityLow),
	}
	_, final, _ := defaultCalc().Compute(findings, nil, nil, sandboxOK, true)
	if final != 81 {
		t.Fatalf("final = %d, want 81", final)
	}
}

// ─── Threshold configuration ─────────────────────────────────────────────────

func TestOutOfRangeThresholdFallsBackTo70(t *testing.T) {
	for _, th := range []int{0, -5, 101, 200} {
		calc := New(config.ScoringConfig{PassThreshold: th})
		_, _, verdict := calc.Compute(nil, nil, nil, sandboxOK, true)
		if verdict != sec.VerdictApproved {
			t.Fatalf("threshold %d: verdict = %q, want %q", th, verdict, sec.VerdictApproved)
		}
	}
}

func TestCustomThreshold(t *testing.T) {
	// final 81 with a 90 threshold must not approve.
	calc := New(config.ScoringConfig{PassThreshold: 90})
	findings := []sec.Finding{
		finding(sec.SeverityHigh), finding(sec.SeverityHigh), finding(sec.SeverityHigh),
		finding(sec.SeverityLow),
	}
	_, final, verdict := calc.Compute(findings, nil, nil, sandboxOK, true)
	if final != 81 {
		t.Fatalf("final = %d, want 81", final)
	}
	if verdict != sec.VerdictWarning {
		t.Fatalf("verdict = %q, want %q", verdict, sec.VerdictWarning)
	}
}

// ─── Sandbox sub-score semantics ─────────────────────────────────────────────

func TestSandboxSubScores(t *testing.T) {
	cases := []struct {
		name     string
		sandbox  sec.SandboxResult
		want     int
		complete bool // for these cases analysis is complete
	}{
		{"executed success", sec.SandboxResult{Executed: true, Success: true, Mode: "process"}, 100, true},
		{"executed failed", sec.SandboxResult{Executed: true, Success: false, Mode: "process"}, 0, true},
		{"deliberately skipped", sec.SandboxResult{Skipped: true, SkipReason: "opt-out"}, 100, true},
		{"required but not run", sec.SandboxResult{Executed: false, Mode: "process"}, 50, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stages, _, _ := defaultCalc().Compute(nil, nil, nil, tc.sandbox, tc.complete)
			if stages.Sandbox != tc.want {
				t.Fatalf("sandbox stage = %d, want %d", stages.Sandbox, tc.want)
			}
		})
	}
}

func TestSkippedSandboxIsNotIncomplete(t *testing.T) {
	// A deliberate opt-out (--no-sandbox) is a complete analysis: the user
	// accepted the risk, so this is APPROVED, not ANALYSIS_INCOMPLETE.
	_, final, verdict := defaultCalc().Compute(nil, nil, nil, sandboxSkipped, true)
	if final != 100 || verdict != sec.VerdictApproved {
		t.Fatalf("final=%d verdict=%q, want 100/%q", final, verdict, sec.VerdictApproved)
	}
}

func TestRequiredSandboxNotRunIsIncomplete(t *testing.T) {
	// A required sandbox that did not execute sets analysisComplete=false in
	// the pipeline; the fail-closed calculator must refuse to approve.
	_, _, verdict := defaultCalc().Compute(nil, nil, nil, sandboxNotRun, false)
	if verdict != sec.VerdictAnalysisIncomplete {
		t.Fatalf("verdict = %q, want %q", verdict, sec.VerdictAnalysisIncomplete)
	}
}

// ─── Policy and dependency scoring ───────────────────────────────────────────

func TestPolicyScoreClamps(t *testing.T) {
	// 6 violations → Policy = 100 - 120 = -20 → clamped to 0.
	stages, final, _ := defaultCalc().Compute(nil, nil, violations(6), sandboxOK, true)
	if stages.Policy != 0 {
		t.Fatalf("policy stage = %d, want 0", stages.Policy)
	}
	if final != 70 { // 40 + 30 + 0 + 10
		t.Fatalf("final = %d, want 70", final)
	}
}

func TestDependencyScoreBySeverity(t *testing.T) {
	// 1 High + 1 Medium + 1 Low = 15 + 8 + 3 = 26 → Deps = 74.
	stages, _, _ := defaultCalc().Compute(
		nil,
		[]sec.Vulnerability{
			vuln(sec.SeverityHigh), vuln(sec.SeverityMedium), vuln(sec.SeverityLow),
		},
		nil, sandboxOK, true,
	)
	if stages.Deps != 74 {
		t.Fatalf("deps stage = %d, want 74", stages.Deps)
	}
}

func TestInfoFindingsScoreZero(t *testing.T) {
	// INFO findings carry no penalty but never trigger blocking.
	stages, final, verdict := defaultCalc().Compute(
		[]sec.Finding{finding(sec.SeverityInfo), finding(sec.SeverityInfo)},
		nil, nil, sandboxOK, true,
	)
	if stages.SAST != 100 || final != 100 || verdict != sec.VerdictApproved {
		t.Fatalf("sast=%d final=%d verdict=%q, want 100/100/%q",
			stages.SAST, final, verdict, sec.VerdictApproved)
	}
}
