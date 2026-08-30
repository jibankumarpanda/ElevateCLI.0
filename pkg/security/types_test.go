package security

import "testing"

// ─── SeverityScore ────────────────────────────────────────────────────────────

func TestSeverityScore(t *testing.T) {
	cases := []struct {
		sev  Severity
		want int
	}{
		{SeverityCritical, 25},
		{SeverityHigh, 15},
		{SeverityMedium, 8},
		{SeverityLow, 3},
		{SeverityInfo, 0},
		{Severity("unknown"), 0},
	}
	for _, c := range cases {
		if got := c.sev.SeverityScore(); got != c.want {
			t.Errorf("SeverityScore(%q) = %d, want %d", c.sev, got, c.want)
		}
	}
}

// ─── Report helpers ───────────────────────────────────────────────────────────

func TestFindingsBySeverity(t *testing.T) {
	r := &Report{Findings: []Finding{
		{ID: "a", Severity: SeverityHigh},
		{ID: "b", Severity: SeverityCritical},
		{ID: "c", Severity: SeverityHigh},
	}}
	high := r.FindingsBySeverity(SeverityHigh)
	if len(high) != 2 {
		t.Fatalf("got %d high findings, want 2", len(high))
	}
	for _, f := range high {
		if f.Severity != SeverityHigh {
			t.Errorf("found finding %q with severity %q", f.ID, f.Severity)
		}
	}
}

func TestCriticalCount(t *testing.T) {
	r := &Report{Findings: []Finding{
		{ID: "a", Severity: SeverityCritical},
		{ID: "b", Severity: SeverityHigh},
		{ID: "c", Severity: SeverityCritical},
	}}
	if got := r.CriticalCount(); got != 2 {
		t.Fatalf("CriticalCount() = %d, want 2", got)
	}
}

func TestHasBlockers(t *testing.T) {
	cases := []struct {
		name   string
		report *Report
		want   bool
	}{
		{
			name:   "critical finding blocks",
			report: &Report{Findings: []Finding{{Severity: SeverityCritical}}},
			want:   true,
		},
		{
			name:   "failed sandbox blocks",
			report: &Report{Sandbox: SandboxResult{Executed: true, Success: false}},
			want:   true,
		},
		{
			name:   "clean approved",
			report: &Report{Sandbox: SandboxResult{Executed: true, Success: true}},
			want:   false,
		},
		{
			name:   "skipped sandbox does not block",
			report: &Report{Sandbox: SandboxResult{Skipped: true}},
			want:   false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.report.HasBlockers(); got != c.want {
				t.Errorf("HasBlockers() = %v, want %v", got, c.want)
			}
		})
	}
}

// ─── Error types ──────────────────────────────────────────────────────────────
	err := NewPipelineError("sast", "boom", nil)
	if got := err.Error(); got != "[sast] boom" {
		t.Errorf("Error() = %q, want %q", got, "[sast] boom")
	}
	withCause := NewPipelineError("sast", "boom", &ConfigError{Field: "x", Message: "bad"})
	if !contains(withCause.Error(), "[sast] boom") {
		t.Errorf("Error() = %q, want wrapped message", withCause.Error())
	}
	if withCause.Unwrap() == nil {
		t.Error("Unwrap() returned nil, want the cause")
	}
}

func TestErrorTypeStrings(t *testing.T) {
	if got := (&SandboxError{Mode: "process", Message: "oops", Err: nil}).Error(); got != "sandbox[process]: oops: <nil>" {
		t.Errorf("SandboxError = %q", got)
	}
	if got := (&ConfigError{Field: "ai.model", Message: "invalid"}).Error(); got != "config error [ai.model]: invalid" {
		t.Errorf("ConfigError = %q", got)
	}
	provErr := &AIProviderError{Provider: "openai", Message: "empty key", Err: nil}
	if got := provErr.Error(); got != "ai[openai]: empty key: <nil>" {
		t.Errorf("AIProviderError = %q", got)
	}
	if provErr.Unwrap() != nil {
		t.Error("AIProviderError.Unwrap() should be nil")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
