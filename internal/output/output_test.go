package output

import (
	"bytes"
	"strings"
	"testing"

	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

func sampleReport() *sec.Report {
	return &sec.Report{
		ID:            "scan-123",
		Prompt:        "write a REST handler with very long prompt text that gets truncated",
		Language:      "go",
		FinalScore:    92,
		Verdict:       sec.VerdictApproved,
		AIProvider:    "openai",
		AIModel:       "gpt-4o",
		GeneratedCode: "package main",
		StageScores:   sec.StageScores{SAST: 95, Deps: 90, Policy: 100, Sandbox: 100},
		Findings: []sec.Finding{
			{ID: "f1", RuleID: "G101", Title: "hardcoded credential", Description: "key in code", Suggestion: "remove it", Severity: sec.SeverityLow, Line: 3, Source: "gosec"},
		},
	}
}

func TestReporterFormats(t *testing.T) {
	cases := []struct {
		format string
		want   string
	}{
		{"json", `"final_score": 92`},
		{"plain", "Score    : 92/100"},
		{"sarif", `"version": "2.1.0"`},
		{"rich", "Verdict"},
		{"unknown-format-falls-back-to-rich", "Verdict"},
	}
	for _, c := range cases {
		t.Run(c.format, func(t *testing.T) {
			var buf bytes.Buffer
			r := NewReporter(c.format, true, &buf)
			if err := r.Print(sampleReport()); err != nil {
				t.Fatalf("Print(%s): %v", c.format, err)
			}
			if !strings.Contains(buf.String(), c.want) {
				t.Errorf("%s output missing %q:\n%s", c.format, c.want, buf.String())
			}
		})
	}
}

func TestReporterNilWriterDefaultsToStdout(t *testing.T) {
	r := NewReporter("json", false, nil)
	if r.out == nil {
		t.Error("nil writer should fall back to os.Stdout")
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 60); got != "short" {
		t.Errorf("truncate short = %q", got)
	}
	long := strings.Repeat("x", 100)
	got := truncate(long, 60)
	if len(got) != 60 || !strings.HasSuffix(got, "...") {
		t.Errorf("truncate long = %q (len %d)", got, len(got))
	}
}

func TestVerdictIcon(t *testing.T) {
	if verdictIcon(sec.VerdictApproved) != "✓" {
		t.Error("approved icon")
	}
	if verdictIcon(sec.VerdictWarning) != "⚠" {
		t.Error("warning icon")
	}
	if verdictIcon(sec.VerdictRejected) != "✗" {
		t.Error("rejected icon")
	}
	if verdictIcon(sec.VerdictBlocked) != "✗" {
		t.Error("blocked icon")
	}
}

