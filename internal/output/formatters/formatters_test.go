package formatters

import (
	"bytes"
	"strings"
	"testing"
	"time"

	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

func formatterReport() *sec.Report {
	return &sec.Report{
		ID:            "scan-123",
		Prompt:        "a short prompt",
		Language:      "go",
		FinalScore:    92,
		Verdict:       sec.VerdictApproved,
		AIProvider:    "openai",
		AIModel:       "gpt-4o",
		GeneratedCode: "package main\n",
		StageScores:   sec.StageScores{SAST: 95, Deps: 90, Policy: 100, Sandbox: 100},
		Findings: []sec.Finding{
			{ID: "f1", RuleID: "G101", Title: "hardcoded credential", Description: "key in code", Suggestion: "remove it", Severity: sec.SeverityLow, Line: 3, Source: "gosec"},
		},
		Violations: []sec.PolicyViolation{
			{Rule: "BLOCKED_IMPORT", Description: "os/exec blocked", File: "generated.go", Line: 1},
		},
	}
}

func TestPrintJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintJSON(&buf, formatterReport()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"scan-123"`) {
		t.Errorf("JSON missing scan id: %s", buf.String())
	}
}

func TestPrintPlain(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintPlain(&buf, formatterReport(), true); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Scan ID", "score", "SAST", "LOW", "hardcoded credential"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("plain output missing %q:\n%s", want, buf.String())
		}
	}
}

func TestPrintSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintSARIF(&buf, formatterReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{`"version": "2.1.0"`, `"G101"`, `"ruleId"`, "BLOCKED_IMPORT"} {
		if !strings.Contains(out, want) {
			t.Errorf("SARIF missing %q", want)
		}
	}
}

func TestSARIFLevel(t *testing.T) {
	cases := []struct {
		sev  sec.Severity
		want string
	}{
		{sec.SeverityCritical, "error"},
		{sec.SeverityHigh, "error"},
		{sec.SeverityMedium, "warning"},
		{sec.SeverityLow, "note"},
		{sec.SeverityInfo, "note"},
	}
	for _, c := range cases {
		if got := sarifLevel(c.sev); got != c.want {
			t.Errorf("sarifLevel(%s) = %q, want %q", c.sev, got, c.want)
		}
	}
}

func TestSummaryLine(t *testing.T) {
	line := SummaryLine("id1", time.Date(2026, 8, 15, 10, 30, 0, 0, time.UTC), "prompt", 85, sec.VerdictApproved, "go")
	if !strings.Contains(line, "85/100") || !strings.Contains(line, "go") {
		t.Errorf("SummaryLine = %q", line)
	}
	if !strings.Contains(line, "2026-08-15 10:30") {
		t.Errorf("SummaryLine missing timestamp: %q", line)
	}
}

func TestSummaryLineTruncatesPrompt(t *testing.T) {
	long := strings.Repeat("x", 200)
	line := SummaryLine("id", time.Time{}, long, 10, sec.VerdictRejected, "py")
	if strings.Count(line, "x") > 56 {
		t.Errorf("prompt not truncated: %q", line)
	}
}
