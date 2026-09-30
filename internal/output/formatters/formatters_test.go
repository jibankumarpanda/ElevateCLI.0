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

// fixedReport returns a report whose fix loop converged, plus one whose round was
// rolled back, so both outcomes are covered.
func fixedReport() *sec.Report {
	r := formatterReport()
	r.FinalScore = 100
	r.Verdict = sec.VerdictApproved
	r.Fix = &sec.FixLoopSummary{
		PreFixScore:    68,
		PreFixVerdict:  sec.VerdictWarning,
		PostFixScore:   100,
		PostFixVerdict: sec.VerdictApproved,
		StoppedCleanly: true,
		StopReason:     "converged: verdict is APPROVED",
		FixRounds: []sec.FixRound{
			{
				Round: 1, Strategy: sec.FixStrategyMechanical, Accepted: true,
				Repairs:        []string{"removed blocked import \"os/exec\""},
				PreFixScore:    68,
				PostFixScore:   100,
				PreFixVerdict:  sec.VerdictWarning,
				PostFixVerdict: sec.VerdictApproved,
			},
			{
				Round: 2, Strategy: sec.FixStrategySemantic, Accepted: false,
				Unrepairable:   []string{"patch regressed the score from 100 to 91 and was rolled back"},
				PreFixScore:    100,
				PostFixScore:   100,
				PreFixVerdict:  sec.VerdictApproved,
				PostFixVerdict: sec.VerdictApproved,
			},
		},
	}
	return r
}

func TestPlainRendersFixSummary(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintPlain(&buf, fixedReport(), false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Repair Loop (2 rounds)",
		"68 → 100",
		"converged: verdict is APPROVED",
		"mechanical",
		"semantic",
		"rolled back",
		"removed blocked import",
		"patch regressed the score",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plain fix summary missing %q:\n%s", want, out)
		}
	}
}

func TestRichRendersFixSummary(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintRich(&buf, fixedReport(), false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Repair Loop", "68", "100", "converged", "rolled back"} {
		if !strings.Contains(out, want) {
			t.Errorf("rich fix summary missing %q:\n%s", want, out)
		}
	}
}

func TestFormattersOmitFixSectionWhenNoLoopRan(t *testing.T) {
	// A report from a plain scan has no fix summary; the section must not appear
	// so a clean run is not made to look like it went through a repair loop.
	for name, print := range map[string]func(*bytes.Buffer) error{
		"plain": func(b *bytes.Buffer) error { return PrintPlain(b, formatterReport(), true) },
		"rich":  func(b *bytes.Buffer) error { return PrintRich(b, formatterReport(), true) },
	} {
		var buf bytes.Buffer
		if err := print(&buf); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(buf.String(), "Repair Loop") {
			t.Errorf("%s printed a fix section for a report that had no repair loop", name)
		}
	}
}

func TestJSONIncludesFixSummary(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintJSON(&buf, fixedReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{`"pre_fix_score": 68`, `"post_fix_score": 100`, `"fix_rounds"`} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON missing %q:\n%s", want, out)
		}
	}
}

func TestPluralS(t *testing.T) {
	if got := pluralS(1); got != "" {
		t.Errorf("pluralS(1) = %q, want empty", got)
	}
	if got := pluralS(2); got != "s" {
		t.Errorf("pluralS(2) = %q, want \"s\"", got)
	}
}
