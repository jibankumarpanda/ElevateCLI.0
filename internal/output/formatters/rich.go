// Package formatters provides output formatters for ElevatedCLI scan reports.
// rich.go produces a colorful, human-readable terminal display.
package formatters

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	sec "github.com/jibankumarpanda/ElevateCLI/pkg/security"
)

// ─── Colors ──────────────────────────────────────────────────────────────────

var (
	bold       = color.New(color.Bold)
	green      = color.New(color.FgGreen, color.Bold)
	yellow     = color.New(color.FgYellow, color.Bold)
	red        = color.New(color.FgRed, color.Bold)
	cyan       = color.New(color.FgCyan)
	white      = color.New(color.FgWhite)
	gray       = color.New(color.FgHiBlack)
	bgGreen    = color.New(color.BgGreen, color.FgBlack, color.Bold)
	bgYellow   = color.New(color.BgYellow, color.FgBlack, color.Bold)
	bgRed      = color.New(color.BgRed, color.FgWhite, color.Bold)
)

// PrintRich writes a fully formatted, color-coded report to w.
func PrintRich(w io.Writer, r *sec.Report, showCode bool) error {
	printDivider(w)
	printHeader(w, r)
	printDivider(w)
	printScoreBar(w, r)
	printStageScores(w, r)
	printDivider(w)

	if len(r.Findings) > 0 {
		printFindings(w, r.Findings)
	}
	if len(r.Vulns) > 0 {
		printVulns(w, r.Vulns)
	}
	if len(r.Violations) > 0 {
		printViolations(w, r.Violations)
	}
	if r.Sandbox.Executed {
		printSandbox(w, r.Sandbox)
	}

	if showCode && r.GeneratedCode != "" {
		printCode(w, r.GeneratedCode, r.Language)
	}

	printDivider(w)
	printVerdict(w, r)
	printDivider(w)
	return nil
}

// ─── Sections ─────────────────────────────────────────────────────────────────

func printHeader(w io.Writer, r *sec.Report) {
	fmt.Fprintf(w, "\n")
	bold.Fprintf(w, "  ElevatedCLI Security Report\n")
	gray.Fprintf(w, "  Scan ID : %s\n", r.ID)
	gray.Fprintf(w, "  Provider: %s / %s\n", r.AIProvider, r.AIModel)
	gray.Fprintf(w, "  Language: %s\n", r.Language)
	gray.Fprintf(w, "  Duration: %s\n", r.Duration.Round(1e6))
	fmt.Fprintf(w, "\n")
}

func printScoreBar(w io.Writer, r *sec.Report) {
	score := r.FinalScore
	barWidth := 40
	filled := (score * barWidth) / 100

	var bar strings.Builder
	for i := 0; i < barWidth; i++ {
		if i < filled {
			if score >= 70 {
				bar.WriteString("█")
			} else if score >= 40 {
				bar.WriteString("▓")
			} else {
				bar.WriteString("░")
			}
		} else {
			bar.WriteString("·")
		}
	}

	fmt.Fprintf(w, "  Security Score  ")
	switch {
	case score >= 70:
		green.Fprintf(w, "%3d/100", score)
	case score >= 40:
		yellow.Fprintf(w, "%3d/100", score)
	default:
		red.Fprintf(w, "%3d/100", score)
	}
	fmt.Fprintf(w, "  [%s]\n\n", bar.String())
}

func printStageScores(w io.Writer, r *sec.Report) {
	stages := []struct {
		name  string
		score int
		emoji string
	}{
		{"SAST          ", r.StageScores.SAST, "🔍"},
		{"Dependencies  ", r.StageScores.Deps, "📦"},
		{"Policy        ", r.StageScores.Policy, "📋"},
		{"Sandbox       ", r.StageScores.Sandbox, "🔒"},
	}
	for _, s := range stages {
		fmt.Fprintf(w, "  %s %s  ", s.emoji, s.name)
		scoreColor(w, s.score)
		fmt.Fprintf(w, "/100\n")
	}
	fmt.Fprintf(w, "\n")
}

func scoreColor(w io.Writer, score int) {
	switch {
	case score >= 70:
		green.Fprintf(w, "%3d", score)
	case score >= 40:
		yellow.Fprintf(w, "%3d", score)
	default:
		red.Fprintf(w, "%3d", score)
	}
}

func printFindings(w io.Writer, findings []sec.Finding) {
	bold.Fprintf(w, "  Static Analysis Findings (%d)\n", len(findings))
	fmt.Fprintf(w, "\n")
	for _, f := range findings {
		severityBadge(w, f.Severity)
		fmt.Fprintf(w, "  %s", f.Title)
		if f.Line > 0 {
			gray.Fprintf(w, " (line %d)", f.Line)
		}
		fmt.Fprintf(w, "\n")
		if f.Code != "" {
			gray.Fprintf(w, "     Code: %s\n", f.Code)
		}
		if f.Suggestion != "" {
			cyan.Fprintf(w, "     Fix:  %s\n", f.Suggestion)
		}
		fmt.Fprintf(w, "\n")
	}
}

func printVulns(w io.Writer, vulns []sec.Vulnerability) {
	bold.Fprintf(w, "  Vulnerable Dependencies (%d)\n", len(vulns))
	fmt.Fprintf(w, "\n")
	for _, v := range vulns {
		severityBadge(w, v.Severity)
		fmt.Fprintf(w, "  %s @ %s — %s\n", v.Package, v.Version, v.ID)
		if v.FixedVersion != "" {
			cyan.Fprintf(w, "     Fix: upgrade to %s\n", v.FixedVersion)
		}
		if v.Description != "" {
			gray.Fprintf(w, "     %s\n", v.Description)
		}
		fmt.Fprintf(w, "\n")
	}
}

func printViolations(w io.Writer, violations []sec.PolicyViolation) {
	bold.Fprintf(w, "  Policy Violations (%d)\n", len(violations))
	fmt.Fprintf(w, "\n")
	for _, v := range violations {
		red.Fprintf(w, "  [POLICY]")
		fmt.Fprintf(w, "  %s", v.Description)
		if v.Line > 0 {
			gray.Fprintf(w, " (line %d)", v.Line)
		}
		fmt.Fprintf(w, "\n")
	}
	fmt.Fprintf(w, "\n")
}

func printSandbox(w io.Writer, s sec.SandboxResult) {
	bold.Fprintf(w, "  Sandbox Execution\n")
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  Mode    : %s\n", s.Mode)
	fmt.Fprintf(w, "  Duration: %s\n", s.Duration.Round(1e6))

	if s.Success {
		green.Fprintf(w, "  Result  : PASS\n")
	} else {
		red.Fprintf(w, "  Result  : FAIL\n")
	}
	if s.Stdout != "" {
		gray.Fprintf(w, "\n  Output:\n")
		for _, line := range strings.Split(strings.TrimSpace(s.Stdout), "\n") {
			gray.Fprintf(w, "    %s\n", line)
		}
	}
	fmt.Fprintf(w, "\n")
}

func printCode(w io.Writer, code, lang string) {
	bold.Fprintf(w, "  Generated Code (%s)\n\n", lang)
	for _, line := range strings.Split(code, "\n") {
		gray.Fprintf(w, "  │ %s\n", line)
	}
	fmt.Fprintf(w, "\n")
}

func printVerdict(w io.Writer, r *sec.Report) {
	fmt.Fprintf(w, "\n  Verdict: ")
	switch r.Verdict {
	case sec.VerdictApproved:
		bgGreen.Fprintf(w, "  ✓  APPROVED  ")
		fmt.Fprintf(w, "  Score %d/100 — safe to use\n", r.FinalScore)
	case sec.VerdictWarning:
		bgYellow.Fprintf(w, "  ⚠  WARNING   ")
		fmt.Fprintf(w, "  Score %d/100 — review findings before using\n", r.FinalScore)
	case sec.VerdictRejected:
		bgRed.Fprintf(w, "  ✗  REJECTED  ")
		fmt.Fprintf(w, "  Score %d/100 — do not use\n", r.FinalScore)
	}
	fmt.Fprintf(w, "\n")
}

func printDivider(w io.Writer) {
	gray.Fprintf(w, "  %s\n", strings.Repeat("─", 70))
}

func severityBadge(w io.Writer, s sec.Severity) {
	switch s {
	case sec.SeverityCritical:
		bgRed.Fprintf(w, " CRITICAL ")
	case sec.SeverityHigh:
		red.Fprintf(w, " [HIGH]   ")
	case sec.SeverityMedium:
		yellow.Fprintf(w, " [MEDIUM] ")
	case sec.SeverityLow:
		white.Fprintf(w, " [LOW]    ")
	default:
		gray.Fprintf(w, " [INFO]   ")
	}
}
