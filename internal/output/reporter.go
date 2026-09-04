// Package output handles all result formatting and display for ElevateCLI.
// reporter.go dispatches a completed Report to the correct formatter
// based on the configured output format.
package output

import (
	"fmt"
	"io"
	"os"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/output/formatters"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// Reporter dispatches a Report to the correct output formatter.
type Reporter struct {
	format   string
	showCode bool
	out      io.Writer
}

// NewReporter creates a Reporter writing to the given writer (usually os.Stdout).
func NewReporter(format string, showCode bool, out io.Writer) *Reporter {
	if out == nil {
		out = os.Stdout
	}
	return &Reporter{format: format, showCode: showCode, out: out}
}

// Print formats and writes the report to the configured output.
func (r *Reporter) Print(report *sec.Report) error {
	switch r.format {
	case "json":
		return formatters.PrintJSON(r.out, report)
	case "sarif":
		return formatters.PrintSARIF(r.out, report)
	case "plain":
		return formatters.PrintPlain(r.out, report, r.showCode)
	default: // "rich"
		return formatters.PrintRich(r.out, report, r.showCode)
	}
}

// PrintSummary writes a one-line scan summary (used in history listings).
func PrintSummary(report *sec.Report) {
	icon := verdictIcon(report.Verdict)
	fmt.Printf("%s  [%3d]  %-10s  %-8s  %s\n",
		icon,
		report.FinalScore,
		report.Language,
		string(report.Verdict),
		truncate(report.Prompt, 60),
	)
}

func verdictIcon(v sec.Verdict) string {
	switch v {
	case sec.VerdictApproved:
		return "✓"
	case sec.VerdictWarning:
		return "⚠"
	default:
		return "✗"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
