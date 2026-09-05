package output

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

var (
	styleTitle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	styleApproved = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	styleWarning  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))
	styleRejected = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
)

type model struct {
	report security.Report
}

func NewUI(report security.Report) *tea.Program {
	return tea.NewProgram(model{report: report})
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m model) View() string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("Secure AI Developer CLI - Report") + "\n\n")

	verdictStyle := styleApproved
	switch m.report.Verdict {
	case security.VerdictWarning:
		verdictStyle = styleWarning
	case security.VerdictRejected,
		security.VerdictBlocked,
		security.VerdictAnalysisIncomplete,
		security.VerdictExecutionFailed:
		verdictStyle = styleRejected
	}

	fmt.Fprintf(&b, "Verdict: %s\n", verdictStyle.Render(string(m.report.Verdict)))
	fmt.Fprintf(&b, "Security Score: %d/100\n\n", m.report.FinalScore)

	b.WriteString("Findings:\n")
	if len(m.report.Findings) == 0 && len(m.report.Vulns) == 0 && len(m.report.Violations) == 0 {
		b.WriteString("  No issues found. Clean code!\n")
	}

	for _, f := range m.report.Findings {
		fmt.Fprintf(&b, "  [SAST] [%s] %s\n", f.Severity, f.Title)
	}
	for _, v := range m.report.Vulns {
		b.WriteString(fmt.Sprintf("  [VULN] [%s] %s\n", v.Severity, v.Package))
	}
	for _, p := range m.report.Violations {
		b.WriteString(fmt.Sprintf("  [POLICY] %s — %s\n", p.Rule, p.Description))
	}

	b.WriteString("\nPress 'q' to exit.")

	return b.String()
}
