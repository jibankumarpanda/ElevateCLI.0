package output

import (
	"fmt"
	"time"

	"github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

type Reporter struct{}

func NewReporter() *Reporter {
	return &Reporter{}
}

func (r *Reporter) CreateReport(prompt, code, lang string, findings []security.Finding, vulns []security.Vulnerability, policies []security.Finding, sandbox security.SandboxResult) security.Report {
	score := r.CalculateScore(findings, vulns, policies, sandbox)
	
	verdict := security.VerdictApproved
	if score < 40 {
		verdict = security.VerdictRejected
	} else if score < 70 {
		verdict = security.VerdictWarning
	}

	return security.Report{
		Prompt:           prompt,
		GeneratedCode:    code,
		Language:         lang,
		Timestamp:        time.Now(),
		Findings:         findings,
		Vulnerabilities:  vulns,
		PolicyViolations: policies,
		SandboxResult:    sandbox,
		Score:            score,
		Verdict:          verdict,
	}
}

func (r *Reporter) CalculateScore(findings []security.Finding, vulns []security.Vulnerability, policies []security.Finding, sandbox security.SandboxResult) int {
	score := 100

	// Deductions for SAST Findings
	for _, f := range findings {
		switch f.Severity {
		case security.SeverityCritical: score -= 25
		case security.SeverityHigh:     score -= 15
		case security.SeverityMedium:   score -= 8
		case security.SeverityLow:      score -= 3
		}
	}

	// Deductions for Vulnerabilities
	for range vulns {
		score -= 15
	}

	// Deductions for Policy Violations
	for range policies {
		score -= 20
	}

	// Deductions for Sandbox Failure
	if sandbox.ExitCode != 0 || sandbox.Error != "" {
		score = 0 // Automatic rejection if sandbox fails to run
	}

	if score < 0 {
		score = 0
	}

	return score
}

func (r *Reporter) PrintRich(report security.Report) {
	fmt.Printf("\n--- SECURITY REPORT ---\n")
	fmt.Printf("Verdict: %s (Score: %d/100)\n", report.Verdict, report.Score)
	fmt.Printf("Findings: %d | Vulns: %d | Policy: %d\n", len(report.Findings), len(report.Vulnerabilities), len(report.PolicyViolations))
	
	if len(report.Findings) > 0 {
		fmt.Println("\nSAST Findings:")
		for _, f := range report.Findings {
			fmt.Printf("- [%s] %s (Line: %d)\n", f.Severity, f.Title, f.Line)
		}
	}
	
	fmt.Println("\n-----------------------\n")
}
