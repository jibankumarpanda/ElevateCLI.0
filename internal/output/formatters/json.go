package formatters

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// ─── JSON formatter ───────────────────────────────────────────────────────────

// PrintJSON writes the full report as indented JSON.
// Useful for CI/CD pipelines that parse scan results programmatically.
func PrintJSON(w io.Writer, r *sec.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// ─── Plain text formatter ─────────────────────────────────────────────────────

// PrintPlain writes a simple human-readable report with no color codes.
// Useful when piping output to a file or running in non-TTY environments.
func PrintPlain(w io.Writer, r *sec.Report, showCode bool) error {
	line := strings.Repeat("-", 72)
	fmt.Fprintln(w, line)
	fmt.Fprintf(w, "ElevateCLI Security Report\n")
	fmt.Fprintf(w, "Scan ID  : %s\n", r.ID)
	fmt.Fprintf(w, "Provider : %s / %s\n", r.AIProvider, r.AIModel)
	fmt.Fprintf(w, "Language : %s\n", r.Language)
	fmt.Fprintf(w, "Score    : %d/100\n", r.FinalScore)
	fmt.Fprintf(w, "Verdict  : %s\n", r.Verdict)
	fmt.Fprintln(w, line)

	fmt.Fprintf(w, "Stage scores — SAST:%d  Deps:%d  Policy:%d  Sandbox:%d\n",
		r.StageScores.SAST, r.StageScores.Deps, r.StageScores.Policy, r.StageScores.Sandbox)
	fmt.Fprintln(w, line)

	if len(r.Findings) > 0 {
		fmt.Fprintf(w, "SAST Findings (%d):\n", len(r.Findings))
		for _, f := range r.Findings {
			fmt.Fprintf(w, "  [%s] %s (line %d) — %s\n",
				f.Severity, f.Title, f.Line, f.Source)
			if f.Suggestion != "" {
				fmt.Fprintf(w, "    Fix: %s\n", f.Suggestion)
			}
		}
		fmt.Fprintln(w, line)
	}

	if len(r.Vulns) > 0 {
		fmt.Fprintf(w, "Vulnerabilities (%d):\n", len(r.Vulns))
		for _, v := range r.Vulns {
			fmt.Fprintf(w, "  [%s] %s @ %s — %s\n",
				v.Severity, v.Package, v.Version, v.ID)
			if v.FixedVersion != "" {
				fmt.Fprintf(w, "    Fix: upgrade to %s\n", v.FixedVersion)
			}
		}
		fmt.Fprintln(w, line)
	}

	if len(r.Violations) > 0 {
		fmt.Fprintf(w, "Policy Violations (%d):\n", len(r.Violations))
		for _, v := range r.Violations {
			fmt.Fprintf(w, "  [%s] %s (line %d)\n", v.Rule, v.Description, v.Line)
		}
		fmt.Fprintln(w, line)
	}

	if showCode && r.GeneratedCode != "" {
		fmt.Fprintf(w, "Generated Code:\n")
		fmt.Fprintln(w, r.GeneratedCode)
		fmt.Fprintln(w, line)
	}

	return nil
}

// ─── SARIF formatter ──────────────────────────────────────────────────────────

// SARIF 2.1.0 structures for GitHub Code Scanning integration.

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	Properties       map[string]string `json:"properties"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// PrintSARIF writes the report in SARIF 2.1.0 format for GitHub Code Scanning.
func PrintSARIF(w io.Writer, r *sec.Report) error {
	var rules []sarifRule
	var results []sarifResult
	rulesSeen := map[string]bool{}

	// Convert SAST findings to SARIF results
	for _, f := range r.Findings {
		if !rulesSeen[f.RuleID] {
			rules = append(rules, sarifRule{
				ID:               f.RuleID,
				Name:             f.Title,
				ShortDescription: sarifMessage{Text: f.Title},
				Properties:       map[string]string{"source": f.Source},
			})
			rulesSeen[f.RuleID] = true
		}
		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: fmt.Sprintf("%s. %s", f.Description, f.Suggestion)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: "generated_code"},
					Region:           sarifRegion{StartLine: max(f.Line, 1)},
				},
			}},
		})
	}

	// Convert policy violations to SARIF results
	for _, v := range r.Violations {
		if !rulesSeen[v.Rule] {
			rules = append(rules, sarifRule{
				ID:               v.Rule,
				Name:             v.Rule,
				ShortDescription: sarifMessage{Text: v.Description},
			})
			rulesSeen[v.Rule] = true
		}
		results = append(results, sarifResult{
			RuleID:  v.Rule,
			Level:   "error",
			Message: sarifMessage{Text: v.Description},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: v.File},
					Region:           sarifRegion{StartLine: max(v.Line, 1)},
				},
			}},
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "ElevateCLI",
					Version:        "1.0.0",
					InformationURI: "https://github.com/yourusername/elevated-cli",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifLevel(s sec.Severity) string {
	switch s {
	case sec.SeverityCritical, sec.SeverityHigh:
		return "error"
	case sec.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ─── History summary line ─────────────────────────────────────────────────────

// SummaryLine returns a single formatted line for history listings.
func SummaryLine(id string, ts time.Time, prompt string, score int, verdict sec.Verdict, lang string) string {
	icon := "✗"
	switch verdict {
	case sec.VerdictApproved:
		icon = "✓"
	case sec.VerdictWarning:
		icon = "⚠"
	}
	p := prompt
	if len(p) > 55 {
		p = p[:52] + "..."
	}
	return fmt.Sprintf("%s  %3d/100  %-8s  %-10s  %s  %s",
		icon, score, lang, verdict, ts.Format("2006-01-02 15:04"), p)
}
