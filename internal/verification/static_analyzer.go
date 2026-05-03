package verification

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// StaticAnalyzer handles SAST analysis.
type StaticAnalyzer struct{}

func NewStaticAnalyzer() *StaticAnalyzer {
	return &StaticAnalyzer{}
}

// Analyze runs SAST tools on the generated code.
func (sa *StaticAnalyzer) Analyze(ctx context.Context, code string, lang string) ([]security.Finding, error) {
	if lang != "go" {
		// For now, we only support deep SAST for Go.
		// Future: Integrate Semgrep for other languages.
		return nil, nil
	}

	// Create a temporary directory to store the code for analysis
	tmpDir, err := os.MkdirTemp("", "secure-ai-sast-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	filePath := filepath.Join(tmpDir, "generated.go")
	if err := os.WriteFile(filePath, []byte(code), 0644); err != nil {
		return nil, err
	}

	// Run gosec
	// Note: gosec needs a module or valid package structure.
	// For single files, we can use gosec -fmt=json -quiet [file]
	cmd := exec.CommandContext(ctx, "gosec", "-fmt=json", "-quiet", filePath)
	output, _ := cmd.CombinedOutput() // gosec returns non-zero if findings are found

	var findings []security.Finding
	if len(output) > 0 {
		var result struct {
			Issues []struct {
				Severity string `json:"severity"`
				RuleID   string `json:"rule_id"`
				Details  string `json:"details"`
				Line     string `json:"line"`
			} `json:"Issues"`
		}

		if err := json.Unmarshal(output, &result); err == nil {
			for _, issue := range result.Issues {
				findings = append(findings, security.Finding{
					ID:          issue.RuleID,
					Title:       fmt.Sprintf("Gosec: %s", issue.RuleID),
					Description: issue.Details,
					Severity:    sa.mapSeverity(issue.Severity),
					Tool:        "gosec",
					File:        "generated.go",
				})
			}
		}
	}

	return findings, nil
}

func (sa *StaticAnalyzer) mapSeverity(s string) security.Severity {
	switch s {
	case "HIGH":
		return security.SeverityHigh
	case "MEDIUM":
		return security.SeverityMedium
	case "LOW":
		return security.SeverityLow
	default:
		return security.SeverityInfo
	}
}
