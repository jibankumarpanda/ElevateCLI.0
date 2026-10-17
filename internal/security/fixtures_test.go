package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// fixtureExpectation describes the findings expected for one fixture file.
type fixtureExpectation struct {
	Language    string `json:"language"`
	MinFindings int    `json:"min_findings"`
	MinHigh     int    `json:"min_high"`
	MaxHigh     int    `json:"max_high"`
}

// TestFixtureCorpus runs the in-process analyzers over the curated corpus of
// vulnerable, malicious, and safe samples. The corpus lives under
// test/data/code_samples and its expectations under test/data/expected_results,
// so it doubles as executable documentation of what the analyzers must catch.
func TestFixtureCorpus(t *testing.T) {
	root := filepath.Join("..", "..", "test", "data")
	raw, err := os.ReadFile(filepath.Join(root, "expected_results", "fixtures.json"))
	if err != nil {
		t.Fatalf("reading fixture expectations: %v", err)
	}
	var expectations map[string]fixtureExpectation
	if err := json.Unmarshal(raw, &expectations); err != nil {
		t.Fatalf("parsing fixture expectations: %v", err)
	}
	if len(expectations) == 0 {
		t.Fatal("no fixture expectations found")
	}

	for rel, want := range expectations {
		rel, want := rel, want
		t.Run(rel, func(t *testing.T) {
			code, err := os.ReadFile(filepath.Join(root, "code_samples", rel))
			if err != nil {
				t.Fatalf("reading fixture: %v", err)
			}
			findings := analyzeFixture(t, string(code), want.Language)
			high := countHigh(findings)

			if len(findings) < want.MinFindings {
				t.Errorf("got %d findings, want >= %d: %+v", len(findings), want.MinFindings, findings)
			}
			if high < want.MinHigh {
				t.Errorf("got %d high findings, want >= %d: %+v", high, want.MinHigh, findings)
			}
			if want.MaxHigh > 0 && high > want.MaxHigh {
				t.Errorf("got %d high findings, want <= %d: %+v", high, want.MaxHigh, findings)
			}
		})
	}
}

func analyzeFixture(t *testing.T, code, language string) []sec.Finding {
	t.Helper()
	switch language {
	case "go":
		f, err := runGoAST(code)
		if err != nil {
			t.Fatalf("runGoAST: %v", err)
		}
		return f
	case "python":
		return append(validateSyntax(code, "python"), runPatternCheck(code, "python")...)
	case "javascript":
		return append(validateSyntax(code, "javascript"), runPatternCheck(code, "javascript")...)
	default:
		t.Fatalf("unsupported fixture language %q", language)
		return nil
	}
}

func countHigh(findings []sec.Finding) int {
	n := 0
	for _, f := range findings {
		if f.Severity == sec.SeverityHigh || f.Severity == sec.SeverityCritical {
			n++
		}
	}
	return n
}
