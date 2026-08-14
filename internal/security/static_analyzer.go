// Package security — Stage 1: Static Analysis (SAST)
// Runs gosec on Go code and custom AST pattern matching for all languages.
// Invoked concurrently with dep_auditor and policy_engine by pipeline.go.
package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/logger"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
	"go.uber.org/zap"
)

// StaticAnalyzerImpl implements the StaticAnalyzer interface.
type StaticAnalyzerImpl struct{}

// NewStaticAnalyzer returns a ready-to-use StaticAnalyzerImpl.
func NewStaticAnalyzer() *StaticAnalyzerImpl {
	return &StaticAnalyzerImpl{}
}

// Analyze runs SAST on the generated code.
// For Go: runs gosec + custom AST checks.
// For all languages: runs pattern-based checks for common vulnerabilities.
//
// The returned error is non-nil only when a mandatory check could not be
// completed (e.g. the gosec binary is missing). Findings are still returned
// so nothing is lost, but the pipeline treats a non-nil error as an
// incomplete analysis and fails closed. A missing scanner must never be
// reported as a clean scan.
func (a *StaticAnalyzerImpl) Analyze(ctx context.Context, code, language string) ([]sec.Finding, error) {
	log := logger.WithStage("sast")
	var findings []sec.Finding

	switch strings.ToLower(language) {
	case "go", "golang":
		// AST checks run first; a syntax error is reported as a finding and
		// does not block the remaining checks.
		astFindings, err := runGoAST(code)
		if err != nil {
			log.Warn("AST analysis failed", zap.Error(err))
		}
		findings = append(findings, astFindings...)

		// gosec is a mandatory SAST stage for Go. If it cannot run, report
		// the failure so the pipeline marks the analysis incomplete.
		gosecFindings, err := runGosec(ctx, code)
		if err != nil {
			log.Warn("gosec unavailable — static analysis incomplete", zap.Error(err))
			return findings, err
		}
		findings = append(findings, gosecFindings...)

	case "python", "python3":
		findings = append(findings, runPatternCheck(code, "python")...)

	case "javascript", "js", "typescript", "ts":
		findings = append(findings, runPatternCheck(code, "javascript")...)

	default:
		findings = append(findings, runPatternCheck(code, "generic")...)
	}

	log.Info("static analysis complete", zap.Int("findings", len(findings)))
	return findings, nil
}

// ─── gosec integration ────────────────────────────────────────────────────────

// gosecIssue matches the JSON output from gosec -fmt=json
type gosecIssue struct {
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	RuleID     string `json:"rule_id"`
	Details    string `json:"details"`
	File       string `json:"file"`
	Code       string `json:"code"`
	Line       string `json:"line"`
	Column     string `json:"column"`
}

type gosecOutput struct {
	Issues []gosecIssue `json:"Issues"`
}

func runGosec(ctx context.Context, code string) ([]sec.Finding, error) {
	// Write code to temp file
	tmpDir, err := os.MkdirTemp("", "elevated-sast-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	codeFile := filepath.Join(tmpDir, "main.go")
	modFile := filepath.Join(tmpDir, "go.mod")

	if err := os.WriteFile(codeFile, []byte(code), 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(modFile, []byte("module sandbox\ngo 1.22\n"), 0600); err != nil {
		return nil, err
	}

	// Run gosec — output as JSON for reliable parsing.
	// gosec exits non-zero when it finds issues; `out` is still valid JSON.
	cmd := exec.CommandContext(ctx, "gosec", "-fmt=json", "-quiet", "./...")
	cmd.Dir = tmpDir

	out, runErr := cmd.Output()

	// A missing gosec binary is a hard, fail-closed error: the scanner did not
	// actually run, so a "clean" result would be false. The pipeline uses this
	// error to mark the analysis incomplete rather than scoring it as safe.
	if runErr != nil && errors.Is(runErr, exec.ErrNotFound) {
		return nil, fmt.Errorf("gosec binary not found in PATH: %w", runErr)
	}

	// No output at all: either a clean scan or a silent tool failure. Only a
	// successful exit with no output is a true clean scan.
	if len(bytes.TrimSpace(out)) == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("gosec produced no output: %w", runErr)
		}
		return nil, nil
	}

	var result gosecOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parsing gosec output: %w", err)
	}

	var findings []sec.Finding
	for _, issue := range result.Issues {
		findings = append(findings, sec.Finding{
			ID:          fmt.Sprintf("gosec-%s", issue.RuleID),
			RuleID:      issue.RuleID,
			Title:       issue.Details,
			Description: issue.Details,
			Severity:    mapGosecSeverity(issue.Severity),
			File:        "generated_code.go",
			Code:        strings.TrimSpace(issue.Code),
			Source:      "gosec",
			Suggestion:  gosecSuggestion(issue.RuleID),
		})
	}
	return findings, nil
}

func mapGosecSeverity(s string) sec.Severity {
	switch strings.ToUpper(s) {
	case "HIGH":
		return sec.SeverityHigh
	case "MEDIUM":
		return sec.SeverityMedium
	case "LOW":
		return sec.SeverityLow
	default:
		return sec.SeverityInfo
	}
}

func gosecSuggestion(ruleID string) string {
	suggestions := map[string]string{
		"G101": "Do not hardcode credentials. Use environment variables or a secrets manager.",
		"G102": "Bind to a specific interface, not 0.0.0.0, unless intentional.",
		"G103": "Avoid using the unsafe package in production code.",
		"G104": "Always handle errors — do not use blank identifier _ for error returns.",
		"G201": "Use parameterized queries to prevent SQL injection.",
		"G202": "Use parameterized queries to prevent SQL injection.",
		"G304": "Ensure file paths are validated to prevent path traversal.",
		"G401": "Use a secure hashing algorithm (SHA-256 or stronger), not MD5 or SHA1.",
		"G501": "Use crypto/sha256 or crypto/sha512 instead of weak hash functions.",
	}
	if s, ok := suggestions[ruleID]; ok {
		return s
	}
	return "Review this finding and apply the principle of least privilege."
}

// ─── Custom Go AST analysis ───────────────────────────────────────────────────

func runGoAST(code string) ([]sec.Finding, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "generated.go", code, parser.AllErrors)
	if err != nil {
		// Syntax error in generated code — report it as a finding
		return []sec.Finding{{
			ID:          "ast-syntax-error",
			RuleID:      "SYNTAX",
			Title:       "Generated code has syntax errors",
			Severity:    sec.SeverityHigh,
			Source:      "custom-ast",
			Description: fmt.Sprintf("The AI-generated code contains syntax errors: %v", err),
			Suggestion:  "Regenerate with a more specific prompt.",
		}}, nil
	}

	var findings []sec.Finding

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {

		// Check for hardcoded string literals that look like secrets
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				val := strings.Trim(node.Value, `"`)
				if looksLikeSecret(val) {
					findings = append(findings, sec.Finding{
						ID:          "ast-hardcoded-secret",
						RuleID:      "HARDCODED_SECRET",
						Title:       "Possible hardcoded secret detected",
						Severity:    sec.SeverityHigh,
						Source:      "custom-ast",
						Description: "A string literal that may contain a credential or API key was detected.",
						Suggestion:  "Use environment variables or a secrets manager. Never hardcode secrets.",
						Line:        fset.Position(node.Pos()).Line,
					})
				}
			}

		// Check for dangerous function calls
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				call := fmt.Sprintf("%v.%v", sel.X, sel.Sel.Name)
				if finding := checkDangerousCall(call, fset.Position(node.Pos()).Line); finding != nil {
					findings = append(findings, *finding)
				}
			}
		}
		return true
	})

	return findings, nil
}

func looksLikeSecret(s string) bool {
	s = strings.ToLower(s)
	secretPatterns := []string{
		"sk-", "api_key=", "password=", "secret=", "token=",
		"auth=", "bearer ", "private_key", "aws_secret",
	}
	for _, p := range secretPatterns {
		if strings.Contains(s, p) && len(s) > 8 {
			return true
		}
	}
	return false
}

func checkDangerousCall(call string, line int) *sec.Finding {
	dangerous := map[string]string{
		"exec.Command":    "Direct command execution detected. Use a sandboxed approach instead.",
		"os.Remove":       "File deletion detected. Ensure path is validated and deletion is intentional.",
		"os.RemoveAll":    "Recursive file deletion detected. Highly dangerous if path is user-controlled.",
		"net.Dial":        "Direct network connection detected. Ensure destination is validated.",
		"http.Get":        "Outbound HTTP request detected. Validate and whitelist target URLs.",
		"ioutil.ReadFile": "File read detected. Validate the file path to prevent directory traversal.",
		"fmt.Sprintf":     "", // not dangerous on its own — skip
	}
	msg, exists := dangerous[call]
	if !exists || msg == "" {
		return nil
	}
	return &sec.Finding{
		ID:          fmt.Sprintf("ast-%s", strings.ReplaceAll(call, ".", "-")),
		RuleID:      "DANGEROUS_CALL",
		Title:       fmt.Sprintf("Dangerous function call: %s", call),
		Severity:    sec.SeverityMedium,
		Source:      "custom-ast",
		Description: msg,
		Suggestion:  msg,
		Line:        line,
	}
}

// ─── Pattern-based checks for non-Go languages ───────────────────────────────

type pattern struct {
	match      string
	title      string
	severity   sec.Severity
	suggestion string
}

var pythonPatterns = []pattern{
	{"eval(", "Use of eval() detected", sec.SeverityCritical, "Never use eval() — it executes arbitrary code."},
	{"exec(", "Use of exec() detected", sec.SeverityCritical, "Never use exec() with untrusted input."},
	{"os.system(", "os.system() call detected", sec.SeverityHigh, "Use subprocess.run() with shell=False instead."},
	{"pickle.loads", "Insecure deserialization with pickle", sec.SeverityHigh, "Never unpickle untrusted data. Use JSON instead."},
	{"subprocess.call(", "subprocess.call() detected", sec.SeverityMedium, "Prefer subprocess.run() and avoid shell=True."},
	{"shell=True", "Shell injection risk", sec.SeverityHigh, "Never use shell=True with user-controlled input."},
	{"password", "Possible password in code", sec.SeverityMedium, "Do not hardcode passwords. Use environment variables."},
}

var jsPatterns = []pattern{
	{"eval(", "Use of eval() detected", sec.SeverityCritical, "Never use eval() — it executes arbitrary code."},
	{"innerHTML", "XSS risk via innerHTML", sec.SeverityHigh, "Use textContent or DOMPurify to sanitise HTML."},
	{"document.write(", "Dangerous document.write() call", sec.SeverityHigh, "Avoid document.write() — it can overwrite the entire page."},
	{"dangerouslySetInnerHTML", "XSS risk via dangerouslySetInnerHTML", sec.SeverityHigh, "Sanitise all HTML before using dangerouslySetInnerHTML."},
	{"process.env", "Environment variable access detected", sec.SeverityInfo, "Ensure env vars are not exposed to the client."},
}

var genericPatterns = []pattern{
	{"password", "Possible hardcoded password", sec.SeverityHigh, "Use environment variables or a secrets manager."},
	{"secret", "Possible hardcoded secret", sec.SeverityHigh, "Never hardcode secrets in source code."},
	{"TODO: security", "Security TODO found", sec.SeverityMedium, "Resolve all security TODOs before production use."},
}

func runPatternCheck(code, lang string) []sec.Finding {
	var patterns []pattern
	switch lang {
	case "python":
		patterns = pythonPatterns
	case "javascript":
		patterns = jsPatterns
	default:
		patterns = genericPatterns
	}

	var findings []sec.Finding
	lines := strings.Split(code, "\n")

	for _, p := range patterns {
		for lineNum, line := range lines {
			if strings.Contains(line, p.match) {
				findings = append(findings, sec.Finding{
					ID:          fmt.Sprintf("pattern-%s", strings.ReplaceAll(p.match, ".", "-")),
					RuleID:      "PATTERN_MATCH",
					Title:       p.title,
					Severity:    p.severity,
					Source:      "custom-ast",
					Description: p.title,
					Suggestion:  p.suggestion,
					Code:        strings.TrimSpace(line),
					Line:        lineNum + 1,
				})
				break // one finding per pattern max
			}
		}
	}
	return findings
}
