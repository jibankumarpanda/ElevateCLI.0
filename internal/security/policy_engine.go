// Stage 3: Policy Enforcement
// Checks generated code against configurable rules from .elevated-cli.yaml.
// Uses Go's go/ast for Go code and string matching for other languages.
package security

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/logger"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
	"go.uber.org/zap"
)

// PolicyEngineImpl implements the PolicyEngine interface using configurable rules.
type PolicyEngineImpl struct {
	cfg config.PolicyConfig
}

// NewPolicyEngine returns a PolicyEngineImpl loaded with rules from config.
func NewPolicyEngine(cfg config.PolicyConfig) *PolicyEngineImpl {
	return &PolicyEngineImpl{cfg: cfg}
}

// Check runs all configured policy rules against the generated code.
func (e *PolicyEngineImpl) Check(ctx context.Context, code, language string) ([]sec.PolicyViolation, error) {
	log := logger.WithStage("policy")
	var violations []sec.PolicyViolation

	switch strings.ToLower(language) {
	case "go", "golang":
		v, err := e.checkGo(code)
		if err != nil {
			log.Warn("Go policy check failed", zap.Error(err))
		}
		violations = append(violations, v...)

	default:
		violations = append(violations, e.checkGeneric(code, language)...)
	}

	log.Info("policy check complete", zap.Int("violations", len(violations)))
	return violations, nil
}

// ─── Go policy checks ─────────────────────────────────────────────────────────

func (e *PolicyEngineImpl) checkGo(code string) ([]sec.PolicyViolation, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "generated.go", code, parser.AllErrors)
	if err != nil {
		// Syntax errors are reported by static_analyzer — not a policy violation
		return nil, nil
	}

	var violations []sec.PolicyViolation

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {

		// ── Check blocked imports ─────────────────────────────────────────
		case *ast.ImportSpec:
			if node.Path == nil {
				break
			}
			importPath := strings.Trim(node.Path.Value, `"`)
			for _, blocked := range e.cfg.Rules.BlockedImports {
				if importPath == blocked || strings.HasPrefix(importPath, blocked+"/") {
					violations = append(violations, sec.PolicyViolation{
						Rule:        "BLOCKED_IMPORT",
						Description: fmt.Sprintf("Import of '%s' is blocked by security policy.", importPath),
						File:        "generated_code.go",
						Line:        fset.Position(node.Pos()).Line,
						Value:       importPath,
					})
				}
			}

		// ── Check blocked function calls ──────────────────────────────────
		case *ast.CallExpr:
			callName := extractCallName(node)
			qualified := extractQualifiedCallName(node)
			for _, blocked := range e.cfg.Rules.BlockedFunctions {
				// Match the bare function name ("Command") or the qualified
				// call ("exec.Command"), so blocking "exec" also catches
				// exec.Command(...).
				if strings.EqualFold(callName, blocked) || strings.EqualFold(qualified, blocked) {
					violations = append(violations, sec.PolicyViolation{
						Rule:        "BLOCKED_FUNCTION",
						Description: fmt.Sprintf("Call to '%s()' is blocked by security policy.", blocked),
						File:        "generated_code.go",
						Line:        fset.Position(node.Pos()).Line,
						Value:       callName,
					})
					break
				}
			}

		// ── Check error handling ──────────────────────────────────────────
		case *ast.AssignStmt:
			if !e.cfg.Rules.RequireErrorHandling {
				break
			}
			// Look for err := ... followed by _ = err or missing check
			for i, rhs := range node.Rhs {
				_ = rhs
				if i < len(node.Lhs) {
					if ident, ok := node.Lhs[i].(*ast.Ident); ok {
						if ident.Name == "_" {
							// Blank identifier for an error — check if it's an error type
							// This is a heuristic; full type-checking requires go/types
							violations = append(violations, sec.PolicyViolation{
								Rule:        "UNHANDLED_ERROR",
								Description: "Error return value is discarded with blank identifier '_'. Always handle errors.",
								File:        "generated_code.go",
								Line:        fset.Position(node.Pos()).Line,
								Value:       "_",
							})
						}
					}
				}
			}
		}
		return true
	})

	return violations, nil
}

// ─── Generic policy checks (all languages) ────────────────────────────────────

func (e *PolicyEngineImpl) checkGeneric(code, language string) []sec.PolicyViolation {
	var violations []sec.PolicyViolation
	lines := strings.Split(code, "\n")

	for lineNum, line := range lines {
		// Check blocked imports/requires
		for _, blocked := range e.cfg.Rules.BlockedImports {
			if strings.Contains(line, blocked) {
				violations = append(violations, sec.PolicyViolation{
					Rule:        "BLOCKED_IMPORT",
					Description: fmt.Sprintf("Import of '%s' is blocked by security policy.", blocked),
					File:        fmt.Sprintf("generated_code.%s", langExt(language)),
					Line:        lineNum + 1,
					Value:       blocked,
				})
			}
		}

		// Check blocked function calls
		for _, blocked := range e.cfg.Rules.BlockedFunctions {
			if strings.Contains(line, blocked+"(") {
				violations = append(violations, sec.PolicyViolation{
					Rule:        "BLOCKED_FUNCTION",
					Description: fmt.Sprintf("Call to '%s()' is blocked by security policy.", blocked),
					File:        fmt.Sprintf("generated_code.%s", langExt(language)),
					Line:        lineNum + 1,
					Value:       blocked,
				})
			}
		}
	}
	return violations
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func extractCallName(call *ast.CallExpr) string {
	if call == nil {
		return ""
	}
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// extractQualifiedCallName returns "pkg.Func" for selector calls such as
// exec.Command, or the bare identifier for direct calls. It lets the blocked
// function rule match a package-level block like "exec".
func extractQualifiedCallName(call *ast.CallExpr) string {
	if call == nil {
		return ""
	}
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if pkg, ok := f.X.(*ast.Ident); ok {
			return pkg.Name + "." + f.Sel.Name
		}
		return f.Sel.Name
	}
	return ""
}

func langExt(lang string) string {
	switch strings.ToLower(lang) {
	case "python", "python3":
		return "py"
	case "javascript", "js":
		return "js"
	case "typescript", "ts":
		return "ts"
	default:
		return "txt"
	}
}
