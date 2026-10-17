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

// Default severities applied to each built-in violation rule when the operator
// has not overridden them via policy.rule_severities.
var defaultRuleSeverity = map[string]sec.Severity{
	"BLOCKED_IMPORT":   sec.SeverityHigh,
	"BLOCKED_FUNCTION": sec.SeverityHigh,
	"UNHANDLED_ERROR":  sec.SeverityMedium,
	"HIGH_COMPLEXITY":  sec.SeverityLow,
}

// actionFor resolves the configured action for a violation rule. An explicit
// policy.rule_actions entry wins; otherwise policy.default_action applies; an
// empty default falls back to "block" so an unconfigured rule fails safe.
func (e *PolicyEngineImpl) actionFor(rule string) string {
	if a, ok := e.cfg.RuleActions[rule]; ok {
		if a = strings.ToLower(strings.TrimSpace(a)); a == "warn" || a == "block" {
			return a
		}
	}
	if a := strings.ToLower(strings.TrimSpace(e.cfg.DefaultAction)); a == "warn" || a == "block" {
		return a
	}
	return sec.PolicyActionBlock
}

// severityFor resolves the configured severity for a violation rule, falling
// back to the rule's built-in default and then to MEDIUM.
func (e *PolicyEngineImpl) severityFor(rule string) sec.Severity {
	if s, ok := e.cfg.RuleSeverities[rule]; ok {
		if sev := parseSeverity(s); sev != "" {
			return sev
		}
	}
	if sev, ok := defaultRuleSeverity[rule]; ok {
		return sev
	}
	return sec.SeverityMedium
}

// violation constructs a PolicyViolation with the resolved action and severity.
func (e *PolicyEngineImpl) violation(rule, description, file string, line int, value string) sec.PolicyViolation {
	return sec.PolicyViolation{
		Rule:        rule,
		Description: description,
		File:        file,
		Line:        line,
		Value:       value,
		Severity:    e.severityFor(rule),
		Action:      e.actionFor(rule),
	}
}

// parseSeverity maps a configured severity string to a sec.Severity, returning
// "" for an unrecognised value.
func parseSeverity(s string) sec.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return sec.SeverityCritical
	case "HIGH":
		return sec.SeverityHigh
	case "MEDIUM":
		return sec.SeverityMedium
	case "LOW":
		return sec.SeverityLow
	case "INFO":
		return sec.SeverityInfo
	default:
		return ""
	}
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
					violations = append(violations, e.violation(
						"BLOCKED_IMPORT",
						fmt.Sprintf("Import of '%s' is blocked by security policy.", importPath),
						"generated_code.go",
						fset.Position(node.Pos()).Line,
						importPath,
					))
				}
			}

		// ── Check blocked function calls ──────────────────────────────────
		case *ast.CallExpr:
			callName := extractCallName(node)
			qualified := extractQualifiedCallName(node)
			lowerQualified := strings.ToLower(qualified)
			for _, blocked := range e.cfg.Rules.BlockedFunctions {
				// Match the bare function name ("Command"), the full qualified
				// call ("exec.Command"), or the package prefix ("exec"), so a
				// block on "exec" catches every exec.* call.
				if strings.EqualFold(callName, blocked) ||
					strings.EqualFold(qualified, blocked) ||
					strings.HasPrefix(lowerQualified, strings.ToLower(blocked)+".") {
					violations = append(violations, e.violation(
						"BLOCKED_FUNCTION",
						fmt.Sprintf("Call to '%s()' is blocked by security policy.", blocked),
						"generated_code.go",
						fset.Position(node.Pos()).Line,
						callName,
					))
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
							violations = append(violations, e.violation(
								"UNHANDLED_ERROR",
								"Error return value is discarded with blank identifier '_'. Always handle errors.",
								"generated_code.go",
								fset.Position(node.Pos()).Line,
								"_",
							))
						}
					}
				}
			}
		}
		return true
	})

	if e.cfg.Rules.MaxCyclomaticComplexity > 0 {
		violations = append(violations, e.checkCyclomaticComplexity(fset, f)...)
	}

	return violations, nil
}

// checkCyclomaticComplexity inspects every top-level function declaration and
// flags any whose cyclomatic complexity exceeds the configured threshold. It
// uses the conventional definition of cyclomatic complexity: a function's base
// complexity is 1, and every decision point adds 1. Decision points counted are
// branches (if/else-if), loops (for), iterators (range), switch/select cases,
// guard clauses (go/defer) and short-circuit boolean operators (&&, ||). Inline
// function literals and methods are counted per declaration.
//
// max_cyclomatic_complexity <= 0 disables the rule (callers gate on this), so
// an unset threshold never produces spurious violations.
func (e *PolicyEngineImpl) checkCyclomaticComplexity(fset *token.FileSet, f *ast.File) []sec.PolicyViolation {
	if e.cfg.Rules.MaxCyclomaticComplexity <= 0 {
		return nil
	}

	limit := e.cfg.Rules.MaxCyclomaticComplexity
	var violations []sec.PolicyViolation

	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		// Skip method declarations on test files and generated helper stubs?
		// Keep it simple and count every FuncDecl, matching gocyclo.
		complexity := cyclomaticComplexity(fn.Body)
		if complexity > limit {
			violations = append(violations, e.violation(
				"HIGH_COMPLEXITY",
				fmt.Sprintf(
					"Function '%s' has cyclomatic complexity %d, exceeding the configured limit of %d.",
					fn.Name.Name, complexity, limit),
				"generated_code.go",
				fset.Position(fn.Pos()).Line,
				fmt.Sprintf("%d", complexity),
			))
		}
	}
	return violations
}

// cyclomaticComplexity returns the cyclomatic complexity of a function body,
// or 0 when the body is nil. Each decision point increments the count.
func cyclomaticComplexity(body *ast.BlockStmt) int {
	if body == nil {
		return 0
	}
	v := &complexityVisitor{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			v.n++
		case *ast.ForStmt:
			v.n++
		case *ast.RangeStmt:
			v.n++
		case *ast.CaseClause:
			if len(node.List) > 0 { // default: adds no complexity
				v.n++
			}
		case *ast.CommClause:
			if node.Comm != nil { // default case: no complexity
				v.n++
			}
		case *ast.BinaryExpr:
			if node.Op == token.LAND || node.Op == token.LOR {
				v.n++
			}
		case *ast.GoStmt:
			v.n++
		case *ast.DeferStmt:
			v.n++
		}
		return true
	})
	// Base complexity of 1 plus one per decision point.
	return 1 + v.n
}

// complexityVisitor accumulates the number of decision points in a function body.
type complexityVisitor struct {
	n int
}

// ─── Generic policy checks (all languages) ────────────────────────────────────

func (e *PolicyEngineImpl) checkGeneric(code, language string) []sec.PolicyViolation {
	var violations []sec.PolicyViolation
	lines := strings.Split(code, "\n")

	for lineNum, line := range lines {
		// Check blocked imports/requires
		for _, blocked := range e.cfg.Rules.BlockedImports {
			if strings.Contains(line, blocked) {
				violations = append(violations, e.violation(
					"BLOCKED_IMPORT",
					fmt.Sprintf("Import of '%s' is blocked by security policy.", blocked),
					fmt.Sprintf("generated_code.%s", langExt(language)),
					lineNum+1,
					blocked,
				))
			}
		}

		// Check blocked function calls
		for _, blocked := range e.cfg.Rules.BlockedFunctions {
			if strings.Contains(line, blocked+"(") {
				violations = append(violations, e.violation(
					"BLOCKED_FUNCTION",
					fmt.Sprintf("Call to '%s()' is blocked by security policy.", blocked),
					fmt.Sprintf("generated_code.%s", langExt(language)),
					lineNum+1,
					blocked,
				))
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
