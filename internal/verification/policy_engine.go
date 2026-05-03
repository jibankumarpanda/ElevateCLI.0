package verification

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	"github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// PolicyEngine enforces custom security policies using AST traversal.
type PolicyEngine struct {
	cfg *config.Config
}

func NewPolicyEngine(cfg *config.Config) *PolicyEngine {
	return &PolicyEngine{cfg: cfg}
}

func (pe *PolicyEngine) Check(code string, lang string) ([]security.Finding, error) {
	if lang != "go" {
		return nil, nil // Policy engine currently only supports Go AST
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "generated.go", code, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to parse code: %w", err)
	}

	var violations []security.Finding

	// Rule 1: Blocked Imports
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, "\"")
		for _, blocked := range pe.cfg.Policy.Rules.BlockedImports {
			if path == blocked {
				violations = append(violations, security.Finding{
					ID:          "POLICY001",
					Title:       "Blocked Import",
					Description: fmt.Sprintf("Import of '%s' is prohibited by policy.", path),
					Severity:    security.SeverityCritical,
					Line:        fset.Position(imp.Pos()).Line,
					Tool:        "policy_engine",
				})
			}
		}
	}

	// Rule 2: Blocked Functions (e.g., eval, exec)
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		var funcName string
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			funcName = fn.Name
		case *ast.SelectorExpr:
			funcName = fn.Sel.Name
		}

		for _, blocked := range pe.cfg.Policy.Rules.BlockedFunctions {
			if funcName == blocked {
				violations = append(violations, security.Finding{
					ID:          "POLICY002",
					Title:       "Blocked Function Call",
					Description: fmt.Sprintf("Call to '%s' is prohibited by policy.", funcName),
					Severity:    security.SeverityCritical,
					Line:        fset.Position(call.Pos()).Line,
					Tool:        "policy_engine",
				})
			}
		}

		return true
	})

	return violations, nil
}
