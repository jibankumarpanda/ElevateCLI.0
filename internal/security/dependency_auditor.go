// Stage 2: Dependency audit.
//
// This is a minimal implementation that extracts the dependency/import
// declarations from generated code. Full CVE scanning via govulncheck or
// osv-scanner is not yet integrated — see the architecture plan. Until it is,
// this stage returns no vulnerabilities (logged) rather than fabricating a
// clean bill of health against an empty database.
package security

import (
	"context"
	"go/parser"
	"go/token"
	"regexp"
	"strings"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/logger"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
	"go.uber.org/zap"
)

// DependencyAuditorImpl implements the DependencyAuditor interface.
type DependencyAuditorImpl struct{}

// NewDependencyAuditor returns a DependencyAuditorImpl.
func NewDependencyAuditor() *DependencyAuditorImpl {
	return &DependencyAuditorImpl{}
}

// Audit extracts declared dependencies and checks them for known
// vulnerabilities. Scanner integration is pending, so this currently logs the
// discovered imports and returns no vulnerabilities.
func (d *DependencyAuditorImpl) Audit(ctx context.Context, code, language string) ([]sec.Vulnerability, error) {
	log := logger.WithStage("deps")

	imports := extractImports(code, language)
	if len(imports) == 0 {
		log.Info("dependency audit: no imports detected")
		return nil, nil
	}
	log.Info("dependency audit: scanner not yet integrated — returning no findings",
		zap.Int("imports", len(imports)))
	return nil, nil
}

// extractImports pulls import/require/using declarations out of code.
func extractImports(code, language string) []string {
	switch strings.ToLower(language) {
	case "go", "golang":
		return goImports(code)
	case "python", "python3":
		return matchRepeated(code, `(?:^|\n)\s*(?:import|from)\s+([\w.]+)`)
	case "javascript", "js", "typescript", "ts":
		return matchRepeated(code, `(?:require|import)\s*\(?\s*['"]([^'"]+)['"]`)
	default:
		return nil
	}
}

func goImports(code string) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "generated.go", code, parser.ImportsOnly)
	if err != nil {
		return nil
	}
	var out []string
	for _, imp := range f.Imports {
		if imp.Path != nil {
			out = append(out, strings.Trim(imp.Path.Value, `"`))
		}
	}
	return out
}

func matchRepeated(s, pattern string) []string {
	re := regexp.MustCompile(pattern)
	matches := re.FindAllStringSubmatch(s, -1)
	var out []string
	for _, m := range matches {
		if len(m) > 1 {
			out = append(out, m[1])
		}
	}
	return out
}
