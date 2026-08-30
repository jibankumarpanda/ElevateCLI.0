package security

import (
	"context"
	"testing"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
)

func policyConfig(blockedImports, blockedFuncs []string, requireErr bool) config.PolicyConfig {
	cfg := config.PolicyConfig{}
	cfg.Rules.BlockedImports = blockedImports
	cfg.Rules.BlockedFunctions = blockedFuncs
	cfg.Rules.RequireErrorHandling = requireErr
	return cfg
}

func TestGoBlockedImport(t *testing.T) {
	e := NewPolicyEngine(policyConfig([]string{"os/exec"}, nil, false))
	code := `package main
import (
	"os/exec"
)
func main() { _ = exec.Command("ls") }
`
	violations, err := e.Check(context.Background(), code, "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 1 {
		t.Fatalf("got %d violations, want 1: %+v", len(violations), violations)
	}
	if violations[0].Rule != "BLOCKED_IMPORT" {
		t.Errorf("rule = %q", violations[0].Rule)
	}
}

func TestGoBlockedImportWithSubpath(t *testing.T) {
	e := NewPolicyEngine(policyConfig([]string{"net/http"}, nil, false))
	code := `package main
import "net/http/httptest"
func main() {}
`
	violations, _ := e.Check(context.Background(), code, "go")
	if len(violations) != 1 {
		t.Fatalf("subpath import should be blocked: %+v", violations)
	}
}

func TestGoBlockedFunction(t *testing.T) {
	e := NewPolicyEngine(policyConfig(nil, []string{"exec"}, false))
	code := `package main
import "os/exec"
func main() { exec.Command("ls") }
`
	violations, err := e.Check(context.Background(), code, "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 1 || violations[0].Rule != "BLOCKED_FUNCTION" {
		t.Fatalf("got %+v", violations)
	}
}

func TestGoUnhandledErrorRule(t *testing.T) {
	e := NewPolicyEngine(policyConfig(nil, nil, true))
	code := `package main
import "os"
func main() { f, _ := os.Open("x"); _ = f }
`
	violations, err := e.Check(context.Background(), code, "go")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range violations {
		if v.Rule == "UNHANDLED_ERROR" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected UNHANDLED_ERROR violation, got %+v", violations)
	}
}

func TestGoCleanCodeNoViolations(t *testing.T) {
	e := NewPolicyEngine(policyConfig([]string{"os/exec", "syscall"}, nil, true))
	code := `package main
import "fmt"
func main() {
	err := run()
	if err != nil {
		fmt.Println(err)
	}
}
func run() error { return nil }
`
	violations, err := e.Check(context.Background(), code, "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Errorf("clean code should have no violations: %+v", violations)
	}
}

func TestGenericPythonBlockedImport(t *testing.T) {
	e := NewPolicyEngine(policyConfig([]string{"subprocess"}, []string{"eval"}, false))
	code := "import subprocess\nresult = eval('1+1')\n"
	violations, err := e.Check(context.Background(), code, "python")
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 2 {
		t.Fatalf("got %d violations, want 2: %+v", len(violations), violations)
	}
}

func TestGenericCleanPython(t *testing.T) {
	e := NewPolicyEngine(policyConfig([]string{"subprocess"}, nil, false))
	violations, err := e.Check(context.Background(), "import math\nprint(math.sqrt(4))\n", "python")
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Errorf("clean python should have no violations: %+v", violations)
	}
}

func TestExtractCallName(t *testing.T) {
	if got := extractCallName(nil); got != "" {
		t.Errorf("nil call = %q", got)
	}
}

func TestMaxCyclomaticComplexityExceeded(t *testing.T) {
	cfg := policyConfig(nil, nil, false)
	cfg.Rules.MaxCyclomaticComplexity = 3
	e := NewPolicyEngine(cfg)

	// Complexity: 1 base + 2 ifs + 1 for = 4 > 3 => flagged.
	code := `package main
func classify(n int) int {
	if n < 0 {
		return -1
	}
	if n == 0 {
		return 0
	}
	for i := 0; i < n; i++ {
		_ = i
	}
	return 1
}
`
	violations, err := e.Check(context.Background(), code, "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 1 {
		t.Fatalf("got %d violations, want 1: %+v", len(violations), violations)
	}
	if violations[0].Rule != "HIGH_COMPLEXITY" {
		t.Errorf("rule = %q, want HIGH_COMPLEXITY", violations[0].Rule)
	}
}

func TestMaxCyclomaticComplexityWithinLimit(t *testing.T) {
	cfg := policyConfig(nil, nil, false)
	cfg.Rules.MaxCyclomaticComplexity = 3
	e := NewPolicyEngine(cfg)

	// Complexity: 1 base + 1 if = 2 <= 3 => no violation.
	code := `package main
func simple(n int) int {
	if n > 0 {
		return 1
	}
	return 0
}
`
	violations, err := e.Check(context.Background(), code, "go")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range violations {
		if v.Rule == "HIGH_COMPLEXITY" {
			t.Errorf("unexpected HIGH_COMPLEXITY violation: %+v", violations)
		}
	}
}

func TestMaxCyclomaticComplexityDisabled(t *testing.T) {
	cfg := policyConfig(nil, nil, false)
	cfg.Rules.MaxCyclomaticComplexity = 0 // explicit zero = rule disabled
	e := NewPolicyEngine(cfg)

	code := `package main
func complex(n int) int {
	if 1 != 0 { a }
	if 1 != 0 { b }
	if 1 != 0 { c }
	if 1 != 0 { d }
	return n
}
`
	violations, err := e.Check(context.Background(), code, "go")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range violations {
		if v.Rule == "HIGH_COMPLEXITY" {
			t.Errorf("rule should be disabled with max=0: %+v", violations)
		}
	}
}

