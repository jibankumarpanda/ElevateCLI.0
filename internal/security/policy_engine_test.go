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
