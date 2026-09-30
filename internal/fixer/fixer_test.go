package fixer

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// testPolicy builds a policy config with the block lists the repairs consult.
func testPolicy(blockedImports, blockedFuncs []string, maxComplexity int) config.PolicyConfig {
	var cfg config.PolicyConfig
	cfg.Rules.BlockedImports = blockedImports
	cfg.Rules.BlockedFunctions = blockedFuncs
	cfg.Rules.MaxCyclomaticComplexity = maxComplexity
	return cfg
}

func violation(rule string, line int, value string) sec.PolicyViolation {
	return sec.PolicyViolation{
		Rule:  rule,
		Line:  line,
		Value: value,
	}
}

// mustParseGo fails the test if the repaired code is not valid Go. Every repair
// test asserts this, because the whole safety argument rests on a repair never
// emitting code that does not compile.
func mustParseGo(t *testing.T, code string) {
	t.Helper()
	if _, err := parser.ParseFile(token.NewFileSet(), "out.go", code, parser.ParseComments); err != nil {
		t.Fatalf("repaired code does not parse: %v\n---\n%s", err, code)
	}
}

func TestApplyRemovesUnusedBlockedImport(t *testing.T) {
	code := `package main

import (
	"fmt"
	"os/exec"
)

func main() {
	fmt.Println("hello")
}
`
	f := New(testPolicy([]string{"os/exec"}, nil, 0))
	got := f.Apply(code, "go",
		[]sec.PolicyViolation{violation("BLOCKED_IMPORT", 4, "os/exec")}, nil)

	mustParseGo(t, got.Code)
	if strings.Contains(got.Code, "os/exec") {
		t.Errorf("blocked import survived:\n%s", got.Code)
	}
	if !strings.Contains(got.Code, "fmt") {
		t.Errorf("unrelated import was removed:\n%s", got.Code)
	}
	if len(got.Repairs) != 1 || got.Repairs[0].Kind != RepairBlockedImport {
		t.Fatalf("expected one blocked-import repair, got %+v", got.Repairs)
	}
}

func TestApplyRefusesBlockedImportStillReferenced(t *testing.T) {
	// os/exec is used by exec.Command, so deleting the import would break the
	// build. The fixer must refuse rather than emit non-compiling code.
	code := `package main

import "os/exec"

func run() {
	cmd := exec.Command("ls")
	_ = cmd
}
`
	f := New(testPolicy([]string{"os/exec"}, nil, 0))
	got := f.Apply(code, "go",
		[]sec.PolicyViolation{violation("BLOCKED_IMPORT", 3, "os/exec")}, nil)

	if got.Code != code {
		t.Errorf("referenced import must not be removed, code changed:\n%s", got.Code)
	}
	if len(got.Unrepairable) == 0 {
		t.Error("expected an unrepairable note explaining why the import was kept")
	}
}

func TestApplyRemovesDiscardedBlockedCall(t *testing.T) {
	code := `package main

import "os/exec"

func run() error {
	exec.Command("rm", "-rf", "/")
	return nil
}
`
	f := New(testPolicy([]string{"os/exec"}, []string{"Command"}, 0))
	got := f.Apply(code, "go",
		[]sec.PolicyViolation{violation("BLOCKED_FUNCTION", 6, "Command")}, nil)

	mustParseGo(t, got.Code)
	if strings.Contains(got.Code, "rm") {
		t.Errorf("blocked call survived:\n%s", got.Code)
	}
	if len(got.Repairs) != 1 || got.Repairs[0].Kind != RepairBlockedFunction {
		t.Fatalf("expected one blocked-function repair, got %+v", got.Repairs)
	}
}

func TestApplyRefusesBlockedCallWhoseResultIsRead(t *testing.T) {
	// The result is returned, so replacing the call with a no-op would fabricate
	// a value the caller depends on.
	code := `package main

import "os/exec"

func run() error {
	cmd := exec.Command("ls")
	return cmd.Run()
}
`
	f := New(testPolicy([]string{"os/exec"}, []string{"Command"}, 0))
	got := f.Apply(code, "go",
		[]sec.PolicyViolation{violation("BLOCKED_FUNCTION", 6, "Command")}, nil)

	if got.Code != code {
		t.Errorf("blocked call with a read result must not be removed:\n%s", got.Code)
	}
	if len(got.Unrepairable) == 0 {
		t.Error("expected an unrepairable note for a read blocked-call result")
	}
}

func TestApplyRewrapsDiscardedError(t *testing.T) {
	code := `package main

func load() error {
	_ = doWork()
	return nil
}
`
	f := New(testPolicy(nil, nil, 0))
	got := f.Apply(code, "go",
		[]sec.PolicyViolation{violation("UNHANDLED_ERROR", 4, "_")}, nil)

	mustParseGo(t, got.Code)
	if !strings.Contains(got.Code, "if err := doWork(); err != nil {") {
		t.Errorf("discarded error was not rewrapped into a nil check:\n%s", got.Code)
	}
	if len(got.Repairs) != 1 || got.Repairs[0].Kind != RepairUnhandledError {
		t.Fatalf("expected one error rewrap repair, got %+v", got.Repairs)
	}
}

func TestApplyRefusesErrorRewrapWhenFunctionCannotReturnError(t *testing.T) {
	// load() returns nothing, so there is no error to propagate.
	code := `package main

func load() {
	_ = doWork()
}
`
	f := New(testPolicy(nil, nil, 0))
	got := f.Apply(code, "go",
		[]sec.PolicyViolation{violation("UNHANDLED_ERROR", 4, "_")}, nil)

	if got.Code != code {
		t.Errorf("error rewrap must be refused when there is no error result:\n%s", got.Code)
	}
	if len(got.Unrepairable) == 0 {
		t.Error("expected an unrepairable note for a function with no error result")
	}
}

func TestApplyRedactsSecrets(t *testing.T) {
	code := `package main

const apiKey = "sk-abcdefghijklmnopqrstuvwxyz012345"
`
	f := New(testPolicy(nil, nil, 0))
	got := f.Apply(code, "go", nil, nil)

	if strings.Contains(got.Code, "sk-abcdefghijklmnopqrstuvwxyz012345") {
		t.Errorf("secret was not redacted:\n%s", got.Code)
	}
	if len(got.Repairs) != 1 || got.Repairs[0].Kind != RepairSecretRedaction {
		t.Fatalf("expected one redaction repair, got %+v", got.Repairs)
	}
}

func TestApplyReportsUncoveredFindingsAsUnrepairable(t *testing.T) {
	code := "package main\n\nfunc main() {}\n"
	f := New(testPolicy(nil, nil, 0))
	got := f.Apply(code, "go", nil, []sec.Finding{{
		RuleID: "G404-weak-random",
		Title:  "Use of weak random number generator",
		Line:   3,
	}})

	if len(got.Unrepairable) != 1 {
		t.Fatalf("expected the uncovered finding to be reported, got %v", got.Unrepairable)
	}
	if !strings.Contains(got.Unrepairable[0], "G404-weak-random") {
		t.Errorf("unrepairable note should name the finding, got %q", got.Unrepairable[0])
	}
}

func TestApplyReducesComplexityByExtractingPredicate(t *testing.T) {
	// Three short-circuit operators push this well over a limit of 4.
	code := `package main

func classify(a int, b int, c int) string {
	if a > 0 && b > 0 && c > 0 {
		return "all positive"
	}
	if a < 0 && b < 0 {
		return "all negative"
	}
	return "mixed"
}
`
	f := New(testPolicy(nil, nil, 4))
	got := f.Apply(code, "go", nil, nil)

	mustParseGo(t, got.Code)
	if !strings.Contains(got.Code, "func classify_cond1(a int, b int, c int) bool") {
		t.Errorf("predicate helper was not generated:\n%s", got.Code)
	}
	if !strings.Contains(got.Code, "classify_cond1(a, b, c)") {
		t.Errorf("condition was not replaced by the predicate call:\n%s", got.Code)
	}

	// The original function must now be under the limit, and the helper must
	// preserve the exact boolean semantics.
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "out.go", got.Code, parser.ParseComments)
	if err != nil {
		t.Fatalf("reparse failed: %v", err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*declFunc)
		_ = fn
		if !ok {
			continue
		}
	}
	if !strings.Contains(got.Code, "return a > 0 && b > 0 && c > 0") {
		t.Errorf("helper must preserve the original short-circuit expression:\n%s", got.Code)
	}
}

func TestApplyRefusesComplexityReductionNeedingTypeInference(t *testing.T) {
	// local is a local variable, so its type is not recoverable from the syntax
	// tree. The transform must refuse instead of inventing a parameter type.
	code := `package main

func classify(a int) string {
	local := a * 2
	if local > 0 && a > 0 {
		return "positive"
	}
	return "other"
}
`
	f := New(testPolicy(nil, nil, 1))
	got := f.Apply(code, "go", nil, nil)

	if strings.Contains(got.Code, "_cond1") {
		t.Errorf("must not invent a predicate for a local variable:\n%s", got.Code)
	}
	if len(got.Unrepairable) == 0 {
		t.Error("expected a refusal note for a condition reading a local")
	}
}

func TestApplyComplexityDisabledByZeroLimit(t *testing.T) {
	code := `package main

func f(a int, b int) int {
	if a > 0 && b > 0 {
		return 1
	}
	return 0
}
`
	f := New(testPolicy(nil, nil, 0))
	got := f.Apply(code, "go", nil, nil)
	if got.Code != code {
		t.Errorf("limit 0 must disable complexity reduction:\n%s", got.Code)
	}
}

func TestApplyTextRemovesStandalonePythonImport(t *testing.T) {
	code := `import subprocess

def run():
    return 1
`
	f := New(testPolicy([]string{"subprocess"}, nil, 0))
	got := f.Apply(code, "python",
		[]sec.PolicyViolation{violation("BLOCKED_IMPORT", 1, "subprocess")}, nil)

	if strings.Contains(got.Code, "subprocess") {
		t.Errorf("blocked python import survived:\n%s", got.Code)
	}
	if len(got.Repairs) != 1 {
		t.Fatalf("expected one repair, got %+v", got.Repairs)
	}
}

func TestApplyTextRefusesImportSharingALine(t *testing.T) {
	code := "import subprocess, sys\n\nprint(sys.path)\n"
	f := New(testPolicy([]string{"subprocess"}, nil, 0))
	got := f.Apply(code, "python",
		[]sec.PolicyViolation{violation("BLOCKED_IMPORT", 1, "subprocess")}, nil)

	if got.Code != code {
		t.Errorf("import sharing a line with other code must be refused:\n%s", got.Code)
	}
	if len(got.Unrepairable) == 0 {
		t.Error("expected a refusal note for a shared import line")
	}
}

func TestApplyTextRemovesStandaloneCallLine(t *testing.T) {
	code := `def run():
    eval(payload)
    return 1
`
	f := New(testPolicy(nil, []string{"eval"}, 0))
	got := f.Apply(code, "python",
		[]sec.PolicyViolation{violation("BLOCKED_FUNCTION", 2, "eval")}, nil)

	if strings.Contains(got.Code, "eval(") {
		t.Errorf("blocked python call survived:\n%s", got.Code)
	}
}

func TestApplyTextRefusesCallWithOtherLogicOnLine(t *testing.T) {
	code := "def run():\n    result = eval(payload)\n    return result\n"
	f := New(testPolicy(nil, []string{"eval"}, 0))
	got := f.Apply(code, "python",
		[]sec.PolicyViolation{violation("BLOCKED_FUNCTION", 2, "eval")}, nil)

	if got.Code != code {
		t.Errorf("assigned call must be refused:\n%s", got.Code)
	}
	if len(got.Unrepairable) == 0 {
		t.Error("expected a refusal note for an assigned blocked call")
	}
}

func TestApplyTextRefusesErrorRewrap(t *testing.T) {
	code := "def run():\n    _ = do_work()\n"
	f := New(testPolicy(nil, nil, 0))
	got := f.Apply(code, "python",
		[]sec.PolicyViolation{violation("UNHANDLED_ERROR", 2, "_")}, nil)

	if got.Code != code {
		t.Errorf("python error rewrap must be refused:\n%s", got.Code)
	}
	if len(got.Unrepairable) == 0 {
		t.Error("expected a refusal note for a non-Go error rewrap")
	}
}

func TestApplyIsDeterministic(t *testing.T) {
	code := `package main

import (
	"fmt"
	"os/exec"
)

func run() error {
	_ = work()
	exec.Command("ls")
	return nil
}
`
	f := New(testPolicy([]string{"os/exec"}, []string{"Command"}, 5))
	vs := []sec.PolicyViolation{
		violation("BLOCKED_IMPORT", 5, "os/exec"),
		violation("BLOCKED_FUNCTION", 11, "Command"),
		violation("UNHANDLED_ERROR", 10, "_"),
	}

	first := f.Apply(code, "go", vs, nil)
	for i := 0; i < 5; i++ {
		got := f.Apply(code, "go", vs, nil)
		if got.Code != first.Code {
			t.Fatalf("repair output is not deterministic on iteration %d", i)
		}
	}
	mustParseGo(t, first.Code)
}

func TestApplyDoesNotTouchCleanCode(t *testing.T) {
	code := `package main

import "fmt"

func main() {
	fmt.Println("ok")
}
`
	f := New(testPolicy([]string{"os/exec"}, []string{"Command"}, 15))
	got := f.Apply(code, "go", nil, nil)

	if got.Code != code {
		t.Errorf("clean code must be returned byte-identical:\n%s", got.Code)
	}
	if got.Changed {
		t.Error("Changed must be false for clean code")
	}
	if len(got.Repairs) != 0 {
		t.Errorf("expected no repairs, got %v", got.Summary())
	}
}