package security

import (
	"strings"
	"testing"

	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

func TestValidateSyntaxCleanCode(t *testing.T) {
	cases := map[string]string{
		"python":     "def f(x):\n    return {'a': [1, 2]}\n# comment with ( unbalanced\ns = \"a string with ) bracket\"\n",
		"javascript": "function f(){ return {a:[1,2]}; } // note (\nconst s = `template ${x} )`;\n",
		"typescript": "const f = (x: number): number => { return x; };\nconst s: string = 'ok )';\n",
		"go":         "package main\nfunc main() { s := `raw ) string`; _ = s }\n",
	}
	for lang, code := range cases {
		if got := validateSyntax(code, lang); len(got) != 0 {
			t.Errorf("%s: expected clean, got %+v", lang, got)
		}
	}
}

func TestValidateSyntaxUnbalancedBracket(t *testing.T) {
	got := validateSyntax("def f():\n    return [1, 2\n", "python")
	if len(got) == 0 {
		t.Fatal("expected unclosed bracket finding")
	}
	if got[0].Severity != sec.SeverityHigh {
		t.Errorf("severity = %v want high", got[0].Severity)
	}
	if !strings.Contains(got[0].Description, "unclosed") {
		t.Errorf("description = %q", got[0].Description)
	}
}

func TestValidateSyntaxUnexpectedClose(t *testing.T) {
	got := validateSyntax("const x = 1);\n", "javascript")
	if len(got) != 1 || !strings.Contains(got[0].Description, "unexpected") {
		t.Fatalf("expected unexpected ')' finding, got %+v", got)
	}
}

func TestValidateSyntaxUnterminatedString(t *testing.T) {
	got := validateSyntax("const s = \"never closed\n", "javascript")
	if len(got) == 0 || !strings.Contains(got[0].Description, "unterminated string") {
		t.Fatalf("expected unterminated string, got %+v", got)
	}
}

func TestValidateSyntaxPythonTripleQuote(t *testing.T) {
	clean := "x = \"\"\"a ) b ( c\"\"\"\n"
	if got := validateSyntax(clean, "python"); len(got) != 0 {
		t.Fatalf("triple-quoted content should be ignored: %+v", got)
	}
	broken := "x = \"\"\"never closed\n"
	if got := validateSyntax(broken, "python"); len(got) == 0 {
		t.Fatal("expected unterminated triple-quote finding")
	}
}

func TestValidateSyntaxUnterminatedBlockComment(t *testing.T) {
	got := validateSyntax("/* never closed\nconst x = 1;\n", "javascript")
	if len(got) == 0 || !strings.Contains(got[0].Description, "block comment") {
		t.Fatalf("expected unterminated block comment, got %+v", got)
	}
}

func TestValidateSyntaxUnknownLanguage(t *testing.T) {
	if got := validateSyntax("anything )(", "ruby"); got != nil {
		t.Fatalf("unknown language should yield no findings, got %+v", got)
	}
}
