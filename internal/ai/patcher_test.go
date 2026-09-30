package ai

import (
	"context"
	"strings"
	"testing"

	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

type stubClient struct {
	response string
	err      error
	prompt   string
	calls    int
}

func (s *stubClient) Generate(_ context.Context, prompt string) (string, error) {
	s.calls++
	s.prompt = prompt
	return s.response, s.err
}

func (s *stubClient) Provider() string { return "stub" }
func (s *stubClient) Model() string    { return "stub-model" }

func patchReport() *sec.Report {
	return &sec.Report{
		Findings: []sec.Finding{
			{ID: "f1", RuleID: "G104", Title: "unhandled error", Severity: sec.SeverityHigh, Line: 12},
		},
		Violations: []sec.PolicyViolation{
			{Rule: "BLOCKED_IMPORT", Description: "Import of 'os/exec' is blocked", Line: 3},
		},
	}
}

func TestPatcherReturnsFullCodeFromFence(t *testing.T) {
	client := &stubClient{
		response: "Here is the fix:\n```go\npackage main\n\nfunc main() {}\n```\nThat fixes it.",
	}
	p := NewPatcher(client)

	got, err := p.Patch(context.Background(), "package main\n\nfunc main() { _ = 1 }", "go", patchReport())
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if got != "package main\n\nfunc main() {}" {
		t.Errorf("patch = %q, want the fenced block only", got)
	}
}

func TestPatcherIncludesFindingsInPrompt(t *testing.T) {
	client := &stubClient{response: "```go\npackage main\n```"}
	p := NewPatcher(client)

	if _, err := p.Patch(context.Background(), "package main", "go", patchReport()); err != nil {
		t.Fatalf("Patch: %v", err)
	}

	prompt := client.prompt
	// The model can only act on what it is told, so the rule, the severity, the
	// line, the violation, and the original code all have to be in the prompt.
	for _, want := range []string{"G104", "HIGH", "line 12", "BLOCKED_IMPORT", "package main"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

func TestPatcherRejectsEmptyResponse(t *testing.T) {
	p := NewPatcher(&stubClient{response: "I cannot fix this without changing behaviour."})
	if _, err := p.Patch(context.Background(), "package main", "go", patchReport()); err == nil {
		t.Error("a response with no code must be an error, not an empty patch")
	}
}

func TestPatcherRejectsWrongLanguage(t *testing.T) {
	// Verifying a python patch against the Go analyser would check the wrong
	// thing entirely, so it must fail rather than proceed.
	p := NewPatcher(&stubClient{response: "```python\nprint('hi')\n```"})
	_, err := p.Patch(context.Background(), "package main", "go", patchReport())
	if err == nil {
		t.Fatal("a patch in the wrong language must be rejected")
	}
	if !strings.Contains(err.Error(), "wrong language") {
		t.Errorf("error = %v, want it to name the language mismatch", err)
	}
}

func TestPatcherRejectsEmptyCode(t *testing.T) {
	client := &stubClient{response: "```go\npackage main\n```"}
	p := NewPatcher(client)
	if _, err := p.Patch(context.Background(), "   ", "go", patchReport()); err == nil {
		t.Error("patching empty code must be an error")
	}
	if client.calls != 0 {
		t.Error("the model must not be called for empty code")
	}
}

func TestPatcherRequiresClient(t *testing.T) {
	var p *Patcher
	if _, err := p.Patch(context.Background(), "package main", "go", patchReport()); err == nil {
		t.Error("a nil patcher must fail rather than panic")
	}
}

func TestPatcherSurfacesClientError(t *testing.T) {
	p := NewPatcher(&stubClient{err: context.Canceled})
	_, err := p.Patch(context.Background(), "package main", "go", patchReport())
	if err == nil {
		t.Fatal("a provider error must be returned, not swallowed")
	}
	if !strings.Contains(err.Error(), "semantic patch request failed") {
		t.Errorf("error = %v, want it to name the failed request", err)
	}
}