package security

import (
	"context"
	"testing"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// stubStaticAnalyzer returns canned findings.
type stubStaticAnalyzer struct {
	findings []sec.Finding
	err      error
}

func (s *stubStaticAnalyzer) Analyze(ctx context.Context, code, language string) ([]sec.Finding, error) {
	return s.findings, s.err
}

// stubDependencyAuditor returns canned vulnerabilities.
type stubDependencyAuditor struct {
	vulns []sec.Vulnerability
	err   error
}

func (s *stubDependencyAuditor) Audit(ctx context.Context, code, language string) ([]sec.Vulnerability, error) {
	return s.vulns, s.err
}

// stubPolicyEngine returns canned violations.
type stubPolicyEngine struct {
	violations []sec.PolicyViolation
	err        error
}

func (s *stubPolicyEngine) Check(ctx context.Context, code, language string) ([]sec.PolicyViolation, error) {
	return s.violations, s.err
}

// stubSandboxRunner returns canned sandbox results.
type stubSandboxRunner struct {
	result sec.SandboxResult
	err    error
}

func (s *stubSandboxRunner) Run(ctx context.Context, code, language string) (sec.SandboxResult, error) {
	return s.result, s.err
}

func pipelineConfig(sandboxMode string) config.Config {
	return config.Config{
		Sandbox: config.SandboxConfig{Mode: sandboxMode, TimeoutSec: 5, MaxMemoryMB: 256},
		Scoring: config.ScoringConfig{},
	}
}

func newTestPipeline(cfg config.Config, sandbox sec.SandboxResult, sandboxErr error) *Pipeline {
	return New(cfg,
		&stubStaticAnalyzer{},
		&stubDependencyAuditor{},
		&stubPolicyEngine{},
		&stubSandboxRunner{result: sandbox, err: sandboxErr},
	)
}

func TestPipelineCleanCodeApproved(t *testing.T) {
	p := newTestPipeline(pipelineConfig("skip"), sec.SandboxResult{Skipped: true, Mode: "none"}, nil)
	report, err := p.Run(context.Background(), "prompt", "package main", "go", "openai", "gpt-4o")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Verdict != sec.VerdictApproved {
		t.Errorf("verdict = %q, want APPROVED", report.Verdict)
	}
	if report.FinalScore != 100 {
		t.Errorf("final score = %d, want 100", report.FinalScore)
	}
	if report.ID == "" {
		t.Error("report ID empty")
	}
	if report.CodeHash == "" {
		t.Error("code hash empty")
	}
	if !report.AnalysisComplete {
		t.Error("clean run should be analysis complete")
	}
}

func TestPipelineStageErrorFailsClosed(t *testing.T) {
	cfg := pipelineConfig("skip")
	p := New(cfg,
		&stubStaticAnalyzer{err: context.DeadlineExceeded},
		&stubDependencyAuditor{},
		&stubPolicyEngine{},
		&stubSandboxRunner{result: sec.SandboxResult{Skipped: true, Mode: "none"}},
	)
	report, err := p.Run(context.Background(), "p", "code", "go", "x", "y")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.AnalysisComplete {
		t.Error("stage error should mark analysis incomplete")
	}
	if report.Verdict != sec.VerdictAnalysisIncomplete {
		t.Errorf("verdict = %q, want ANALYSIS_INCOMPLETE", report.Verdict)
	}
}

func TestPipelineSandboxFailureFailsClosed(t *testing.T) {
	p := newTestPipeline(pipelineConfig("process"), sec.SandboxResult{}, context.Canceled)
	report, err := p.Run(context.Background(), "p", "code", "go", "x", "y")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.AnalysisComplete {
		t.Error("required sandbox that errored should fail closed")
	}
	if report.Verdict != sec.VerdictAnalysisIncomplete {
		t.Errorf("verdict = %q", report.Verdict)
	}
}

func TestPipelineFindingsAggregated(t *testing.T) {
	cfg := pipelineConfig("skip")
	p := New(cfg,
		&stubStaticAnalyzer{findings: []sec.Finding{{ID: "f", RuleID: "G101", Severity: sec.SeverityHigh}}},
		&stubDependencyAuditor{vulns: []sec.Vulnerability{{ID: "CVE-1", Severity: sec.SeverityMedium}}},
		&stubPolicyEngine{violations: []sec.PolicyViolation{{Rule: "BLOCKED_IMPORT"}}},
		&stubSandboxRunner{result: sec.SandboxResult{Skipped: true, Mode: "none"}},
	)
	report, err := p.Run(context.Background(), "p", "code", "go", "x", "y")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(report.Findings) != 1 || len(report.Vulns) != 1 || len(report.Violations) != 1 {
		t.Errorf("stages not aggregated: %+v", report)
	}
	if report.Verdict == sec.VerdictApproved {
		t.Error("report with findings should not be approved")
	}
}

func TestHashCodeDeterministic(t *testing.T) {
	a := hashCode("package main")
	b := hashCode("package main")
	c := hashCode("package other")
	if a != b {
		t.Error("hash should be deterministic")
	}
	if a == c {
		t.Error("different code should hash differently")
	}
	if len(a) != 64 {
		t.Errorf("hash length = %d, want 64 (sha256 hex)", len(a))
	}
}
