// Package security provides the 4-stage verification pipeline that every
// piece of AI-generated code passes through before being shown to the developer.
package security

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/logger"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/security/scoring"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
	"go.uber.org/zap"
)

// Pipeline runs the 4 verification stages and returns a complete Report.
// Stages 1–3 run in parallel; Stage 4 runs after all three complete.
type Pipeline struct {
	cfg        config.Config
	static     StaticAnalyzer
	deps       DependencyAuditor
	policy     PolicyEngine
	sandbox    SandboxRunner
	calculator *scoring.Calculator
}

// ─── Interfaces for each stage ────────────────────────────────────────────────

// StaticAnalyzer runs SAST on generated code.
type StaticAnalyzer interface {
	Analyze(ctx context.Context, code, language string) ([]sec.Finding, error)
}

// DependencyAuditor checks dependencies for known CVEs.
type DependencyAuditor interface {
	Audit(ctx context.Context, code, language string) ([]sec.Vulnerability, error)
}

// PolicyEngine enforces configured rules against the code.
type PolicyEngine interface {
	Check(ctx context.Context, code, language string) ([]sec.PolicyViolation, error)
}

// SandboxRunner executes code in isolation.
type SandboxRunner interface {
	Run(ctx context.Context, code, language string) (sec.SandboxResult, error)
}

// ─── Constructor ─────────────────────────────────────────────────────────────

// New creates a Pipeline wired with real implementations.
func New(cfg config.Config, static StaticAnalyzer, deps DependencyAuditor,
	policy PolicyEngine, sandbox SandboxRunner) *Pipeline {
	return &Pipeline{
		cfg:        cfg,
		static:     static,
		deps:       deps,
		policy:     policy,
		sandbox:    sandbox,
		calculator: scoring.New(cfg.Scoring),
	}
}

// ─── Run ─────────────────────────────────────────────────────────────────────

// Run executes the full 4-stage pipeline and returns the Report.
func (p *Pipeline) Run(ctx context.Context, prompt, code, language, aiProvider, aiModel string) (*sec.Report, error) {
	start := time.Now()
	scanID := uuid.New().String()
	log := logger.WithRequestID(scanID)

	log.Info("pipeline started",
		zap.String("language", language),
		zap.String("provider", aiProvider),
	)

	report := &sec.Report{
		ID:            scanID,
		Timestamp:     start,
		Prompt:        prompt,
		Language:      language,
		GeneratedCode: code,
		CodeHash:      hashCode(code), // store hash, never raw keys in code
		AIProvider:    aiProvider,
		AIModel:       aiModel,
	}

	// ── Stages 1–3 in parallel ────────────────────────────────────────────
	type stageResult struct {
		findings   []sec.Finding
		vulns      []sec.Vulnerability
		violations []sec.PolicyViolation
		err        error
		stage      string
	}

	ch := make(chan stageResult, 3)
	var wg sync.WaitGroup

	// Stage 1: Static analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("stage 1: static analysis started")
		findings, err := p.static.Analyze(ctx, code, language)
		ch <- stageResult{findings: findings, err: err, stage: "sast"}
		log.Info("stage 1: static analysis complete", zap.Int("findings", len(findings)))
	}()

	// Stage 2: Dependency audit
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("stage 2: dependency audit started")
		vulns, err := p.deps.Audit(ctx, code, language)
		ch <- stageResult{vulns: vulns, err: err, stage: "deps"}
		log.Info("stage 2: dependency audit complete", zap.Int("vulns", len(vulns)))
	}()

	// Stage 3: Policy enforcement
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("stage 3: policy enforcement started")
		violations, err := p.policy.Check(ctx, code, language)
		ch <- stageResult{violations: violations, err: err, stage: "policy"}
		log.Info("stage 3: policy enforcement complete", zap.Int("violations", len(violations)))
	}()

	// Wait for all three then close channel
	go func() {
		wg.Wait()
		close(ch)
	}()

	// Collect stage results
	for r := range ch {
		if r.err != nil {
			// Non-fatal: log and continue; the stage contributes 0 to its score
			log.Warn("pipeline stage error",
				zap.String("stage", r.stage),
				zap.Error(r.err),
			)
		}
		report.Findings = append(report.Findings, r.findings...)
		report.Vulns = append(report.Vulns, r.vulns...)
		report.Violations = append(report.Violations, r.violations...)
	}

	// ── Stage 4: Sandbox execution ────────────────────────────────────────
	log.Info("stage 4: sandbox execution started")
	sandboxResult, err := p.sandbox.Run(ctx, code, language)
	if err != nil {
		log.Warn("sandbox execution error", zap.Error(err))
		sandboxResult = sec.SandboxResult{
			Executed:   false,
			Skipped:    true,
			SkipReason: fmt.Sprintf("sandbox error: %v", err),
		}
	}
	report.Sandbox = sandboxResult
	log.Info("stage 4: sandbox execution complete",
		zap.Bool("success", sandboxResult.Success),
		zap.String("mode", sandboxResult.Mode),
	)

	// ── Scoring ───────────────────────────────────────────────────────────
	stages, final, verdict := p.calculator.Compute(
		report.Findings,
		report.Vulns,
		report.Violations,
		report.Sandbox,
	)
	report.StageScores = stages
	report.FinalScore = final
	report.Verdict = verdict
	report.Duration = time.Since(start)

	log.Info("pipeline complete",
		zap.Int("score", final),
		zap.String("verdict", string(verdict)),
		zap.Duration("duration", report.Duration),
	)

	return report, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func hashCode(code string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(code)))
}
