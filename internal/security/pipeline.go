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

// sandboxRequired reports whether the configured sandbox mode mandates actual
// execution. When the user opts out (--no-sandbox, mode "skip") skipping is a
// deliberate decision, not an analysis failure.
func (p *Pipeline) sandboxRequired() bool {
	switch p.cfg.Sandbox.Mode {
	case "process", "gvisor", "firecracker", "docker":
		return true
	default:
		return false
	}
}

// ─── Run ─────────────────────────────────────────────────────────────────────// Run executes the full 4-stage pipeline and returns the Report.
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

	// Collect stage results.
	// analysisComplete stays true only when every mandatory stage ran. A stage
	// error (e.g. gosec binary missing) means the result is partial, and the
	// final verdict must fail closed instead of being presented as safe.
	analysisComplete := true
	for r := range ch {
		if r.err != nil {
			analysisComplete = false
			// Non-fatal to collection: the stage's findings are still kept, but
			// the pipeline is now marked incomplete.
			log.Warn("pipeline stage error — analysis incomplete",
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
	sandboxRequired := p.sandboxRequired()
	sandboxResult, err := p.sandbox.Run(ctx, code, language)
	if err != nil {
		log.Warn("sandbox execution error", zap.Error(err))
		if sandboxRequired {
			// The sandbox was required and failed to run: runtime behaviour
			// was never verified — fail closed.
			analysisComplete = false
		}
		// Preserve the runner's detailed result (mode, fail-closed reason) so
		// the report says what was attempted, never that host execution ran.
		sandboxResult.Executed = false
		sandboxResult.Skipped = sandboxResult.Skipped && !sandboxRequired
		if sandboxResult.SkipReason == "" {
			sandboxResult.SkipReason = fmt.Sprintf("sandbox execution error: %v", err)
		}
	}
	report.Sandbox = sandboxResult

	// A required sandbox that did not execute (e.g. unsupported language)
	// means runtime behaviour could not be verified — fail closed.
	if sandboxRequired && !sandboxResult.Executed && !sandboxResult.Skipped {
		analysisComplete = false
	}
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
		analysisComplete,
	)
	report.StageScores = stages
	report.FinalScore = final
	report.Verdict = verdict
	report.AnalysisComplete = analysisComplete
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
