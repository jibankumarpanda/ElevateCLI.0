package verification

import (
	"context"
	"sync"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	"github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// PipelineOrchestrator manages the 4-stage verification pipeline.
type PipelineOrchestrator struct {
	sa     *StaticAnalyzer
	da     *DepAuditor
	pe     *PolicyEngine
}

func NewPipelineOrchestrator(cfg *config.Config) *PipelineOrchestrator {
	return &PipelineOrchestrator{
		sa: NewStaticAnalyzer(),
		da: NewDepAuditor(),
		pe: NewPolicyEngine(cfg),
	}
}

// RunParallel runs SAST, Deps, and Policy checks concurrently.
func (po *PipelineOrchestrator) RunParallel(ctx context.Context, code string, lang string) ([]security.Finding, []security.Vulnerability, []security.Finding, error) {
	var (
		findings []security.Finding
		vulns    []security.Vulnerability
		policies []security.Finding
		errSA, errDA, errPE error
		wg sync.WaitGroup
	)

	wg.Add(3)

	// Stage 1: Static Analysis
	go func() {
		defer wg.Done()
		findings, errSA = po.sa.Analyze(ctx, code, lang)
	}()

	// Stage 2: Dependency Auditing
	go func() {
		defer wg.Done()
		vulns, errDA = po.da.Audit(ctx, code, lang)
	}()

	// Stage 3: Policy Enforcement
	go func() {
		defer wg.Done()
		policies, errPE = po.pe.Check(code, lang)
	}()

	wg.Wait()

	if errSA != nil { return nil, nil, nil, errSA }
	if errDA != nil { return nil, nil, nil, errDA }
	if errPE != nil { return nil, nil, nil, errPE }

	return findings, vulns, policies, nil
}
