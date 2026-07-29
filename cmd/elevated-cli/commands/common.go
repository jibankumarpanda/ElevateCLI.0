package commands

import (
	"fmt"
	"io"
	"os"

	"github.com/yourusername/elevated-cli/internal/config"
	"github.com/yourusername/elevated-cli/internal/output"
	"github.com/yourusername/elevated-cli/internal/sandbox"
	"github.com/yourusername/elevated-cli/internal/security"
	sec "github.com/yourusername/elevated-cli/pkg/security"
)

// buildPipeline wires together all 4 pipeline stages and returns a ready Pipeline.
// Called by generate.go and audit.go so the wiring is in one place.
func buildPipeline(cfg config.Config, runSandbox bool) (*security.Pipeline, error) {
	// Stage 1: Static analyzer
	staticAnalyzer := security.NewStaticAnalyzer()

	// Stage 2: Dependency auditor
	depAuditor := security.NewDependencyAuditor()

	// Stage 3: Policy engine (loaded from config rules)
	policyEngine := security.NewPolicyEngine(cfg.Policy)

	// Stage 4: Sandbox runner (chosen by config or --no-sandbox flag)
	var sandboxRunner security.SandboxRunner
	if !runSandbox || cfg.Sandbox.Mode == "skip" {
		sandboxRunner = &noopSandbox{}
	} else {
		switch cfg.Sandbox.Mode {
		case "firecracker":
			// Firecracker is implemented in internal/sandbox/firecracker_runner.go (batch 3)
			// Fall back to process runner if Firecracker binary not found
			sandboxRunner = sandbox.NewProcessRunner(
				cfg.Sandbox.TimeoutSec,
				cfg.Sandbox.MaxMemoryMB,
				cfg.Sandbox.BlockNetwork,
			)
		default: // "process" or "docker" (docker wrapper is batch 3)
			sandboxRunner = sandbox.NewProcessRunner(
				cfg.Sandbox.TimeoutSec,
				cfg.Sandbox.MaxMemoryMB,
				cfg.Sandbox.BlockNetwork,
			)
		}
	}

	return security.New(cfg, staticAnalyzer, depAuditor, policyEngine, sandboxRunner), nil
}

// printReport dispatches the completed report to the configured formatter.
func printReport(report *sec.Report, format string, showCode bool) {
	var w io.Writer = os.Stdout
	reporter := output.NewReporter(format, showCode, w)
	if err := reporter.Print(report); err != nil {
		fmt.Fprintf(os.Stderr, "Error printing report: %v\n", err)
	}
}

// noopSandbox satisfies the SandboxRunner interface but skips execution.
// Used when --no-sandbox flag is set or sandbox mode is "skip".
type noopSandbox struct{}

func (n *noopSandbox) Run(_ interface{ Done() <-chan struct{} }, code, language string) (sec.SandboxResult, error) {
	return sec.SandboxResult{
		Skipped:    true,
		SkipReason: "sandbox disabled via --no-sandbox flag or config",
		Mode:       "none",
	}, nil
}
