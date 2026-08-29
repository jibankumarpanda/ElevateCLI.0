package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/database"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/output"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/sandbox"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/security"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// buildPipeline wires together all 4 pipeline stages and returns a ready Pipeline.
// Called by generate.go and audit.go so the wiring is in one place.
// srcDir is the project directory used for lockfile discovery in the
// dependency stage; pass "" when only raw code is available (generate).
func buildPipeline(cfg config.Config, runSandbox bool, srcDir string) (*security.Pipeline, error) {
	// Stage 1: Static analyzer
	staticAnalyzer := security.NewStaticAnalyzer()

	// Stage 2: Dependency auditor (CVE scan via govulncheck/osv-scanner)
	depAuditor := security.NewDependencyAuditor(cfg.Analysis)
	depAuditor.Dir = srcDir

	// Stage 3: Policy engine (loaded from config rules)
	policyEngine := security.NewPolicyEngine(cfg.Policy)

	// Stage 4: Sandbox runner (chosen by config or --no-sandbox flag)
	var sandboxRunner security.SandboxRunner
	if !runSandbox || cfg.Sandbox.Mode == "skip" {
		sandboxRunner = &noopSandbox{}
	} else {
		switch cfg.Sandbox.Mode {
		case "firecracker":
			// Firecracker microVM execution fails closed: the runner returns an
			// error when the runtime is unavailable or not yet implemented, so
			// the pipeline marks the run ANALYSIS_INCOMPLETE instead of silently
			// executing on the host with os/exec.
			sandboxRunner = sandbox.NewFirecrackerRunner(sandbox.ResourceLimits{
				MemoryMB: cfg.Sandbox.MaxMemoryMB,
				Timeout:  time.Duration(cfg.Sandbox.TimeoutSec) * time.Second,
				AllowNet: !cfg.Sandbox.BlockNetwork,
			})
		case "docker":
			// Docker execution is documented as a config value but has no
			// implemented runner. Fail closed (ANALYSIS_INCOMPLETE) rather than
			// silently substituting host os/exec execution.
			sandboxRunner = &unavailableSandbox{
				reason: "sandbox.mode: docker is not implemented; no container runner is available",
			}
		default: // "process"
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

// saveAuditRecord persists a completed report to the local audit trail,
// honouring the configured retention and redaction settings. Failures to
// write history are warnings, not command failures: analysis already ran and
// was reported to the user, and a full audit DB must not block development.
func saveAuditRecord(cfg *config.Config, report *sec.Report) {
	db, err := database.Open(cfg.Output.AuditDB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ audit history unavailable: %v\n", err)
		return
	}
	defer db.Close() //nolint:errcheck

	if err := db.SaveReport(*report, database.SaveOptions{
		StorePrompts:       cfg.Audit.StorePrompts,
		StoreGeneratedCode: cfg.Audit.StoreGeneratedCode,
		RedactSecrets:      cfg.Audit.RedactSecrets,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to save audit record: %v\n", err)
	}
}

// noopSandbox satisfies the SandboxRunner interface but skips execution.
// Used when --no-sandbox flag is set or sandbox mode is "skip".
type noopSandbox struct{}

func (n *noopSandbox) Run(_ context.Context, code, language string) (sec.SandboxResult, error) {
	return sec.SandboxResult{
		Skipped:    true,
		SkipReason: "sandbox disabled via --no-sandbox flag or config",
		Mode:       "none",
	}, nil
}

// unavailableSandbox satisfies the SandboxRunner interface but always fails.
// Used when a sandbox mode is configured that has no implemented runner
// (currently "docker"). The pipeline treats the error as incomplete analysis
// under fail-closed mode, so a missing runtime is never reported as a clean
// or executed run.
type unavailableSandbox struct {
	reason string
}

func (u *unavailableSandbox) Run(_ context.Context, code, language string) (sec.SandboxResult, error) {
	return sec.SandboxResult{
		Executed:   false,
		Skipped:    false,
		SkipReason: u.reason,
		Mode:       "unavailable",
	}, fmt.Errorf("%s", u.reason)
}
