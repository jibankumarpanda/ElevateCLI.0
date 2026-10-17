package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/audit"
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
	staticAnalyzer := security.NewStaticAnalyzerWithPlugins(cfg.Plugins.Analyzers)

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
				MemoryMB:      cfg.Sandbox.MaxMemoryMB,
				Timeout:       time.Duration(cfg.Sandbox.TimeoutSec) * time.Second,
				AllowNet:      !cfg.Sandbox.BlockNetwork,
				MaxCPUSeconds: cfg.Sandbox.MaxCPUSeconds,
				MaxNProc:      cfg.Sandbox.MaxNProc,
				MaxOutputKB:   cfg.Sandbox.MaxOutputKB,
				MaxFSWriteMB:  cfg.Sandbox.MaxFSWriteMB,
			})
		case "gvisor":
			// gVisor executes the generated code inside a user-space kernel
			// (syscall interception), rootless, with the host filesystem presented
			// read-only behind a memory overlay and a fresh network namespace.
			// Fails closed if the boundary cannot be provided; never degrades to
			// the host os/exec process runner.
			sandboxRunner = sandbox.NewGVisorRunner(
				cfg.Sandbox.TimeoutSec,
				cfg.Sandbox.MaxMemoryMB,
				cfg.Sandbox.BlockNetwork,
				sandbox.ResourceLimits{
					MaxOutputKB: cfg.Sandbox.MaxOutputKB,
				},
			)
		case "docker":
			// Docker executes the generated code in a disposable, hardened
			// container: no network, read-only root with a tmpfs /tmp, dropped
			// capabilities, a non-root user, and memory/CPU/PID caps. Fails
			// closed if the daemon or image is unavailable; never degrades to
			// host os/exec.
			sandboxRunner = sandbox.NewDockerRunner(
				cfg.Sandbox.TimeoutSec,
				cfg.Sandbox.MaxMemoryMB,
				cfg.Sandbox.BlockNetwork,
				sandbox.ResourceLimits{
					MaxNProc:     cfg.Sandbox.MaxNProc,
					MaxOutputKB:  cfg.Sandbox.MaxOutputKB,
					MaxFSWriteMB: cfg.Sandbox.MaxFSWriteMB,
				},
				cfg.Sandbox.DockerImage,
			)
		default: // "process"
			sandboxRunner = sandbox.NewProcessRunnerWithLimits(
				cfg.Sandbox.TimeoutSec,
				cfg.Sandbox.MaxMemoryMB,
				cfg.Sandbox.BlockNetwork,
				sandbox.ResourceLimits{
					MaxCPUSeconds: cfg.Sandbox.MaxCPUSeconds,
					MaxNProc:      cfg.Sandbox.MaxNProc,
					MaxOutputKB:   cfg.Sandbox.MaxOutputKB,
					MaxFSWriteMB:  cfg.Sandbox.MaxFSWriteMB,
				},
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
	db, err := openAuditDB(cfg)
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
		return
	}
	exportAuditRecord(cfg, report)
}

// openAuditDB opens the local audit database with the configured retention and
// encryption policy. When encryption is enabled but no usable key is present it
// fails closed rather than silently writing plaintext reports.
func openAuditDB(cfg *config.Config) (*database.SQLiteDB, error) {
	opts := database.OpenOptions{
		RetentionDays: cfg.Audit.RetentionDays,
		MaxRecords:    cfg.Audit.MaxRecords,
	}
	if cfg.Audit.Encrypt {
		envName := cfg.Audit.EncryptionKeyEnv
		if envName == "" {
			envName = "ELEVATED_CLI_AUDIT_KEY"
		}
		key := os.Getenv(envName)
		if key == "" {
			return nil, fmt.Errorf("audit encryption enabled but %s is not set", envName)
		}
		opts.EncryptionKey = database.KeyFromString(key)
	}
	return database.OpenWithOptions(cfg.Output.AuditDB, opts)
}

// exportAuditRecord ships a completed report to the configured centralized
// audit endpoint. Like local persistence, export failures are warnings.
func exportAuditRecord(cfg *config.Config, report *sec.Report) {
	if !cfg.Audit.Export.Enabled || cfg.Audit.Export.Endpoint == "" {
		return
	}
	token := ""
	if cfg.Audit.Export.TokenEnv != "" {
		token = os.Getenv(cfg.Audit.Export.TokenEnv)
	}
	payload, err := json.Marshal(report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ audit export skipped: %v\n", err)
		return
	}
	exporter := audit.New(cfg.Audit.Export.Endpoint, token)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := exporter.Export(ctx, payload); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ audit export failed: %v\n", err)
	}
}

// checkFeatureGates enforces the experimental opt-in for the repair flags.
//
// The configuration is passed in rather than read from the global, so the gate
// is testable and cannot be affected by config load order.
//
// The gate is explicit about which feature is missing rather than reporting a
// generic failure, because these flags are the only way a user reaches
// LLM-proposed code changes and a silent "unknown flag" error would send them
// looking for a typo instead of a configuration change. Every dependent feature
// must be listed separately: opting into fix_semantic does not imply fix_loop.
func checkFeatureGates(exp config.ExperimentalConfig, fix, semantic, review bool) error {
	if fix && !exp.FeatureEnabled(config.FeatureFixLoop) {
		return fmt.Errorf(
			"--fix is experimental and disabled by default; enable it by adding %q to experimental.features",
			config.FeatureFixLoop)
	}
	if semantic && !exp.FeatureEnabled(config.FeatureFixSemantic) {
		return fmt.Errorf(
			"--fix-semantic is experimental and disabled by default; enable it by adding %q to experimental.features",
			config.FeatureFixSemantic)
	}
	if review && !exp.FeatureEnabled(config.FeatureReview) {
		return fmt.Errorf(
			"--review is experimental and disabled by default; enable it by adding %q to experimental.features",
			config.FeatureReview)
	}

	// A dependent feature cannot work without its dependency, and silently
	// ignoring the missing one would produce a run that quietly does less than
	// the user asked for.
	if (semantic || review) && !exp.FeatureEnabled(config.FeatureFixLoop) {
		return fmt.Errorf(
			"this flag requires %q to be enabled in experimental.features as well",
			config.FeatureFixLoop)
	}
	if semantic && !fix {
		return fmt.Errorf("--fix-semantic requires --fix")
	}
	if review && !fix {
		return fmt.Errorf("--review requires --fix")
	}
	return nil
}

// announceFixOutcome writes a short note to stderr describing how the repair loop
// terminated.
//
// It goes to stderr rather than stdout so machine-readable output is untouched,
// and it never claims success: the score and verdict in the report are the
// authoritative answer, and this line only says what the loop did.
func announceFixOutcome(report *sec.Report) {
	if report == nil || report.Fix == nil {
		return
	}
	f := report.Fix
	fmt.Fprintf(os.Stderr, "🔧 Repair loop finished after %d round(s): %d → %d, %s → %s\n",
		len(f.FixRounds), f.PreFixScore, f.PostFixScore, f.PreFixVerdict, f.PostFixVerdict)
	fmt.Fprintf(os.Stderr, "   Stopped: %s\n", f.StopReason)
	if len(f.FixRounds) == 0 {
		fmt.Fprintf(os.Stderr, "   No repairs were needed or attempted.\n")
		return
	}
	last := f.FixRounds[len(f.FixRounds)-1]
	if last.Strategy == sec.FixStrategySemantic && last.Accepted {
		fmt.Fprintf(os.Stderr, "   ⚠ A model-written patch was accepted; review the diff before using the code.\n")
	}
	for _, un := range last.Unrepairable {
		fmt.Fprintf(os.Stderr, "   ⚠ %s\n", un)
	}
}

// printReview renders the diff of the last repair round so a human can see
// exactly what changed. It is deliberately plain, uncoloured output: this is
// the artefact meant to be read and argued with, not skimmed.
func printReview(report *sec.Report) {
	diff := security.LastDiff(report.Fix)
	fmt.Fprintln(os.Stderr, "\n── Review: changes made by the repair loop ──────────")
	if strings.TrimSpace(diff) == "" {
		fmt.Fprintln(os.Stderr, "No changes were made, so there is no diff to review.")
		fmt.Fprintln(os.Stderr, "──────────────────────────────────────────────────")
		return
	}
	fmt.Fprintln(os.Stderr, diff)
	fmt.Fprintln(os.Stderr, "──────────────────────────────────────────────────")
	fmt.Fprintln(os.Stderr, "Review the diff above before using this code. The verdict above")
	fmt.Fprintln(os.Stderr, "describes the repaired code, not your approval of it.")
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
