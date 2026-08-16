package commands

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/database"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/output/formatters"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// ─── history command ──────────────────────────────────────────────────────────

func newHistoryCmd() *cobra.Command {
	var (
		last   int
		date   string
		scanID string
	)

	cmd := &cobra.Command{
		Use:   "history",
		Short: "Browse past scan results from the audit database",
		Example: `  # Show last 20 scans
  elevated-cli history --last 20

  # Show scans from a specific date
  elevated-cli history --date 2025-04-24

  # Show full report for a scan ID
  elevated-cli history --id abc123`,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := database.Open(cfg.Output.AuditDB)
			if err != nil {
				return fmt.Errorf("opening audit database: %w", err)
			}
			defer db.Close()

			ctx := context.Background()

			// Show full report for a specific scan
			if scanID != "" {
				report, err := db.GetReport(ctx, scanID)
				if err != nil {
					return fmt.Errorf("fetching scan %s: %w", scanID, err)
				}
				printReport(report, cfg.Output.Format, true)
				return nil
			}

			// List by date
			if date != "" {
				if _, err := time.Parse("2006-01-02", date); err != nil {
					return fmt.Errorf("invalid date format, use YYYY-MM-DD")
				}
				summaries, err := db.ListByDate(ctx, date)
				if err != nil {
					return fmt.Errorf("querying history: %w", err)
				}
				printHistoryTable(summaries)
				return nil
			}

			// Default: last N scans
			if last <= 0 {
				last = 10
			}
			summaries, err := db.ListRecent(ctx, last)
			if err != nil {
				return fmt.Errorf("querying history: %w", err)
			}
			printHistoryTable(summaries)
			return nil
		},
	}

	cmd.Flags().IntVarP(&last, "last", "n", 10, "Number of recent scans to show")
	cmd.Flags().StringVarP(&date, "date", "d", "", "Filter by date (YYYY-MM-DD)")
	cmd.Flags().StringVar(&scanID, "id", "", "Show full report for a specific scan ID")

	return cmd
}

func printHistoryTable(summaries []database.ScanSummary) {
	if len(summaries) == 0 {
		fmt.Println("No scan history found. Run 'elevated-cli generate' to create entries.")
		return
	}

	gray := color.New(color.FgHiBlack)
	bold := color.New(color.Bold)

	_, _ = bold.Printf("\n  %-5s  %-8s  %-8s  %-10s  %-19s  %s\n",
		"Score", "Verdict", "Lang", "Provider", "Date", "Prompt")
	_, _ = gray.Printf("  %s\n", strings.Repeat("─", 85))

	for _, s := range summaries {
		line := formatters.SummaryLine(
			s.ID, s.Timestamp, s.Prompt,
			s.FinalScore, s.Verdict, s.Language,
		)
		switch s.Verdict {
		case sec.VerdictApproved:
			color.Green("  %s\n", line)
		case sec.VerdictWarning:
			color.Yellow("  %s\n", line)
		default:
			color.Red("  %s\n", line)
		}
	}

	_, _ = gray.Printf("\n  Use --id <scan_id> to see the full report for any scan.\n\n")
}

// ─── config command ───────────────────────────────────────────────────────────

func newConfigCmd() *cobra.Command {
	var (
		showFlag bool
		setFlag  string
	)

	cmd := &cobra.Command{
		Use:   "config",
		Short: "View or modify ElevatedCLI configuration",
		Example: `  # Show current resolved config
  elevated-cli config --show

  # Override a value in .elevated-cli.yaml
  elevated-cli config --set ai.model=gpt-4o
  elevated-cli config --set sandbox.mode=firecracker
  elevated-cli config --set scoring.passing_threshold=80`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if setFlag != "" {
				return setConfigValue(setFlag)
			}
			// Default: show
			printConfig()
			return nil
		},
	}

	cmd.Flags().BoolVar(&showFlag, "show", true, "Print current configuration")
	cmd.Flags().StringVar(&setFlag, "set", "", "Set a config value: key=value")

	return cmd
}

func printConfig() {
	bold := color.New(color.Bold)
	gray := color.New(color.FgHiBlack)
	cyan := color.New(color.FgCyan)

	_, _ = bold.Println("\n  ElevatedCLI — Current Configuration")

	section := func(name string) {
		_, _ = gray.Printf("  ── %s\n", name)
	}
	row := func(key, val string) {
		fmt.Printf("  %-35s ", key)
		_, _ = cyan.Println(val)
	}

	section("AI")
	row("ai.provider", cfg.AI.Provider)
	row("ai.model", cfg.AI.Model)
	row("ai.api_key", "[set via env var]")
	row("ai.timeout_sec", fmt.Sprintf("%d", cfg.AI.TimeoutSec))

	section("Sandbox")
	row("sandbox.mode", cfg.Sandbox.Mode)
	row("sandbox.timeout_sec", fmt.Sprintf("%d", cfg.Sandbox.TimeoutSec))
	row("sandbox.max_memory_mb", fmt.Sprintf("%d", cfg.Sandbox.MaxMemoryMB))
	row("sandbox.block_network", fmt.Sprintf("%v", cfg.Sandbox.BlockNetwork))

	section("Scoring")
	row("scoring.sast_weight", fmt.Sprintf("%.2f", cfg.Scoring.SASTWeight))
	row("scoring.dep_weight", fmt.Sprintf("%.2f", cfg.Scoring.DepWeight))
	row("scoring.policy_weight", fmt.Sprintf("%.2f", cfg.Scoring.PolicyWeight))
	row("scoring.sandbox_weight", fmt.Sprintf("%.2f", cfg.Scoring.SandboxWeight))
	row("scoring.passing_threshold", fmt.Sprintf("%d", cfg.Scoring.PassThreshold))

	section("Output")
	row("output.format", cfg.Output.Format)
	row("output.audit_db", cfg.Output.AuditDB)

	fmt.Println()
}

func setConfigValue(kv string) error {
	// Find the project-level config file and update it
	// For now, print instructions — full write-back is batch 3
	parts := strings.SplitN(kv, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid format, use key=value")
	}
	key, val := parts[0], parts[1]

	fmt.Printf("To set %s = %s, add this to your .elevated-cli.yaml:\n\n", key, val)

	// Convert dot-notation to YAML path hint
	yamlKey := strings.ReplaceAll(key, ".", ":\n  ")
	fmt.Printf("  %s: %s\n\n", yamlKey, val)

	fmt.Println("Or set it via environment variable:")
	envKey := "ELEVATED_CLI_" + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
	fmt.Printf("  export %s=%s\n\n", envKey, val)

	_ = os.Stderr // suppress unused import
	return nil
}
