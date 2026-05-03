package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/ai"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/database"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/output"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/sandbox"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/verification"
	"github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
	"github.com/spf13/cobra"
)

var (
	cfg *config.Config
)

func main() {
	var err error
	cfg, err = config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	rootCmd := &cobra.Command{
		Use:   "elevated-cli",
		Short: "ElevatedCLI - Production-grade security-first code generation",
	}

	rootCmd.AddCommand(generateCmd())
	rootCmd.AddCommand(auditCmd())
	rootCmd.AddCommand(historyCmd())
	rootCmd.AddCommand(configCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generateCmd() *cobra.Command {
	var prompt, lang, model, sandboxMode string
	var run, dryRun bool

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate secure code from a natural language prompt",
		Run: func(cmd *cobra.Command, args []string) {
			if dryRun {
				fmt.Printf("Dry-run: Generating %s code for: %s\n", lang, prompt)
				return
			}

			// Initialize AI client
			var client ai.LLMClient
			provider := cfg.AI.Provider
			if provider == "openai" {
				client = ai.NewOpenAIClient(cfg.AI.APIKey, cfg.AI.Model)
			} else if provider == "ollama" {
				client = ai.NewOllamaClient(cfg.AI.Endpoint, cfg.AI.Model)
			} else {
				log.Fatalf("Unknown AI provider: %s", provider)
			}

			pe := ai.NewPromptEngineer(lang)
			fullPrompt := pe.ConstructPrompt(prompt, lang)

			fmt.Println("Calling LLM...")
			code, err := client.GenerateCode(context.Background(), fullPrompt, lang)
			if err != nil {
				log.Fatalf("AI generation failed: %v", err)
			}

			fmt.Println("--- Generated Code ---")
			fmt.Println(code)
			fmt.Println("----------------------")

			// Phase 2: Verification Pipeline
			orchestrator := verification.NewPipelineOrchestrator(cfg)
			findings, vulns, policies, err := orchestrator.RunParallel(context.Background(), code, lang)
			if err != nil {
				log.Fatalf("Verification pipeline failed: %v", err)
			}

			// Phase 3: Sandbox Execution
			var sbResult security.SandboxResult
			if run {
				limits := sandbox.DefaultLimits()
				runner := sandbox.NewProcessRunner(limits)
				sbResult, err = runner.Run(context.Background(), code, lang)
				if err != nil {
					log.Printf("Sandbox execution error: %v", err)
				}
			}

			// Phase 4: Scoring, Reporting, and Database
			reporter := output.NewReporter()
			report := reporter.CreateReport(prompt, code, lang, findings, vulns, policies, sbResult)

			db, err := database.NewSQLiteDB(cfg.Database.Path)
			if err == nil {
				db.SaveReport(report)
			}

			// Show TUI result
			p := output.NewUI(report)
			if _, err := p.Run(); err != nil {
				log.Fatalf("TUI error: %v", err)
			}
		},
	}

	cmd.Flags().StringVarP(&prompt, "prompt", "p", "", "Natural language description of code to generate")
	cmd.Flags().StringVarP(&lang, "lang", "l", "go", "Target language")
	cmd.Flags().StringVarP(&model, "model", "m", "", "LLM model to use")
	cmd.Flags().StringVarP(&sandboxMode, "sandbox", "s", "process", "Sandbox mode override")
	cmd.Flags().BoolVar(&run, "run", false, "Execute in sandbox after verification")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show prompt only, do not call LLM")

	cmd.MarkFlagRequired("prompt")

	return cmd
}

func auditCmd() *cobra.Command {
	var file, dir string

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit an existing file or directory for security vulnerabilities",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Audit command not yet fully implemented.")
		},
	}

	cmd.Flags().StringVarP(&file, "file", "f", "", "Audit an existing file")
	cmd.Flags().StringVarP(&dir, "dir", "d", "", "Audit all files in a directory")

	return cmd
}

func historyCmd() *cobra.Command {
	var last int
	var date string

	cmd := &cobra.Command{
		Use:   "history",
		Short: "Show scan history from the audit database",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("History command not yet implemented.")
		},
	}

	cmd.Flags().IntVarP(&last, "last", "n", 10, "Show last N scan records")
	cmd.Flags().StringVar(&date, "date", "", "Filter by date (YYYY-MM-DD)")

	return cmd
}

func configCmd() *cobra.Command {
	var show bool
	var set string

	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage configuration",
		Run: func(cmd *cobra.Command, args []string) {
			if show {
				fmt.Printf("Provider: %s\n", cfg.AI.Provider)
				fmt.Printf("Model: %s\n", cfg.AI.Model)
				fmt.Printf("Endpoint: %s\n", cfg.AI.Endpoint)
				fmt.Printf("Sandbox: %s\n", cfg.Sandbox.Mode)
				fmt.Printf("Database: %s\n", cfg.Database.Path)
			} else {
				fmt.Println("Use --show to see config or implement --set")
			}
		},
	}

	cmd.Flags().BoolVar(&show, "show", false, "Print current config")
	cmd.Flags().StringVar(&set, "set", "", "Set a config value (key=value)")

	return cmd
}
