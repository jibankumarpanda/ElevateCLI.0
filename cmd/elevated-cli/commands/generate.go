package commands

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/ai"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/fixer"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/logger"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/security"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
	"go.uber.org/zap"
)

func newGenerateCmd() *cobra.Command {
	var (
		prompt       string
		language     string
		model        string
		sandbox      string
		runCode      bool
		dryRun       bool
		outFormat    string
		doFix        bool
		fixSemantic  bool
		fixMaxRounds int
		showReview   bool
	)

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate code with AI and verify it through the security pipeline",
		Example: `  # Generate a Go REST handler
  elevated-cli generate --prompt "write a REST API handler for user login" --lang go

  # Generate Python code and run it in the sandbox
  elevated-cli generate --prompt "read a CSV and print row count" --lang python --run

  # Output raw JSON (useful for CI/CD)
  elevated-cli generate --prompt "..." --output json

  # Dry run — see the prompt without calling the LLM
  elevated-cli generate --prompt "..." --dry-run

  # Repair rule-driven findings, then re-verify (experimental)
  elevated-cli generate --prompt "..." --fix --review

  # Also ask the model to patch what no rule could fix (experimental)
  elevated-cli generate --prompt "..." --fix --fix-semantic --review`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if prompt == "" {
				return fmt.Errorf("--prompt is required")
			}

			log := logger.Get()

			// ── Experimental gates ────────────────────────────────────────
			// Checked before anything is generated so an unopted-in flag costs
			// no LLM call and no sandbox run.
			if err := checkFeatureGates(cfg.Experimental, doFix, fixSemantic, showReview); err != nil {
				return err
			}

			// ── Dry run ───────────────────────────────────────────────────
			if dryRun {
				builtPrompt := ai.BuildGeneratePrompt(prompt, language)
				fmt.Println("── Prompt (dry run) ──────────────────────────────")
				fmt.Println(builtPrompt)
				fmt.Println("──────────────────────────────────────────────────")
				return nil
			}

			// ── Override config from flags ─────────────────────────────────
			if model != "" {
				cfg.AI.Model = model
			}
			if sandbox != "" {
				cfg.Sandbox.Mode = sandbox
			}
			if outFormat != "" {
				cfg.Output.Format = outFormat
			}
			if cmd.Flags().Changed("no-sandbox") {
				cfg.Sandbox.Mode = "skip"
			}

			// ── Build AI client ───────────────────────────────────────────
			client, err := ai.New(cfg.AI)
			if err != nil {
				return fmt.Errorf("initialising AI client: %w", err)
			}

			// ── Call LLM ──────────────────────────────────────────────────
			ctx, cancel := context.WithTimeout(
				context.Background(),
				time.Duration(cfg.AI.TimeoutSec)*time.Second,
			)
			defer cancel()

			fmt.Fprintf(os.Stderr, "⏳ Generating %s code with %s/%s...\n",
				language, client.Provider(), client.Model())

			builtPrompt := ai.BuildGeneratePrompt(prompt, language)
			rawResponse, err := client.Generate(ctx, builtPrompt)
			if err != nil {
				return fmt.Errorf("AI generation failed: %w", err)
			}

			// Extract code from markdown code fence
			code, detectedLang := ai.ExtractCodeBlock(rawResponse)
			if detectedLang != "" && language == "go" {
				// Use LLM-detected language if user didn't specify
				language = detectedLang
			}

			log.Info("code generated",
				zap.String("language", language),
				zap.Int("code_length", len(code)),
			)

			// ── Run through security pipeline ─────────────────────────────
			fmt.Fprintf(os.Stderr, "🔍 Running security pipeline...\n")

			pipeline, err := buildPipeline(*cfg, runCode, "")
			if err != nil {
				return fmt.Errorf("building pipeline: %w", err)
			}

			pipelineCtx, pipelineCancel := context.WithTimeout(
				context.Background(),
				120*time.Second,
			)
			defer pipelineCancel()

			report, err := pipeline.Run(
				pipelineCtx,
				prompt,
				code,
				language,
				client.Provider(),
				client.Model(),
			)
			if err != nil {
				return fmt.Errorf("security pipeline failed: %w", err)
			}

			// ── Repair loop (experimental) ────────────────────────────────
			if doFix {
				// The patcher shares the generate context so a hung model
				// cannot outlive the overall timeout.
				fixOpts := security.FixLoopOptions{
					MaxRounds: fixMaxRounds,
					Semantic:  fixSemantic,
				}
				if fixSemantic {
					fixOpts.Patch = ai.NewPatcher(client)
				}

				loop := security.NewFixLoop(pipeline, fixer.New(cfg.Policy), fixOpts)
				fixed, err := loop.Run(pipelineCtx, report, language)
				if err != nil {
					return fmt.Errorf("fix loop failed: %w", err)
				}
				report = fixed
				announceFixOutcome(report)
			}

			// ── Display results ───────────────────────────────────────────
			printReport(report, cfg.Output.Format, cfg.Output.ShowCode)

			// ── Review diff (experimental) ───────────────────────────────
			// Printed after the report so the verdict is the first thing the
			// reader sees and the diff is the evidence behind it.
			if showReview {
				printReview(report)
			}

			// ── Persist to the local audit trail ──────────────────────────
			saveAuditRecord(cfg, report)

			// ── Exit code based on verdict ────────────────────────────────
			// Every hard-stop verdict (REJECTED, BLOCKED, ANALYSIS_INCOMPLETE,
			// EXECUTION_FAILED) exits non-zero so CI/CD gates on the outcome and
			// can distinguish the cause via the specific code.
			if code := sec.ExitCodeFor(report.Verdict); code != sec.ExitCodeOK {
				os.Exit(code)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&prompt, "prompt", "p", "", "Natural language description of code to generate (required)")
	cmd.Flags().StringVarP(&language, "lang", "l", "go", "Target language: go | python | javascript | typescript")
	cmd.Flags().StringVarP(&model, "model", "m", "", "LLM model override (e.g. gpt-4o, claude-3-5-sonnet-20241022)")
	cmd.Flags().StringVar(&sandbox, "sandbox", "", "Sandbox mode override: firecracker | process | docker")
	cmd.Flags().BoolVar(&runCode, "run", false, "Execute generated code in sandbox after verification")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print the prompt without calling the LLM")
	cmd.Flags().StringVarP(&outFormat, "output", "o", "", "Output format: rich | json | sarif | plain")

	// Repair flags ship dark. Each requires its experimental feature to be
	// listed in experimental.features; see checkFeatureGates.
	cmd.Flags().BoolVar(&doFix, "fix", false, "Repair rule-driven findings and re-verify (experimental, requires fix_loop)")
	cmd.Flags().BoolVar(&fixSemantic, "fix-semantic", false, "Also ask the model to patch findings no rule could fix (experimental, requires fix_loop and fix_semantic)")
	cmd.Flags().IntVar(&fixMaxRounds, "max-fix-rounds", security.DefaultFixRounds, "Maximum repair rounds before giving up")
	cmd.Flags().BoolVar(&showReview, "review", false, "Print the before/after diff of the latest repair round (experimental, requires fix_loop)")

	_ = cmd.MarkFlagRequired("prompt")

	return cmd
}
