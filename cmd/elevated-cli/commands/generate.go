package commands

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jibankumarpanda/ElevatedCLI/internal/ai"
	"github.com/jibankumarpanda/ElevatedCLI/internal/logger"
	sec "github.com/jibankumarpanda/ElevatedCLI/pkg/security"
	"go.uber.org/zap"
)

func newGenerateCmd() *cobra.Command {
	var (
		prompt    string
		language  string
		model     string
		sandbox   string
		runCode   bool
		dryRun    bool
		outFormat string
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
  elevated-cli generate --prompt "..." --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if prompt == "" {
				return fmt.Errorf("--prompt is required")
			}

			log := logger.Get()

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

			pipeline, err := buildPipeline(*cfg, runCode)
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

			// ── Display results ───────────────────────────────────────────
			printReport(report, cfg.Output.Format, cfg.Output.ShowCode)

			// ── Exit code based on verdict ────────────────────────────────
			if report.Verdict == sec.VerdictRejected {
				os.Exit(2) // exit 2 = security rejection (CI can check this)
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

	_ = cmd.MarkFlagRequired("prompt")

	return cmd
}
