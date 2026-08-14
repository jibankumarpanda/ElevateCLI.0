// Package commands contains all Cobra CLI command definitions for ElevatedCLI.
package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	"github.com/jibankumarpanda/ElevateCLI.0/internal/logger"
)

var (
	cfgFile string
	cfg     *config.Config
)

// RootCmd is the base command. Every subcommand is attached to this.
var RootCmd = &cobra.Command{
	Use:   "elevated-cli",
	Short: "Secure AI Developer CLI — verified, scored AI code generation",
	Long: `ElevatedCLI generates code using AI and runs it through a 4-stage
security pipeline (SAST → dependency audit → policy enforcement → sandbox)
before showing you the result.

Every piece of generated code receives a Security Score (0–100):
  ✓ APPROVED  (70–100)  — safe to use
  ⚠ WARNING   (40–69)   — review findings before using
  ✗ REJECTED  (0–39)    — do not use

Usage:
  elevated-cli generate --prompt "write a REST handler" --lang go
  elevated-cli audit    --file ./mycode.go
  elevated-cli history  --last 10
`,
	SilenceErrors: true,
	SilenceUsage:  true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load config before every command
		var err error
		cfg, err = config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// Initialise logger
		return logger.Init(logger.LoggerConfig{
			Level:      cfg.Logger.Level,
			Format:     cfg.Logger.Format,
			File:       cfg.Logger.File,
			MaxSizeMB:  cfg.Logger.MaxSizeMB,
			MaxBackups: cfg.Logger.MaxBackups,
		})
	},
}

// Execute is called from main.go. It runs the appropriate subcommand.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func init() {
	// Persistent flags — available to every subcommand
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		"config file path (default: .elevated-cli.yaml in home or current dir)")
	RootCmd.PersistentFlags().String("output", "",
		"output format: rich | json | sarif | plain (overrides config)")
	RootCmd.PersistentFlags().Bool("no-sandbox", false,
		"skip sandbox execution (faster, less safe)")
	RootCmd.PersistentFlags().Bool("verbose", false,
		"enable verbose/debug logging")

	// Bind flags to viper so config file, env, and flags all work together
	_ = viper.BindPFlag("output.format", RootCmd.PersistentFlags().Lookup("output"))
	_ = viper.BindPFlag("logger.level", RootCmd.PersistentFlags().Lookup("verbose"))

	// Register all subcommands
	RootCmd.AddCommand(
		newGenerateCmd(),
		newAuditCmd(),
		newHistoryCmd(),
		newConfigCmd(),
	)
}
