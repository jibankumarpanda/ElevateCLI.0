package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	AI struct {
		Provider string `mapstructure:"provider"`
		Model    string `mapstructure:"model"`
		APIKey   string `mapstructure:"api_key"`
		Endpoint string `mapstructure:"endpoint"` // For Ollama
	} `mapstructure:"ai"`
	Database struct {
		Path string `mapstructure:"path"`
	} `mapstructure:"database"`
	Sandbox struct {
		Mode string `mapstructure:"mode"` // process, firecracker, docker
	} `mapstructure:"sandbox"`
	Policy  PolicyConfig  `mapstructure:"policy"`
	Scoring ScoringConfig `mapstructure:"scoring"`
}

// PolicyConfig defines the security-policy rules enforced against generated code.
// These rules are explicit and configurable; blocking rules are enforced before
// any sandbox execution (see the pipeline).
type PolicyConfig struct {
	File  string `mapstructure:"file"`
	Rules struct {
		BlockedImports          []string `mapstructure:"blocked_imports"`
		BlockedFunctions        []string `mapstructure:"blocked_functions"`
		RequireErrorHandling    bool     `mapstructure:"require_error_handling"`
		MaxCyclomaticComplexity int      `mapstructure:"max_cyclomatic_complexity"`
	} `mapstructure:"rules"`
}

// ScoringConfig controls the deterministic security scoring algorithm.
//
// The final score is the weighted sum of the four stage sub-scores:
//
//	final = SAST*sast_weight + Deps*dep_weight + Policy*policy_weight + Sandbox*sandbox_weight
//
// Weights must sum to 1.0 (they are normalised if they do not). FailClosed
// defaults to true: when a mandatory check cannot complete, the result is
// ANALYSIS_INCOMPLETE rather than a partial score that could be read as safe.
// It is a *bool so that a zero-value ScoringConfig{} fails closed by default —
// only an explicit `fail_closed: false` opts into fail-open.
type ScoringConfig struct {
	SASTWeight    float64 `mapstructure:"sast_weight"`
	DepWeight     float64 `mapstructure:"dep_weight"`
	PolicyWeight  float64 `mapstructure:"policy_weight"`
	SandboxWeight float64 `mapstructure:"sandbox_weight"`
	PassThreshold int     `mapstructure:"pass_threshold"` // 0–100, default 70
	FailClosed    *bool   `mapstructure:"fail_closed"`    // default true
}

func LoadConfig() (*Config, error) {
	v := viper.New()

	// Set defaults
	v.SetDefault("ai.provider", "openai")
	v.SetDefault("ai.model", "gpt-4o")
	v.SetDefault("ai.endpoint", "http://localhost:11434")
	v.SetDefault("database.path", "secure-ai.db")
	v.SetDefault("sandbox.mode", "process")
	v.SetDefault("policy.file", ".elevated-cli.yaml")

	// Security scoring defaults — the formula and fail-closed behaviour are
	// part of the documented security contract, so they must never silently
	// change between releases.
	v.SetDefault("scoring.sast_weight", 0.40)
	v.SetDefault("scoring.dep_weight", 0.30)
	v.SetDefault("scoring.policy_weight", 0.20)
	v.SetDefault("scoring.sandbox_weight", 0.10)
	v.SetDefault("scoring.pass_threshold", 70)
	v.SetDefault("scoring.fail_closed", true)

	// Config file locations
	v.SetConfigName(".elevated-cli")
	v.SetConfigType("yaml")
	v.AddConfigPath(".") // Project level

	home, err := os.UserHomeDir()
	if err == nil {
		v.AddConfigPath(home) // User level (~/.secure-ai.yaml)
	}

	// Environment variables
	v.AutomaticEnv()
	v.SetEnvPrefix("SECURE_AI")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
		// Config file not found is fine, we use defaults or env vars
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Ensure database path is absolute or relative to a sensible place
	if cfg.Database.Path == "secure-ai.db" {
		cfg.Database.Path = filepath.Join(".", cfg.Database.Path)
	}

	return &cfg, nil
}
