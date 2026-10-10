package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	AI           AIConfig           `mapstructure:"ai"`
	Database     DatabaseConfig     `mapstructure:"database"`
	Sandbox      SandboxConfig      `mapstructure:"sandbox"`
	Output       OutputConfig       `mapstructure:"output"`
	Audit        AuditConfig        `mapstructure:"audit"`
	Logger       LoggerConfig       `mapstructure:"logger"`
	Policy       PolicyConfig       `mapstructure:"policy"`
	Scoring      ScoringConfig      `mapstructure:"scoring"`
	Analysis     AnalysisConfig     `mapstructure:"analysis"`
	Experimental ExperimentalConfig `mapstructure:"experimental"`
}

// AIConfig configures the LLM provider used for code generation.
type AIConfig struct {
	Provider   string `mapstructure:"provider"` // openai | anthropic | local
	Model      string `mapstructure:"model"`
	APIKey     string `mapstructure:"api_key"`
	Endpoint   string `mapstructure:"endpoint"`    // For Ollama/local providers
	TimeoutSec int    `mapstructure:"timeout_sec"` // LLM call timeout in seconds
}

// DatabaseConfig controls the local audit database.
type DatabaseConfig struct {
	Path string `mapstructure:"path"`
}

// SandboxConfig controls how generated code is executed in isolation.
// The resource limits below are enforced by the process runner (prlimit on
// Linux) and fail closed: a configured limit that cannot be enforced blocks
// execution rather than being silently ignored (see process_runner.go).
type SandboxConfig struct {
	Mode         string `mapstructure:"mode"` // process | gvisor | firecracker | docker | skip
	TimeoutSec   int    `mapstructure:"timeout_sec"`
	MaxMemoryMB  int    `mapstructure:"max_memory_mb"`
	BlockNetwork bool   `mapstructure:"block_network"`

	// MaxCPUSeconds caps CPU time consumed by the sandboxed process via
	// RLIMIT_CPU (prlimit --cpu). 0 = no explicit cap (the wall-clock timeout
	// still applies).
	MaxCPUSeconds int `mapstructure:"max_cpu_seconds"`
	// MaxNProc caps the process count via RLIMIT_NPROC (prlimit --nproc).
	// Caveat: RLIMIT_NPROC is per real UID system-wide, so the cap also applies
	// to other processes of the executing user. 0 = no cap.
	MaxNProc int `mapstructure:"max_nproc"`
	// MaxOutputKB caps the combined stdout+stderr captured from the sandboxed
	// process. Output beyond the cap is discarded (memory-bounded capture) and
	// surfaced as a runtime warning. 0 = no cap.
	MaxOutputKB int `mapstructure:"max_output_kb"`
	// MaxFSWriteMB caps the size a single file may reach via RLIMIT_FSIZE
	// (prlimit --fsize). 0 = no cap.
	MaxFSWriteMB int `mapstructure:"max_fs_write_mb"`
}

// OutputConfig controls how scan results are displayed and stored.
type OutputConfig struct {
	Format   string `mapstructure:"format"` // rich | json | sarif | plain
	ShowCode bool   `mapstructure:"show_code"`
	AuditDB  string `mapstructure:"audit_db"` // SQLite path for scan history
}

// AuditConfig controls what the local audit trail retains and how it is
// sanitised before it is written to disk. Prompts and generated source may
// contain business logic or secrets, so retention is configurable and secret
// redaction is enabled by default.
type AuditConfig struct {
	StorePrompts       bool `mapstructure:"store_prompts"`        // default true
	StoreGeneratedCode bool `mapstructure:"store_generated_code"` // default true
	RedactSecrets      bool `mapstructure:"redact_secrets"`       // default true — redact before writing
}

// LoggerConfig mirrors the logger package's config for structured logging.
type LoggerConfig struct {
	Level      string `mapstructure:"level"`  // debug | info | warn | error
	Format     string `mapstructure:"format"` // json | console
	File       string `mapstructure:"file"`
	MaxSizeMB  int    `mapstructure:"max_size_mb"`
	MaxBackups int    `mapstructure:"max_backups"`
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

// AnalysisConfig controls which optional security scanners are run as part of
// the pipeline. A scanner that is enabled but cannot run (binary missing) is
// treated as incomplete analysis and fails closed, matching the documented
// security contract: a missing scanner must never be reported as a clean scan.
type AnalysisConfig struct {
	Govulncheck    bool `mapstructure:"govulncheck"`
	OSVScanner     bool `mapstructure:"osv_scanner"`
	CustomASTRules bool `mapstructure:"custom_ast_rules"`
}

// ExperimentalConfig gates features that are implemented but not yet stable.
// The list is empty by default, so every experimental feature ships dark and
// must be named here explicitly (config file or ELEVATED_CLI_EXPERIMENTAL_FEATURES)
// before its flags are accepted.
type ExperimentalConfig struct {
	Features []string `mapstructure:"features"`
}

// Experimental feature identifiers. A feature must be listed in
// ExperimentalConfig.Features before the corresponding flags take effect.
const (
	// FeatureFixLoop enables `generate --fix`: rule-driven mechanical repairs
	// re-verified by the full fail-closed pipeline on every round.
	FeatureFixLoop = "fix_loop"

	// FeatureFixSemantic enables `generate --fix-semantic`: LLM-proposed
	// patches, re-verified fail-closed, always requiring human diff review.
	// Requires FeatureFixLoop.
	FeatureFixSemantic = "fix_semantic"

	// FeatureReview enables `generate --review`: before/after diff of the
	// latest fix round. Requires FeatureFixLoop.
	FeatureReview = "review"
)

// FeatureEnabled reports whether the named experimental feature is opted in.
// Matching is case-insensitive and ignores surrounding whitespace so that
// "fix_loop", "FIX_LOOP" and " fix_loop " behave identically. Enabling an
// implicitly dependent feature does not enable its dependency: FeatureFixSemantic
// and FeatureReview each require FeatureFixLoop to be listed as well.
func (e ExperimentalConfig) FeatureEnabled(name string) bool {
	want := strings.ToLower(strings.TrimSpace(name))
	if want == "" {
		return false
	}
	for _, f := range e.Features {
		if strings.ToLower(strings.TrimSpace(f)) == want {
			return true
		}
	}
	return false
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

// LoadConfig loads configuration using the default search paths.
// It is kept as a convenience wrapper for callers that have no explicit file.
func LoadConfig() (*Config, error) {
	return Load("")
}

// Load resolves the configuration from defaults, an optional explicit config
// file, environment variables, and flags. cfgFile may be empty to use the
// default search paths (project directory, then user home).
func Load(cfgFile string) (*Config, error) {
	v := viper.New()

	// Set defaults
	v.SetDefault("ai.provider", "openai")
	v.SetDefault("ai.model", "gpt-4o")
	v.SetDefault("ai.api_key", "")
	v.SetDefault("ai.endpoint", "http://localhost:11434")
	v.SetDefault("ai.timeout_sec", 120)
	v.SetDefault("database.path", "elevated-cli.db")
	v.SetDefault("sandbox.mode", "process")
	v.SetDefault("sandbox.timeout_sec", 10)
	v.SetDefault("sandbox.max_memory_mb", 256)
	v.SetDefault("sandbox.block_network", true)
	// Resource limits. max_cpu_seconds and max_nproc default to 0 (no explicit
	// cap): the wall-clock timeout still bounds CPU time, and RLIMIT_NPROC is a
	// per-UID limit so a low default could break the user's own processes.
	// max_output_kb and max_fs_write_mb default to enforced caps.
	v.SetDefault("sandbox.max_cpu_seconds", 0)
	v.SetDefault("sandbox.max_nproc", 0)
	v.SetDefault("sandbox.max_output_kb", 1024)
	v.SetDefault("sandbox.max_fs_write_mb", 10)
	v.SetDefault("output.format", "rich")
	v.SetDefault("output.show_code", false)
	v.SetDefault("output.audit_db", "elevated-cli.db")
	v.SetDefault("audit.store_prompts", true)
	v.SetDefault("audit.store_generated_code", true)
	v.SetDefault("audit.redact_secrets", true)
	v.SetDefault("logger.level", "info")
	v.SetDefault("logger.format", "console")
	v.SetDefault("logger.file", "")
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

	// Analysis — scanners run in the dependency stage. Enabled scanners that
	// cannot run (missing binary) fail closed instead of reporting a clean scan.
	v.SetDefault("analysis.govulncheck", true)
	v.SetDefault("analysis.osv_scanner", true)
	v.SetDefault("analysis.custom_ast_rules", true)

	// Experimental features ship dark: no feature is enabled by default, so
	// --fix / --fix-semantic / --review are rejected unless the user opts in
	// via config (`experimental.features`) or
	// ELEVATED_CLI_EXPERIMENTAL_FEATURES.
	v.SetDefault("experimental.features", []string{})

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		// Config file locations
		v.SetConfigName(".elevated-cli")
		v.SetConfigType("yaml")
		v.AddConfigPath(".") // Project level

		home, err := os.UserHomeDir()
		if err == nil {
			v.AddConfigPath(home) // User level (~/.elevated-cli.yaml)
		}
	}

	// Environment variables
	v.AutomaticEnv()
	v.SetEnvPrefix("ELEVATED_CLI")
	// Map nested keys (ai.provider -> ELEVATED_CLI_AI_PROVIDER) to env vars.
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
		// Config file not found is fine, we use defaults or env vars
	}

	// API key resolution from the environment. Viper's AutomaticEnv does not
	// populate a key during Unmarshal unless it is already known, so the key is
	// bound explicitly. ELEVATED_CLI_AI_API_KEY always wins; the conventional
	// provider variable (OPENAI_API_KEY / ANTHROPIC_API_KEY) is accepted as a
	// fallback so a fresh checkout works with the env vars users already have.
	apiKeyEnv := []string{"ai.api_key", "ELEVATED_CLI_AI_API_KEY"}
	switch strings.ToLower(v.GetString("ai.provider")) {
	case "anthropic":
		apiKeyEnv = append(apiKeyEnv, "ANTHROPIC_API_KEY")
	case "local", "ollama":
		// Local providers do not use an API key.
	default:
		apiKeyEnv = append(apiKeyEnv, "OPENAI_API_KEY")
	}
	if err := v.BindEnv(apiKeyEnv...); err != nil {
		return nil, fmt.Errorf("binding ai.api_key environment variables: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Ensure database path is absolute or relative to a sensible place
	if cfg.Database.Path == "elevated-cli.db" {
		cfg.Database.Path = filepath.Join(".", cfg.Database.Path)
	}

	return &cfg, nil
}
