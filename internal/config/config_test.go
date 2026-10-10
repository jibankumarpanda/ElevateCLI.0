package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDefaults(t *testing.T) {
	path := writeTempConfig(t, "# empty config uses defaults\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AI.Provider != "openai" {
		t.Errorf("ai.provider = %q, want openai", cfg.AI.Provider)
	}
	if cfg.Sandbox.Mode != "process" {
		t.Errorf("sandbox.mode = %q, want process", cfg.Sandbox.Mode)
	}
	if cfg.Sandbox.TimeoutSec != 10 {
		t.Errorf("sandbox.timeout_sec = %d, want 10", cfg.Sandbox.TimeoutSec)
	}
	if cfg.Sandbox.MaxMemoryMB != 256 {
		t.Errorf("sandbox.max_memory_mb = %d, want 256", cfg.Sandbox.MaxMemoryMB)
	}
	if !cfg.Sandbox.BlockNetwork {
		t.Errorf("sandbox.block_network should default to true")
	}
	if cfg.Sandbox.MaxCPUSeconds != 0 || cfg.Sandbox.MaxNProc != 0 {
		t.Errorf("cpu/nproc caps should default to 0 (no cap), got cpu=%d nproc=%d", cfg.Sandbox.MaxCPUSeconds, cfg.Sandbox.MaxNProc)
	}
	if cfg.Sandbox.MaxOutputKB != 1024 || cfg.Sandbox.MaxFSWriteMB != 10 {
		t.Errorf("output/fs caps should default to enforced caps, got out=%dKB fs=%dMB", cfg.Sandbox.MaxOutputKB, cfg.Sandbox.MaxFSWriteMB)
	}
	if cfg.Output.Format != "rich" {
		t.Errorf("output.format = %q, want rich", cfg.Output.Format)
	}
	if cfg.Scoring.PassThreshold != 70 {
		t.Errorf("scoring.pass_threshold = %d, want 70", cfg.Scoring.PassThreshold)
	}
	if cfg.Scoring.SASTWeight != 0.40 || cfg.Scoring.DepWeight != 0.30 ||
		cfg.Scoring.PolicyWeight != 0.20 || cfg.Scoring.SandboxWeight != 0.10 {
		t.Errorf("scoring weights wrong: %+v", cfg.Scoring)
	}
	if cfg.Scoring.FailClosed == nil || !*cfg.Scoring.FailClosed {
		t.Errorf("scoring.fail_closed should default to true")
	}
	if !cfg.Analysis.Govulncheck || !cfg.Analysis.OSVScanner {
		t.Errorf("analysis scanners should default to enabled: %+v", cfg.Analysis)
	}
}

func TestLoadFromFile(t *testing.T) {
	content := `ai:
  provider: anthropic
  model: claude-3-5-sonnet
sandbox:
  mode: firecracker
  timeout_sec: 30
  max_cpu_seconds: 5
  max_nproc: 32
  max_output_kb: 512
  max_fs_write_mb: 2
scoring:
  pass_threshold: 85
  fail_closed: false
`
	cfg, err := Load(writeTempConfig(t, content))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AI.Provider != "anthropic" || cfg.AI.Model != "claude-3-5-sonnet" {
		t.Errorf("ai = %+v", cfg.AI)
	}
	if cfg.Sandbox.Mode != "firecracker" || cfg.Sandbox.TimeoutSec != 30 {
		t.Errorf("sandbox = %+v", cfg.Sandbox)
	}
	if cfg.Sandbox.MaxCPUSeconds != 5 || cfg.Sandbox.MaxNProc != 32 {
		t.Errorf("custom cpu/nproc caps lost: %+v", cfg.Sandbox)
	}
	if cfg.Sandbox.MaxOutputKB != 512 || cfg.Sandbox.MaxFSWriteMB != 2 {
		t.Errorf("custom output/fs caps lost: %+v", cfg.Sandbox)
	}
	if cfg.Scoring.PassThreshold != 85 {
		t.Errorf("pass_threshold = %d, want 85", cfg.Scoring.PassThreshold)
	}
	if cfg.Scoring.FailClosed == nil || *cfg.Scoring.FailClosed {
		t.Errorf("fail_closed should be explicitly false")
	}
}

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("ELEVATED_CLI_AI_PROVIDER", "ollama")
	t.Setenv("ELEVATED_CLI_AI_MODEL", "llama3")
	t.Setenv("ELEVATED_CLI_SCORING_PASS_THRESHOLD", "55")

	cfg, err := Load(writeTempConfig(t, "# defaults + env"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AI.Provider != "ollama" {
		t.Errorf("ai.provider = %q, want ollama (env override)", cfg.AI.Provider)
	}
	if cfg.AI.Model != "llama3" {
		t.Errorf("ai.model = %q, want llama3 (env override)", cfg.AI.Model)
	}
	if cfg.Scoring.PassThreshold != 55 {
		t.Errorf("pass_threshold = %d, want 55 (env override)", cfg.Scoring.PassThreshold)
	}
}

func TestLoadAPIKeyFromPrefixedEnv(t *testing.T) {
	// Regression: before the fix, ELEVATED_CLI_AI_API_KEY was silently ignored
	// whenever the config file did not already declare ai.api_key, so a fresh
	// checkout could never authenticate even with the documented env var set.
	t.Setenv("ELEVATED_CLI_AI_API_KEY", "sk-prefixed")
	t.Setenv("OPENAI_API_KEY", "")

	cfg, err := Load(writeTempConfig(t, "# no ai.api_key declared\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AI.APIKey != "sk-prefixed" {
		t.Errorf("ai.api_key = %q, want the prefixed env value", cfg.AI.APIKey)
	}
}

func TestLoadAPIKeyFallsBackToProviderEnv(t *testing.T) {
	// The conventional provider variable is accepted as a fallback so users do
	// not have to relearn the env var name.
	t.Setenv("ELEVATED_CLI_AI_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "sk-openai")

	cfg, err := Load(writeTempConfig(t, "ai:\n  provider: openai\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AI.APIKey != "sk-openai" {
		t.Errorf("ai.api_key = %q, want the OPENAI_API_KEY fallback", cfg.AI.APIKey)
	}
}

func TestLoadAPIKeyAnthropicFallback(t *testing.T) {
	t.Setenv("ELEVATED_CLI_AI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant")

	cfg, err := Load(writeTempConfig(t, "ai:\n  provider: anthropic\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AI.APIKey != "sk-ant" {
		t.Errorf("ai.api_key = %q, want the ANTHROPIC_API_KEY fallback", cfg.AI.APIKey)
	}
}

func TestLoadAPIKeyPrefixedWinsOverProviderEnv(t *testing.T) {
	t.Setenv("ELEVATED_CLI_AI_API_KEY", "sk-prefixed")
	t.Setenv("OPENAI_API_KEY", "sk-openai")

	cfg, err := Load(writeTempConfig(t, "ai:\n  provider: openai\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AI.APIKey != "sk-prefixed" {
		t.Errorf("ai.api_key = %q, want the prefixed value to take precedence", cfg.AI.APIKey)
	}
}

func TestLoadAPIKeyEmptyWhenNothingSet(t *testing.T) {
	t.Setenv("ELEVATED_CLI_AI_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")

	cfg, err := Load(writeTempConfig(t, "# nothing set\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AI.APIKey != "" {
		t.Errorf("ai.api_key = %q, want empty when no env var is set", cfg.AI.APIKey)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	path := writeTempConfig(t, "ai: [not, a, map\n")
	if _, err := Load(path); err == nil {
		t.Error("Load on invalid YAML should return an error")
	}
}

func TestLoadMissingExplicitFileErrors(t *testing.T) {
	// An explicitly requested config file that does not exist is a user error.
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Error("Load on a missing explicit config file should error")
	}
}

func TestLoadConfig(t *testing.T) {
	// LoadConfig is a convenience wrapper — it must not panic and must return
	// a non-nil config or an error (default search paths may or may not find
	// a file depending on CWD, so only the error contract is checked).
	cfg, err := LoadConfig()
	if err == nil && cfg == nil {
		t.Error("LoadConfig returned nil config and nil error")
	}
}
