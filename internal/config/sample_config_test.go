package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestSampleConfigAndBundleLoads exercises the checked-in example config and
// policy bundle end to end, proving bundles referenced by a config file are
// resolved relative to that file and merged.
func TestSampleConfigAndBundleLoads(t *testing.T) {
	cfgPath, err := filepath.Abs(filepath.Join("..", "..", "test", "data", "configs", "sample.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Sandbox.Mode != "process" {
		t.Errorf("sandbox.mode = %q", cfg.Sandbox.Mode)
	}
	if cfg.Audit.RetentionDays != 90 {
		t.Errorf("audit.retention_days = %d", cfg.Audit.RetentionDays)
	}
	if cfg.SBOM.Format != "cyclonedx" {
		t.Errorf("sbom.format = %q", cfg.SBOM.Format)
	}
	// The bundle blocks syscall in addition to the inline exec block.
	found := false
	for _, fn := range cfg.Policy.Rules.BlockedFunctions {
		if fn == "syscall" {
			found = true
		}
	}
	if !found {
		t.Errorf("bundle blocked_functions not merged: %+v", cfg.Policy.Rules.BlockedFunctions)
	}
	// Inline severity for HIGH_COMPLEXITY must win over the bundle's warn.
	if !actionEquals(cfg.Policy.RuleActions, "HIGH_COMPLEXITY", "warn") {
		t.Errorf("expected bundle rule action: %v", cfg.Policy.RuleActions)
	}
	if !actionEquals(cfg.Policy.RuleSeverities, "HIGH_COMPLEXITY", "low") {
		t.Errorf("inline severity should win: %v", cfg.Policy.RuleSeverities)
	}
}

// actionEquals reports whether m maps key (case-insensitively, since Viper
// lowercases map keys) to want.
func actionEquals(m map[string]string, key, want string) bool {
	for k, v := range m {
		if strings.EqualFold(k, key) && strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}
