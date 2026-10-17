package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeBundle(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPolicyBundlesMerges(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, "base.yaml", `
version: "1"
default_action: warn
rule_severities:
  BLOCKED_IMPORT: critical
rules:
  blocked_imports:
    - unsafe
  blocked_functions:
    - exec
  require_error_handling: true
  max_cyclomatic_complexity: 15
`)
	bundlePath := filepath.Join(dir, "base.yaml")

	cfg := Config{}
	cfg.Policy.Bundles = []string{bundlePath}
	cfg.Policy.RuleSeverities = map[string]string{"BLOCKED_IMPORT": "low"}
	cfg.Policy.Rules.BlockedImports = []string{"os/exec"}

	if err := loadPolicyBundles(&cfg, dir); err != nil {
		t.Fatalf("loadPolicyBundles: %v", err)
	}
	if len(cfg.Policy.Rules.BlockedImports) != 2 {
		t.Errorf("blocked imports not unioned: %+v", cfg.Policy.Rules.BlockedImports)
	}
	if !cfg.Policy.Rules.RequireErrorHandling {
		t.Error("bundle requirement not applied")
	}
	if cfg.Policy.Rules.MaxCyclomaticComplexity != 15 {
		t.Errorf("complexity = %d", cfg.Policy.Rules.MaxCyclomaticComplexity)
	}
	if cfg.Policy.RuleSeverities["BLOCKED_IMPORT"] != "low" {
		t.Errorf("inline severity should win over bundle: %v", cfg.Policy.RuleSeverities)
	}
}

func TestLoadPolicyBundlesRejectsBadVersion(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, "bad.yaml", "version: \"99\"\nrules: {}\n")
	cfg := Config{}
	cfg.Policy.Bundles = []string{filepath.Join(dir, "bad.yaml")}
	if err := loadPolicyBundles(&cfg, dir); err == nil {
		t.Fatal("expected unsupported version to be rejected")
	}
}

func TestLoadPolicyBundlesMissingFile(t *testing.T) {
	cfg := Config{}
	cfg.Policy.Bundles = []string{"does-not-exist.yaml"}
	if err := loadPolicyBundles(&cfg, t.TempDir()); err == nil {
		t.Fatal("expected error for missing bundle")
	}
}

func TestUnion(t *testing.T) {
	got := union([]string{"a", "b", "a"}, []string{"b", "c"})
	if len(got) != 3 {
		t.Fatalf("union = %v", got)
	}
}
