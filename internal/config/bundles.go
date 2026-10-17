package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// policyBundle is the on-disk shape of a reusable policy bundle. Bundles let an
// organisation ship a reviewed rule set (for example "pci-dss" or "internal")
// that projects reference by path, rather than copying rule lists by hand.
//
// Bundles are versioned with the same schema version as inline policy. Rules
// from bundles are additive: blocked import/function lists are unioned, boolean
// requirements are OR-ed, and the highest complexity limit wins. The project's
// own inline configuration always takes precedence for actions and severities,
// so a bundle cannot silently loosen a rule the project has pinned.
type policyBundle struct {
	Version        string            `yaml:"version"`
	DefaultAction  string            `yaml:"default_action"`
	RuleActions    map[string]string `yaml:"rule_actions"`
	RuleSeverities map[string]string `yaml:"rule_severities"`
	Rules          struct {
		BlockedImports          []string `yaml:"blocked_imports"`
		BlockedFunctions        []string `yaml:"blocked_functions"`
		RequireErrorHandling    bool     `yaml:"require_error_handling"`
		MaxCyclomaticComplexity int      `yaml:"max_cyclomatic_complexity"`
	} `yaml:"rules"`
}

// loadPolicyBundles loads and merges every bundle referenced by the policy
// configuration into cfg.Policy. Paths are resolved relative to baseDir (the
// directory of the config file) and then the working directory. A bundle with
// an unsupported schema version is rejected rather than partially applied.
func loadPolicyBundles(cfg *Config, baseDir string) error {
	for _, ref := range cfg.Policy.Bundles {
		path := resolveBundlePath(ref, baseDir)
		data, err := os.ReadFile(path) // #nosec G304 -- operator-configured bundle path
		if err != nil {
			return fmt.Errorf("reading policy bundle %q: %w", ref, err)
		}
		var b policyBundle
		if err := yaml.Unmarshal(data, &b); err != nil {
			return fmt.Errorf("parsing policy bundle %q: %w", ref, err)
		}
		if v := strings.TrimSpace(b.Version); v != "" && v != SupportedPolicyVersion {
			return fmt.Errorf("policy bundle %q declares unsupported version %q (want %s)",
				ref, v, SupportedPolicyVersion)
		}
		mergePolicyBundle(&cfg.Policy, b)
	}
	return nil
}

// mergePolicyBundle folds a bundle into the effective policy. List rules are
// unioned, requirements are OR-ed, the stricter (higher) complexity limit wins,
// and the project's inline actions/severities take precedence over the bundle's.
func mergePolicyBundle(p *PolicyConfig, b policyBundle) {
	p.Rules.BlockedImports = union(p.Rules.BlockedImports, b.Rules.BlockedImports)
	p.Rules.BlockedFunctions = union(p.Rules.BlockedFunctions, b.Rules.BlockedFunctions)
	p.Rules.RequireErrorHandling = p.Rules.RequireErrorHandling || b.Rules.RequireErrorHandling
	if b.Rules.MaxCyclomaticComplexity > p.Rules.MaxCyclomaticComplexity {
		p.Rules.MaxCyclomaticComplexity = b.Rules.MaxCyclomaticComplexity
	}
	if p.RuleActions == nil {
		p.RuleActions = map[string]string{}
	}
	for rule, action := range b.RuleActions {
		if _, exists := p.RuleActions[rule]; !exists {
			p.RuleActions[rule] = action
		}
	}
	if p.RuleSeverities == nil {
		p.RuleSeverities = map[string]string{}
	}
	for rule, sev := range b.RuleSeverities {
		if _, exists := p.RuleSeverities[rule]; !exists {
			p.RuleSeverities[rule] = sev
		}
	}
}

func union(a, b []string) []string {
	seen := make(map[string]bool, len(a))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// resolveBundlePath returns the first existing candidate for a bundle reference,
// trying baseDir then the working directory. If neither exists the baseDir
// candidate is returned so the resulting error names a deterministic path.
func resolveBundlePath(ref, baseDir string) string {
	if filepath.IsAbs(ref) {
		return ref
	}
	if baseDir != "" {
		candidate := filepath.Join(baseDir, ref)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ref
}
