package commands

import (
	"strings"
	"testing"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// withFeatures replaces the package-level config for one test and restores it,
// since checkFeatureGates reads the shared cfg.
func withFeatures(t *testing.T, features ...string) {
	t.Helper()
	prev := cfg
	cfg.Experimental = config.ExperimentalConfig{Features: features}
	t.Cleanup(func() { cfg = prev })
}

func TestFeatureGatesRejectEveryUnflaggedFlag(t *testing.T) {
	cases := []struct {
		name                        string
		fix, semantic, review       bool
	}{
		{"fix", true, false, false},
		{"fix-semantic", true, true, false},
		{"review", true, false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withFeatures(t) // no features enabled

			err := checkFeatureGates(tc.fix, tc.semantic, tc.review)
			if err == nil {
				t.Fatal("an unopted-in experimental flag must be refused")
			}
			if !strings.Contains(err.Error(), "experimental.features") {
				t.Errorf("error should name the config key, got: %v", err)
			}
		})
	}
}

func TestFeatureGatesAllowFullyOptedInRun(t *testing.T) {
	withFeatures(t, config.FeatureFixLoop, config.FeatureFixSemantic, config.FeatureReview)
	if err := checkFeatureGates(true, true, true); err != nil {
		t.Fatalf("a fully opted-in run must be allowed, got: %v", err)
	}
}

func TestFeatureGatesRequireDependency(t *testing.T) {
	// Opting into fix_semantic must not silently enable fix_loop; a missing
	// dependency is an error rather than a quietly narrower run.
	withFeatures(t, config.FeatureFixSemantic)
	err := checkFeatureGates(true, true, false)
	if err == nil {
		t.Fatal("fix_semantic without fix_loop must be refused")
	}
	if !strings.Contains(err.Error(), config.FeatureFixLoop) {
		t.Errorf("error should name the missing dependency, got: %v", err)
	}
}

func TestFeatureGatesRequireTheFixFlag(t *testing.T) {
	withFeatures(t, config.FeatureFixLoop, config.FeatureFixSemantic, config.FeatureReview)

	if err := checkFeatureGates(false, true, false); err == nil {
		t.Error("--fix-semantic without --fix must be refused")
	}
	if err := checkFeatureGates(false, false, true); err == nil {
		t.Error("--review without --fix must be refused")
	}
}

func TestFeatureGatesIgnoreUnflaggedFeatures(t *testing.T) {
	// Every feature enabled but no flag set must not fail: the gate exists to
	// block unrequested behaviour, not to require it.
	withFeatures(t, config.FeatureFixLoop, config.FeatureFixSemantic, config.FeatureReview)
	if err := checkFeatureGates(false, false, false); err != nil {
		t.Fatalf("a plain generate must work with features enabled, got: %v", err)
	}
}

func TestPrintReviewWithNoFixLoop(t *testing.T) {
	// Nothing was repaired, so there is nothing to review. Printing an empty
	// diff header is fine; printing a diff would not be.
	if diff := security.LastDiff(nil); diff != "" {
		t.Errorf("LastDiff(nil) = %q, want empty", diff)
	}
}

func TestLastDiffPrefersTheLatestRound(t *testing.T) {
	summary := &sec.FixLoopSummary{
		FixRounds: []sec.FixRound{
			{Round: 1, Diff: "round one diff"},
			{Round: 2, Diff: "round two diff"},
		},
	}
	if got := lastDiffFor(summary); got != "round two diff" {
		t.Errorf("LastDiff = %q, want the latest round's diff", got)
	}
}

// lastDiffFor is a thin wrapper so the tests read as behaviour, not plumbing.
func lastDiffFor(summary *sec.FixLoopSummary) string {
	return securityLastDiff(summary)
}