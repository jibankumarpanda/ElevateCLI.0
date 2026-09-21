//go:build !linux

package sandbox

import (
	"context"
	"strings"
	"testing"
)

// TestGVisorRunnerFailsClosedOffLinux verifies the gVisor runner is a true
// fail-closed stub on non-Linux platforms: code never executes, never falls
// back to the host, and is never reported as a deliberate skip.
func TestGVisorRunnerFailsClosedOffLinux(t *testing.T) {
	r := NewGVisorRunner(5, 0, true, ResourceLimits{})
	res, err := r.Run(context.Background(), "print('must not run')", "python")
	if err == nil {
		t.Fatal("expected an error from the gVisor runner on a non-Linux platform")
	}
	if res.Executed {
		t.Error("must not execute generated code on a non-Linux platform")
	}
	if res.Skipped {
		t.Error("non-Linux gVisor is a failure, not a deliberate skip")
	}
	if !strings.Contains(res.SkipReason, "Linux") {
		t.Errorf("unexpected skip reason: %q", res.SkipReason)
	}
}
