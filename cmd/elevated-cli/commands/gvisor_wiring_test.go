//go:build linux

package commands

import (
	"context"
	"testing"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
)

// TestBuildPipelineGVisorMode verifies sandbox.mode: gvisor wires the gVisor
// runner into the pipeline and that the sandbox stage reports gVisor semantics
// (never a deliberate skip). When the boundary is absent the run fails closed
// (analysis incomplete); when runsc is present it executes.
func TestBuildPipelineGVisorMode(t *testing.T) {
	cfg := config.Config{
		Sandbox: config.SandboxConfig{
			Mode:        "gvisor",
			TimeoutSec:  30,
			MaxOutputKB: 512,
		},
	}
	p, err := buildPipeline(cfg, true, t.TempDir())
	if err != nil {
		t.Fatalf("buildPipeline: %v", err)
	}
	report, err := p.Run(context.Background(),
		"print hello", "print('hello from gvisor')", "python", "test", "test")
	if err != nil {
		t.Fatalf("pipeline Run: %v", err)
	}
	if report.Sandbox.Mode != "gvisor" {
		t.Errorf("sandbox mode = %q, want gvisor", report.Sandbox.Mode)
	}
	if report.Sandbox.Skipped {
		t.Errorf("gVisor sandbox must never be a deliberate skip, got %+v", report.Sandbox)
	}
	if !report.Sandbox.Executed {
		// No runsc on PATH and no ELEVATED_CLI_RUNSC_BINARY: gVisor must fail
		// closed so the analysis is incomplete, never silently host-executed.
		if report.AnalysisComplete {
			t.Error("missing gVisor boundary with required sandbox must fail closed (incomplete analysis)")
		}
	}
}
