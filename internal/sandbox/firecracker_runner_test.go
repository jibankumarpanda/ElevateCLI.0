package sandbox

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFirecrackerRunnerFailsClosed(t *testing.T) {
	// A FirecrackerRunner must never execute code through the host process
	// runner. Until microVM orchestration exists, Run must always return an
	// error so the pipeline marks the result ANALYSIS_INCOMPLETE.
	fr := NewFirecrackerRunner(ResourceLimits{
		MemoryMB: 256,
		Timeout:  10 * time.Second,
		AllowNet: false,
	})

	result, err := fr.Run(context.Background(), "print('should never run')", "python")
	if err == nil {
		t.Fatal("expected an error: firecracker microVM execution must fail closed")
	}
	if result.Executed {
		t.Error("generated code must never be executed through a failed microVM boundary")
	}
	if result.Success {
		t.Error("a failed microVM run must not report success")
	}
	for _, want := range []string{"refused to fall back", "microVM"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

func TestFirecrackerRunnerRespectsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fr := NewFirecrackerRunner(DefaultLimits())
	_, err := fr.Run(ctx, "print('nope')", "python")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is -> context.Canceled = false, got %v", err)
	}
}

func TestFirecrackerNotInstalled(t *testing.T) {
	prev := firecrackerBinary
	firecrackerBinary = "firecracker-binary-that-does-not-exist-xyz"
	t.Cleanup(func() { firecrackerBinary = prev })

	if !firecrackerNotInstalled() {
		t.Error("firecrackerNotInstalled() = false for a nonexistent binary")
	}
}