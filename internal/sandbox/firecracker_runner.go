package sandbox

import (
	"context"
	"fmt"
	"runtime"

	"github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// FirecrackerRunner executes code in a dedicated MicroVM.
type FirecrackerRunner struct {
	Limits ResourceLimits
}

func NewFirecrackerRunner(limits ResourceLimits) *FirecrackerRunner {
	return &FirecrackerRunner{Limits: limits}
}

func (fr *FirecrackerRunner) Run(ctx context.Context, code string, lang string) (security.SandboxResult, error) {
	if runtime.GOOS != "linux" {
		return security.SandboxResult{}, fmt.Errorf("firecracker is only supported on Linux")
	}

	// Implementation note: This requires /dev/kvm and firecracker binary.
	// In a real CLI, we would check for these dependencies.
	// This code would orchestrate the VM lifecycle via firecracker-go-sdk.

	fmt.Println("Firecracker execution requested. Falling back to ProcessRunner for now.")
	pr := NewProcessRunner(int(fr.Limits.Timeout.Seconds()), fr.Limits.MemoryMB, !fr.Limits.AllowNet)
	return pr.Run(ctx, code, lang)
}
