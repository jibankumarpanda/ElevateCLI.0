package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// firecrackerBinary is the name of the Firecracker CLI binary. It is a
// package-level var so tests can exercise the missing-binary path.
var firecrackerBinary = "firecracker"

// kvmDevice is the device Firecracker requires to boot a microVM.
const kvmDevice = "/dev/kvm"

// FirecrackerRunner is the microVM execution backend.
//
// MicroVM orchestration is not implemented yet. Selecting sandbox.mode:
// firecracker must therefore fail closed and never silently degrade to host
// os/exec execution: the process runner does not provide the hardware-level
// isolation boundary that a requested microVM promises. The pipeline treats a
// required-but-unavailable sandbox as ANALYSIS_INCOMPLETE, surfacing the
// missing hardening in the report instead of pretending execution happened
// inside a microVM.
type FirecrackerRunner struct {
	Limits ResourceLimits
}

// NewFirecrackerRunner creates a FirecrackerRunner with the given resource limits.
func NewFirecrackerRunner(limits ResourceLimits) *FirecrackerRunner {
	return &FirecrackerRunner{Limits: limits}
}

// Run fails closed. It returns an error describing the missing enforcement
// rather than running the code on the host. A caller must treat any error from
// Run as "the requested microVM boundary is not available" and mark the
// analysis incomplete.
func (fr *FirecrackerRunner) Run(ctx context.Context, code, lang string) (security.SandboxResult, error) {
	if err := ctx.Err(); err != nil {
		return security.SandboxResult{}, err
	}

	switch {
	case runtime.GOOS != "linux":
		return security.SandboxResult{}, fmt.Errorf(
			"firecracker microVM execution is only supported on Linux (current GOOS=%s)", runtime.GOOS)
	case !pathExists(kvmDevice):
		return security.SandboxResult{}, fmt.Errorf(
			"firecracker microVM execution requires %s (KVM); refused to fall back to host process execution", kvmDevice)
	case firecrackerNotInstalled():
		return security.SandboxResult{}, fmt.Errorf(
			"firecracker microVM execution requires the %q binary; refused to fall back to host process execution", firecrackerBinary)
	}

	// The dependencies above are present, but microVM orchestration via
	// firecracker-go-sdk is not implemented yet. Fail closed regardless so a
	// requested hardware-level boundary is never replaced with host os/exec.
	return security.SandboxResult{}, fmt.Errorf(
		"firecracker microVM orchestration is not yet implemented; refused to fall back to host process execution")
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func firecrackerNotInstalled() bool {
	_, err := exec.LookPath(firecrackerBinary)
	return err != nil
}