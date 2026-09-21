//go:build !linux

package sandbox

import (
	"context"
	"fmt"
	"runtime"

	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// Run fails closed on non-Linux platforms: gVisor is a Linux-only runtime and
// there is no way to provide the boundary elsewhere, so generated code must
// never run on the host under an assumed gVisor guarantee.
func (g *GVisorRunner) Run(ctx context.Context, code, language string) (sec.SandboxResult, error) {
	return sec.SandboxResult{
		Executed:   false,
		Skipped:    false,
		SkipReason: fmt.Sprintf("gVisor is a Linux-only runtime; refusing to fall back to host process execution on %s", runtime.GOOS),
		Mode:       "gvisor",
	}, fmt.Errorf("gVisor sandbox is unavailable on %s", runtime.GOOS)
}
