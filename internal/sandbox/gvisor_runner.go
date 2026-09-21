package sandbox

import "os"

// GVisorRunner executes generated code inside a gVisor sandbox, driven through
// the `runsc do` command. gVisor is a user-space kernel: every syscall from the
// sandboxed process is intercepted by the sentry and does not reach the host
// kernel, which provides a real isolation boundary (no kernel escape, no host
// writes, no network) without hardware virtualization or root.
//
// The runtime profile used here:
//   - rootless mode via an unprivileged user namespace (no root required);
//   - a fresh network namespace per run, so the sandbox has no network at all
//     (loopback included) when block_network is enabled;
//   - a read-only root with a writable in-memory overlay: the sandboxed process
//     can never modify the host, no matter what it attempts. Writes go to the
//     ephemeral overlay and are discarded with the sandbox;
//   - language runtimes are resolved on the host (python3, go, node, ts-node)
//     and executed inside the sandbox.
//
// Boundary notes — read "Platform Support" in the README before relying on it:
//   - The sandboxed process can READ host files (the root view is read-only).
//     It cannot modify them, reach the network, or escape the sentry. For full
//     data confidentiality, supply a self-contained rootfs directory via the
//     ELEVATED_CLI_RUNSC_ROOTFS environment variable; the sandbox then sees
//     only that tree plus an overlay.
//   - Resource caps (max_memory_mb) are applied with the same prlimit wrapper
//     used by the process runner; they bound the runsc supervisor process tree,
//     and therefore its guest.
//   - gVisor is a Linux-only runtime. On macOS and Windows it fails closed.
type GVisorRunner struct {
	timeoutSec  int
	maxMemoryMB int
	maxOutputKB int
	blockNet    bool
	rootFS      string // optional self-contained sandbox root (empty = host read-only root "/")
}

// NewGVisorRunner creates a GVisorRunner. limits.MaxOutputKB sets the
// memory-bounded output capture cap; the remaining limbs of ResourceLimits that
// are prlimit/network-specific are handled by this runner's own fail-closed
// equivalents (memory via prlimit, network isolation via runsc).
func NewGVisorRunner(timeoutSec, maxMemoryMB int, blockNet bool, limits ResourceLimits) *GVisorRunner {
	return &GVisorRunner{
		timeoutSec:  timeoutSec,
		maxMemoryMB: maxMemoryMB,
		maxOutputKB: limits.MaxOutputKB,
		blockNet:    blockNet,
		rootFS:      os.Getenv("ELEVATED_CLI_RUNSC_ROOTFS"),
	}
}

// runscBinary returns the runsc binary to use, honouring the
// ELEVATED_CLI_RUNSC_BINARY override before the PATH default.
func runscBinary() string {
	if b := os.Getenv("ELEVATED_CLI_RUNSC_BINARY"); b != "" {
		return b
	}
	return "runsc"
}