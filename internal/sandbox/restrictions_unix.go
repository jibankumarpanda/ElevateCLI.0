//go:build !windows

package sandbox

import (
	"os/exec"
	"syscall"
)

// applyRestrictions sets process-level safeguards (new process group for
// teardown, minimal scrubbed environment). Address-space limits and network
// namespaces are applied separately because they can require wrappers
// (prlimit / unshare) and must fail closed rather than be silently ignored.
func applyRestrictions(cmd *exec.Cmd) {
	// Create new process group so we can kill the whole tree
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// Minimal environment — no access to user's env vars (secrets, tokens)
	cmd.Env = []string{
		"HOME=/tmp",
		"PATH=/usr/local/go/bin:/usr/bin:/bin",
		"TMPDIR=/tmp",
	}
}
