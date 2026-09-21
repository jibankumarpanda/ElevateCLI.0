//go:build windows

package sandbox

import (
	"os"
	"os/exec"
	"syscall"
)

// applyRestrictions sets process-level safeguards (a new process group so the
// host can terminate the whole tree, and a scrubbed environment that does not
// inherit the user's full env). Windows has no POSIX Setpgid; the equivalent
// is CREATE_NEW_PROCESS_GROUP at creation time.
func applyRestrictions(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}

	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}

	// Minimal environment — no access to user's env vars (secrets, tokens).
	// Windows processes typically require SystemRoot (and a temp dir) to
	// load system DLLs, so unlike the POSIX scrub these are provided with
	// fixed values rather than inherited.
	cmd.Env = []string{
		"SystemRoot=" + sysRoot,
		"PATH=" + sysRoot + `\System32;` + sysRoot,
		"TEMP=" + os.TempDir(),
		"TMP=" + os.TempDir(),
	}
}