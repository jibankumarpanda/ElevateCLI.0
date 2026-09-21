//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// gvisorCapable returns whether runsc is available and the host can provide a
// rootless gVisor boundary. E2E tests gate on this so they are deterministic
// anywhere runsc is (or is not) installed.
func gvisorCapable(t *testing.T) bool {
	t.Helper()
	if runtime.GOOS != "linux" {
		return false
	}
	ok, err := probeGVisor()
	if ok {
		return true
	}
	t.Skipf("gVisor not available: %v", err)
	return false
}

// TestGVisorRunnerFailsClosedWhenUnavailable verifies that when the gVisor
// boundary cannot be provided, generated code does NOT run and the result is a
// failure (not a deliberate skip and not a silent fallback to host execution).
func TestGVisorRunnerFailsClosedWhenUnavailable(t *testing.T) {
	orig := probeGVisor
	probeGVisor = func() (bool, error) {
		return false, errors.New("simulated runsc unavailability")
	}
	t.Cleanup(func() { probeGVisor = orig })

	r := NewGVisorRunner(5, 0, true, ResourceLimits{})
	res, err := r.Run(context.Background(), "print('must not run')", "python")
	if err == nil {
		t.Fatal("expected an error when the gVisor boundary is unavailable")
	}
	if res.Executed {
		t.Error("must not execute generated code when gVisor is unavailable")
	}
	if res.Skipped {
		t.Error("unavailable gVisor boundary is a failure, not a deliberate skip")
	}
	if res.Mode != "gvisor" {
		t.Errorf("Mode = %q, want gvisor", res.Mode)
	}
}

// TestGVisorRunnerFailsClosedOnMemoryLimit performs the same fail-closed check
// for an unenforceable memory cap while the boundary itself is available.
func TestGVisorRunnerFailsClosedOnMemoryLimit(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("gVisor is Linux-only")
	}
	if !gvisorCapable(t) {
		return
	}
	if _, err := exec.LookPath("prlimit"); err != nil {
		t.Skip("prlimit not installed")
	}

	// exercise that a memory cap is honoured fail-closed by forcing ... 64 MiB
	// cap with a 512 MiB allocation must fail either inside the guest (MemoryError)
	// or before the sentry even starts (AS reservation failure) — never succeed.
	r := NewGVisorRunner(15, 64, true, ResourceLimits{})
	res, err := r.Run(context.Background(),
		"import sys,os\nprint('ALLOC')\nb = bytearray(512 * 1024 * 1024)\nprint('UNEXPECTED-SUCCESS')",
		"python")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Executed {
		t.Fatalf("run should have executed, got %+v", res)
	}
	if res.Success {
		t.Errorf("oversized allocation reported success: %+v", res)
	}
	if strings.Contains(res.Stdout, "UNEXPECTED-SUCCESS") {
		t.Errorf("generated code allocated past its memory cap: %q", res.Stdout)
	}
}

// TestGVisorRunPythonEndToEnd executes python inside the sandbox and asserts
// output round-trips through the isolated network namespace.
func TestGVisorRunPythonEndToEnd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("gVisor is Linux-only")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	if !gvisorCapable(t) {
		return
	}

	code := `import os, socket
print("GVISOR_CWD", os.getcwd())
try:
    socket.create_connection(("1.1.1.1", 80), timeout=2)
    print("NET_LEAK")
except OSError:
    print("NET_BLOCKED")
print("PY_OK")
`
	r := NewGVisorRunner(30, 0, true, ResourceLimits{MaxOutputKB: 512})
	res, err := r.Run(context.Background(), code, "python")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Executed || !res.Success {
		t.Fatalf("expected successful gVisor execution, got %+v", res)
	}
	if !strings.Contains(res.Stdout, "PY_OK") {
		t.Errorf("sandboxed python did not run to completion: %q", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "NET_BLOCKED") {
		t.Errorf("network NOT blocked inside the gVisor sandbox: %q", res.Stdout)
	}
	if strings.Contains(res.Stdout, "NET_LEAK") {
		t.Errorf("sandboxed code reached the network: %q", res.Stdout)
	}
}

// TestGVisorWritesAreContained verifies a hostile or buggy program cannot
// modify the host: it keeps the read-only overlay view, writes are ephemeral,
// a marker file attempted at a fixed host path never appears.
func TestGVisorWritesAreContained(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("gVisor is Linux-only")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	if !gvisorCapable(t) {
		return
	}

	marker := filepath.Join(os.TempDir(), "elevated-gvisor-hostmarker-test")
	_ = os.Remove(marker)
	defer os.Remove(marker)

	code := `import os
try:
    open("/tmp/elevated-gvisor-hostmarker-test", "w").close()
    print("OVERLAY_WRITE_OK")
except OSError as e:
    print("HOST_WRITE_BLOCKED", e)
print("HOME_VISIBLE", os.path.isdir("/home"))
`
	r := NewGVisorRunner(30, 0, true, ResourceLimits{})
	res, err := r.Run(context.Background(), code, "python")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Executed || !res.Success {
		t.Fatalf("expected successful gVisor execution, got %+v", res)
	}
	if strings.Contains(res.Stdout, "HOST_WRITE_BLOCKED") {
		t.Logf("host write blocked at syscall level: %q", res.Stdout)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Errorf("sandboxed code wrote a file to the host filesystem: %q", marker)
	}
}

// TestGVisorTimeoutKillsRunawayProcess verifies an infinite loop inside the
// sandbox is terminated by the configured timeout instead of hanging the CLI.
func TestGVisorTimeoutKillsRunawayProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("gVisor is Linux-only")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	if !gvisorCapable(t) {
		return
	}

	start := time.Now()
	r := NewGVisorRunner(3, 0, true, ResourceLimits{})
	res, err := r.Run(context.Background(), "import time\nwhile True: time.sleep(0.2)", "python")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Executed {
		t.Fatalf("run should have executed, got %+v", res)
	}
	if res.Success {
		t.Error("runaway process reported success")
	}
	if elapsed := time.Since(start); elapsed > 25*time.Second {
		t.Errorf("timeout did not terminate the sandbox promptly (took %v)", elapsed)
	}
	hasTimeout := false
	for _, m := range res.RuntimeErrors {
		if strings.Contains(m, "timed out") {
			hasTimeout = true
		}
	}
	if !hasTimeout {
		t.Errorf("expected a timeout runtime error, got %+v", res.RuntimeErrors)
	}
}

// TestGVisorUnsupportedLanguageSkips verifies unsupported languages skip
// without attempting execution.
func TestGVisorUnsupportedLanguageSkips(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("gVisor is Linux-only")
	}
	r := NewGVisorRunner(5, 0, true, ResourceLimits{})
	res, err := r.Run(context.Background(), "puts 1", "ruby")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Skipped || res.Executed {
		t.Errorf("unsupported language should skip, got %+v", res)
	}
}
