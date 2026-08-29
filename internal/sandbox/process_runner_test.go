package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDefaultLimits(t *testing.T) {
	lim := DefaultLimits()
	if lim.MemoryMB != 256 || lim.CPUPerc != 50 || lim.AllowNet {
		t.Errorf("unexpected defaults: %+v", lim)
	}
	if lim.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", lim.Timeout)
	}
}

func TestLangToExt(t *testing.T) {
	cases := map[string]string{
		"go": ".go", "golang": ".go",
		"python": ".py", "python3": ".py",
		"javascript": ".js", "js": ".js", "node": ".js",
		"typescript": ".ts", "ts": ".ts",
		"ruby": ".txt",
		"":     ".txt",
	}
	for in, want := range cases {
		if got := langToExt(in); got != want {
			t.Errorf("langToExt(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteCodeFile(t *testing.T) {
	dir := t.TempDir()
	path, err := writeCodeFile(dir, "print('hi')", "python")
	if err != nil {
		t.Fatalf("writeCodeFile: %v", err)
	}
	if filepath.Base(path) != "main.py" {
		t.Errorf("file = %q, want main.py", filepath.Base(path))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("perm = %o, want 0600", perm)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "print('hi')" {
		t.Errorf("content = %q", string(b))
	}
}

func TestEnsureInside(t *testing.T) {
	dir := t.TempDir()
	if err := ensureInside(filepath.Join(dir, "main.go"), dir); err != nil {
		t.Errorf("same-dir file rejected: %v", err)
	}
	if err := ensureInside(filepath.Join(dir, "sub", "main.go"), dir); err != nil {
		t.Errorf("nested file rejected: %v", err)
	}
	if err := ensureInside(filepath.Join(dir, "..", "escape.go"), dir); err == nil {
		t.Error("path traversal accepted")
	}
	if err := ensureInside("/etc/passwd", dir); err == nil {
		t.Error("absolute outside path accepted")
	}
}

func TestBuildCommandGo(t *testing.T) {
	dir := t.TempDir()
	cmd, err := buildCommand(context.Background(), filepath.Join(dir, "main.go"), "go", dir)
	if err != nil {
		t.Fatalf("buildCommand: %v", err)
	}
	if cmd.Dir != dir {
		t.Errorf("Dir = %q, want %q", cmd.Dir, dir)
	}
	if len(cmd.Args) != 3 || cmd.Args[0] != "go" || cmd.Args[1] != "run" || cmd.Args[2] != "main.go" {
		t.Errorf("unexpected args: %v", cmd.Args)
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		t.Errorf("go.mod not written: %v", err)
	}
}

func TestBuildCommandOtherLanguages(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		lang string
		file string
	}{
		{"python", "main.py"},
		{"javascript", "main.js"},
		{"typescript", "main.ts"},
	}
	for _, c := range cases {
		cmd, err := buildCommand(context.Background(), filepath.Join(dir, c.file), c.lang, dir)
		if err != nil {
			t.Fatalf("buildCommand(%q): %v", c.lang, err)
		}
		if cmd.Args[len(cmd.Args)-1] != c.file {
			t.Errorf("%s: last arg = %q, want %q", c.lang, cmd.Args[len(cmd.Args)-1], c.file)
		}
	}
}

func TestBuildCommandUnsupported(t *testing.T) {
	dir := t.TempDir()
	if _, err := buildCommand(context.Background(), filepath.Join(dir, "main.txt"), "ruby", dir); err == nil {
		t.Error("unsupported language should error")
	}
}

func TestBuildCommandRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	if _, err := buildCommand(context.Background(), "/etc/passwd", "python", dir); err == nil {
		t.Error("buildCommand accepted a file outside the sandbox dir")
	}
}

func TestRunUnsupportedLanguageSkips(t *testing.T) {
	r := NewProcessRunner(5, 256, true)
	result, err := r.Run(context.Background(), "puts 1", "ruby")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !result.Skipped {
		t.Errorf("result.Skipped = false, want true: %+v", result)
	}
	if result.Executed {
		t.Errorf("result.Executed = true, want false")
	}
}

func TestRunPythonIntegration(t *testing.T) {
	bin := "python3"
	if _, err := exec.LookPath(bin); err != nil {
		t.Skip("python3 not installed")
	}
	r := NewProcessRunner(10, 256, false)
	result, err := r.Run(context.Background(), "print('elevated-ok')", "python")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !result.Executed || !result.Success {
		t.Fatalf("expected successful execution, got %+v", result)
	}
	if result.Stdout != "elevated-ok\n" {
		t.Errorf("Stdout = %q, want %q", result.Stdout, "elevated-ok\n")
	}
}

func TestRunPythonIntegrationWithNetworkIsolation(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	if ok, err := probeNetworkIsolation(); !ok {
		t.Skipf("network isolation unavailable: %v", err)
	}
	r := NewProcessRunner(10, 256, true)
	result, err := r.Run(context.Background(), "print('elevated-ok')", "python")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !result.Executed || !result.Success {
		t.Fatalf("expected successful execution under isolation, got %+v", result)
	}
	if result.Stdout != "elevated-ok\n" {
		t.Errorf("Stdout = %q, want %q", result.Stdout, "elevated-ok\n")
	}
}

func TestNetworkIsolationBlocksConnectivity(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	if ok, err := probeNetworkIsolation(); !ok {
		t.Skipf("network isolation unavailable: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot open a loopback listener: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	snippet := fmt.Sprintf(`import socket
try:
    socket.create_connection(("127.0.0.1", %d), timeout=3).close()
    print("CONNECTED")
except OSError:
    print("BLOCKED")
`, port)

	// With block_network=true the child must not reach the listener.
	isolated := NewProcessRunner(10, 256, true)
	ires, err := isolated.Run(context.Background(), snippet, "python")
	if err != nil {
		t.Fatalf("isolated Run: %v", err)
	}
	if !ires.Executed || !ires.Success {
		t.Fatalf("isolated run should execute, got %+v", ires)
	}
	if !strings.Contains(ires.Stdout, "BLOCKED") {
		t.Errorf("network NOT blocked under block_network=true; stdout=%q", ires.Stdout)
	}

	// Control: with block_network=false the same code must connect.
	open := NewProcessRunner(10, 256, false)
	cres, err := open.Run(context.Background(), snippet, "python")
	if err != nil {
		t.Fatalf("control Run: %v", err)
	}
	if !cres.Executed || !cres.Success {
		t.Fatalf("control run should execute, got %+v", cres)
	}
	if !strings.Contains(cres.Stdout, "CONNECTED") {
		t.Errorf("control could not connect without isolation; stdout=%q", cres.Stdout)
	}
}

func TestRunFailsClosedWhenNetworkIsolationUnavailable(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}

	orig := probeNetworkIsolation
	probeNetworkIsolation = func() (bool, error) {
		return false, errors.New("simulated namespace failure")
	}
	t.Cleanup(func() { probeNetworkIsolation = orig })

	r := NewProcessRunner(5, 256, true)
	result, err := r.Run(context.Background(), "print('should not run')", "python")
	if err == nil {
		t.Fatal("expected an error when network isolation is requested but unavailable")
	}
	if result.Executed {
		t.Error("must not execute generated code when isolation is unavailable")
	}
	if result.Skipped {
		t.Error("unavailable isolation is a failure, not a deliberate skip")
	}

	ctrl := NewProcessRunner(5, 256, false)
	cres, err := ctrl.Run(context.Background(), "print('elevated-ok')", "python")
	if err != nil {
		t.Fatalf("control Run with block_network=false should succeed: %v", err)
	}
	if !cres.Executed || !cres.Success || cres.Stdout != "elevated-ok\n" {
		t.Errorf("control result unexpected: %+v", cres)
	}
}

// TestRunScrubsEnvironment verifies that host environment variables (which may
// hold API keys, tokens, and other secrets) never reach the generated code.
func TestRunScrubsEnvironment(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	const secret = "SUPER-SECRET-ENV-VALUE-xyzzy"
	t.Setenv("ELEVATED_SECRET_FIXTURE", secret)

	code := `import os
print("LEAKED" if "ELEVATED_SECRET_FIXTURE" in os.environ else "CLEAN")
print("HOME_INVALID" if os.environ.get("HOME") != "/tmp" else "HOME_OK")
`
	r := NewProcessRunner(10, 256, false)
	res, err := r.Run(context.Background(), code, "python")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Executed || !res.Success {
		t.Fatalf("run failed: %+v", res)
	}
	if strings.Contains(res.Stdout, "LEAKED") || strings.Contains(res.Stdout, secret) {
		t.Errorf("host environment leaked into sandbox: stdout=%q", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "HOME_OK") {
		t.Errorf("scrubbed environment not applied: stdout=%q", res.Stdout)
	}
}

// TestRunCleansTempDir verifies the disposable working directory is removed
// after execution, leaving no artifacts behind.
func TestRunCleansTempDir(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	count := func() int {
		entries, err := os.ReadDir(os.TempDir())
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		n := 0
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "elevated-sandbox-") {
				n++
			}
		}
		return n
	}

	before := count()
	r := NewProcessRunner(10, 256, false)
	res, err := r.Run(context.Background(), "print('cleanup-check')", "python")
	if err != nil || !res.Success {
		t.Fatalf("Run: %v %+v", err, res)
	}
	after := count()
	if after != before {
		t.Errorf("temp dir count changed: before=%d after=%d (leaked sandbox dir)", before, after)
	}
}

// TestRunTimeoutKillsRunawayProcess verifies an infinite loop is terminated by
// the timeout instead of hanging the CLI.
func TestRunTimeoutKillsRunawayProcess(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	start := time.Now()
	r := NewProcessRunner(2, 256, false)
	res, err := r.Run(context.Background(), "while True: pass", "python")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Executed {
		t.Fatalf("run should have executed, got %+v", res)
	}
	if res.Success {
		t.Error("runaway process reported success")
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("timeout did not terminate the runaway process promptly (took %v)", time.Since(start))
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

// TestRunEnforcesMemoryLimit verifies generated code that exceeds the
// configured address-space cap is stopped instead of exhausting the host.
func TestRunEnforcesMemoryLimit(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	if _, err := exec.LookPath("prlimit"); err != nil {
		t.Skip("prlimit not installed")
	}
	if runtime.GOOS != "linux" {
		t.Skip("memory limits are enforced on Linux only")
	}

	// 64 MiB cap; the allocation requests 512 MiB, so it must fail.
	r := NewProcessRunner(15, 64, false)
	res, err := r.Run(context.Background(),
		"import sys\nprint('BIG-BALLOC: attempted 512MiB')\nsys.stdout.flush()\nb = bytearray(512 * 1024 * 1024)\nprint('UNEXPECTED-SUCCESS')\n",
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
