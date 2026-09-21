// Package sandbox provides code execution environments for ElevateCLI.
// This file implements the cross-platform process runner — the safe fallback
// used on macOS and Windows (and as a fallback on Linux when Firecracker
// is unavailable). It uses restricted os/exec with:
//   - strict timeout via context
//   - temp directory isolation
//   - process group management for clean teardown
//   - network isolation via unprivileged user+network namespaces (Linux)
//     when block_network is enabled
package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// probeNetworkIsolation verifies that generated code can actually be cut off
// from the network. It relies on unprivileged user+network namespaces via the
// util-linux `unshare` utility (unshare -Un). Inside the fresh network
// namespace no interface is up, so the child has no network access at all —
// loopback included. The probe result is cached because spawning clone(2)
// namespaces costs a subprocess. probeNetworkIsolation is a package-level var
// so tests can inject failures to exercise the fail-closed path.
var (
	netProbeOnce sync.Once
	netProbeOK   bool
	netProbeErr  error
)

var probeNetworkIsolation = func() (bool, error) {
	netProbeOnce.Do(func() {
		if _, err := exec.LookPath("unshare"); err != nil {
			netProbeErr = fmt.Errorf("block_network requires the 'unshare' utility (util-linux): %w", err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := exec.CommandContext(ctx, "unshare", "-U", "-n", "--", "true").Run(); err != nil {
			netProbeErr = fmt.Errorf("network isolation via unprivileged user/network namespace unavailable: %w", err)
			return
		}
		netProbeOK = true
	})
	return netProbeOK, netProbeErr
}

// ProcessRunner executes code in a restricted child process.
// It is safe to use on all platforms. For production Linux deployments
// prefer FirecrackerRunner for true hardware-level isolation.
type ProcessRunner struct {
	timeoutSec  int
	maxMemoryMB int
	blockNet    bool

	// Extended hard limits (P0). Zero values disable the corresponding cap
	// (except maxOutputKB, where zero means no capture cap at all).
	maxCPUSeconds  int // RLIMIT_CPU (prlimit --cpu)
	maxNProc       int // RLIMIT_NPROC (prlimit --nproc)
	maxOutputKB    int // combined stdout+stderr capture cap
	maxFSWriteMB   int // RLIMIT_FSIZE (prlimit --fsize)
}

// NewProcessRunner creates a ProcessRunner with the given resource limits.
// It does not apply the extended CPU/process/output/filesystem caps; use
// NewProcessRunnerWithLimits for the full fail-closed control set.
func NewProcessRunner(timeoutSec, maxMemoryMB int, blockNet bool) *ProcessRunner {
	return NewProcessRunnerWithLimits(timeoutSec, maxMemoryMB, blockNet, ResourceLimits{})
}

// NewProcessRunnerWithLimits creates a ProcessRunner with the full set of hard
// limits. The extended fields of limits are honoured directly (0 = no cap).
func NewProcessRunnerWithLimits(timeoutSec, maxMemoryMB int, blockNet bool, limits ResourceLimits) *ProcessRunner {
	return &ProcessRunner{
		timeoutSec:   timeoutSec,
		maxMemoryMB:  maxMemoryMB,
		blockNet:     blockNet,
		maxCPUSeconds: limits.MaxCPUSeconds,
		maxNProc:      limits.MaxNProc,
		maxOutputKB:   limits.MaxOutputKB,
		maxFSWriteMB:  limits.MaxFSWriteMB,
	}
}

// Run writes the code to a temp directory and executes it in a restricted process.
func (r *ProcessRunner) Run(ctx context.Context, code, language string) (sec.SandboxResult, error) {
	start := time.Now()

	// Establish the timeout before building any command so the deadline is
	// baked into the exec.Cmd at creation — no need to rebuild it afterwards.
	timeoutCtx, cancel := context.WithTimeout(ctx,
		time.Duration(r.timeoutSec)*time.Second)
	defer cancel()

	// Create isolated temp working directory
	tmpDir, err := os.MkdirTemp("", "elevated-sandbox-*")
	if err != nil {
		return sec.SandboxResult{}, fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir) // always clean up

	// Write code to file
	codeFile, err := writeCodeFile(tmpDir, code, language)
	if err != nil {
		return sec.SandboxResult{}, err
	}

	// Build the execution command for this language
	cmd, err := buildCommand(timeoutCtx, codeFile, language, tmpDir)
	if err != nil {
		return sec.SandboxResult{
			Executed:   false,
			Skipped:    true,
			SkipReason: fmt.Sprintf("unsupported language for sandbox: %s", language),
			Mode:       "process",
		}, nil
	}

	// Apply network isolation. Fails closed: if block_network is requested but
	// the platform or kernel cannot provide a fresh network namespace, the
	// generated code must not run with host network access.
	cmd, err = r.withNetworkIsolation(timeoutCtx, cmd)
	if err != nil {
		return sec.SandboxResult{
			Executed:   false,
			Skipped:    false,
			SkipReason: fmt.Sprintf("network isolation unavailable: %v", err),
			Mode:       "process",
		}, err
	}

	// Apply the configured hard resource limits (memory, CPU time, process
	// count, per-file write size) in a single prlimit wrapper. Fails closed:
	// on platforms or runtimes that cannot enforce a configured limit, the
	// generated code must not run with a silently-ignored cap.
	cmd, err = r.withResourceLimits(timeoutCtx, cmd)
	if err != nil {
		return sec.SandboxResult{
			Executed:   false,
			Skipped:    false,
			SkipReason: fmt.Sprintf("resource limits unavailable: %v", err),
			Mode:       "process",
		}, err
	}

	// Apply process-level restrictions (process group, scrubbed environment).
	applyRestrictions(cmd)

	// Execute. Output capture is memory-bounded: combined stdout+stderr is
	// capped at maxOutputKB bytes so a chatty or hostile child cannot exhaust
	// the host via unbounded writes to our buffer. Bytes beyond the cap are
	// discarded, never buffered.
	capture := newCappedOutput(r.maxOutputKB * 1024)
	cmd.Stdout = capture
	cmd.Stderr = capture
	runErr := cmd.Run()
	duration := time.Since(start)

	result := sec.SandboxResult{
		Executed: true,
		Mode:     "process",
		Duration: duration,
		Stdout:   capture.String(),
	}

	if capture.exceeded() {
		result.RuntimeErrors = append(result.RuntimeErrors,
			fmt.Sprintf("output exceeded the %d KB capture cap; trailing output discarded", r.maxOutputKB))
	}

	if runErr != nil {
		result.Success = false
		result.Stderr = runErr.Error()
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		}
		// Distinguish timeout from actual failure
		if timeoutCtx.Err() == context.DeadlineExceeded {
			result.RuntimeErrors = append(result.RuntimeErrors,
				fmt.Sprintf("execution timed out after %ds", r.timeoutSec))
		}
	} else {
		result.Success = true
		result.ExitCode = 0
	}

	return result, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func writeCodeFile(dir, code, language string) (string, error) {
	ext := langToExt(language)
	path := filepath.Join(dir, "main"+ext)
	if err := os.WriteFile(path, []byte(code), 0600); err != nil {
		return "", fmt.Errorf("writing code file: %w", err)
	}
	return path, nil
}

func buildCommand(ctx context.Context, codeFile, language, workDir string) (*exec.Cmd, error) {
	// Defense in depth: the code file must live inside the sandbox working
	// directory. The subprocess is launched with a bare filename and cmd.Dir
	// scoping, so a stray path can never be parsed as a flag or reach outside
	// the sandbox.
	if err := ensureInside(codeFile, workDir); err != nil {
		return nil, err
	}

	switch strings.ToLower(language) {
	case "go", "golang":
		// For Go we need a minimal go.mod in the temp dir
		modContent := "module sandbox\ngo 1.22\n"
		if err := os.WriteFile(filepath.Join(workDir, "go.mod"), []byte(modContent), 0600); err != nil {
			return nil, fmt.Errorf("writing go.mod: %w", err)
		}
		cmd := exec.CommandContext(ctx, "go", "run", "main.go")
		cmd.Dir = workDir
		return cmd, nil

	case "python", "python3":
		cmd := exec.CommandContext(ctx, "python3", "main.py")
		cmd.Dir = workDir
		return cmd, nil

	case "javascript", "js", "node":
		cmd := exec.CommandContext(ctx, "node", "main.js")
		cmd.Dir = workDir
		return cmd, nil

	case "typescript", "ts":
		cmd := exec.CommandContext(ctx, "ts-node", "main.ts")
		cmd.Dir = workDir
		return cmd, nil

	default:
		return nil, fmt.Errorf("unsupported: %s", language)
	}
}

// ensureInside verifies that file resolves within dir, rejecting path
// traversal. Both paths are cleaned before comparison.
func ensureInside(file, dir string) error {
	cleanDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolving directory %q: %w", dir, err)
	}
	cleanFile, err := filepath.Abs(file)
	if err != nil {
		return fmt.Errorf("resolving file %q: %w", file, err)
	}
	rel, err := filepath.Rel(cleanDir, cleanFile)
	if err != nil {
		return fmt.Errorf("relating %q to %q: %w", cleanFile, cleanDir, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("code file %q is outside sandbox directory %q", file, dir)
	}
	return nil
}

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

// withResourceLimits wraps cmd with a single prlimit invocation applying every
// configured hard limit: address space (--as), CPU time (--cpu), process count
// (--nproc), and per-file write size (--fsize). It fails closed: if any limit
// is configured but the platform or runtime cannot enforce it, it returns an
// error and generated code is not executed with a silently-ignored cap.
// Values <= 0 disable the corresponding limit (except maxOutputKB, which is
// enforced separately in Run via capped output capture, not prlimit).
func (r *ProcessRunner) withResourceLimits(ctx context.Context, cmd *exec.Cmd) (*exec.Cmd, error) {
	var flags []string
	prefix := func(name string, value uint64) {
		flags = append(flags, name+"="+fmt.Sprintf("%d", value))
	}

	if r.maxMemoryMB > 0 {
		prefix("--as", uint64(r.maxMemoryMB)*1024*1024)
	}
	if r.maxCPUSeconds > 0 {
		prefix("--cpu", uint64(r.maxCPUSeconds))
	}
	if r.maxNProc > 0 {
		prefix("--nproc", uint64(r.maxNProc))
	}
	if r.maxFSWriteMB > 0 {
		prefix("--fsize", uint64(r.maxFSWriteMB)*1024*1024)
	}

	if len(flags) == 0 {
		return cmd, nil
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("hard resource limits (%s) cannot be enforced on %s: they are hard caps, not hints; use prlimit-capable Linux or a hardened runtime (Firecracker/gVisor)", strings.Join(flags, " "), runtime.GOOS)
	}
	if _, err := exec.LookPath("prlimit"); err != nil {
		return nil, fmt.Errorf("hard resource limits require the 'prlimit' utility (util-linux): %w", err)
	}

	argv := make([]string, 0, len(cmd.Args)+len(flags)+2)
	argv = append(argv, "prlimit")
	argv = append(argv, flags...)
	argv = append(argv, "--")
	argv = append(argv, cmd.Args...)

	// #nosec G204 -- argv is assembled from fixed per-language commands plus
	// numeric, config-derived prlimit flags; generated code is written to a
	// file, never interpolated into command arguments.
	wrapped := exec.CommandContext(ctx, argv[0], argv[1:]...)
	wrapped.Dir = cmd.Dir
	wrapped.Env = cmd.Env
	return wrapped, nil
}

// withNetworkIsolation wraps cmd so the generated code runs in a fresh network
// namespace when network blocking is enabled. It fails closed: on platforms
// that cannot provide namespace isolation (macOS, Windows) or when the kernel
// rejects unprivileged name spaces, it returns an error so the caller must not
// proceed to execute the code with host network access.
func (r *ProcessRunner) withNetworkIsolation(ctx context.Context, cmd *exec.Cmd) (*exec.Cmd, error) {
	if !r.blockNet {
		return cmd, nil
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("block_network cannot be enforced on %s: set block_network: false or use a hardened runtime (Firecracker/gVisor)", runtime.GOOS)
	}
	if ok, err := probeNetworkIsolation(); !ok {
		return nil, err
	}

	argv := make([]string, 0, len(cmd.Args)+4)
	argv = append(argv, "unshare", "-U", "-n", "--")
	argv = append(argv, cmd.Args...)

	// #nosec G204 -- argv is assembled from a fixed per-language allowlist in
	// buildCommand ("unshare -U -n --" + "go run main.go" / "python3 main.py" /
	// ...). Generated code content is written to a file, never interpolated
	// into command arguments, and the working directory is a fresh temp dir.
	wrapped := exec.CommandContext(ctx, argv[0], argv[1:]...)
	wrapped.Dir = cmd.Dir
	wrapped.Env = cmd.Env
	return wrapped, nil
}

// langToExt maps a language name to its source file extension.
func langToExt(lang string) string {
	switch strings.ToLower(lang) {
	case "go", "golang":
		return ".go"
	case "python", "python3":
		return ".py"
	case "javascript", "js", "node":
		return ".js"
	case "typescript", "ts":
		return ".ts"
	default:
		return ".txt"
	}
}

// cappedOutput buffers up to max bytes of combined child output, discarding
// anything beyond the cap so memory use stays bounded. It always reports the
// full write length so exec's copy loop keeps draining the child and never
// deadlocks; exceeding the cap is surfaced via exceeded() and the caller adds
// a runtime warning for the report. max <= 0 means "no cap" (unbounded).
// It is safe for concurrent use by exec's stdout/stderr copy goroutines.
type cappedOutput struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	max       int
	overLimit bool
}

func newCappedOutput(max int) *cappedOutput {
	return &cappedOutput{max: max}
}

func (c *cappedOutput) Write(p []byte) (int, error) {
	if c.max <= 0 {
		return c.buf.Write(p)
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	room := c.max - c.buf.Len()
	if room > 0 {
		if len(p) <= room {
			return c.buf.Write(p)
		}
		c.buf.Write(p[:room])
		c.overLimit = true
		return len(p), nil
	}
	c.overLimit = true
	return len(p), nil
}

func (c *cappedOutput) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func (c *cappedOutput) exceeded() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.overLimit
}
