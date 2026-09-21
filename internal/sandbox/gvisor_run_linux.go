//go:build linux

package sandbox

import (
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

var (
	gvisorProbeOnce sync.Once
	gvisorProbeOK   bool
	gvisorProbeErr  error
)

// probeGVisor is a package-level var so tests can inject failures and exercise
// the fail-closed path. It verifies that runsc is present and that the host can
// provide what rootless gVisor needs (runsc on the PATH, unprivileged user
// namespaces when running as a non-root user, and a working binary).
var probeGVisor = func() (bool, error) {
	gvisorProbeOnce.Do(func() {
		if runtime.GOOS != "linux" {
			gvisorProbeErr = fmt.Errorf("gVisor is a Linux-only runtime")
			return
		}
		bin := runscBinary()
		if _, err := exec.LookPath(bin); err != nil {
			gvisorProbeErr = fmt.Errorf("gVisor binary %q not found in PATH (install runsc per https://gvisor.dev/docs/user_guide/install/ or set ELEVATED_CLI_RUNSC_BINARY): %w", bin, err)
			return
		}
		if os.Geteuid() != 0 {
			// Rootless gVisor re-executes itself inside an unprivileged user
			// namespace. Without that kernel feature the sandbox cannot start
			// at all, so block execution rather than degrading to the host.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := exec.CommandContext(ctx, "unshare", "-U", "-n", "--", "true").Run(); err != nil {
				gvisorProbeErr = fmt.Errorf("gVisor requires unprivileged user namespaces in rootless mode, unavailable here: %w", err)
				return
			}
		}
		if out, err := exec.Command(bin, "--version").CombinedOutput(); err != nil {
			gvisorProbeErr = fmt.Errorf("gVisor binary %q version probe failed: %v (%s)", bin, err, strings.TrimSpace(string(out)))
			return
		}
		gvisorProbeOK = true
	})
	return gvisorProbeOK, gvisorProbeErr
}

// Run executes the generated code inside a gVisor sandbox.
//
// It fails closed: if the gVisor boundary cannot be provided or a configured
// hard cap cannot be enforced, the code does not run (no silent fallback to the
// host os/exec process runner).
func (g *GVisorRunner) Run(ctx context.Context, code, language string) (sec.SandboxResult, error) {
	start := time.Now()
	failClosed := func(reason string) (sec.SandboxResult, error) {
		return sec.SandboxResult{
			Executed:   false,
			Skipped:    false,
			SkipReason: reason,
			Mode:       "gvisor",
		}, fmt.Errorf("%s", reason)
	}

	// Establish the timeout before building any command so the deadline is
	// baked into runsc's exec.Cmd at creation.
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(g.timeoutSec)*time.Second)
	defer cancel()

	// The gVisor boundary must be provably available before any code runs.
	if ok, err := probeGVisor(); !ok {
		return failClosed(fmt.Sprintf("gVisor boundary unavailable and refusing to fall back to host process execution: %v", err))
	}

	rootFS := g.rootFS
	workDir, err := os.MkdirTemp("", "elevated-gvisor-*")
	if err != nil {
		return sec.SandboxResult{}, fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(workDir) // always clean up

	if rootFS != "" {
		// A self-contained rootfs was provided: the code must live inside it
		// because the sandbox sees nothing outside that tree. A unique workdir
		// keeps repeated runs from colliding and is removed afterwards.
		workDir = filepath.Join(rootFS, fmt.Sprintf("elevated-work-%d", time.Now().UnixNano()))
		if err := os.MkdirAll(workDir, 0700); err != nil {
			return sec.SandboxResult{}, fmt.Errorf("creating workdir inside sandbox rootfs %q: %w", rootFS, err)
		}
		defer os.RemoveAll(workDir)
	} else {
		rootFS = "/" // host filesystem presented read-only with a memory overlay
	}

	codeFile, err := writeCodeFile(workDir, code, language)
	if err != nil {
		return sec.SandboxResult{}, err
	}

	// Reuse the per-language command construction (allowlist of interpreters)
	// from the process runner. buildCommand resolves the interpreter to an
	// absolute path (cmd.Path) which is what the sandboxed guest sees.
	cmd, err := buildCommand(timeoutCtx, codeFile, language, workDir)
	if err != nil {
		return sec.SandboxResult{
			Executed:   false,
			Skipped:    true,
			SkipReason: fmt.Sprintf("unsupported language for sandbox: %s", language),
			Mode:       "gvisor",
		}, nil
	}

	argv := make([]string, 0, 8+len(cmd.Args))
	argv = append(argv, runscBinary())
	if os.Geteuid() != 0 {
		argv = append(argv, "--rootless")
	}
	if g.blockNet {
		argv = append(argv, "--network=none")
	} else {
		argv = append(argv, "--network=host")
	}
	argv = append(argv, "do",
		"--root="+rootFS,
		"--cwd="+workDir,
		"--quiet",
		"--",
		cmd.Path,
	)
	argv = append(argv, cmd.Args[1:]...)

	// #nosec G204 -- argv is assembled from a fixed per-language allowlist in
	// buildCommand plus runsc's static flags; generated code is written to a
	// file, never interpolated into command arguments, and the working dir is a
	// fresh temp dir.
	hcmd := exec.CommandContext(timeoutCtx, argv[0], argv[1:]...)
	hcmd.Dir = workDir

	// Memory cap. gVisor already isolates the guest, but an unbounded sentry
	// could still starve the host; RLIMIT_AS on the runsc supervisor bounds the
	// whole tree (sentry + gofer + guest allocations). Applied fail-closed: a
	// requested cap that cannot be enforced means the code does not run.
	if g.maxMemoryMB > 0 {
		if runtime.GOOS != "linux" {
			return failClosed(fmt.Sprintf("memory limits cannot be enforced on %s; not executing generated code with a silently-ignored cap", runtime.GOOS))
		}
		if _, err := exec.LookPath("prlimit"); err != nil {
			return failClosed(fmt.Sprintf("memory limits require the 'prlimit' utility (util-linux): %v", err))
		}
		wrapped := exec.CommandContext(timeoutCtx, "prlimit",
			fmt.Sprintf("--as=%d", uint64(g.maxMemoryMB)*1024*1024), "--")
		wrapped.Args = append(wrapped.Args, hcmd.Args...)
		wrapped.Dir = workDir
		hcmd = wrapped
	}

	// Process-level restrictions (new process group for teardown, scrubbed
	// environment). The guest inherits this minimal environment, so host
	// secrets never reach the code.
	applyRestrictions(hcmd)
	hcmd.Env = append(hcmd.Env,
		"GOCACHE=/tmp/gocache",
		"GOPATH=/tmp/gopath",
		"XDG_RUNTIME_DIR=/tmp/xdg",
		"NUMBA_CACHE_DIR=/tmp/numba",
	)

	// Memory-bounded output capture: a chatty or hostile child cannot exhaust
	// host memory through our capture buffer.
	capture := newCappedOutput(g.maxOutputKB * 1024)
	hcmd.Stdout = capture
	hcmd.Stderr = capture
	runErr := hcmd.Run()
	duration := time.Since(start)

	result := sec.SandboxResult{
		Executed: true,
		Mode:     "gvisor",
		Duration: duration,
		Stdout:   capture.String(),
	}

	if capture.exceeded() {
		result.RuntimeErrors = append(result.RuntimeErrors,
			fmt.Sprintf("output exceeded the %d KB capture cap; trailing output discarded", g.maxOutputKB))
	}

	if timeoutCtx.Err() == context.DeadlineExceeded {
		// runsc has been killed by the context; best-effort SIGKILL of the whole
		// process group so no sentry/gofer survives to leak resources.
		if hcmd.Process != nil {
			_ = syscall.Kill(-hcmd.Process.Pid, syscall.SIGKILL)
		}
		result.Success = false
		result.Stderr = runErr.Error()
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		}
		result.RuntimeErrors = append(result.RuntimeErrors,
			fmt.Sprintf("execution timed out after %ds", g.timeoutSec))
		return result, nil
	}

	if runErr != nil {
		if hcmd.Process != nil {
			_ = syscall.Kill(-hcmd.Process.Pid, syscall.SIGKILL)
		}
		result.Success = false
		result.Stderr = runErr.Error()
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		}
	} else {
		result.Success = true
		result.ExitCode = 0
	}

	return result, nil
}
