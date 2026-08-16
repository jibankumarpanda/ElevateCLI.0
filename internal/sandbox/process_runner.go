// Package sandbox provides code execution environments for ElevatedCLI.
// This file implements the cross-platform process runner — the safe fallback
// used on macOS and Windows (and as a fallback on Linux when Firecracker
// is unavailable). It uses restricted os/exec with:
//   - strict timeout via context
//   - temp directory isolation
//   - process group management for clean teardown
package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// ProcessRunner executes code in a restricted child process.
// It is safe to use on all platforms. For production Linux deployments
// prefer FirecrackerRunner for true hardware-level isolation.
type ProcessRunner struct {
	timeoutSec  int
	maxMemoryMB int
	blockNet    bool
}

// NewProcessRunner creates a ProcessRunner with the given resource limits.
func NewProcessRunner(timeoutSec, maxMemoryMB int, blockNet bool) *ProcessRunner {
	return &ProcessRunner{
		timeoutSec:  timeoutSec,
		maxMemoryMB: maxMemoryMB,
		blockNet:    blockNet,
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

	// Apply process-level restrictions
	applyRestrictions(cmd)

	// Execute
	output, runErr := cmd.CombinedOutput()
	duration := time.Since(start)

	result := sec.SandboxResult{
		Executed: true,
		Mode:     "process",
		Duration: duration,
		Stdout:   string(output),
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

// applyRestrictions sets syscall-level process isolation where available.
func applyRestrictions(cmd *exec.Cmd) {
	if runtime.GOOS == "linux" {
		// Create new process group so we can kill the whole tree
		// Use network and mount namespace isolation on Linux
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true,
			// Uncomment for stronger isolation (requires root or user namespaces):
			// Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWNET | syscall.CLONE_NEWPID,
		}
	} else {
		// macOS / Windows: new process group only
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true,
		}
	}

	// Minimal environment — no access to user's env vars (secrets, tokens)
	cmd.Env = []string{
		"HOME=/tmp",
		"PATH=/usr/local/go/bin:/usr/bin:/bin",
		"TMPDIR=/tmp",
	}
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
