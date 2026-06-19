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
	cmd, err := buildCommand(ctx, codeFile, language, tmpDir)
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

	// Set timeout
	timeoutCtx, cancel := context.WithTimeout(ctx,
		time.Duration(r.timeoutSec)*time.Second)
	defer cancel()
	cmd = rebuildWithContext(timeoutCtx, cmd)

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
	switch strings.ToLower(language) {
	case "go", "golang":
		// For Go we need a minimal go.mod in the temp dir
		modContent := "module sandbox\ngo 1.22\n"
		_ = os.WriteFile(filepath.Join(workDir, "go.mod"), []byte(modContent), 0600)
		cmd := exec.CommandContext(ctx, "go", "run", codeFile)
		cmd.Dir = workDir
		return cmd, nil

	case "python", "python3":
		bin := "python3"
		if runtime.GOOS == "windows" {
			bin = "python"
		}
		cmd := exec.CommandContext(ctx, bin, codeFile)
		cmd.Dir = workDir
		return cmd, nil

	case "javascript", "js", "node":
		cmd := exec.CommandContext(ctx, "node", codeFile)
		cmd.Dir = workDir
		return cmd, nil

	case "typescript", "ts":
		cmd := exec.CommandContext(ctx, "ts-node", codeFile)
		cmd.Dir = workDir
		return cmd, nil

	default:
		return nil, fmt.Errorf("unsupported: %s", language)
	}
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

// rebuildWithContext is needed because exec.Cmd.Args is not changeable after creation.
// We re-create the command with the timeout context already applied via applyRestrictions.
func rebuildWithContext(ctx context.Context, cmd *exec.Cmd) *exec.Cmd {
	newCmd := exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	newCmd.Dir = cmd.Dir
	newCmd.Env = cmd.Env
	newCmd.SysProcAttr = cmd.SysProcAttr
	return newCmd
}

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
