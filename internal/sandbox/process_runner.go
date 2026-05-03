package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// ProcessRunner executes code in a restricted local process.
type ProcessRunner struct {
	Limits ResourceLimits
}

func NewProcessRunner(limits ResourceLimits) *ProcessRunner {
	return &ProcessRunner{Limits: limits}
}

func (pr *ProcessRunner) Run(ctx context.Context, code string, lang string) (security.SandboxResult, error) {
	// 1. Write code to temp file
	tmpDir, err := os.MkdirTemp("", "secure-ai-sandbox-*")
	if err != nil {
		return security.SandboxResult{}, err
	}
	defer os.RemoveAll(tmpDir)

	var ext string
	switch lang {
	case "go": ext = ".go"
	case "python": ext = ".py"
	case "js": ext = ".js"
	default: ext = ".txt"
	}

	filePath := filepath.Join(tmpDir, "main"+ext)
	if err := os.WriteFile(filePath, []byte(code), 0644); err != nil {
		return security.SandboxResult{}, err
	}

	// 2. Prepare execution command
	var cmd *exec.Cmd
	switch lang {
	case "go":
		cmd = exec.CommandContext(ctx, "go", "run", filePath)
	case "python":
		cmd = exec.CommandContext(ctx, "python3", filePath)
	case "js":
		cmd = exec.CommandContext(ctx, "node", filePath)
	default:
		return security.SandboxResult{}, fmt.Errorf("unsupported language for sandbox: %s", lang)
	}

	// 3. Apply restrictions (Linux specific)
	if runtime.GOOS == "linux" {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWNET, // Namespace isolation
			Setpgid:    true,
		}
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err = cmd.Run()
	duration := time.Since(start)

	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			return security.SandboxResult{Error: err.Error()}, nil
		}
	}

	return security.SandboxResult{
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		ExitCode:   exitCode,
		Duration:   duration,
		Suspicious: false, // Future: Monitor syscalls
	}, nil
}
