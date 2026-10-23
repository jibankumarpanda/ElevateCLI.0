package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// DockerRunner executes generated code inside a hardened, disposable container.
//
// The runtime profile is deliberately restrictive:
//   - `--network none` when block_network is enabled: the container has no
//     network stack at all;
//   - `--read-only` root with an in-memory `/tmp` tmpfs: nothing the guest
//     writes can persist or touch the host;
//   - the code directory is bind-mounted read-only at /work and used as the
//     working directory, so generated code is never interpolated into argv;
//   - `--cap-drop ALL --security-opt no-new-privileges` and a non-root user
//     remove the container's ability to gain privileges;
//   - `--memory`, `--cpus`, and `--pids-limit` bound host resource use.
//
// It fails closed: if the docker CLI/daemon is unavailable, the image is
// missing, or docker cannot start the container at all, Run returns an error so
// the pipeline reports ANALYSIS_INCOMPLETE instead of silently executing the
// code on the host.
type DockerRunner struct {
	timeoutSec    int
	maxMemoryMB   int
	maxCPUSeconds int
	maxNProc      int
	maxOutputKB   int
	maxFSWriteMB  int
	cpuPerc       int
	blockNet      bool
	image         string
}

// NewDockerRunner creates a DockerRunner. image is the container image; an
// empty value selects a per-language default. limits carries the process-count,
// output and filesystem caps.
func NewDockerRunner(timeoutSec, maxMemoryMB int, blockNet bool, limits ResourceLimits, image string) *DockerRunner {
	return &DockerRunner{
		timeoutSec:    timeoutSec,
		maxMemoryMB:   maxMemoryMB,
		maxCPUSeconds: limits.MaxCPUSeconds,
		maxNProc:      limits.MaxNProc,
		maxOutputKB:   limits.MaxOutputKB,
		maxFSWriteMB:  limits.MaxFSWriteMB,
		cpuPerc:       limits.CPUPerc,
		blockNet:      blockNet,
		image:         image,
	}
}

// dockerBinary returns the docker CLI to use, honouring the
// ELEVATED_CLI_DOCKER_BINARY override before the PATH default.
func dockerBinary() string {
	if b := os.Getenv("ELEVATED_CLI_DOCKER_BINARY"); b != "" {
		return b
	}
	return "docker"
}

var (
	dockerProbeOnce sync.Once
	dockerProbeOK   bool
	dockerProbeErr  error
)

// probeDocker verifies the docker CLI is present and a daemon answers. It is a
// package-level var so tests can inject outcomes.
var probeDocker = func() (bool, error) {
	dockerProbeOnce.Do(func() {
		bin := dockerBinary()
		if _, err := exec.LookPath(bin); err != nil {
			dockerProbeErr = err
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// #nosec G204 -- bin is either the constant "docker" or the
		// operator-set ELEVATED_CLI_DOCKER_BINARY path; it is not tainted by
		// generated code and the remaining arguments are fixed.
		if _, err := exec.CommandContext(ctx, bin, "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
			dockerProbeErr = err
			return
		}
		dockerProbeOK = true
	})
	return dockerProbeOK, dockerProbeErr
}

// dockerExec runs the docker command and captures bounded output. It is a var so
// tests can exercise Run without a docker daemon.
var dockerExec = func(ctx context.Context, dir string, argv []string, maxOutputKB int) (stdout, stderr string, exitCode int, err error) {
	// #nosec G204 -- argv is assembled from the fixed docker CLI flags in this
	// package plus the read-only bind mount; generated code is written to a
	// file and never interpolated into command arguments.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	out := newCappedOutput(maxOutputKB * 1024)
	errOut := newCappedOutput(maxOutputKB * 1024)
	cmd.Stdout = out
	cmd.Stderr = errOut
	runErr := cmd.Run()
	stdout, stderr = out.String(), errOut.String()
	if runErr == nil {
		return stdout, stderr, 0, nil
	}
	if exitErr, ok := runErr.(*exec.ExitError); ok {
		return stdout, stderr, exitErr.ExitCode(), runErr
	}
	return stdout, stderr, -1, runErr
}

// normalizeLang canonicalises a language name to the set handled by the
// container runner.
func normalizeLang(lang string) string {
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case "go", "golang":
		return "go"
	case "python", "python3":
		return "python"
	case "javascript", "js", "node":
		return "javascript"
	default:
		return strings.ToLower(strings.TrimSpace(lang))
	}
}

// guestCommand returns the in-container argv for a language given the path the
// code file is mounted at.
func guestCommand(language, mounted string) ([]string, bool) {
	switch normalizeLang(language) {
	case "go":
		return []string{"go", "run", mounted}, true
	case "python":
		return []string{"python3", mounted}, true
	case "javascript":
		return []string{"node", mounted}, true
	default:
		return nil, false
	}
}

// imageForLanguage returns the container image for a language, preferring the
// operator-configured image when set.
func (d *DockerRunner) imageForLanguage(language string) (string, bool) {
	if d.image != "" {
		return d.image, true
	}
	switch normalizeLang(language) {
	case "go":
		return "golang:1.25-alpine", true
	case "python":
		return "python:3.12-alpine", true
	case "javascript":
		return "node:20-alpine", true
	default:
		return "", false
	}
}

// buildRunArgs assembles the `docker run` argument vector. It is separated from
// Run so the exact containment flags can be asserted in tests without a daemon.
func (d *DockerRunner) buildRunArgs(workDir, image string, guest []string) []string {
	argv := []string{
		dockerBinary(), "run", "--rm", "--init",
		"--read-only",
		"--tmpfs", "/tmp:rw,exec,size=64m,mode=1777",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--user", "65534:65534",
		"-v", workDir + ":/work:ro",
		"-w", "/work",
	}
	if d.blockNet {
		argv = append(argv, "--network", "none")
	}
	if d.maxMemoryMB > 0 {
		argv = append(argv, "--memory", fmt.Sprintf("%dm", d.maxMemoryMB))
	}
	if d.cpuPerc > 0 {
		argv = append(argv, "--cpus", fmt.Sprintf("%.2f", float64(d.cpuPerc)/100))
	}
	if d.maxNProc > 0 {
		argv = append(argv, "--pids-limit", fmt.Sprintf("%d", d.maxNProc))
	}
	argv = append(argv,
		"-e", "GOCACHE=/tmp/gocache",
		"-e", "GOPATH=/tmp/gopath",
		"-e", "HOME=/tmp",
		image,
	)
	return append(argv, guest...)
}

// Run executes the generated code inside a Docker container.
func (d *DockerRunner) Run(ctx context.Context, code, language string) (sec.SandboxResult, error) {
	start := time.Now()
	image, ok := d.imageForLanguage(language)
	if !ok {
		return sec.SandboxResult{
			Executed:   false,
			Skipped:    true,
			SkipReason: fmt.Sprintf("unsupported language for docker sandbox: %s", language),
			Mode:       "docker",
		}, nil
	}

	guest, ok := guestCommand(language, "/work/code"+langToExt(language))
	if !ok {
		return sec.SandboxResult{
			Executed:   false,
			Skipped:    true,
			SkipReason: fmt.Sprintf("unsupported language for docker sandbox: %s", language),
			Mode:       "docker",
		}, nil
	}

	workDir, err := os.MkdirTemp("", "elevated-docker-*")
	if err != nil {
		return sec.SandboxResult{}, fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(workDir) //nolint:errcheck

	codeFile, err := writeCodeFile(workDir, code, language)
	if err != nil {
		return sec.SandboxResult{}, err
	}
	// The container runs as an unprivileged UID that does not own the
	// bind-mounted files. The random temp directory is created 0700 and the
	// code file 0600, which the container user cannot read, so relax only the
	// browse/read bits for the lifetime of this run.
	if err := os.Chmod(workDir, 0o755); err != nil {
		return sec.SandboxResult{}, fmt.Errorf("making sandbox dir traversable: %w", err)
	}
	if err := os.Chmod(codeFile, 0o644); err != nil {
		return sec.SandboxResult{}, fmt.Errorf("making sandbox code readable: %w", err)
	}
	// Address the mounted file by its real basename to keep guest argv exact.
	guest[len(guest)-1] = "/work/" + filepath.Base(codeFile)

	if ok, err := probeDocker(); !ok {
		reason := fmt.Sprintf("docker boundary unavailable: %v", err)
		return sec.SandboxResult{Executed: false, SkipReason: reason, Mode: "docker"}, fmt.Errorf("%s", reason)
	}

	argv := d.buildRunArgs(workDir, image, guest)

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(d.timeoutSec)*time.Second)
	defer cancel()

	stdout, stderr, exitCode, runErr := dockerExec(timeoutCtx, workDir, argv, d.maxOutputKB)

	result := sec.SandboxResult{
		Executed: true,
		Stdout:   stdout,
		Stderr:   stderr,
		Mode:     "docker",
		Duration: time.Since(start),
		ExitCode: exitCode,
	}

	if d.maxOutputKB > 0 && len(stdout)+len(stderr) >= d.maxOutputKB*1024 {
		result.RuntimeErrors = append(result.RuntimeErrors,
			fmt.Sprintf("output reached the %d KB capture cap; trailing output discarded", d.maxOutputKB))
	}

	if timeoutCtx.Err() == context.DeadlineExceeded {
		result.Success = false
		result.RuntimeErrors = append(result.RuntimeErrors,
			fmt.Sprintf("execution timed out after %ds", d.timeoutSec))
		if runErr != nil {
			result.Stderr = runErr.Error()
		}
		return result, nil
	}

	// docker reserves 125 for "the daemon or container could not run". Treat
	// that as a fail-closed boundary error rather than a guest failure, so a
	// missing image is never mistaken for a successful analysis.
	if exitCode == 125 {
		return result, fmt.Errorf("docker could not run the container (exit 125): %s", strings.TrimSpace(stderr))
	}

	result.Success = runErr == nil
	if runErr != nil {
		if result.Stderr == "" {
			result.Stderr = runErr.Error()
		}
	}
	return result, nil
}
