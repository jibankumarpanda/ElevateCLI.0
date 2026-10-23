package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newTestDockerRunner() *DockerRunner {
	return NewDockerRunner(5, 128, true, ResourceLimits{MaxNProc: 64, MaxOutputKB: 32, CPUPerc: 50}, "")
}

func containsSeq(haystack, needle []string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		ok := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestDockerRunArgsContainment(t *testing.T) {
	d := newTestDockerRunner()
	args := d.buildRunArgs("/tmp/work", "python:3.12-alpine", []string{"python3", "/work/code.py"})

	mustContain := [][]string{
		{"--read-only"},
		{"--tmpfs", "/tmp:rw,exec,size=64m,mode=1777"},
		{"--network", "none"},
		{"--cap-drop", "ALL"},
		{"--security-opt", "no-new-privileges"},
		{"--user", "65534:65534"},
		{"--memory", "128m"},
		{"--pids-limit", "64"},
		{"--cpus", "0.50"},
		{"-v", "/tmp/work:/work:ro"},
		{"python:3.12-alpine", "python3", "/work/code.py"},
	}
	for _, want := range mustContain {
		if !containsSeq(args, want) {
			t.Errorf("run args missing %v; got %v", want, args)
		}
	}
}

func TestDockerRunArgsBlockNetworkToggle(t *testing.T) {
	d := newTestDockerRunner()
	if !containsSeq(d.buildRunArgs("/w", "img", []string{"x"}), []string{"--network", "none"}) {
		t.Fatal("blocked network should add --network none")
	}
	d.blockNet = false
	if containsSeq(d.buildRunArgs("/w", "img", []string{"x"}), []string{"--network"}) {
		t.Fatal("allowed network should not add --network")
	}
}

func TestDockerUnsupportedLanguageSkips(t *testing.T) {
	d := newTestDockerRunner()
	res, err := d.Run(context.Background(), "puts 1", "ruby")
	if err != nil {
		t.Fatalf("unsupported language must be a skip, not an error: %v", err)
	}
	if !res.Skipped || res.Executed {
		t.Fatalf("expected skipped result, got %+v", res)
	}
}

func TestDockerProbeFailureIsFailClosed(t *testing.T) {
	orig := probeDocker
	probeDocker = func() (bool, error) { return false, errors.New("no daemon") }
	defer func() { probeDocker = orig }()

	d := newTestDockerRunner()
	res, err := d.Run(context.Background(), "print(1)", "python")
	if err == nil {
		t.Fatal("expected fail-closed error when docker is unavailable")
	}
	if res.Executed {
		t.Fatal("code must not execute when the boundary is unavailable")
	}
}

func TestDockerExit125IsFailClosed(t *testing.T) {
	origProbe, origExec := probeDocker, dockerExec
	probeDocker = func() (bool, error) { return true, nil }
	dockerExec = func(context.Context, string, []string, int) (string, string, int, error) {
		return "", "Unable to find image locally", 125, errors.New("exit status 125")
	}
	defer func() { probeDocker, dockerExec = origProbe, origExec }()

	d := newTestDockerRunner()
	if _, err := d.Run(context.Background(), "print(1)", "python"); err == nil {
		t.Fatal("expected fail-closed error when docker cannot start the container")
	}
}

func TestDockerSuccess(t *testing.T) {
	origProbe, origExec := probeDocker, dockerExec
	probeDocker = func() (bool, error) { return true, nil }
	dockerExec = func(context.Context, string, []string, int) (string, string, int, error) {
		return "hello from sandbox", "", 0, nil
	}
	defer func() { probeDocker, dockerExec = origProbe, origExec }()

	res, err := newTestDockerRunner().Run(context.Background(), "print('hi')", "python")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Executed || !res.Success || res.Stdout != "hello from sandbox" || res.Mode != "docker" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestDockerMountedFilesAreReadableByContainerUser(t *testing.T) {
	origProbe, origExec := probeDocker, dockerExec
	probeDocker = func() (bool, error) { return true, nil }
	var dirMode, fileMode os.FileMode
	dockerExec = func(_ context.Context, dir string, _ []string, _ int) (string, string, int, error) {
		di, err := os.Stat(dir)
		if err != nil {
			return "", "", -1, err
		}
		fi, err := os.Stat(filepath.Join(dir, "main.py"))
		if err != nil {
			return "", "", -1, err
		}
		dirMode, fileMode = di.Mode().Perm(), fi.Mode().Perm()
		return "ok", "", 0, nil
	}
	defer func() { probeDocker, dockerExec = origProbe, origExec }()

	if _, err := newTestDockerRunner().Run(context.Background(), "print(1)", "python"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if dirMode != 0o755 {
		t.Errorf("sandbox dir mode = %o, want 755 so the container user can traverse it", dirMode)
	}
	if fileMode != 0o644 {
		t.Errorf("code file mode = %o, want 644 so the container user can read it", fileMode)
	}
}

func TestDockerGuestFailureIsNotRunnerError(t *testing.T) {
	origProbe, origExec := probeDocker, dockerExec
	probeDocker = func() (bool, error) { return true, nil }
	dockerExec = func(context.Context, string, []string, int) (string, string, int, error) {
		return "", "boom", 1, errors.New("exit status 1")
	}
	defer func() { probeDocker, dockerExec = origProbe, origExec }()

	res, err := newTestDockerRunner().Run(context.Background(), "raise", "python")
	if err != nil {
		t.Fatalf("guest failure should not be a runner error: %v", err)
	}
	if res.Success || res.ExitCode != 1 {
		t.Fatalf("expected failed result, got %+v", res)
	}
}

func TestDockerConfigImageOverride(t *testing.T) {
	d := NewDockerRunner(5, 0, false, ResourceLimits{}, "custom:latest")
	if img, ok := d.imageForLanguage("go"); !ok || img != "custom:latest" {
		t.Fatalf("expected image override, got %q ok=%v", img, ok)
	}
	if _, ok := d.imageForLanguage("ruby"); !ok {
		t.Fatal("override should apply to any language")
	}
}

func TestNormalizeLang(t *testing.T) {
	cases := map[string]string{"Go": "go", "golang": "go", "node": "javascript", "JS": "javascript", "python3": "python", "ruby": "ruby"}
	for in, want := range cases {
		if got := normalizeLang(in); got != want {
			t.Errorf("normalizeLang(%q) = %q want %q", in, got, want)
		}
	}
}

func TestGuestCommand(t *testing.T) {
	if _, ok := guestCommand("go", "/work/code.go"); !ok {
		t.Fatal("go should be supported")
	}
	if _, ok := guestCommand("typescript", "/work/code.ts"); ok {
		t.Fatal("typescript has no container runtime here and must be unsupported")
	}
}
