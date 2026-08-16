package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
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
	r := NewProcessRunner(10, 256, true)
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
