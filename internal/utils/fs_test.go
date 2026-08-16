package util

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExists(t *testing.T) {
	dir := t.TempDir()
	if Exists(dir) != true {
		t.Error("Exists() = false for existing temp dir")
	}
	if Exists(filepath.Join(dir, "nope")) {
		t.Error("Exists() = true for a missing file")
	}
}

func TestEnsureDirCreates(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "a", "b", "c")
	if err := EnsureDir(target); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	if !Exists(target) {
		t.Fatal("EnsureDir did not create the directory tree")
	}
	if err := EnsureDir(target); err != nil {
		t.Fatalf("EnsureDir on existing dir should be a no-op: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0750 {
			t.Errorf("dir perm = %o, want 0750", perm)
		}
	}
}

func TestEnsureDirRejectsFile(t *testing.T) {
	parent := t.TempDir()
	file := filepath.Join(parent, "blocker")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(filepath.Join(file, "child")); err == nil {
		t.Error("EnsureDir under a regular file should fail")
	}
}

func TestReadWriteFileContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "out.txt")
	if err := WriteFileContent(path, "hello"); err != nil {
		t.Fatalf("WriteFileContent: %v", err)
	}
	got, err := ReadFileContent(path)
	if err != nil {
		t.Fatalf("ReadFileContent: %v", err)
	}
	if got != "hello" {
		t.Errorf("ReadFileContent = %q, want %q", got, "hello")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("file perm = %o, want 0600", perm)
		}
	}
}

func TestReadFileContentMissing(t *testing.T) {
	if _, err := ReadFileContent("/definitely/not/here.txt"); err == nil {
		t.Error("ReadFileContent on a missing file should error")
	}
}
