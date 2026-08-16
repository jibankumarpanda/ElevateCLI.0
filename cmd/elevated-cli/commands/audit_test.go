package commands

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLangToExtension(t *testing.T) {
	cases := map[string]string{
		"python": ".py", "python3": ".py",
		"javascript": ".js", "js": ".js",
		"typescript": ".ts", "ts": ".ts",
		"go": ".go", "golang": ".go",
		"unknown": ".go",
		"":        ".go",
	}
	for in, want := range cases {
		if got := langToExtension(in); got != want {
			t.Errorf("langToExtension(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDetectLang(t *testing.T) {
	cases := map[string]string{
		"a.go":  "go",
		"a.py":  "python",
		"a.js":  "javascript",
		"a.ts":  "typescript",
		"a.rb":  "go", // unknown ext defaults to go
		"noext": "go",
	}
	for in, want := range cases {
		if got := detectLang(in); got != want {
			t.Errorf("detectLang(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCollectFilesByLanguage(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.go", "package a")
	write("b.py", "print(1)")
	write("c.js", "console.log(1)")
	write("d.ts", "const x: number = 1")
	write("e.txt", "ignore me")
	write("vendor/v.go", "package v")
	write(".hidden/h.go", "package h")
	write("sub/sub.py", "print(2)")

	files, err := collectFiles(dir, "")
	if err != nil {
		t.Fatalf("collectFiles: %v", err)
	}
	got := map[string]bool{}
	for _, f := range files {
		got[filepath.Base(f)] = true
	}
	for _, want := range []string{"a.go", "b.py", "c.js", "d.ts", "sub.py"} {
		if !got[want] {
			t.Errorf("expected %q in collected files: %v", want, files)
		}
	}
	for _, banned := range []string{"e.txt", "v.go", "h.go"} {
		if got[banned] {
			t.Errorf("should not collect %q (ignored path type)", banned)
		}
	}
}

func TestCollectFilesSingleLanguage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.py"), []byte("print"), 0600); err != nil {
		t.Fatal(err)
	}
	files, err := collectFiles(dir, "python")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || filepath.Base(files[0]) != "b.py" {
		t.Errorf("collectFiles(python) = %v", files)
	}
}

func TestCollectFilesMissingDir(t *testing.T) {
	if _, err := collectFiles("/does/not/exist", ""); err == nil {
		t.Error("collectFiles on missing dir should error")
	}
}

func TestSetConfigValueInvalid(t *testing.T) {
	if err := setConfigValue("no-equals-here"); err == nil {
		t.Error("setConfigValue without '=' should error")
	}
}
