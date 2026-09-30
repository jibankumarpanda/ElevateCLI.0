package fixer

import (
	"strings"
	"testing"
)

func TestDiffEmptyWhenIdentical(t *testing.T) {
	code := "package main\n\nfunc main() {}\n"
	if got := Diff(code, code, "out.go"); got != "" {
		t.Errorf("identical input must produce no diff, got:\n%s", got)
	}
}

func TestDiffSingleLineChange(t *testing.T) {
	before := "package main\n\nfunc main() {\n\tprintln(1)\n}\n"
	after := "package main\n\nfunc main() {\n\tprintln(2)\n}\n"

	got := Diff(before, after, "out.go")

	if !strings.HasPrefix(got, "--- a/out.go\n+++ b/out.go\n") {
		t.Errorf("missing unified-diff headers:\n%s", got)
	}
	if !strings.Contains(got, "@@ -") {
		t.Errorf("missing hunk header:\n%s", got)
	}
	if !strings.Contains(got, "-\tprintln(1)") {
		t.Errorf("missing deletion line:\n%s", got)
	}
	if !strings.Contains(got, "+\tprintln(2)") {
		t.Errorf("missing insertion line:\n%s", got)
	}
	// The untouched surrounding lines must appear as context.
	if !strings.Contains(got, " package main") {
		t.Errorf("missing context line:\n%s", got)
	}
}

func TestDiffHunkRangesAreAccurate(t *testing.T) {
	before := "one\ntwo\nthree\nfour\nfive\n"
	after := "one\ntwo\nthree\nFOUR\nfive\n"

	got := Diff(before, after, "f.txt")

	// Lines 1-3 are context, line 4 changes, line 5 is context: -1,5 +1,5.
	if !strings.Contains(got, "@@ -1,5 +1,5 @@") {
		t.Errorf("unexpected hunk header:\n%s", got)
	}
}

func TestDiffEmptyBeforeLine(t *testing.T) {
	got := Diff("", "hello\n", "new.go")

	if !strings.Contains(got, "+++ b/new.go") {
		t.Errorf("missing header:\n%s", got)
	}
	if !strings.Contains(got, "+hello") {
		t.Errorf("missing inserted line:\n%s", got)
	}
}

func TestDiffPureDeletion(t *testing.T) {
	before := "a\nb\nc\n"
	after := "a\nc\n"

	got := Diff(before, after, "f.txt")

	if !strings.Contains(got, "-b") {
		t.Errorf("missing deletion:\n%s", got)
	}
	if strings.Contains(got, "+b") {
		t.Errorf("deletion must not appear as an insertion:\n%s", got)
	}
}

func TestDiffSeparateHunksAreNotMergedWhenDistant(t *testing.T) {
	var beforeLines, afterLines []string
	for i := range 40 {
		beforeLines = append(beforeLines, "line"+itoa(i))
		afterLines = append(afterLines, "line"+itoa(i))
	}
	afterLines[2] = "CHANGED-TOP"
	afterLines[35] = "CHANGED-BOTTOM"

	got := Diff(strings.Join(beforeLines, "\n")+"\n", strings.Join(afterLines, "\n")+"\n", "f.txt")

	if strings.Count(got, "@@ -") != 2 {
		t.Errorf("distant changes should produce two hunks, got:\n%s", got)
	}
}

func TestDiffAdjacentChangesShareOneHunk(t *testing.T) {
	before := "a\nb\nc\nd\n"
	after := "A\nB\nc\nd\n"

	got := Diff(before, after, "f.txt")

	if strings.Count(got, "@@ -") != 1 {
		t.Errorf("adjacent changes should produce one hunk, got:\n%s", got)
	}
}

func TestDiffIsDeterministic(t *testing.T) {
	before := "a\nb\nc\nd\ne\n"
	after := "A\nb\nC\nd\nE\n"

	first := Diff(before, after, "f.txt")
	for range 5 {
		if got := Diff(before, after, "f.txt"); got != first {
			t.Fatal("diff output is not deterministic")
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}
