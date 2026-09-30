package fixer

import (
	"fmt"
	"strings"
)

// Diff renders a unified diff between two versions of a source file.
//
// It is written by hand rather than pulled from a dependency because the output
// is user-facing review material: a human decides whether to keep a patch, so
// the diff has to be predictable and stable, with context that is identical
// between rounds. The format is the standard unified diff with three lines of
// context, which is what `git apply` and every review tool already understands.
func Diff(before, after, path string) string {
	if before == after {
		return ""
	}
	if path == "" {
		path = "generated_code"
	}

	beforeLines := splitLines(before)
	afterLines := splitLines(after)

	ops := diffOps(beforeLines, afterLines)

	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n", path)
	fmt.Fprintf(&b, "+++ b/%s\n", path)
	writeHunks(&b, ops, beforeLines, afterLines)
	return b.String()
}

const diffContext = 3

type opKind int

const (
	opEqual opKind = iota
	opDelete
	opInsert
)

type diffOp struct {
	kind opKind
	// index is the 0-based position in the before-lines for opEqual/opDelete,
	// and in the after-lines for opInsert.
	index int
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

// diffOps produces a minimal line-level edit script using the classic
// longest-common-subsequence dynamic program.
//
// Generated files are small, so the quadratic table is not a concern; the
// minimality it guarantees is what keeps review diffs readable instead of
// rewriting the whole file.
func diffOps(before, after []string) []diffOp {
	n, m := len(before), len(after)

	// lcs[i][j] is the LCS length of before[i:] and after[j:].
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if before[i] == after[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
				continue
			}
			if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	var ops []diffOp
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case before[i] == after[j]:
			ops = append(ops, diffOp{opEqual, i})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, diffOp{opDelete, i})
			i++
		default:
			ops = append(ops, diffOp{opInsert, j})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, diffOp{opDelete, i})
	}
	for ; j < m; j++ {
		ops = append(ops, diffOp{opInsert, j})
	}
	return ops
}

// writeHunks groups the edit script into unified-diff hunks with context and
// emits them with the correct before/after line ranges.
func writeHunks(b *strings.Builder, ops []diffOp, before, after []string) {
	changed := make([]bool, len(ops))
	for i, op := range ops {
		if op.kind != opEqual {
			changed[i] = true
		}
	}
	if !anyTrue(changed) {
		return
	}

	// Extend each change run by diffContext lines on both sides, then merge runs
	// that overlap so a hunk is never emitted twice for one region.
	spans := make([][2]int, 0)
	for i := 0; i < len(ops); i++ {
		if !changed[i] {
			continue
		}
		start := maxInt(i-diffContext, 0)
		end := i
		for end+1 < len(ops) && changed[end+1] {
			end++
		}
		end = minInt(end+diffContext, len(ops)-1)

		if len(spans) > 0 && start <= spans[len(spans)-1][1] {
			if end > spans[len(spans)-1][1] {
				spans[len(spans)-1][1] = end
			}
			continue
		}
		spans = append(spans, [2]int{start, end})
		i = end
	}

	for _, span := range spans {
		var beforeStart, beforeCount int
		var afterStart, afterCount int
		seenBefore, seenAfter := false, false

		for i := span[0]; i <= span[1]; i++ {
			switch ops[i].kind {
			case opEqual:
				if !seenBefore {
					beforeStart, seenBefore = ops[i].index+1, true
				}
				if !seenAfter {
					afterStart, seenAfter = ops[i].index+1, true
				}
				beforeCount++
				afterCount++
			case opDelete:
				if !seenBefore {
					beforeStart, seenBefore = ops[i].index+1, true
				}
				beforeCount++
			case opInsert:
				if !seenAfter {
					afterStart, seenAfter = ops[i].index+1, true
				}
				afterCount++
			}
		}

		fmt.Fprintf(b, "@@ -%d,%d +%d,%d @@\n", beforeStart, beforeCount, afterStart, afterCount)

		for i := span[0]; i <= span[1]; i++ {
			switch ops[i].kind {
			case opEqual:
				fmt.Fprintf(b, " %s\n", before[ops[i].index])
			case opDelete:
				fmt.Fprintf(b, "-%s\n", before[ops[i].index])
			case opInsert:
				fmt.Fprintf(b, "+%s\n", after[ops[i].index])
			}
		}
	}
}

func anyTrue(bs []bool) bool {
	for _, b := range bs {
		if b {
			return true
		}
	}
	return false
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
