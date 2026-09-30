package fixer

import (
	"fmt"
	"strings"

	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// applyTextRepairs is the line-based repair pass used for languages without a
// syntax-tree repair. It is intentionally conservative: it only edits a line when
// the offending construct occupies that entire line, and it only removes a
// blocked import when the identifier it binds is not referenced anywhere else.
//
// When the construct shares a line with other logic, or the identifier is still
// referenced, the violation is reported as unrepairable rather than rewritten.
// A partial line edit is how an automated repair corrupts working code, so the
// pass declines instead.
func applyTextRepairs(code, lang string, kind RepairKind, vs []sec.PolicyViolation) passResult {
	var out passResult

	lines := strings.Split(code, "\n")
	drop := make(map[int]bool) // 0-based line index
	var taken []int

	for _, v := range vs {
		idx := v.Line - 1
		if idx < 0 || idx >= len(lines) {
			out.unrepairable = append(out.unrepairable, fmt.Sprintf(
				"%s: reported line %d is outside the code, so it cannot be repaired safely",
				v.Rule, v.Line))
			continue
		}
		if drop[idx] {
			continue
		}

		switch kind {
		case RepairBlockedImport:
			handled, ok := planImportRemoval(lines, idx, v)
			if !ok {
				out.unrepairable = append(out.unrepairable, handled)
				continue
			}
			if countWordUses(lines, v.Value) > 0 {
				out.unrepairable = append(out.unrepairable, fmt.Sprintf(
					"%s at line %d: cannot remove import %q because it is still referenced; the call "+
						"sites must be rewritten, which is a semantic change", v.Rule, v.Line, v.Value))
				continue
			}
			drop[idx] = true
			taken = append(taken, idx)
			out.repairs = append(out.repairs, Repair{
				Kind:   kind,
				Rule:   v.Rule,
				Line:   v.Line,
				Detail: fmt.Sprintf("removed blocked import %q", v.Value),
			})

		case RepairBlockedFunction:
			handled, ok := planCallRemoval(lines, idx, v, lang)
			if !ok {
				out.unrepairable = append(out.unrepairable, handled)
				continue
			}
			drop[idx] = true
			taken = append(taken, idx)
			out.repairs = append(out.repairs, Repair{
				Kind:   kind,
				Rule:   v.Rule,
				Line:   v.Line,
				Detail: fmt.Sprintf("removed blocked call to %s", v.Value),
			})

		case RepairUnhandledError:
			out.unrepairable = append(out.unrepairable, fmt.Sprintf(
				"%s at line %d: discarded error handling cannot be rewrapped automatically in %s "+
					"without knowing the enclosing function's error contract; handle it by hand",
				v.Rule, v.Line, lang))
		}
	}

	if len(taken) == 0 {
		return out
	}

	out.code = dropLines(lines, drop)
	return out
}

// planImportRemoval decides whether the whole offending line is an import
// declaration that can be deleted. It returns a human-readable refusal when the
// line holds more than the import.
func planImportRemoval(lines []string, idx int, v sec.PolicyViolation) (string, bool) {
	trimmed := strings.TrimSpace(stripComment(lines[idx]))
	if trimmed == "" {
		return "", false
	}

	// A multi-line or parenthesised import block puts the spec on its own line,
	// which is the only shape that can be removed without touching neighbours.
	switch {
	case strings.HasPrefix(trimmed, "import "), strings.HasPrefix(trimmed, "from "):
		// Single-line form: `import x` / `from x import a, b` — safe to drop.
		return "", true
	case trimmed == strings.TrimSpace(v.Value):
		// Bare spec inside a parenthesised block: `    os,` or `    "os/exec"`.
		return "", true
	case strings.HasSuffix(strings.TrimSuffix(trimmed, ","), strings.TrimSpace(v.Value)):
		return "", true
	}

	return fmt.Sprintf(
		"%s at line %d: the import shares its line with other code (%q), so removing it would "+
			"change unrelated logic; move it to its own line or handle it by hand",
		v.Rule, v.Line, trimmed), false
}

// planCallRemoval decides whether the offending line is a standalone call whose
// effect the policy blocks, so the statement can be deleted outright.
func planCallRemoval(lines []string, idx int, v sec.PolicyViolation, lang string) (string, bool) {
	trimmed := strings.TrimSpace(stripComment(lines[idx]))
	if trimmed == "" {
		return "", false
	}

	body := strings.TrimSuffix(trimmed, ";")
	prefixes := []string{"defer ", "go ", "await ", "return "}
	for _, prefix := range prefixes {
		body = strings.TrimPrefix(body, strings.TrimSpace(prefix))
	}

	// Only a bare `name(...)` statement qualifies. Anything with an assignment,
	// a comparison, or a chained expression is left for a human.
	name := v.Value
	if !strings.HasSuffix(body, ")") {
		return fmt.Sprintf(
			"%s at line %d: %q is not a standalone call statement, so removing it would change "+
				"program behaviour; handle it by hand", v.Rule, v.Line, name), false
	}

	open := strings.Index(body, "(")
	if open <= 0 {
		return fmt.Sprintf(
			"%s at line %d: could not identify the blocked call in %q; handle it by hand",
			v.Rule, v.Line, trimmed), false
	}
	callee := strings.TrimSpace(body[:open])
	if callee != name && !strings.HasSuffix(callee, "."+name) {
		return fmt.Sprintf(
			"%s at line %d: the call on this line is %q, not the blocked %q; handle it by hand",
			v.Rule, v.Line, callee, name), false
	}

	if !balancedParens(body) {
		return fmt.Sprintf(
			"%s at line %d: the call spans multiple lines, so it cannot be removed as a single "+
				"statement; handle it by hand", v.Rule, v.Line), false
	}

	_ = lang
	return "", true
}

// balancedParens reports whether every opening parenthesis is closed, which is a
// cheap guard against deleting half of a multi-line call.
func balancedParens(s string) bool {
	depth := 0
	for _, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

// dropLines rebuilds the source without the removed lines, preserving the
// original trailing-newline behaviour.
func dropLines(lines []string, drop map[int]bool) string {
	kept := make([]string, 0, len(lines))
	for i, line := range lines {
		if drop[i] {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// stripComment removes a trailing line comment so commented-out code is not
// mistaken for a live construct.
func stripComment(line string) string {
	for _, marker := range []string{"#", "//"} {
		if idx := strings.Index(line, marker); idx >= 0 {
			return line[:idx]
		}
	}
	return line
}

// countWordUses counts references to a name across the source, ignoring matches
// inside the import statement that binds it.
func countWordUses(lines []string, name string) int {
	if name == "" {
		return 0
	}
	total := 0
	for i, line := range lines {
		if isImportLine(line) {
			continue
		}
		total += strings.Count(line, name)
	}
	return total
}

func isImportLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "import ") ||
		strings.HasPrefix(trimmed, "from ") ||
		trimmed == "import ("
}