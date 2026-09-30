// Package fixer implements the rule-driven mechanical repairs used by the
// fail-closed fix loop.
//
// The repairs here are deliberately deterministic and language-aware. They are
// driven entirely by findings and policy violations the pipeline already
// produced — no LLM is involved, so a mechanical round is reproducible from the
// same inputs and carries none of the trust assumptions of a semantic patch.
//
// Every repair follows one invariant: a repair either produces code that still
// parses, or it is refused and reported as unrepairable. When a repair cannot
// be completed safely it is never partially applied and never approximated,
// because a silently-wrong patch that still parses is the failure mode most
// likely to reach production.
package fixer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

// RepairKind identifies a single mechanical repair.
type RepairKind string

const (
	// RepairBlockedImport removes an import the policy blocks.
	RepairBlockedImport RepairKind = "blocked_import"
	// RepairBlockedFunction removes a call to a function the policy blocks.
	RepairBlockedFunction RepairKind = "blocked_function"
	// RepairUnhandledError replaces a discarded error with a real check.
	RepairUnhandledError RepairKind = "unhandled_error"
	// RepairSecretRedaction replaces a detected credential with a placeholder.
	RepairSecretRedaction RepairKind = "secret_redaction"
	// RepairComplexity extracts boolean sub-conditions into helper functions to
	// bring a function under the configured cyclomatic complexity limit.
	RepairComplexity RepairKind = "complexity"
)

// Repair describes one applied mechanical change.
type Repair struct {
	Kind RepairKind
	// Rule is the policy rule or finding rule id the repair addressed.
	Rule string
	// Line is the 1-based line in the round's input code.
	Line int
	// Detail is a short human-readable description of the change.
	Detail string
}

// String renders a repair as a single audit-trail line.
func (r Repair) String() string {
	return fmt.Sprintf("%s (%s at line %d): %s", r.Kind, r.Rule, r.Line, r.Detail)
}

// Result is the outcome of one mechanical repair pass over a piece of code.
type Result struct {
	// Code is the repaired source. It always parses when Err is nil.
	Code string
	// Repairs lists every change applied, in application order.
	Repairs []Repair
	// Unrepairable lists violations that were detected but could not be
	// repaired safely. The fix loop stops and surfaces these rather than
	// claiming the code is clean.
	Unrepairable []string
	// Changed reports whether any repair altered the code.
	Changed bool
}

// Summary returns the repairs as audit-trail strings.
func (r Result) Summary() []string {
	out := make([]string, 0, len(r.Repairs))
	for _, rep := range r.Repairs {
		out = append(out, rep.String())
	}
	return out
}

// Fixer applies rule-driven mechanical repairs for one language.
type Fixer struct {
	policy config.PolicyConfig
}

// New returns a Fixer configured from the loaded policy rules.
func New(policy config.PolicyConfig) *Fixer {
	return &Fixer{policy: policy}
}

// Apply runs every mechanical repair applicable to the violations found in
// code, for the given language.
func (f *Fixer) Apply(code, language string, violations []sec.PolicyViolation, findings []sec.Finding) Result {
	res := Result{Code: code}
	lang := normaliseLanguage(language)

	if redacted := redactInCode(code); redacted != code {
		res.Repairs = append(res.Repairs, Repair{
			Kind:   RepairSecretRedaction,
			Rule:   "HARDCODED_SECRET",
			Line:   firstChangedLine(code, redacted),
			Detail: "replaced detected credential values with [REDACTED] placeholders",
		})
		res.Code = redacted
		res.Changed = true
	}

	byRule := groupByRule(violations)

	if lang == "go" {
		res.absorb(f.applyGoAST(res.Code, byRule))
	} else {
		for _, kind := range []RepairKind{
			RepairBlockedImport,
			RepairBlockedFunction,
			RepairUnhandledError,
		} {
			v := byRule[ruleForKind(kind)]
			if len(v) == 0 {
				continue
			}
			res.absorb(applyTextRepairs(res.Code, lang, kind, v))
		}
	}

	if limit := f.policy.Rules.MaxCyclomaticComplexity; limit > 0 {
		res.absorb(reduceComplexity(res.Code, lang, limit))
	}

	res.Unrepairable = append(res.Unrepairable, unrepairableFindings(findings, violations)...)
	res.Changed = len(res.Repairs) > 0
	return res
}

// absorb folds a pass result into the accumulated result.
func (r *Result) absorb(pass passResult) {
	if pass.code != "" && pass.code != r.Code {
		r.Code = pass.code
	}
	r.Repairs = append(r.Repairs, pass.repairs...)
	r.Unrepairable = append(r.Unrepairable, pass.unrepairable...)
}

type passResult struct {
	code         string
	repairs      []Repair
	unrepairable []string
}

// ruleForKind maps a repair kind to the policy rule it addresses.
func ruleForKind(kind RepairKind) string {
	switch kind {
	case RepairBlockedImport:
		return "BLOCKED_IMPORT"
	case RepairBlockedFunction:
		return "BLOCKED_FUNCTION"
	case RepairUnhandledError:
		return "UNHANDLED_ERROR"
	default:
		return ""
	}
}

// groupByRule indexes violations by rule id for O(1) lookup per repair kind.
func groupByRule(vs []sec.PolicyViolation) map[string][]sec.PolicyViolation {
	out := make(map[string][]sec.PolicyViolation, len(vs))
	for _, v := range vs {
		out[v.Rule] = append(out[v.Rule], v)
	}
	return out
}

// unrepairableFindings reports SAST findings that no mechanical rule covers.
// Dependency vulnerabilities are excluded: they are fixed by upgrading a
// package, which is a lockfile change, not a source repair.
func unrepairableFindings(findings []sec.Finding, violations []sec.PolicyViolation) []string {
	covered := make(map[string]bool, len(violations))
	for _, v := range violations {
		covered[v.Rule] = true
	}

	seen := make(map[string]bool)
	var out []string
	for _, f := range findings {
		// A finding whose rule is already covered by a policy repair is handled
		// by that pass; anything else needs a human or a semantic patch.
		if covered[f.RuleID] || seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		out = append(out, fmt.Sprintf(
			"%s at line %d: %s — no mechanical repair rule covers this finding",
			f.RuleID, f.Line, f.Title))
	}
	sort.Strings(out)
	return out
}

// normaliseLanguage folds the language aliases the CLI accepts onto the small
// set the repair passes distinguish between.
func normaliseLanguage(lang string) string {
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case "go", "golang":
		return "go"
	case "python", "python3", "py":
		return "python"
	case "javascript", "js", "node":
		return "javascript"
	case "typescript", "ts":
		return "typescript"
	default:
		return strings.ToLower(strings.TrimSpace(lang))
	}
}

// firstChangedLine returns the 1-based line number of the first line that
// differs between two versions of the same code, or 1 when they are identical.
func firstChangedLine(before, after string) int {
	b := strings.Split(before, "\n")
	a := strings.Split(after, "\n")
	for i := range b {
		if i >= len(a) || b[i] != a[i] {
			return i + 1
		}
	}
	if len(a) > len(b) {
		return len(b) + 1
	}
	return 1
}
