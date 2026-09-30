package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/logger"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
	"go.uber.org/zap"
)

// Patcher asks the model to repair code that no deterministic rule could fix.
//
// It is deliberately the weakest link in the fix loop and is treated as such:
// nothing here inspects or trusts the model's reasoning. The patcher only
// assembles a prompt and extracts whatever source the model returns. Every
// judgement about whether that source is an improvement is made afterwards, by
// the full security pipeline re-running on it, and by the loop discarding it if
// the deterministic score drops.
type Patcher struct {
	client Client
}

// NewPatcher returns a Patcher backed by an existing AI client.
func NewPatcher(client Client) *Patcher {
	return &Patcher{client: client}
}

// ErrNoPatch is returned when the model's response contained no source code at
// all. It is a distinct error so the loop can record "the model declined" rather
// than "the model was unreachable".
var ErrNoPatch = fmt.Errorf("the model returned no code to patch")

// Patch asks the model to repair code given the findings that survived
// verification.
//
// It returns complete source, never a diff: the fix loop re-runs the entire
// pipeline on whatever comes back, so a partial or malformed response is caught
// by the same validation as any other candidate patch rather than being trusted
// because the model produced it.
func (p *Patcher) Patch(ctx context.Context, code, language string, report *sec.Report) (string, error) {
	if p == nil || p.client == nil {
		return "", fmt.Errorf("no AI client configured for semantic patching")
	}
	if strings.TrimSpace(code) == "" {
		return "", fmt.Errorf("cannot patch empty code")
	}

	prompt := BuildFixPrompt(code, language, report)
	logger.Get().Debug("semantic patch prompt built",
		zap.String("stage", "ai-patch"),
		zap.String("language", language),
		zap.Int("findings", len(report.Findings)),
	)

	raw, err := p.client.Generate(ctx, prompt)
	if err != nil {
		return "", fmt.Errorf("semantic patch request failed: %w", err)
	}

	// Unlike generation, a patch must come back fenced. ExtractCodeBlock falls
	// back to treating an unfenced response as source, which is the right
	// default for "here is your code" but wrong here: an unfenced refusal ("I
	// cannot fix this without changing behaviour") would be re-verified as if it
	// were the file, silently replacing the user's code with a sentence.
	if !fenceRegexp.MatchString(raw) {
		return "", ErrNoPatch
	}

	patched, lang := ExtractCodeBlock(raw)
	if strings.TrimSpace(patched) == "" {
		return "", ErrNoPatch
	}

	// A model that ignored the requested language and answered in another one
	// would have the patch verified by the wrong analyser, so that is a failure
	// rather than something to paper over.
	if language != "" && lang != "" && !strings.EqualFold(lang, language) {
		return "", fmt.Errorf(
			"semantic patch came back as %s but the code is %s; refusing to verify a patch in the wrong language",
			lang, language)
	}

	return patched, nil
}

// BuildFixPrompt describes the outstanding findings and asks for corrected code.
//
// The prompt states the output contract explicitly because the whole safety
// argument depends on it: the response must be complete, parseable source,
// because anything less cannot be verified and will be discarded.
func BuildFixPrompt(code, language string, report *sec.Report) string {
	if language == "" {
		language = "go"
	}

	var b strings.Builder
	fmt.Fprintf(&b, `The following %s code failed a security review. Repair it.

`, language)

	writeFindings(&b, "Static analysis findings", report.Findings)
	writeViolations(&b, "Policy violations", report.Violations)

	b.WriteString("\nCode under review:\n")
	b.WriteString(fence)
	b.WriteString(language)
	b.WriteString("\n")
	b.WriteString(code)
	b.WriteString("\n")
	b.WriteString(fence)
	b.WriteString("\n")

	fmt.Fprintf(&b, `Rules for your answer:
- Return ONLY the complete corrected %s file inside a single `+"```"+`%s ... `+"```"+` code block.
- Include the whole file, not just the changed lines. A diff or a fragment cannot be verified and will be discarded.
- Preserve the existing behaviour, function names, and public API. This is a security repair, not a rewrite.
- Do not add dependencies or suppress the findings by deleting the code that triggers them.
- Every error must still be handled. Do not introduce a discarded return value.
- If a finding cannot be fixed without changing behaviour, leave that code alone and return the file unchanged.

Corrected %s file:`, language, language, language)

	return b.String()
}

// writeFindings renders findings in a form the model can act on: the rule that
// fired, the severity, and the line. The message is included because a bare rule
// ID often means nothing on its own.
func writeFindings(b *strings.Builder, heading string, findings []sec.Finding) {
	if len(findings) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%s:\n", heading)
	for _, f := range findings {
		line := ""
		if f.Line > 0 {
			line = fmt.Sprintf(" line %d", f.Line)
		}
		title := f.Title
		if title == "" {
			title = f.Description
		}
		fmt.Fprintf(b, "- [%s] %s%s: %s\n", f.Severity, f.RuleID, line, title)
	}
}

// writeViolations renders policy violations, which are distinct from findings:
// they come from the organisation's policy rather than a detection rule.
func writeViolations(b *strings.Builder, heading string, violations []sec.PolicyViolation) {
	if len(violations) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%s:\n", heading)
	for _, v := range violations {
		line := ""
		if v.Line > 0 {
			line = fmt.Sprintf(" line %d", v.Line)
		}
		fmt.Fprintf(b, "- %s%s: %s\n", v.Description, line, v.Rule)
	}
}