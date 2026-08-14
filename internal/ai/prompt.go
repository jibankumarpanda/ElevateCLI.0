package ai

import (
	"fmt"
	"regexp"
	"strings"
)

// BuildGeneratePrompt wraps the user's request with security-first instructions
// and the target language, so the model returns code in a parseable format.
func BuildGeneratePrompt(prompt, language string) string {
	if language == "" {
		language = "go"
	}
	return fmt.Sprintf(`You are a senior software engineer. Write production-grade, secure %s code for the following request.

Requirements:
- Return ONLY the source code inside a single markdown code block (```%s ... ```).
- No explanations, no commentary, no multiple code blocks.
- Follow security best practices: no hardcoded secrets, validate inputs, handle errors.
- Prefer the standard library over third-party dependencies.

Request: %s`, language, language, prompt)
}

var fenceRegexp = regexp.MustCompile("(?s)```([a-zA-Z0-9_+-]*)[ \t]*\n(.*?)```")

// ExtractCodeBlock extracts the first fenced code block from an LLM response,
// returning the code and the detected language (normalised). When no fenced
// block is present, the trimmed response is returned as-is.
func ExtractCodeBlock(raw string) (code, lang string) {
	m := fenceRegexp.FindStringSubmatch(raw)
	if len(m) < 3 {
		return strings.TrimSpace(raw), ""
	}
	lang = strings.TrimSpace(m[1])
	code = strings.TrimSpace(m[2])

	switch strings.ToLower(lang) {
	case "py", "python3":
		lang = "python"
	case "node", "js":
		lang = "javascript"
	case "tsx":
		lang = "typescript"
	case "golang":
		lang = "go"
	}
	return code, lang
}
