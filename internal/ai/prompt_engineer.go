package ai

import "fmt"

// PromptEngineer handles the construction of high-quality, security-focused prompts.
type PromptEngineer struct {
	DefaultLanguage string
}

func NewPromptEngineer(defaultLang string) *PromptEngineer {
	return &PromptEngineer{
		DefaultLanguage: defaultLang,
	}
}

// ConstructPrompt wraps the user prompt with security-first instructions and constraints.
func (pe *PromptEngineer) ConstructPrompt(userPrompt, lang string) string {
	if lang == "" {
		lang = pe.DefaultLanguage
	}

	return fmt.Sprintf(`Task: Generate production-grade, secure %s code.
Requirement: The code must be self-contained and follow best security practices (no hardcoded secrets, input validation, proper error handling).
Output: Provide ONLY the source code. No markdown tags, no explanations, no preamble.

User Request: %s`, lang, userPrompt)
}
