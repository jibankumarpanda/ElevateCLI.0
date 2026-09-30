package fixer

import (
	util "github.com/jibankumarpanda/ElevateCLI.0/internal/utils"
)

// redactInCode uses the central redaction utility on the whole code block.
// Repairs are reported in the caller when the string changed.
func redactInCode(code string) string {
	return util.RedactSecrets(code)
}
