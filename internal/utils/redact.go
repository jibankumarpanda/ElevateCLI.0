// Package util provides small, dependency-free helpers shared across packages.
package util

import (
	"regexp"
	"strings"
)

// redactionMarker is the placeholder written in place of a detected secret.
const redactionMarker = "[REDACTED]"

// RedactSecrets replaces known credential values in s with a redaction
// marker. It is conservative: only well-known secret shapes (key=value
// assignments with secret-like keys, common API/token formats, and PEM
// private keys) are replaced, so general code is left untouched.
func RedactSecrets(s string) string {
	s = redactAssignments(s)
	for _, re := range secretTokenPatterns {
		s = re.ReplaceAllString(s, redactionMarker)
	}
	return s
}

// secretKeyRe matches an assignment whose key names a credential, for example:
//
//	password = hunter2
//	export API_KEY="sk-..."
//	"client_secret": "abc"
//	Authorization: Bearer xyz
var secretKeyRe = regexp.MustCompile(`(?i)^(\s*(?:export\s+)?[a-zA-Z_.@$#-]*?(?:api[_-]?key|apikey|api_key|password|passwd|pwd|secret|token|auth|credential|consumer[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|aws[_-]?secret[_-]?access[_-]?key)[a-zA-Z0-9_.-]*\s*)([=:]\s*)(.*)$`)

func redactAssignments(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		m := secretKeyRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		keyPart, sep := m[1], m[2]
		value := strings.TrimSpace(m[3])
		value = strings.TrimRight(value, ",")

		// Nothing to hide, or already sanitised.
		if value == "" || value == redactionMarker || strings.Contains(value, redactionMarker) {
			continue
		}

		quoted := len(value) >= 2 &&
			((value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\''))
		if quoted {
			value = `"` + redactionMarker + `"`
		} else {
			value = redactionMarker
		}
		lines[i] = keyPart + sep + value
	}
	return strings.Join(lines, "\n")
}

// secretTokenPatterns replaces standalone credential tokens regardless of the
// surrounding key name.
var secretTokenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}`),                          // OpenAI
	regexp.MustCompile(`ghp_[A-Za-z0-9]{30,}`),                           // GitHub PAT
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),                   // GitHub fine-grained PAT
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                               // AWS access key
	regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`),                       // GitLab PAT
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),                   // Slack tokens
	regexp.MustCompile(`AIza[0-9A-Za-z_-]{20,}`),                         // Google API key
	regexp.MustCompile(`ya29\.[0-9A-Za-z_-]+`),                           // Google OAuth
	regexp.MustCompile(`gho_[A-Za-z0-9]{30,}`),                           // GitHub OAuth
	regexp.MustCompile(`(?i)bearer [A-Za-z0-9-._~+/]+=*`),               // Bearer auth
	regexp.MustCompile(`(?i)basic [a-z0-9+/]{8,}={0,2}`),                // Basic auth (base64)
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`), // PEM
	regexp.MustCompile(`-----BEGIN [A-Z ]*CERTIFICATE-----[\s\S]*?-----END [A-Z ]*CERTIFICATE-----`), // PEM cert
}