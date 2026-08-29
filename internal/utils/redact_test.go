package util

import (
	"strings"
	"testing"
)

func TestRedactSecretsAssignments(t *testing.T) {
	cases := map[string]string{
		`password = hunter2`:             `password = [REDACTED]`,
		`export API_KEY=sk-abcdef`:       `export API_KEY=[REDACTED]`,
		`"client_secret": "abc123"`:      `"client_secret": "[REDACTED]"`,
		`Authorization: Bearer abc.def`:  `Authorization: [REDACTED]`,
		`access_key = AKIAI44QH8DHBEXAMPLE`: `access_key = [REDACTED]`,
	}
	for in, want := range cases {
		got := RedactSecrets(in)
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("RedactSecrets(%q) = %q, want a redaction marker", in, got)
			continue
		}
		if !strings.Contains(got, want[strings.Index(want, "="):]) || strings.Contains(got, "hunter2") {
			t.Errorf("RedactSecrets(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactSecretsTokenFormats(t *testing.T) {
	cases := []string{
		"sk-proj-abcdefghijklmnopqrstuvwxyz",
		"ghp_1234567890123456789012345678901234",
		"AKIAIOSFODNN7EXAMPLE",
		"glpat-token-abcdefghij123456",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
	}
	for _, secret := range cases {
		text := "prefix " + secret + " suffix"
		got := RedactSecrets(text)
		if strings.Contains(got, secret) {
			t.Errorf("RedactSecrets leaked %q: %q", secret, got)
		}
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("RedactSecrets(%q) = %q, want marker", text, got)
		}
	}
}

func TestRedactSecretsLeavesNormalCodeUntouched(t *testing.T) {
	in := `package main
func main() {
	sum := 2 + 2
	title := "secret mountain"
	fmt.Println(sum, title)
}`
	got := RedactSecrets(in)
	if got != in {
		t.Errorf("normal code was modified:\n%s", got)
	}
}

func TestRedactSecretsIdempotent(t *testing.T) {
	in := "api_key=sk-abcdefghijklmnopqrstuvwxyz more"
	once := RedactSecrets(in)
	twice := RedactSecrets(once)
	if once != twice {
		t.Errorf("redaction not idempotent: %q -> %q", once, twice)
	}
}