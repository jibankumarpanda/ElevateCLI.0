package util

import (
	"strings"
	"testing"
)

func TestRedactSecretsAssignments(t *testing.T) {
	cases := map[string]string{
		`password = hunter2`:                    "hunter2",
		`export API_KEY=sk-abcdefghijklmnopqrs`: "sk-abcdefghijklmnopqrs",
		`"client_secret": "abc123"`:             "abc123",
		`Authorization: Bearer abc.def`:         "abc.def",
		`access_key = AKIAI44QH8DHBEXAMPLE`:     "AKIAI44QH8DHBEXAMPLE",
	}
	for in, secret := range cases {
		got := RedactSecrets(in)
		if strings.Contains(got, secret) {
			t.Errorf("RedactSecrets(%q) leaked %q: %q", in, secret, got)
		}
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("RedactSecrets(%q) = %q, want a redaction marker", in, got)
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