package security

import (
	"context"
	"os/exec"
	"testing"
)

const insecureGoCode = `package main

import (
	"context"
	"os/exec"
	"strconv"
)

func run(filePath string) error {
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "ts-node", filePath)
	_ = cmd
	strconv.Atoi("42")
	apiKey := "AKIAIOSFODNN7EXAMPLE" //nolint:gosec
	_ = apiKey
	return nil
}
`

func TestRunGosecFindsInsecureCode(t *testing.T) {
	if _, err := exec.LookPath("gosec"); err != nil {
		t.Skip("gosec not installed")
	}
	findings, err := runGosec(context.Background(), insecureGoCode)
	if err != nil {
		t.Fatalf("runGosec: %v", err)
	}

	var hasG204, hasG101 bool
	for _, f := range findings {
		switch f.RuleID {
		case "G204":
			hasG204 = true
		case "G101":
			hasG101 = true
		}
	}
	if !hasG204 {
		t.Errorf("expected a G204 (command execution) finding, got %d findings", len(findings))
	}
	if !hasG101 {
		t.Errorf("expected a G101 (hardcoded credential) finding")
	}
	for _, f := range findings {
		if f.Line == 0 && f.RuleID != "" {
			t.Errorf("finding %s has zero line (parsing failed): %+v", f.RuleID, f)
		}
	}
}

func TestParseRangeStart(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"42", 42},
		{"42-45", 42},
		{"  7  ", 7},
		{"abc", 0},
		{"", 0},
		{"-5", 0},
	}
	for _, c := range cases {
		if got := parseRangeStart(c.in); got != c.want {
			t.Errorf("parseRangeStart(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
