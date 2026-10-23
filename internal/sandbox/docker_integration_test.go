//go:build integration

package sandbox

import (
	"context"
	"strings"
	"testing"
)

// These tests exercise a real Docker daemon and are opt-in:
//
//	make test-docker
//
// They pull the default per-language images on first run.
func TestDockerIntegration(t *testing.T) {
	cases := []struct {
		name, lang, code, want string
	}{
		{"python", "python", "print('hello python')", "hello python"},
		{"javascript", "javascript", "console.log('hello js')", "hello js"},
		{"go", "go", "package main\nimport \"fmt\"\nfunc main(){fmt.Println(\"hello go\")}", "hello go"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := NewDockerRunner(120, 512, true, ResourceLimits{MaxOutputKB: 64}, "").Run(context.Background(), tc.code, tc.lang)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if !res.Success || !strings.Contains(res.Stdout, tc.want) {
				t.Fatalf("expected %q in stdout, got %+v", tc.want, res)
			}
		})
	}
}

func TestDockerIntegrationNetworkBlocked(t *testing.T) {
	code := "import urllib.request\nurllib.request.urlopen('https://example.com', timeout=3)\nprint('network reached')"
	res, err := NewDockerRunner(60, 128, true, ResourceLimits{MaxOutputKB: 64}, "python:3.12-alpine").Run(context.Background(), code, "python")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Success {
		t.Fatalf("network should be blocked, got success: %+v", res)
	}
}

func TestDockerIntegrationReadOnlyRoot(t *testing.T) {
	code := "open('/etc/should-fail', 'w').write('x')\nprint('wrote rootfs')"
	res, err := NewDockerRunner(60, 128, true, ResourceLimits{MaxOutputKB: 64}, "python:3.12-alpine").Run(context.Background(), code, "python")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Success {
		t.Fatalf("root filesystem should be read-only, got success: %+v", res)
	}
}
