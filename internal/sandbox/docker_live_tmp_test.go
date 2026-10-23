package sandbox

import (
	"context"
	"strings"
	"testing"
)

func TestDockerLiveTmp(t *testing.T) {
	cases := []struct {
		name, lang, code, want string
	}{
		{"python", "python", "print('hello python')", "hello python"},
		{"javascript", "javascript", "console.log('hello js')", "hello js"},
		{"go", "go", "package main\nimport \"fmt\"\nfunc main(){fmt.Println(\"hello go\")}", "hello go"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDockerRunner(120, 512, true, ResourceLimits{MaxOutputKB: 64}, "")
			res, err := d.Run(context.Background(), tc.code, tc.lang)
			t.Logf("result=%+v err=%v", res, err)
			if err != nil {
				t.Fatalf("docker run failed: %v", err)
			}
			if !res.Success || !strings.Contains(res.Stdout, tc.want) {
				t.Fatalf("unexpected result: %+v", res)
			}
		})
	}
}

func TestDockerLiveNetworkBlockedTmp(t *testing.T) {
	d := NewDockerRunner(60, 128, true, ResourceLimits{MaxOutputKB: 64}, "python:3.12-alpine")
	code := "import urllib.request\nurllib.request.urlopen('https://example.com', timeout=3)\nprint('network reached')"
	res, err := d.Run(context.Background(), code, "python")
	t.Logf("result=%+v err=%v", res, err)
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	if res.Success {
		t.Fatalf("network should be blocked, got success: %+v", res)
	}
}

func TestDockerLiveReadOnlyRootTmp(t *testing.T) {
	d := NewDockerRunner(60, 128, true, ResourceLimits{MaxOutputKB: 64}, "python:3.12-alpine")
	code := "open('/etc/should-fail', 'w').write('x')\nprint('wrote rootfs')"
	res, err := d.Run(context.Background(), code, "python")
	t.Logf("result=%+v err=%v", res, err)
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	if res.Success {
		t.Fatalf("root filesystem should be read-only, got success: %+v", res)
	}
}
