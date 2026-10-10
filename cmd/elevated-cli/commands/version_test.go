package commands

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// TestVersionCommandReportsBuildInfo verifies the version command surfaces the
// build metadata injected at compile time, so a published binary can be
// identified (and scripted) without guessing.
func TestVersionCommandReportsBuildInfo(t *testing.T) {
	origVersion, origCommit, origDate := buildVersion, buildCommit, buildDate
	t.Cleanup(func() {
		SetBuildInfo(origVersion, origCommit, origDate)
		viper.Set("output.format", "")
	})

	SetBuildInfo("1.2.3", "deadbeef", "2026-10-10T00:00:00Z")

	var buf bytes.Buffer
	cmd := newVersionCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("version command: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"1.2.3", "deadbeef", "2026-10-10T00:00:00Z"} {
		if !strings.Contains(out, want) {
			t.Errorf("version output %q missing %q", out, want)
		}
	}
	if !strings.HasPrefix(out, "elevated-cli 1.2.3 ") {
		t.Errorf("version output has unexpected shape: %q", out)
	}
}

// TestVersionCommandJSON verifies --output json produces parseable JSON so CI
// can assert on the built version.
func TestVersionCommandJSON(t *testing.T) {
	origVersion, origCommit, origDate := buildVersion, buildCommit, buildDate
	t.Cleanup(func() {
		SetBuildInfo(origVersion, origCommit, origDate)
		viper.Set("output.format", "")
	})

	SetBuildInfo("1.2.3", "deadbeef", "2026-10-10T00:00:00Z")
	viper.Set("output.format", "json")

	var buf bytes.Buffer
	cmd := newVersionCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("version command: %v", err)
	}

	var got struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
		Date    string `json:"date"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("version JSON is not parseable: %v (output %q)", err, buf.String())
	}
	if got.Version != "1.2.3" || got.Commit != "deadbeef" || got.Date != "2026-10-10T00:00:00Z" {
		t.Errorf("version JSON = %+v, want injected build info", got)
	}
}

// TestSetBuildInfoKeepsDefaultsForEmptyInput guards against a build that sets
// only some ldflags wiping the others.
func TestSetBuildInfoKeepsDefaultsForEmptyInput(t *testing.T) {
	origVersion, origCommit, origDate := buildVersion, buildCommit, buildDate
	t.Cleanup(func() { SetBuildInfo(origVersion, origCommit, origDate) })

	SetBuildInfo("2.0.0", "", "")
	if buildVersion != "2.0.0" || buildCommit == "" || buildDate == "" {
		t.Errorf("empty values must not wipe defaults: version=%q commit=%q date=%q",
			buildVersion, buildCommit, buildDate)
	}
}
