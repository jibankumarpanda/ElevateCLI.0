package security

import (
	"context"
	"strings"
	"testing"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/config"
)

func TestRunPluginsMergesFindings(t *testing.T) {
	p := config.PluginAnalyzer{
		Name:    "demo",
		Command: "sh",
		Args:    []string{"-c", `printf '%s' '[{"id":"p1","rule_id":"CUSTOM","title":"t","severity":"HIGH"}]'`},
	}
	got, err := runPlugins(context.Background(), []config.PluginAnalyzer{p}, "code", "python")
	if err != nil {
		t.Fatalf("runPlugins: %v", err)
	}
	if len(got) != 1 || got[0].ID != "p1" {
		t.Fatalf("unexpected findings: %+v", got)
	}
	if got[0].Source != "plugin:demo" {
		t.Errorf("source = %q", got[0].Source)
	}
}

func TestRunPluginsFiltersByLanguage(t *testing.T) {
	p := config.PluginAnalyzer{
		Name:      "go-only",
		Command:   "sh",
		Args:      []string{"-c", `printf '[]'`},
		Languages: []string{"go"},
	}
	got, err := runPlugins(context.Background(), []config.PluginAnalyzer{p}, "code", "python")
	if err != nil || len(got) != 0 {
		t.Fatalf("plugin should be skipped for python: got=%v err=%v", got, err)
	}
}

func TestRunPluginsFailureIsError(t *testing.T) {
	p := config.PluginAnalyzer{Name: "boom", Command: "sh", Args: []string{"-c", "echo bad 1>&2; exit 2"}}
	if _, err := runPlugins(context.Background(), []config.PluginAnalyzer{p}, "code", "go"); err == nil {
		t.Fatal("expected error from failing plugin")
	}
}

func TestRunPluginsInvalidJSONIsError(t *testing.T) {
	p := config.PluginAnalyzer{Name: "bad", Command: "sh", Args: []string{"-c", `printf 'not json'`}}
	if _, err := runPlugins(context.Background(), []config.PluginAnalyzer{p}, "code", "go"); err == nil {
		t.Fatal("expected error for invalid plugin JSON")
	}
}

func TestRunPluginsNoPlugins(t *testing.T) {
	got, err := runPlugins(context.Background(), nil, "code", "go")
	if err != nil || got != nil {
		t.Fatalf("no plugins should be a no-op: got=%v err=%v", got, err)
	}
}

func TestRunPluginsReceivesCodeOnStdin(t *testing.T) {
	p := config.PluginAnalyzer{
		Name:    "echo",
		Command: "sh",
		Args:    []string{"-c", `read -r line; printf '[{"id":"%s","rule_id":"R","title":"t","severity":"LOW"}]' "$line"`},
	}
	got, err := runPlugins(context.Background(), []config.PluginAnalyzer{p}, "hello", "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "hello" {
		t.Fatalf("plugin did not receive stdin: %+v", got)
	}
}

func TestPluginMatchesLanguage(t *testing.T) {
	if !pluginMatchesLanguage(config.PluginAnalyzer{}, "anything") {
		t.Fatal("no language filter should match all")
	}
	if !pluginMatchesLanguage(config.PluginAnalyzer{Languages: []string{"Go"}}, "go") {
		t.Fatal("language matching should be case-insensitive")
	}
	if pluginMatchesLanguage(config.PluginAnalyzer{Languages: []string{"go"}}, "python") {
		t.Fatal("non-matching language should be filtered")
	}
}

var _ = strings.TrimSpace
