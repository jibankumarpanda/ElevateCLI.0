package security

import (
	"os"
	"path/filepath"
	"testing"
)

// ─── CVSS ─────────────────────────────────────────────────────────────────────

func TestCVSSBaseScore(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L", 4.4},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"not-a-vector", 0},
		{"", 0},
	}
	for _, c := range cases {
		if got := cvssBaseScore(c.vector); got != c.want {
			t.Errorf("cvssBaseScore(%q) = %.1f, want %.1f", c.vector, got, c.want)
		}
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		cvss float64
		want string
	}{
		{9.9, "CRITICAL"},
		{9.0, "CRITICAL"},
		{7.5, "HIGH"},
		{4.5, "MEDIUM"},
		{1.0, "LOW"},
		{0, "MEDIUM"},
	}
	for _, c := range cases {
		if got := string(severityFromCVSS(c.cvss)); got != c.want {
			t.Errorf("severityFromCVSS(%.1f) = %q, want %q", c.cvss, got, c.want)
		}
	}
}

func TestConfValue(t *testing.T) {
	if confValue("H") != 0.56 || confValue("L") != 0.22 || confValue("N") != 0 {
		t.Error("unexpected conf values")
	}
	if confValue("X") != -1 {
		t.Error("unknown metric should return -1")
	}
}

// ─── Import extraction ────────────────────────────────────────────────────────

func TestExtractImportsGo(t *testing.T) {
	code := `package main
import (
	"os"
	"net/http"
	alib "example.com/alias"
)
func main() {}`
	got := extractImports(code, "go")
	want := map[string]bool{"os": true, "net/http": true, "example.com/alias": true}
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
	for _, imp := range got {
		if !want[imp] {
			t.Errorf("unexpected import %q", imp)
		}
	}
}

func TestExtractImportsPython(t *testing.T) {
	got := extractImports("import os\nfrom urllib import request\n", "python")
	if len(got) != 2 || got[0] != "os" || got[1] != "urllib" {
		t.Errorf("python imports = %v", got)
	}
}

func TestExtractImportsJS(t *testing.T) {
	got := extractImports("const fs = require('fs');\nimport x from 'y';\n", "javascript")
	if len(got) != 2 || got[0] != "fs" || got[1] != "y" {
		t.Errorf("js imports = %v", got)
	}
}

func TestExtractImportsUnsupported(t *testing.T) {
	if got := extractImports("puts 'x'", "ruby"); got != nil {
		t.Errorf("unsupported language should return nil, got %v", got)
	}
}

func TestGoImportsInvalidCode(t *testing.T) {
	if got := goImports("this is not go {{{"); got != nil {
		t.Errorf("invalid code should yield nil, got %v", got)
	}
}

func TestMatchRepeated(t *testing.T) {
	got := matchRepeated("a=1\nb=2\nc=3\n", `(?m)^(\w+)=`)
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Errorf("matchRepeated = %v", got)
	}
}

// ─── Lockfile discovery ───────────────────────────────────────────────────────

func TestFindLockfiles(t *testing.T) {
	dir := t.TempDir()
	write := func(rel string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod")
	write("go.sum")
	write("sub/package-lock.json")
	write("vendor/go.mod")
	write(".hidden/go.sum")
	write("readme.txt")

	lfs := findLockfiles(dir)
	found := map[string]bool{}
	for _, lf := range lfs {
		found[filepath.Base(lf.Path)] = true
	}
	for _, want := range []string{"go.mod", "go.sum", "package-lock.json"} {
		if !found[want] {
			t.Errorf("missing %q in %v", want, lfs)
		}
	}
	for _, banned := range []string{"readme.txt"} {
		if found[banned] {
			t.Errorf("should not find %q", banned)
		}
	}
	// Hidden dirs and vendor must be skipped.
	for _, lf := range lfs {
		rel, _ := filepath.Rel(dir, lf.Path)
		if containsPath(rel, "vendor") || containsPath(rel, ".hidden") {
			t.Errorf("walked into ignored dir: %q", rel)
		}
	}
}

func TestFilterRedundant(t *testing.T) {
	dir := t.TempDir()
	in := []lockfile{
		{Path: filepath.Join(dir, "go.mod"), IsGo: true},
		{Path: filepath.Join(dir, "go.sum"), IsGo: true},
		{Path: filepath.Join(dir, "no-mod", "go.sum"), IsGo: true},
		{Path: filepath.Join(dir, "package-lock.json"), IsGo: false},
	}
	out := filterRedundant(in)
	var names []string
	for _, lf := range out {
		rel, _ := filepath.Rel(dir, lf.Path)
		names = append(names, rel)
	}
	want := []string{"go.mod", filepath.Join("no-mod", "go.sum"), "package-lock.json"}
	if len(names) != len(want) {
		t.Fatalf("filterRedundant = %v, want %v", names, want)
	}
	for i, w := range want {
		if names[i] != w {
			t.Errorf("filterRedundant = %v, want %v", names, want)
			break
		}
	}
	for _, n := range names {
		if n == "go.sum" {
			t.Errorf("go.sum beside go.mod should be dropped: %v", names)
		}
	}
}

func containsPath(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ─── govulncheck / osv-scanner parsers ────────────────────────────────────────

func TestParseGovulncheckInline(t *testing.T) {
	out := []byte(`{"config":{"go_version":"1.25.0"},"scanner":{"name":"govulncheck","version":"1.1.4"}}
{"finding":{"osv":"GO-2024-1234","fixed_version":"1.22.1","trace":[{"module":"example.com/dep","version":"1.22.0"}]}}
{"osv":{"id":"GO-2024-1234","aliases":["CVE-2024-9999"],"summary":"vuln summary"}}
`)
	vulns, err := parseGovulncheck(out)
	if err != nil {
		t.Fatalf("parseGovulncheck: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("got %d vulns, want 1", len(vulns))
	}
	v := vulns[0]
	if v.ID != "CVE-2024-9999" {
		t.Errorf("ID = %q, want CVE alias", v.ID)
	}
	if v.Package != "example.com/dep" || v.Version != "1.22.0" {
		t.Errorf("pkg = %s@%s", v.Package, v.Version)
	}
	if v.FixedVersion != "1.22.1" {
		t.Errorf("fixed = %q", v.FixedVersion)
	}
}

func TestParseGovulncheckEmpty(t *testing.T) {
	out := []byte(`{"config":{"go_version":"1.25.0"}}`)
	vulns, err := parseGovulncheck(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 0 {
		t.Errorf("no findings should parse to zero vulns, got %v", vulns)
	}
}

func TestParseOSVScannerInline(t *testing.T) {
	out := []byte(`{"results":[{"packages":[{"package":{"name":"lodash","version":"4.17.20","ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-xxxx","aliases":["CVE-2021-23337"],"summary":"prototype pollution","details":"d","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"affected":[{"ranges":[{"events":[{"introduced":"4.17.20","fixed":"4.17.21"}]}]}]}]}]}]}`)
	vulns, err := parseOSVScanner(out)
	if err != nil {
		t.Fatalf("parseOSVScanner: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("got %d vulns", len(vulns))
	}
	v := vulns[0]
	if v.ID != "CVE-2021-23337" || v.Package != "lodash" || v.Version != "4.17.20" {
		t.Errorf("vuln = %+v", v)
	}
	if v.FixedVersion != "4.17.21" {
		t.Errorf("fixed = %q", v.FixedVersion)
	}
	if v.Source != "osv-scanner" || v.Severity != "CRITICAL" {
		t.Errorf("source/severity = %s/%s", v.Source, v.Severity)
	}
}

func TestParseOSVScannerMalformed(t *testing.T) {
	if _, err := parseOSVScanner([]byte("{not json")); err == nil {
		t.Error("malformed osv output should error")
	}
}

func TestParseGovulncheckMalformed(t *testing.T) {
	// Malformed JSON lines are tolerated (skipped) by the streaming decoder.
	vulns, err := parseGovulncheck([]byte("{not json"))
	if err != nil {
		t.Fatalf("parseGovulncheck malformed: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected zero vulns from malformed input, got %v", vulns)
	}
}
