package security

import (
	"os"
	"testing"
)

func TestParseGovulncheckCount(t *testing.T) {
	out, err := os.ReadFile("/tmp/gvn.json")
	if err != nil {
		t.Skip("no fixture")
	}
	vulns, err := parseGovulncheck(out)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("parsed %d vulns", len(vulns))
}
