package sbom

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFromGoMod(t *testing.T) {
	content := `module example.com/app

go 1.25

require github.com/spf13/cobra v1.8.0

require (
	github.com/spf13/viper v1.18.2
	go.uber.org/zap v1.27.0 // indirect
)

replace example.com/old => example.com/new v1.0.0
`
	comps := FromGoMod(content)
	if len(comps) != 3 {
		t.Fatalf("expected 3 components, got %d: %+v", len(comps), comps)
	}
	sorted := Sorted(comps)
	if sorted[0].Name != "github.com/spf13/cobra" || sorted[0].Version != "v1.8.0" {
		t.Errorf("unexpected first component: %+v", sorted[0])
	}
	for _, c := range comps {
		if c.Name == "example.com/old" || c.Name == "example.com/new" {
			t.Errorf("replace directive leaked into components: %+v", c)
		}
	}
}

func TestSortedDeduplicatesAndOrders(t *testing.T) {
	in := []Component{
		{Name: "b", Version: "2"},
		{Name: "a", Version: "1"},
		{Name: "b", Version: "2"},
		{Name: "a", Version: "1"},
		{Name: "a", Version: "0"},
	}
	out := Sorted(in)
	if len(out) != 3 {
		t.Fatalf("expected 3 unique components, got %d", len(out))
	}
	if out[0].Name != "a" || out[0].Version != "0" || out[1].Name != "a" || out[2].Name != "b" {
		t.Fatalf("unexpected order: %+v", out)
	}
}

func TestGenerateCycloneDX(t *testing.T) {
	comps := []Component{{Name: "github.com/x/y", Version: "v1.2.3", Type: "library"}}
	doc, err := Generate("cyclonedx", "0.1.1", comps, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v", parsed["bomFormat"])
	}
	body := string(doc)
	if !strings.Contains(body, "pkg:golang/github.com/x/y@v1.2.3") {
		t.Errorf("missing purl:\n%s", body)
	}
	if strings.Contains(body, "timestamp") {
		t.Errorf("zero time should omit timestamp for reproducibility:\n%s", body)
	}
}

func TestGenerateSPDX(t *testing.T) {
	doc, err := Generate("spdx", "0.1.1", []Component{{Name: "m", Version: "v1"}}, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	body := string(doc)
	for _, want := range []string{"SPDX-2.3", "SPDXRef-DOCUMENT", "2026-01-02T00:00:00Z"} {
		if !strings.Contains(body, want) {
			t.Errorf("SPDX output missing %q:\n%s", want, body)
		}
	}
}

func TestGenerateUnknownFormat(t *testing.T) {
	if _, err := Generate("xml", "0.1.1", nil, time.Time{}); err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	comps := []Component{{Name: "b", Version: "1"}, {Name: "a", Version: "2"}}
	a, _ := Generate("cyclonedx", "1", comps, time.Time{})
	b, _ := Generate("cyclonedx", "1", comps, time.Time{})
	if string(a) != string(b) {
		t.Fatal("output should be deterministic")
	}
}
