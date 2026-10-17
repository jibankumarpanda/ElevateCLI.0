package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/database"
)

func sample() *database.MetricsSummary {
	return &database.MetricsSummary{
		TotalScans:   3,
		AverageScore: 72.5,
		ByVerdict:    map[string]int{"APPROVED": 2, "REJECTED": 1},
		ByLanguage:   map[string]int{"go": 2, "python": 1},
		Oldest:       time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		Newest:       time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC),
	}
}

func TestRenderPrometheus(t *testing.T) {
	out, err := Render(sample(), "prometheus")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"elevated_cli_scans_total 3",
		"elevated_cli_score_average 72.50",
		`elevated_cli_verdict_total{verdict="APPROVED"} 2`,
		`elevated_cli_verdict_total{verdict="REJECTED"} 1`,
		`elevated_cli_language_total{language="go"} 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("prometheus output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderJSON(t *testing.T) {
	out, err := Render(sample(), "json")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"total_scans": 3`, `"average_score": 72.5`, `"newest": "2026-08-15T00:00:00Z"`} {
		if !strings.Contains(out, want) {
			t.Errorf("json output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderDefaultIsPrometheus(t *testing.T) {
	out, err := Render(sample(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "# TYPE elevated_cli_scans_total counter") {
		t.Errorf("default format should be prometheus:\n%s", out)
	}
}

func TestRenderUnknownFormat(t *testing.T) {
	if _, err := Render(sample(), "csv"); err == nil {
		t.Fatal("expected error for unknown format")
	}
}
