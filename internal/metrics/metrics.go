// Package metrics renders aggregate audit statistics in a machine-readable
// form (`json`) or a Prometheus text exposition format suitable for scraping.
// No data leaves the host; rendering is local and on demand.
package metrics

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/database"
)

// Render formats a MetricsSummary as either "prometheus" or "json".
func Render(m *database.MetricsSummary, format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "prometheus", "prom":
		return prometheus(m), nil
	case "json":
		return renderJSON(m)
	default:
		return "", fmt.Errorf("unknown metrics format %q (want prometheus or json)", format)
	}
}

func renderJSON(m *database.MetricsSummary) (string, error) {
	doc := map[string]any{
		"total_scans":   m.TotalScans,
		"average_score": m.AverageScore,
		"by_verdict":    m.ByVerdict,
		"by_language":   m.ByLanguage,
	}
	if !m.Oldest.IsZero() {
		doc["oldest"] = m.Oldest.UTC().Format("2006-01-02T15:04:05Z")
	}
	if !m.Newest.IsZero() {
		doc["newest"] = m.Newest.UTC().Format("2006-01-02T15:04:05Z")
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}

func prometheus(m *database.MetricsSummary) string {
	var b strings.Builder

	b.WriteString("# HELP elevated_cli_scans_total Total scans recorded in the local audit database.\n")
	b.WriteString("# TYPE elevated_cli_scans_total counter\n")
	fmt.Fprintf(&b, "elevated_cli_scans_total %d\n", m.TotalScans)

	b.WriteString("# HELP elevated_cli_score_average Mean final security score across scans.\n")
	b.WriteString("# TYPE elevated_cli_score_average gauge\n")
	fmt.Fprintf(&b, "elevated_cli_score_average %.2f\n", m.AverageScore)

	b.WriteString("# HELP elevated_cli_verdict_total Scans by final verdict.\n")
	b.WriteString("# TYPE elevated_cli_verdict_total counter\n")
	for _, v := range sortedKeys(m.ByVerdict) {
		fmt.Fprintf(&b, "elevated_cli_verdict_total{verdict=%q} %d\n", v, m.ByVerdict[v])
	}

	b.WriteString("# HELP elevated_cli_language_total Scans by detected language.\n")
	b.WriteString("# TYPE elevated_cli_language_total counter\n")
	for _, l := range sortedKeys(m.ByLanguage) {
		fmt.Fprintf(&b, "elevated_cli_language_total{language=%q} %d\n", l, m.ByLanguage[l])
	}

	return b.String()
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
