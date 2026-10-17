package database

import (
	"context"
	"time"
)

// MetricsSummary is an aggregate view of the local audit database, used by the
// `metrics` command. Nothing here leaves the machine.
type MetricsSummary struct {
	TotalScans   int
	AverageScore float64
	ByVerdict    map[string]int
	ByLanguage   map[string]int
	Oldest       time.Time
	Newest       time.Time
}

// Metrics aggregates the audit database into a single summary.
func (s *SQLiteDB) Metrics(ctx context.Context) (*MetricsSummary, error) {
	m := &MetricsSummary{
		ByVerdict:  map[string]int{},
		ByLanguage: map[string]int{},
	}

	var avg *float64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), AVG(final_score) FROM scan_reports`).Scan(&m.TotalScans, &avg); err != nil {
		return nil, err
	}
	if avg != nil {
		m.AverageScore = *avg
	}
	if m.TotalScans == 0 {
		return m, nil
	}

	verdicts, err := s.db.QueryContext(ctx,
		`SELECT verdict, COUNT(*) FROM scan_reports GROUP BY verdict`)
	if err != nil {
		return nil, err
	}
	defer verdicts.Close()
	for verdicts.Next() {
		var v string
		var n int
		if err := verdicts.Scan(&v, &n); err != nil {
			return nil, err
		}
		m.ByVerdict[v] = n
	}

	langs, err := s.db.QueryContext(ctx,
		`SELECT language, COUNT(*) FROM scan_reports GROUP BY language ORDER BY COUNT(*) DESC`)
	if err != nil {
		return nil, err
	}
	defer langs.Close()
	for langs.Next() {
		var lang string
		var n int
		if err := langs.Scan(&lang, &n); err != nil {
			return nil, err
		}
		if lang == "" {
			lang = "unknown"
		}
		m.ByLanguage[lang] = n
	}

	var oldest, newest *string
	if err := s.db.QueryRowContext(ctx,
		`SELECT MIN(timestamp), MAX(timestamp) FROM scan_reports`).Scan(&oldest, &newest); err != nil {
		return nil, err
	}
	if oldest != nil {
		m.Oldest, _ = time.Parse(time.RFC3339, *oldest)
	}
	if newest != nil {
		m.Newest, _ = time.Parse(time.RFC3339, *newest)
	}
	return m, nil
}
