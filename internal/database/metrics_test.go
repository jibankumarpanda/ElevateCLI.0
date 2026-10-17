package database

import (
	"context"
	"testing"
	"time"

	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

func TestMetricsAggregates(t *testing.T) {
	db := openTempDB(t)
	base := time.Now().Add(-time.Hour)

	r1 := testReport("m1", base)
	r1.Language = "go"
	r1.FinalScore = 90
	r1.Verdict = "APPROVED"
	r2 := testReport("m2", base.Add(time.Minute))
	r2.Language = "go"
	r2.FinalScore = 60
	r2.Verdict = "WARNING"
	r3 := testReport("m3", base.Add(2*time.Minute))
	r3.Language = "python"
	r3.FinalScore = 30
	r3.Verdict = "REJECTED"

	for _, r := range []sec.Report{r1, r2, r3} {
		if err := db.SaveReport(r, legacy); err != nil {
			t.Fatalf("SaveReport: %v", err)
		}
	}

	m, err := db.Metrics(context.Background())
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	if m.TotalScans != 3 {
		t.Errorf("TotalScans = %d want 3", m.TotalScans)
	}
	if m.AverageScore != 60 {
		t.Errorf("AverageScore = %v want 60", m.AverageScore)
	}
	if m.ByVerdict["APPROVED"] != 1 || m.ByVerdict["WARNING"] != 1 || m.ByVerdict["REJECTED"] != 1 {
		t.Errorf("ByVerdict = %+v", m.ByVerdict)
	}
	if m.ByLanguage["go"] != 2 || m.ByLanguage["python"] != 1 {
		t.Errorf("ByLanguage = %+v", m.ByLanguage)
	}
	if m.Oldest.IsZero() || m.Newest.IsZero() || !m.Newest.After(m.Oldest) {
		t.Errorf("time range = %v .. %v", m.Oldest, m.Newest)
	}
}

func TestMetricsEmptyDatabase(t *testing.T) {
	db := openTempDB(t)
	m, err := db.Metrics(context.Background())
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	if m.TotalScans != 0 || m.AverageScore != 0 {
		t.Fatalf("expected empty metrics, got %+v", m)
	}
}
