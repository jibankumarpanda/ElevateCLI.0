package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
)

func testReport(id string, ts time.Time) sec.Report {
	return sec.Report{
		ID:         id,
		Timestamp:  ts,
		Prompt:     "prompt " + id,
		Language:   "go",
		FinalScore: 85,
		Verdict:    sec.VerdictApproved,
		AIProvider: "openai",
		AIModel:    "gpt-4o",
		Findings: []sec.Finding{
			{ID: "f1", RuleID: "G101", Severity: sec.SeverityLow, Title: "hardcoded cred"},
		},
	}
}

func openTempDB(t *testing.T) *SQLiteDB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpenAndSaveReport(t *testing.T) {
	db := openTempDB(t)
	report := testReport("scan-1", time.Now())
	if err := db.SaveReport(report); err != nil {
		t.Fatalf("SaveReport: %v", err)
	}
	got, err := db.GetReport(context.Background(), "scan-1")
	if err != nil {
		t.Fatalf("GetReport: %v", err)
	}
	if got.ID != "scan-1" || got.FinalScore != 85 || got.Verdict != sec.VerdictApproved {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if len(got.Findings) != 1 || got.Findings[0].RuleID != "G101" {
		t.Errorf("findings not preserved: %+v", got.Findings)
	}
}

func TestGetReportMissing(t *testing.T) {
	db := openTempDB(t)
	if _, err := db.GetReport(context.Background(), "nope"); err == nil {
		t.Error("expected error for missing scan ID")
	}
}

func TestSaveReportUpserts(t *testing.T) {
	db := openTempDB(t)
	now := time.Now()
	r1 := testReport("scan-up", now)
	r1.FinalScore = 40
	r1.Verdict = sec.VerdictRejected
	if err := db.SaveReport(r1); err != nil {
		t.Fatal(err)
	}
	r2 := testReport("scan-up", now.Add(time.Hour))
	r2.FinalScore = 99
	r2.Verdict = sec.VerdictApproved
	if err := db.SaveReport(r2); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetReport(context.Background(), "scan-up")
	if err != nil {
		t.Fatal(err)
	}
	if got.FinalScore != 99 || got.Verdict != sec.VerdictApproved {
		t.Errorf("upsert did not overwrite: score=%d verdict=%s", got.FinalScore, got.Verdict)
	}
}

func TestListRecentOrder(t *testing.T) {
	db := openTempDB(t)
	base := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 5; i++ {
		r := testReport("recent-"+string(rune('a'+i)), base.Add(time.Duration(i)*time.Minute))
		if err := db.SaveReport(r); err != nil {
			t.Fatal(err)
		}
	}
	sums, err := db.ListRecent(context.Background(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(sums) != 3 {
		t.Fatalf("ListRecent(3) = %d rows", len(sums))
	}
	if sums[0].ID != "recent-e" {
		t.Errorf("newest first expected, got %q", sums[0].ID)
	}
}

func TestListByDate(t *testing.T) {
	db := openTempDB(t)
	day := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	otherDay := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	if err := db.SaveReport(testReport("on-date", day)); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveReport(testReport("off-date", otherDay)); err != nil {
		t.Fatal(err)
	}
	sums, err := db.ListByDate(context.Background(), "2026-08-15")
	if err != nil {
		t.Fatal(err)
	}
	if len(sums) != 1 || sums[0].ID != "on-date" {
		t.Errorf("ListByDate = %+v", sums)
	}
}

func TestListRecentEmpty(t *testing.T) {
	db := openTempDB(t)
	sums, err := db.ListRecent(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(sums) != 0 {
		t.Errorf("expected no rows, got %d", len(sums))
	}
}
