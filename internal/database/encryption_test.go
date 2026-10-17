package database

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestKeyFromString(t *testing.T) {
	if KeyFromString("") != nil {
		t.Fatal("empty string must yield nil key (no encryption)")
	}
	hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	k := KeyFromString(hexKey)
	if len(k) != 32 {
		t.Fatalf("64-char hex should decode to 32 bytes, got %d", len(k))
	}
	if k[0] != 0x01 || k[31] != 0xef {
		t.Fatalf("hex decode wrong: %x", k)
	}
	if len(KeyFromString("a short passphrase")) != 32 {
		t.Fatal("arbitrary strings must be hashed to 32 bytes")
	}
}

func TestSaveReportEncryptedAtRest(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	path := filepath.Join(t.TempDir(), "audit.db")

	db, err := OpenWithOptions(path, OpenOptions{EncryptionKey: key})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	defer db.Close()

	report := testReport("enc-at-rest", time.Now())
	if err := db.SaveReport(report, legacy); err != nil {
		t.Fatalf("SaveReport: %v", err)
	}

	raw := rawOpen(t, path)
	defer raw.Close()
	var stored string
	if err := raw.QueryRow(`SELECT report_json FROM scan_reports WHERE id = ?`, report.ID).Scan(&stored); err != nil {
		t.Fatalf("raw select: %v", err)
	}
	if !bytes.HasPrefix([]byte(stored), []byte(encryptedBlobPrefix)) {
		t.Fatalf("stored blob is not encrypted: %.40q", stored)
	}
	if bytes.Contains([]byte(stored), []byte("prompt enc-at-rest")) {
		t.Fatal("stored blob leaks plaintext report content")
	}

	got, err := db.GetReport(context.Background(), report.ID)
	if err != nil {
		t.Fatalf("GetReport: %v", err)
	}
	if got.ID != report.ID || got.FinalScore != report.FinalScore || got.Prompt != report.Prompt {
		t.Fatalf("encrypted round trip mismatch: %+v", got)
	}
}

func TestReadEncryptedRequiresKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	key := bytes.Repeat([]byte{0x11}, 32)

	enc, err := OpenWithOptions(path, OpenOptions{EncryptionKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.SaveReport(testReport("secret", time.Now()), legacy); err != nil {
		t.Fatal(err)
	}
	enc.Close() //nolint:errcheck

	plain, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if _, err := plain.GetReport(context.Background(), "secret"); err == nil {
		t.Fatal("expected error reading encrypted report without key")
	}
}

func TestPruneByRetention(t *testing.T) {
	db := openTempDB(t)
	old := time.Now().AddDate(0, 0, -90)
	recent := time.Now().AddDate(0, 0, -1)
	for i, ts := range []time.Time{old, recent} {
		r := testReport([]string{"old", "new"}[i], ts)
		if err := db.SaveReport(r, legacy); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Prune(30, 0); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if _, err := db.GetReport(context.Background(), "old"); err == nil {
		t.Fatal("expected aged row to be pruned")
	}
	if _, err := db.GetReport(context.Background(), "new"); err != nil {
		t.Fatalf("recent row should survive: %v", err)
	}
}

func TestPruneByMaxRecords(t *testing.T) {
	db := openTempDB(t)
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		r := testReport(string(rune('a'+i)), base.Add(time.Duration(i)*time.Minute))
		if err := db.SaveReport(r, legacy); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Prune(0, 2); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	sums, err := db.ListRecent(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(sums) != 2 {
		t.Fatalf("expected 2 rows after cap, got %d", len(sums))
	}
}

func TestOpenWithOptionsAppliesRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	seed, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	stale := testReport("stale", time.Now().AddDate(0, 0, -100))
	if err := seed.SaveReport(stale, legacy); err != nil {
		t.Fatal(err)
	}
	seed.Close() //nolint:errcheck

	reopened, err := OpenWithOptions(path, OpenOptions{RetentionDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.GetReport(context.Background(), "stale"); err == nil {
		t.Fatal("retention should have pruned stale row on open")
	}
}

func rawOpen(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	return db
}
