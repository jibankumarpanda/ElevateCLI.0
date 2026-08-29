// Package database persists scan reports to a local SQLite database for the
// `history` command and long-term auditability.
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jibankumarpanda/ElevateCLI.0/internal/util"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
	_ "modernc.org/sqlite"
)

// SQLiteDB is the SQLite-backed audit store.
type SQLiteDB struct {
	db *sql.DB
}

// Open opens (creating if necessary) the audit database at path.
func Open(path string) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	sdb := &SQLiteDB{db: db}
	if err := sdb.initSchema(); err != nil {
		return nil, err
	}
	return sdb, nil
}

// Close closes the underlying database handle.
func (s *SQLiteDB) Close() error {
	return s.db.Close()
}

func (s *SQLiteDB) initSchema() error {
	query := `
	CREATE TABLE IF NOT EXISTS scan_reports (
		id          TEXT PRIMARY KEY,
		timestamp   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		prompt      TEXT,
		language    TEXT,
		provider    TEXT,
		model       TEXT,
		final_score INTEGER,
		verdict     TEXT,
		report_json TEXT
	);`
	_, err := s.db.Exec(query)
	return err
}

// SaveOptions controls what the audit trail retains. Prompts and generated
// source may contain sensitive data, so callers decide whether to keep them
// and whether to redact detected secrets before anything is written to disk.
type SaveOptions struct {
	StorePrompts       bool
	StoreGeneratedCode bool
	RedactSecrets      bool
}

// DefaultSaveOptions mirrors the documented defaults: keep prompts and code
// (as before) but redact secrets before storage.
func DefaultSaveOptions() SaveOptions {
	return SaveOptions{StorePrompts: true, StoreGeneratedCode: true, RedactSecrets: true}
}

// SaveReport persists a sanitised copy of the report according to opts.
// Secrets are redacted and prompts/code may be dropped before the row is
// written, so the on-disk copy never contains raw credentials the caller
// asked to hide.
func (s *SQLiteDB) SaveReport(report sec.Report, opts SaveOptions) error {
	report = sanitizeReport(report, opts)
	blob, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshalling report: %w", err)
	}
	query := `INSERT INTO scan_reports
		(id, timestamp, prompt, language, provider, model, final_score, verdict, report_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			timestamp=excluded.timestamp, prompt=excluded.prompt, language=excluded.language,
			provider=excluded.provider, model=excluded.model, final_score=excluded.final_score,
			verdict=excluded.verdict, report_json=excluded.report_json`
	_, err = s.db.Exec(query,
		report.ID,
		report.Timestamp.UTC().Format(time.RFC3339),
		report.Prompt,
		report.Language,
		report.AIProvider,
		report.AIModel,
		report.FinalScore,
		string(report.Verdict),
		string(blob),
	)
	return err
}

// sanitizeReport returns a copy of r with secrets redacted and the prompt /
// generated code dropped when retention is disabled. The original report is
// never modified.
func sanitizeReport(r sec.Report, o SaveOptions) sec.Report {
	if o.RedactSecrets {
		r.Prompt = utils.RedactSecrets(r.Prompt)
		r.GeneratedCode = utils.RedactSecrets(r.GeneratedCode)
		for i := range r.Findings {
			r.Findings[i].Code = utils.RedactSecrets(r.Findings[i].Code)
			r.Findings[i].Title = utils.RedactSecrets(r.Findings[i].Title)
			r.Findings[i].Description = utils.RedactSecrets(r.Findings[i].Description)
		}
		for i := range r.Violations {
			r.Violations[i].Value = utils.RedactSecrets(r.Violations[i].Value)
			r.Violations[i].Description = utils.RedactSecrets(r.Violations[i].Description)
		}
		r.Sandbox.Stdout = utils.RedactSecrets(r.Sandbox.Stdout)
		r.Sandbox.Stderr = utils.RedactSecrets(r.Sandbox.Stderr)
	}
	if !o.StorePrompts {
		r.Prompt = ""
	}
	if !o.StoreGeneratedCode {
		r.GeneratedCode = ""
	}
	return r
}

// GetReport loads a single report by scan ID.
func (s *SQLiteDB) GetReport(ctx context.Context, id string) (*sec.Report, error) {
	var blob string
	err := s.db.QueryRowContext(ctx,
		`SELECT report_json FROM scan_reports WHERE id = ?`, id).Scan(&blob)
	if err != nil {
		return nil, fmt.Errorf("scan %q: %w", id, err)
	}
	var report sec.Report
	if err := json.Unmarshal([]byte(blob), &report); err != nil {
		return nil, fmt.Errorf("decoding report %q: %w", id, err)
	}
	return &report, nil
}

// ScanSummary is a lightweight row used for history listings.
type ScanSummary struct {
	ID         string
	Timestamp  time.Time
	Prompt     string
	Language   string
	FinalScore int
	Verdict    sec.Verdict
}

// ListRecent returns the most recent n scans, newest first.
func (s *SQLiteDB) ListRecent(ctx context.Context, n int) ([]ScanSummary, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, timestamp, prompt, language, final_score, verdict
		 FROM scan_reports ORDER BY timestamp DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSummaries(rows)
}

// ListByDate returns all scans from the given day (YYYY-MM-DD), newest first.
func (s *SQLiteDB) ListByDate(ctx context.Context, date string) ([]ScanSummary, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, timestamp, prompt, language, final_score, verdict
		 FROM scan_reports WHERE date(timestamp) = ? ORDER BY timestamp DESC`, date)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSummaries(rows)
}

func scanSummaries(rows *sql.Rows) ([]ScanSummary, error) {
	var out []ScanSummary
	for rows.Next() {
		var (
			s       ScanSummary
			ts      string
			verdict string
		)
		if err := rows.Scan(&s.ID, &ts, &s.Prompt, &s.Language, &s.FinalScore, &verdict); err != nil {
			return nil, err
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			t = time.Time{}
		}
		s.Timestamp = t
		s.Verdict = sec.Verdict(verdict)
		out = append(out, s)
	}
	return out, rows.Err()
}
