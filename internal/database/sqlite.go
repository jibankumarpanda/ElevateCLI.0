// Package database persists scan reports to a local SQLite database for the
// `history` command and long-term auditability.
package database

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"crypto/sha256"

	util "github.com/jibankumarpanda/ElevateCLI.0/internal/utils"
	sec "github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
	_ "modernc.org/sqlite"
)

// SQLiteDB is the SQLite-backed audit store.
type SQLiteDB struct {
	db *sql.DB
	// encKey, when non-nil, is the 32-byte AES-256-GCM key used to encrypt the
	// stored report blob at rest.
	encKey []byte
}

// OpenOptions controls retention pruning and at-rest encryption applied when
// the audit database is opened.
type OpenOptions struct {
	// RetentionDays prunes rows older than this many days. 0 keeps forever.
	RetentionDays int
	// MaxRecords caps retained rows; the oldest are pruned first. 0 = unlimited.
	MaxRecords int
	// EncryptionKey, when non-nil, must be 32 bytes and encrypts the stored
	// report blob with AES-256-GCM.
	EncryptionKey []byte
}

// Open opens (creating if necessary) the audit database at path.
func Open(path string) (*SQLiteDB, error) {
	return OpenWithOptions(path, OpenOptions{})
}

// OpenWithOptions opens the audit database, applies retention pruning, and
// configures at-rest encryption when a key is supplied. The schema is created
// before pruning so a fresh database opens cleanly.
func OpenWithOptions(path string, opts OpenOptions) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	sdb := &SQLiteDB{db: db, encKey: opts.EncryptionKey}
	if err := sdb.initSchema(); err != nil {
		return nil, err
	}
	if err := sdb.Prune(opts.RetentionDays, opts.MaxRecords); err != nil {
		return nil, fmt.Errorf("pruning audit database: %w", err)
	}
	return sdb, nil
}

// Prune enforces the audit retention policy: rows older than retentionDays are
// deleted, and the table is trimmed to at most maxRecords newest rows. Both
// values of 0 disable the corresponding rule.
func (s *SQLiteDB) Prune(retentionDays, maxRecords int) error {
	if retentionDays > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format(time.RFC3339)
		if _, err := s.db.Exec(
			`DELETE FROM scan_reports WHERE timestamp < ?`, cutoff); err != nil {
			return err
		}
	}
	if maxRecords > 0 {
		if _, err := s.db.Exec(
			`DELETE FROM scan_reports WHERE id NOT IN (
				SELECT id FROM scan_reports ORDER BY timestamp DESC LIMIT ?
			)`, maxRecords); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the underlying database handle.
func (s *SQLiteDB) Close() error {
	return s.db.Close()
}

// KeyFromString derives a 32-byte AES-256 key from raw material. A 64-character
// hex string is decoded directly (so operators can use `openssl rand -hex 32`);
// any other non-empty value is hashed with SHA-256. An empty string yields nil,
// disabling encryption.
func KeyFromString(raw string) []byte {
	if raw == "" {
		return nil
	}
	if len(raw) == 64 {
		if b, err := hex.DecodeString(raw); err == nil {
			return b
		}
	}
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
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

func (s *SQLiteDB) SaveReport(report sec.Report, opts SaveOptions) error {
	report = sanitizeReport(report, opts)
	blob, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshalling report: %w", err)
	}
	stored, err := s.encodeBlob(blob)
	if err != nil {
		return err
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
		string(stored),
	)
	return err
}

// encryptedBlobPrefix marks a report blob that was encrypted at rest. Storing
// the marker alongside base64 ciphertext lets a database containing a mix of
// plaintext (written before encryption was enabled) and ciphertext rows be read
// back safely.
const encryptedBlobPrefix = "enc:v1:"

// encodeBlob encrypts the JSON report when a key is configured, returning the
// marker-prefixed base64 ciphertext. Without a key it returns the plaintext.
func (s *SQLiteDB) encodeBlob(plain []byte) ([]byte, error) {
	if len(s.encKey) == 0 {
		return plain, nil
	}
	ct, err := util.EncryptAESGCM(s.encKey, plain)
	if err != nil {
		return nil, fmt.Errorf("encrypting report: %w", err)
	}
	encoded := make([]byte, 0, len(encryptedBlobPrefix)+base64.StdEncoding.EncodedLen(len(ct)))
	encoded = append(encoded, encryptedBlobPrefix...)
	encoded = base64.StdEncoding.AppendEncode(encoded, ct)
	return encoded, nil
}

// decodeBlob reverses encodeBlob. A blob without the encryption marker is
// treated as legacy plaintext JSON.
func (s *SQLiteDB) decodeBlob(stored []byte) ([]byte, error) {
	if !bytes.HasPrefix(stored, []byte(encryptedBlobPrefix)) {
		return stored, nil
	}
	if len(s.encKey) == 0 {
		return nil, errors.New("report is encrypted but no audit encryption key is configured")
	}
	raw := stored[len(encryptedBlobPrefix):]
	ct := make([]byte, base64.StdEncoding.DecodedLen(len(raw)))
	n, err := base64.StdEncoding.Decode(ct, raw)
	if err != nil {
		return nil, fmt.Errorf("decoding encrypted report: %w", err)
	}
	plain, err := util.DecryptAESGCM(s.encKey, ct[:n])
	if err != nil {
		return nil, fmt.Errorf("decrypting report: %w", err)
	}
	return plain, nil
}

// sanitizeReport returns a copy of r with secrets redacted and the prompt /
// generated code dropped when retention is disabled. The original report is
// never modified.
func sanitizeReport(r sec.Report, o SaveOptions) sec.Report {
	if o.RedactSecrets {
		r.Prompt = util.RedactSecrets(r.Prompt)
		r.GeneratedCode = util.RedactSecrets(r.GeneratedCode)
		for i := range r.Findings {
			r.Findings[i].Code = util.RedactSecrets(r.Findings[i].Code)
			r.Findings[i].Title = util.RedactSecrets(r.Findings[i].Title)
			r.Findings[i].Description = util.RedactSecrets(r.Findings[i].Description)
		}
		for i := range r.Violations {
			r.Violations[i].Value = util.RedactSecrets(r.Violations[i].Value)
			r.Violations[i].Description = util.RedactSecrets(r.Violations[i].Description)
		}
		r.Sandbox.Stdout = util.RedactSecrets(r.Sandbox.Stdout)
		r.Sandbox.Stderr = util.RedactSecrets(r.Sandbox.Stderr)
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
	plain, err := s.decodeBlob([]byte(blob))
	if err != nil {
		return nil, fmt.Errorf("scan %q: %w", id, err)
	}
	var report sec.Report
	if err := json.Unmarshal(plain, &report); err != nil {
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

func scanSummaries(rows *sql.Rows) ([]ScanSummary, error) {	var out []ScanSummary
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
