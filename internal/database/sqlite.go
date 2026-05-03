package database

import (
	"database/sql"
	"fmt"

	"github.com/jibankumarpanda/ElevateCLI.0/pkg/security"
	_ "modernc.org/sqlite"
)

type SQLiteDB struct {
	db *sql.DB
}

func NewSQLiteDB(path string) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
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

func (s *SQLiteDB) initSchema() error {
	query := `
	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		prompt TEXT,
		code TEXT,
		language TEXT,
		score INTEGER,
		verdict TEXT,
		findings_count INTEGER
	);`
	_, err := s.db.Exec(query)
	return err
}

func (s *SQLiteDB) SaveReport(report security.Report) error {
	query := `INSERT INTO audit_logs (prompt, code, language, score, verdict, findings_count) VALUES (?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, 
		report.Prompt, 
		report.GeneratedCode, 
		report.Language, 
		report.Score, 
		string(report.Verdict), 
		len(report.Findings)+len(report.Vulnerabilities)+len(report.PolicyViolations),
	)
	return err
}
