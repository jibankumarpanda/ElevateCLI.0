package logger

import (
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestBuildConsoleAndJSON(t *testing.T) {
	cfg := LoggerConfig{Level: "debug", Format: "console"}
	l, err := build(cfg)
	if err != nil {
		t.Fatalf("build console: %v", err)
	}
	l.Sync()

	cfg.Format = "json"
	l2, err := build(cfg)
	if err != nil {
		t.Fatalf("build json: %v", err)
	}
	l2.Sync()
}

func TestBuildInvalidLevelFallsBackToInfo(t *testing.T) {
	l, err := build(LoggerConfig{Level: "not-a-level", Format: "json"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if l.Core().Enabled(zap.InfoLevel) != true {
		t.Error("info level should be enabled after fallback")
	}
	l.Sync()
}

func TestBuildWithFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logs", "app.log")
	cfg := LoggerConfig{Level: "info", Format: "json", File: path}
	l, err := build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer l.Sync()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("log file was not created: %v", err)
	}
}

func TestRedactedField(t *testing.T) {
	f := RedactedField("api_key")
	if f.String != "[REDACTED]" {
		t.Errorf("RedactedField value = %q, want [REDACTED]", f.String)
	}
	if f.Key != "api_key" {
		t.Errorf("RedactedField key = %q, want api_key", f.Key)
	}
}

func TestWithStageAndRequestID(t *testing.T) {
	base := Get()
	if base == nil {
		t.Fatal("Get() returned nil")
	}
	if l := WithStage("sast"); l == nil {
		t.Error("WithStage returned nil")
	}
	if l := WithRequestID("abc"); l == nil {
		t.Error("WithRequestID returned nil")
	}
}
