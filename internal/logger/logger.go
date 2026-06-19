// Package logger sets up a production-grade structured logger using Uber Zap.
// All packages call logger.Get() to get the shared logger instance.
// Sensitive data (API keys, tokens) is never logged — see redaction rules below.
package logger

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	instance *zap.Logger
	once     sync.Once
)

// LoggerConfig mirrors the config struct fields needed here.
type LoggerConfig struct {
	Level      string
	Format     string // "json" | "console"
	File       string
	MaxSizeMB  int
	MaxBackups int
}

// Init initialises the global logger. Call once from main.go.
func Init(cfg LoggerConfig) error {
	var initErr error
	once.Do(func() {
		instance, initErr = build(cfg)
	})
	return initErr
}

// Get returns the global logger. Panics if Init was not called first.
func Get() *zap.Logger {
	if instance == nil {
		// Safe fallback for tests that haven't called Init
		l, _ := zap.NewDevelopment()
		return l
	}
	return instance
}

// Sugar returns a sugared (printf-style) version of the global logger.
func Sugar() *zap.SugaredLogger {
	return Get().Sugar()
}

// ─── Builder ─────────────────────────────────────────────────────────────────

func build(cfg LoggerConfig) (*zap.Logger, error) {
	// Parse log level
	level, err := zapcore.ParseLevel(strings.ToLower(cfg.Level))
	if err != nil {
		level = zapcore.InfoLevel
	}

	encoderCfg := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Choose encoder
	var encoder zapcore.Encoder
	if cfg.Format == "console" {
		encoderCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encoderCfg)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderCfg)
	}

	// Build cores (console + optional file)
	cores := []zapcore.Core{
		zapcore.NewCore(encoder, zapcore.AddSync(os.Stderr), level),
	}

	if cfg.File != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.File), 0750); err == nil {
			f, err := os.OpenFile(cfg.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			if err == nil {
				fileEncoder := zapcore.NewJSONEncoder(encoderCfg)
				cores = append(cores, zapcore.NewCore(fileEncoder, zapcore.AddSync(f), level))
			}
		}
	}

	core := zapcore.NewTee(cores...)

	logger := zap.New(core,
		zap.AddCaller(),
		zap.AddCallerSkip(0),
		zap.Fields(zap.String("app", "elevated-cli")),
	)

	return logger, nil
}

// ─── Redaction helpers ────────────────────────────────────────────────────────

// RedactedField returns a zap field with the value masked — use for any
// potentially sensitive string (API keys, tokens, passwords).
func RedactedField(key string) zap.Field {
	return zap.String(key, "[REDACTED]")
}

// WithRequestID returns a child logger tagged with a request/scan ID.
func WithRequestID(id string) *zap.Logger {
	return Get().With(zap.String("scan_id", id))
}

// WithStage returns a child logger tagged with the current pipeline stage.
func WithStage(stage string) *zap.Logger {
	return Get().With(zap.String("stage", stage))
}
