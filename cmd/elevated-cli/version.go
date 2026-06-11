package main

// These variables are injected at build time via -ldflags.
// Build with:
//
//	go build -ldflags="-X main.Version=1.0.0 -X main.Commit=$(git rev-parse --short HEAD) -X main.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" ./cmd/elevated-cli/
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)
