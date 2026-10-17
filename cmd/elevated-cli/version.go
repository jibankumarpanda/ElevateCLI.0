package main

// These variables are injected at build time via -ldflags. The defaults
// describe an unversioned local build; release builds override them.
//
//	go build -trimpath -ldflags="-X main.Version=0.1.1 -X main.Commit=$(git rev-parse --short HEAD) -X main.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" ./cmd/elevated-cli/
var (
	Version = "0.1.1"
	Commit  = "none"
	Date    = "unknown"
)
