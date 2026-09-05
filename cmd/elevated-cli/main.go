package main

import (
	"github.com/jibankumarpanda/ElevateCLI.0/cmd/elevated-cli/commands"
)

// Build metadata, injected at release time via
// -ldflags "-X main.Version=... -X main.Commit=... -X main.Date=...".
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func main() {
	commands.Execute()
}