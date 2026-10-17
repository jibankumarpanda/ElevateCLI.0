package main

import (
	"os/exec"
)

func run(target string) {
	// Vulnerable: command injection via the shell.
	_ = exec.Command("sh", "-c", "ping "+target).Run()
}
