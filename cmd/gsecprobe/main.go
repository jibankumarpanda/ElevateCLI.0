package main

import (
	"fmt"
	"os/exec"
)

func main() {
	password := "hunter2"
	cmd := exec.Command("ls", "-la")
	out, _ := cmd.Output()
	fmt.Println(string(out))
	fmt.Println(password)
}
