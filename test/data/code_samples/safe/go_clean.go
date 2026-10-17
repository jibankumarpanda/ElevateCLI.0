//go:build ignore

package main

import "fmt"

func Add(a, b int) int {
	return a + b
}

func main() {
	fmt.Println(add(1, 2))
}

func add(a, b int) int {
	return a + b
}
