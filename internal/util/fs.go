package util

import (
	"fmt"
	"os"
	"path/filepath"
)

// Exists checks if a file or directory exists at the given path.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// EnsureDir checks if a directory exists, and creates it if it doesn't.
func EnsureDir(path string) error {
	if !Exists(path) {
		err := os.MkdirAll(path, 0755)
		if err != nil {
			return fmt.Errorf("failed to create directory %s: %w", path, err)
		}
	}
	return nil
}

// ReadFileContent reads the entire content of a file and returns it as a string.
func ReadFileContent(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", path, err)
	}
	return string(content), nil
}

// WriteFileContent writes the string content to a file, creating it if necessary.
func WriteFileContent(path string, content string) error {
	dir := filepath.Dir(path)
	if err := EnsureDir(dir); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0644)
}
