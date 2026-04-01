package utils

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// SafePathUnderDir returns an absolute cleaned path and ensures it stays under baseDir.
func SafePathUnderDir(baseDir, path string) (string, error) {
	if baseDir == "" {
		return "", errors.New("base directory is empty")
	}
	absBase, err := filepath.Abs(filepath.Clean(baseDir))
	if err != nil {
		return "", err
	}
	absPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absBase, absPath)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes base dir: %s", path)
	}
	return absPath, nil
}
