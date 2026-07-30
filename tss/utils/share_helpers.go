package utils

import (
	"fmt"
	"strings"
)

// NormalizeKeyID validates and normalizes key id.
func NormalizeKeyID(raw string, emptyErr error) (string, error) {
	keyID := strings.TrimSpace(raw)
	if keyID == "" {
		return "", fmt.Errorf("%w: empty key_id", emptyErr)
	}
	return keyID, nil
}
