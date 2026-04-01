package idgen

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestNewReturnsPrefixedHexID(t *testing.T) {
	got := New("corr")

	if !strings.HasPrefix(got, "corr_") {
		t.Fatalf("New() prefix = %q, want corr_", got)
	}

	suffix := strings.TrimPrefix(got, "corr_")
	if len(suffix) != 16 {
		t.Fatalf("New() suffix length = %d, want 16", len(suffix))
	}
	if _, err := hex.DecodeString(suffix); err != nil {
		t.Fatalf("New() suffix is not hex: %v", err)
	}
}
