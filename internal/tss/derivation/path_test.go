package derivation

import (
	"errors"
	"testing"
)

func TestNormalizeChildPathRejectsBoundaryAndCanonicalIssues(t *testing.T) {
	tests := []string{
		"/0/2147483648",
		"/00/1",
		"/0/01",
		"/0/-1",
		"/0/+1",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, _, err := NormalizeChildPath(input)
			if !errors.Is(err, ErrDerivationPathInvalid) {
				t.Fatalf("expected ErrDerivationPathInvalid, got %v", err)
			}
		})
	}
}

func TestNormalizeAccountPathCanonicalizesHardenedMarkers(t *testing.T) {
	got, err := NormalizeAccountPath("m/44h/60H/0'")
	if err != nil {
		t.Fatalf("NormalizeAccountPath returned error: %v", err)
	}
	if got != "m/44'/60'/0'" {
		t.Fatalf("NormalizeAccountPath = %q", got)
	}
}

func TestNormalizeAccountPathRejectsRoot(t *testing.T) {
	_, err := NormalizeAccountPath("m")
	if !errors.Is(err, ErrInvalidDerivationContext) {
		t.Fatalf("expected ErrInvalidDerivationContext, got %v", err)
	}
}
