package tss

import "testing"

func TestShareStatusConstantsStayStable(t *testing.T) {
	if ShareStatusActive == "" {
		t.Fatal("expected active share status to be exported")
	}
	if ShareStatusDisabled == "" {
		t.Fatal("expected disabled share status to be exported")
	}
}
