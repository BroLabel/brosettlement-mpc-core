package tss

import (
	"reflect"
	"testing"

	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

func TestMarshalAndUnmarshalShareRoundTrip(t *testing.T) {
	original := ecdsakeygen.LocalPartySaveData{}

	blob, err := MarshalShare(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	decoded, err := UnmarshalShare(blob)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if !reflect.DeepEqual(decoded, original) {
		t.Fatal("expected decoded share to match original")
	}
}

func TestShareStatusConstantsStayStable(t *testing.T) {
	if ShareStatusActive == "" {
		t.Fatal("expected active share status to be exported")
	}
	if ShareStatusDisabled == "" {
		t.Fatal("expected disabled share status to be exported")
	}
}
