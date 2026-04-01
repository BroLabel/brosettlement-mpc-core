package shares

import (
	"bytes"
	"encoding/gob"
	"errors"
	"reflect"
	"testing"

	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

func TestMarshalUnmarshalShareRoundTrip(t *testing.T) {
	original := ecdsakeygen.LocalPartySaveData{}

	blob, err := MarshalShare(original)
	if err != nil {
		t.Fatalf("MarshalShare() err = %v", err)
	}

	decoded, err := UnmarshalShare(blob)
	if err != nil {
		t.Fatalf("UnmarshalShare() err = %v", err)
	}

	if !reflect.DeepEqual(decoded, original) {
		t.Fatal("expected decoded share to match original")
	}
}

func TestUnmarshalShareInvalidPayload(t *testing.T) {
	_, err := UnmarshalShare([]byte("broken"))
	if !errors.Is(err, ErrInvalidSharePayload) {
		t.Fatalf("expected ErrInvalidSharePayload, got %v", err)
	}
}

func TestUnmarshalShareUnsupportedVersion(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(shareEnvelope{
		Version: codecVersion + 1,
		Share:   ecdsakeygen.LocalPartySaveData{},
	}); err != nil {
		t.Fatalf("gob encode err = %v", err)
	}

	_, err := UnmarshalShare(buf.Bytes())
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
	}
}
