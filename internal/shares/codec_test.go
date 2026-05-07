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

func TestMarshalUnmarshalKeyMaterialRoundTrip(t *testing.T) {
	original := ECDSAKeyMaterial{
		Share:            ecdsakeygen.LocalPartySaveData{},
		ChainCode:        bytes.Repeat([]byte{0x11}, 32),
		PublicKeyFormat:  "uncompressed_hex",
		DerivationScheme: "bip32_secp256k1",
	}

	blob, err := MarshalKeyMaterial(original)
	if err != nil {
		t.Fatalf("MarshalKeyMaterial() err = %v", err)
	}

	decoded, err := UnmarshalKeyMaterial(blob)
	if err != nil {
		t.Fatalf("UnmarshalKeyMaterial() err = %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Fatalf("decoded material mismatch: want %+v got %+v", original, decoded)
	}
}

func TestUnmarshalKeyMaterialRejectsLegacyV1ShareBlob(t *testing.T) {
	type legacyShareEnvelope struct {
		Version uint32
		Share   ecdsakeygen.LocalPartySaveData
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(legacyShareEnvelope{
		Version: 1,
		Share:   ecdsakeygen.LocalPartySaveData{},
	}); err != nil {
		t.Fatalf("gob encode err = %v", err)
	}

	_, err := UnmarshalKeyMaterial(buf.Bytes())
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
	}
}

func TestShareWrappersUseV2Envelope(t *testing.T) {
	blob, err := MarshalShare(ecdsakeygen.LocalPartySaveData{})
	if err != nil {
		t.Fatalf("MarshalShare() err = %v", err)
	}
	if _, err := UnmarshalShare(blob); err != nil {
		t.Fatalf("UnmarshalShare() err = %v", err)
	}
	if _, err := UnmarshalKeyMaterial(blob); err != nil {
		t.Fatalf("expected share wrapper blob to be v2 material, got %v", err)
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
