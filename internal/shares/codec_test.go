package shares

import (
	"bytes"
	"encoding/gob"
	"errors"
	"reflect"
	"testing"

	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

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
