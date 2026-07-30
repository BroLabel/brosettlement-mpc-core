package shares

import (
	"bytes"
	"encoding/gob"
	"errors"
	"reflect"
	"strings"
	"testing"

	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

func codecV2GoldenMaterial() ECDSAKeyMaterial {
	return ECDSAKeyMaterial{
		Share:            ecdsakeygen.LocalPartySaveData{},
		ChainCode:        bytes.Repeat([]byte{0x11}, 32),
		PublicKeyFormat:  "uncompressed_hex",
		DerivationScheme: "bip32_secp256k1",
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
		t.Fatal("decoded material mismatch")
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

func TestCodecV2RejectsMalformedInput(t *testing.T) {
	_, err := UnmarshalKeyMaterial([]byte("not-a-gob"))
	if !errors.Is(err, ErrInvalidSharePayload) {
		t.Fatalf("UnmarshalKeyMaterial() error = %v, want ErrInvalidSharePayload", err)
	}
}

func TestCodecV2AcceptsBlobAtLimit(t *testing.T) {
	material, blob := codecV2BlobAtSize(t, maxKeyMaterialBlobBytes)

	encoded, err := MarshalKeyMaterial(material)
	if err != nil {
		t.Fatalf("MarshalKeyMaterial() error = %v", err)
	}
	if !bytes.Equal(encoded, blob) {
		t.Fatal("MarshalKeyMaterial() changed the codec-v2 bytes at the size limit")
	}

	decoded, err := UnmarshalKeyMaterial(blob)
	if err != nil {
		t.Fatalf("UnmarshalKeyMaterial() error = %v", err)
	}
	if !reflect.DeepEqual(decoded, material) {
		t.Fatal("UnmarshalKeyMaterial() changed material at the codec-v2 size limit")
	}
}

func TestCodecV2RejectsBlobOverLimit(t *testing.T) {
	material, blob := codecV2BlobAtSize(t, maxKeyMaterialBlobBytes+1)

	_, err := MarshalKeyMaterial(material)
	if !errors.Is(err, ErrInvalidSharePayload) {
		t.Fatalf("MarshalKeyMaterial() error = %v, want ErrInvalidSharePayload for an oversized blob", err)
	}

	_, err = UnmarshalKeyMaterial(blob)
	if !errors.Is(err, ErrInvalidSharePayload) {
		t.Fatalf("UnmarshalKeyMaterial() error = %v, want ErrInvalidSharePayload for an oversized blob", err)
	}
}

func TestCodecV2RejectsTrailingGarbage(t *testing.T) {
	blob, err := MarshalKeyMaterial(codecV2GoldenMaterial())
	if err != nil {
		t.Fatalf("MarshalKeyMaterial() error = %v", err)
	}

	_, err = UnmarshalKeyMaterial(append(blob, []byte("trailing-garbage")...))
	if !errors.Is(err, ErrInvalidSharePayload) {
		t.Fatalf("UnmarshalKeyMaterial() error = %v, want ErrInvalidSharePayload for trailing garbage", err)
	}
}

func TestCodecV2RejectsSecondEnvelope(t *testing.T) {
	first, err := MarshalKeyMaterial(codecV2GoldenMaterial())
	if err != nil {
		t.Fatalf("MarshalKeyMaterial() first encode error = %v", err)
	}
	second, err := MarshalKeyMaterial(codecV2GoldenMaterial())
	if err != nil {
		t.Fatalf("MarshalKeyMaterial() second encode error = %v", err)
	}

	_, err = UnmarshalKeyMaterial(append(first, second...))
	if !errors.Is(err, ErrInvalidSharePayload) {
		t.Fatalf("UnmarshalKeyMaterial() error = %v, want ErrInvalidSharePayload for a second envelope", err)
	}
}

func TestCodecV2RejectsUnsupportedVersion(t *testing.T) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(shareEnvelope{Version: codecVersion + 1}); err != nil {
		t.Fatalf("gob encode error = %v", err)
	}

	_, err := UnmarshalKeyMaterial(buf.Bytes())
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("UnmarshalKeyMaterial() error = %v, want ErrUnsupportedVersion", err)
	}
}

func codecV2BlobAtSize(t *testing.T, target int) (ECDSAKeyMaterial, []byte) {
	t.Helper()
	for low, high := 0, target; low <= high; {
		formatLength := low + (high-low)/2
		material := codecV2GoldenMaterial()
		material.PublicKeyFormat = strings.Repeat("x", formatLength)
		blob := encodeCodecV2Envelope(t, material)
		switch {
		case len(blob) == target:
			return material, blob
		case len(blob) < target:
			low = formatLength + 1
		default:
			high = formatLength - 1
		}
	}
	t.Fatalf("no non-secret codec-v2 material encodes to %d bytes", target)
	return ECDSAKeyMaterial{}, nil
}

func encodeCodecV2Envelope(t *testing.T, material ECDSAKeyMaterial) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(shareEnvelope{
		Version: 2,
		Share:   material.Share,
		Meta: KeyMaterialMeta{
			ChainCode:        append([]byte(nil), material.ChainCode...),
			PublicKeyFormat:  material.PublicKeyFormat,
			DerivationScheme: material.DerivationScheme,
		},
	}); err != nil {
		t.Fatalf("encode codec-v2 boundary envelope: %v", err)
	}
	return buf.Bytes()
}
