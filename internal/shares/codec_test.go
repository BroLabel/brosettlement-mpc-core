package shares

import (
	"bytes"
	"encoding/gob"
	"errors"
	"math/big"
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

func TestMarshalKeyMaterialRejectsUnsupportedMaterialFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ECDSAKeyMaterial)
	}{
		{name: "chain code length", mutate: func(material *ECDSAKeyMaterial) { material.ChainCode = []byte{0x11} }},
		{name: "public key format", mutate: func(material *ECDSAKeyMaterial) { material.PublicKeyFormat = "compressed_hex" }},
		{name: "derivation scheme", mutate: func(material *ECDSAKeyMaterial) { material.DerivationScheme = "slip10_ed25519" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			material := codecV2GoldenMaterial()
			tt.mutate(&material)

			blob, err := MarshalKeyMaterial(material)
			if !errors.Is(err, ErrInvalidSharePayload) {
				t.Fatalf("MarshalKeyMaterial() error = %v, want ErrInvalidSharePayload", err)
			}
			if blob != nil {
				t.Fatalf("MarshalKeyMaterial() blob length = %d, want nil", len(blob))
			}
		})
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
	material := codecV2GoldenMaterial()
	blob := paddedCodecV2BlobAtSize(t, material, maxKeyMaterialBlobBytes)

	decoded, err := UnmarshalKeyMaterial(blob)
	if err != nil {
		t.Fatalf("UnmarshalKeyMaterial() error = %v", err)
	}
	if !reflect.DeepEqual(decoded, material) {
		t.Fatal("UnmarshalKeyMaterial() changed material at the codec-v2 size limit")
	}
}

func TestCodecV2RejectsBlobOverLimit(t *testing.T) {
	material := codecV2GoldenMaterial()
	material.Share.Xi = new(big.Int).SetBytes(bytes.Repeat([]byte{0xff}, maxKeyMaterialBlobBytes+1))

	_, err := MarshalKeyMaterial(material)
	if !errors.Is(err, ErrInvalidSharePayload) || !strings.Contains(err.Error(), "blob exceeds") {
		t.Fatalf("MarshalKeyMaterial() error = %v, want oversized ErrInvalidSharePayload", err)
	}

	blob := make([]byte, maxKeyMaterialBlobBytes+1)
	_, err = UnmarshalKeyMaterial(blob)
	if !errors.Is(err, ErrInvalidSharePayload) || !strings.Contains(err.Error(), "blob exceeds") {
		t.Fatalf("UnmarshalKeyMaterial() error = %v, want oversized ErrInvalidSharePayload", err)
	}
}

func paddedCodecV2BlobAtSize(t *testing.T, material ECDSAKeyMaterial, target int) []byte {
	t.Helper()
	type paddedEnvelope struct {
		Version uint32
		Share   ecdsakeygen.LocalPartySaveData
		Meta    KeyMaterialMeta
		Padding []byte
	}
	for low, high := 0, target; low <= high; {
		paddingLength := low + (high-low)/2
		var buf bytes.Buffer
		err := gob.NewEncoder(&buf).Encode(paddedEnvelope{
			Version: codecVersion,
			Share:   material.Share,
			Meta: KeyMaterialMeta{
				ChainCode:        append([]byte(nil), material.ChainCode...),
				PublicKeyFormat:  material.PublicKeyFormat,
				DerivationScheme: material.DerivationScheme,
			},
			Padding: make([]byte, paddingLength),
		})
		if err != nil {
			t.Fatalf("encode padded codec-v2 envelope: %v", err)
		}
		switch {
		case buf.Len() == target:
			return buf.Bytes()
		case buf.Len() < target:
			low = paddingLength + 1
		default:
			high = paddingLength - 1
		}
	}
	t.Fatalf("no padded codec-v2 envelope encodes to %d bytes", target)
	return nil
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

func TestCodecV2RejectsUnsupportedMaterialFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ECDSAKeyMaterial)
	}{
		{name: "chain code length", mutate: func(material *ECDSAKeyMaterial) { material.ChainCode = []byte{0x11} }},
		{name: "public key format", mutate: func(material *ECDSAKeyMaterial) { material.PublicKeyFormat = "compressed_hex" }},
		{name: "derivation scheme", mutate: func(material *ECDSAKeyMaterial) { material.DerivationScheme = "slip10_ed25519" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			material := codecV2GoldenMaterial()
			tt.mutate(&material)
			blob := encodeCodecV2Envelope(t, material)

			_, err := UnmarshalKeyMaterial(blob)
			if !errors.Is(err, ErrInvalidSharePayload) {
				t.Fatalf("UnmarshalKeyMaterial() error = %v, want ErrInvalidSharePayload", err)
			}
		})
	}
}

func TestCopyAndClearBytesClearsDecoderOwnedChainCodeAfterCopy(t *testing.T) {
	decoderOwnedChainCode := bytes.Repeat([]byte{0x11}, 32)

	copy := copyAndClearBytes(decoderOwnedChainCode)

	if !bytes.Equal(copy, bytes.Repeat([]byte{0x11}, 32)) {
		t.Fatal("copyAndClearBytes() changed the copied chain code")
	}
	if !bytes.Equal(decoderOwnedChainCode, make([]byte, len(decoderOwnedChainCode))) {
		t.Fatal("copyAndClearBytes() did not clear the decoder-owned chain code")
	}
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
