package shares

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"math/big"
	"reflect"
	"testing"

	tsscrypto "github.com/bnb-chain/tss-lib/crypto"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

func TestInspectEncodedECDSAKeyMaterialReturnsCanonicalEvidence(t *testing.T) {
	blob := inspectableECDSAKeyMaterialBlob(t, secp256k1Point(t, 1), 32)

	evidence, err := InspectEncodedECDSAKeyMaterial(blob)
	if err != nil {
		t.Fatalf("InspectEncodedECDSAKeyMaterial() error = %v", err)
	}

	if evidence.CodecVersion != 2 {
		t.Fatalf("CodecVersion = %d, want 2", evidence.CodecVersion)
	}
	wantPublicKey := []byte{
		0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
		0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
		0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
	}
	if !bytes.Equal(evidence.AccountPublicKey, wantPublicKey) {
		t.Fatal("AccountPublicKey is not canonical compressed SEC1")
	}
	wantChainCodeHash := sha256.Sum256(bytes.Repeat([]byte{0x42}, 32))
	if evidence.ChainCodeHash != wantChainCodeHash {
		t.Fatal("ChainCodeHash does not match the chain code digest")
	}
}

func TestInspectEncodedECDSAKeyMaterialRejectsInvalidPublicPoints(t *testing.T) {
	tests := []struct {
		name  string
		point *tsscrypto.ECPoint
	}{
		{
			name:  "point at infinity",
			point: tsscrypto.NewECPointNoCurveCheck(tsslib.S256(), big.NewInt(0), big.NewInt(0)),
		},
		{
			name:  "off curve point",
			point: tsscrypto.NewECPointNoCurveCheck(tsslib.S256(), big.NewInt(1), big.NewInt(1)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := InspectEncodedECDSAKeyMaterial(inspectableECDSAKeyMaterialBlob(t, tt.point, 32))
			if !errors.Is(err, ErrInvalidSharePayload) {
				t.Fatalf("InspectEncodedECDSAKeyMaterial() error = %v, want ErrInvalidSharePayload", err)
			}
		})
	}
}

func TestInspectEncodedECDSAKeyMaterialRejectsWrongChainCodeLength(t *testing.T) {
	_, err := InspectEncodedECDSAKeyMaterial(inspectableECDSAKeyMaterialBlob(t, secp256k1Point(t, 1), 31))
	if !errors.Is(err, ErrInvalidSharePayload) {
		t.Fatalf("InspectEncodedECDSAKeyMaterial() error = %v, want ErrInvalidSharePayload", err)
	}
}

func TestInspectEncodedECDSAKeyMaterialRejectsOversizedAndMalformedBlobs(t *testing.T) {
	tests := []struct {
		name string
		blob []byte
	}{
		{name: "oversized", blob: make([]byte, maxKeyMaterialBlobBytes+1)},
		{name: "malformed", blob: []byte("not-a-gob")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := InspectEncodedECDSAKeyMaterial(tt.blob)
			if !errors.Is(err, ErrInvalidSharePayload) {
				t.Fatalf("InspectEncodedECDSAKeyMaterial() error = %v, want ErrInvalidSharePayload", err)
			}
		})
	}
}

func TestInspectEncodedECDSAKeyMaterialDoesNotMutateInput(t *testing.T) {
	blob := inspectableECDSAKeyMaterialBlob(t, secp256k1Point(t, 1), 32)
	want := append([]byte(nil), blob...)

	if _, err := InspectEncodedECDSAKeyMaterial(blob); err != nil {
		t.Fatalf("InspectEncodedECDSAKeyMaterial() error = %v", err)
	}
	if !bytes.Equal(blob, want) {
		t.Fatal("InspectEncodedECDSAKeyMaterial() mutated its input")
	}
}

func TestInspectEncodedECDSAKeyMaterialIsPanicSafe(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		[]byte{0},
		[]byte("not-a-gob"),
		inspectableECDSAKeyMaterialBlob(t, nil, 32),
	}
	for _, input := range inputs {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("InspectEncodedECDSAKeyMaterial() panicked: %v", recovered)
				}
			}()
			_, _ = InspectEncodedECDSAKeyMaterial(input)
		}()
	}
}

func TestInspectEncodedECDSAKeyMaterialEvidenceExposesNoSecretFields(t *testing.T) {
	typ := reflect.TypeOf(ECDSAKeyMaterialEvidence{})
	if typ.NumField() != 3 {
		t.Fatalf("ECDSAKeyMaterialEvidence field count = %d, want 3", typ.NumField())
	}
	for _, field := range []string{"CodecVersion", "AccountPublicKey", "ChainCodeHash"} {
		if _, ok := typ.FieldByName(field); !ok {
			t.Fatalf("ECDSAKeyMaterialEvidence does not expose %q", field)
		}
	}
}

func TestInspectEncodedECDSAKeyMaterialGoldenEvidenceIsPointCanonical(t *testing.T) {
	curve := tsslib.S256()
	base := secp256k1Point(t, 1)
	basePublicKey := base.ToECDSAPubKey()
	decodedX, decodedY := elliptic.Unmarshal(curve, elliptic.Marshal(curve, basePublicKey.X, basePublicKey.Y))
	fromUncompressed, err := tsscrypto.NewECPoint(curve, decodedX, decodedY)
	if err != nil {
		t.Fatalf("decode uncompressed SEC1 point: %v", err)
	}

	fromBase, err := InspectEncodedECDSAKeyMaterial(inspectableECDSAKeyMaterialBlob(t, base, 32))
	if err != nil {
		t.Fatalf("InspectEncodedECDSAKeyMaterial() base error = %v", err)
	}
	fromUncompressedEvidence, err := InspectEncodedECDSAKeyMaterial(inspectableECDSAKeyMaterialBlob(t, fromUncompressed, 32))
	if err != nil {
		t.Fatalf("InspectEncodedECDSAKeyMaterial() uncompressed point error = %v", err)
	}
	otherPoint, err := InspectEncodedECDSAKeyMaterial(inspectableECDSAKeyMaterialBlob(t, secp256k1Point(t, 2), 32))
	if err != nil {
		t.Fatalf("InspectEncodedECDSAKeyMaterial() other point error = %v", err)
	}

	if !bytes.Equal(fromBase.AccountPublicKey, fromUncompressedEvidence.AccountPublicKey) {
		t.Fatal("same curve point produced different evidence")
	}
	if bytes.Equal(fromBase.AccountPublicKey, otherPoint.AccountPublicKey) {
		t.Fatal("different curve point produced identical evidence")
	}
}

func inspectableECDSAKeyMaterialBlob(t *testing.T, point *tsscrypto.ECPoint, chainCodeLength int) []byte {
	t.Helper()
	var encoded bytes.Buffer
	err := gob.NewEncoder(&encoded).Encode(shareEnvelope{
		Version: codecVersion,
		Share:   ecdsakeygen.LocalPartySaveData{ECDSAPub: point},
		Meta: KeyMaterialMeta{
			ChainCode:        bytes.Repeat([]byte{0x42}, chainCodeLength),
			PublicKeyFormat:  "uncompressed_hex",
			DerivationScheme: "bip32_secp256k1",
		},
	})
	if err != nil {
		t.Fatalf("encode inspectable key material: %v", err)
	}
	return encoded.Bytes()
}

func secp256k1Point(t *testing.T, scalar int64) *tsscrypto.ECPoint {
	t.Helper()
	point := tsscrypto.ScalarBaseMult(tsslib.S256(), big.NewInt(scalar))
	if point == nil {
		t.Fatal("create secp256k1 test point")
	}
	return point
}
