package derivation

import (
	"bytes"
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/bnb-chain/tss-lib/crypto"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

func testShareWithBigXj(t *testing.T) ecdsakeygen.LocalPartySaveData {
	t.Helper()
	pub := crypto.ScalarBaseMult(tsslib.S256(), big.NewInt(5))
	xj := crypto.ScalarBaseMult(tsslib.S256(), big.NewInt(7))
	return ecdsakeygen.LocalPartySaveData{
		ECDSAPub: pub,
		BigXj:    []*crypto.ECPoint{xj},
	}
}

func TestParseChildPath(t *testing.T) {
	got, err := ParseChildPath("/0/15")
	if err != nil {
		t.Fatalf("ParseChildPath returned error: %v", err)
	}
	want := []uint32{0, 15}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v got %v", want, got)
	}
}

func TestDeriveECDSAChildKeyReturnsCanonicalPublicKeyAndDelta(t *testing.T) {
	share := testShareWithBigXj(t)
	chainCode := bytes.Repeat([]byte{0x11}, 32)

	out, err := DeriveECDSAChildKey(share.ECDSAPub, chainCode, []uint32{0, 15})
	if err != nil {
		t.Fatalf("DeriveECDSAChildKey returned error: %v", err)
	}
	if out.KeyDerivationDelta == nil || out.KeyDerivationDelta.Sign() <= 0 {
		t.Fatalf("missing positive key derivation delta: %+v", out.KeyDerivationDelta)
	}
	if err := ValidateUncompressedSecp256k1Hex(out.PublicKeyHex); err != nil {
		t.Fatalf("derived public key is not canonical: %v", err)
	}
	if out.PublicKey == nil || out.PublicKey.Curve != tsslib.S256() {
		t.Fatalf("unexpected child public key: %+v", out.PublicKey)
	}
}

func TestPrepareECDSASigningShareDoesNotMutateOriginal(t *testing.T) {
	share := testShareWithBigXj(t)
	originalPub := EncodeUncompressedSecp256k1(share.ECDSAPub.ToECDSAPubKey())
	originalBigXj := share.BigXj[0]
	chainCode := bytes.Repeat([]byte{0x11}, 32)
	ctx := Context{
		ProfileID:   "profile-1",
		Algorithm:   AlgorithmECDSA,
		Curve:       CurveSecp256k1,
		Scheme:      DerivationSchemeBIP32Secp256k1,
		AccountPath: "m/44'/60'/0'",
		ChildPath:   "/0/15",
		FullPath:    "m/44'/60'/0'/0/15",
	}

	prepared, err := PrepareECDSASigningShare(share, chainCode, ctx)
	if err != nil {
		t.Fatalf("PrepareECDSASigningShare returned error: %v", err)
	}
	if prepared.KeyDerivationDelta == nil {
		t.Fatal("expected key derivation delta")
	}
	if EncodeUncompressedSecp256k1(share.ECDSAPub.ToECDSAPubKey()) != originalPub {
		t.Fatal("original ECDSAPub was mutated")
	}
	if share.BigXj[0] != originalBigXj {
		t.Fatal("original BigXj pointer was replaced")
	}
	if EncodeUncompressedSecp256k1(prepared.Share.ECDSAPub.ToECDSAPubKey()) == originalPub {
		t.Fatal("expected adjusted share public key to differ from account public key")
	}
}

func TestPrepareECDSASigningShareRejectsDerivedPublicKeyMismatch(t *testing.T) {
	share := testShareWithBigXj(t)
	chainCode := bytes.Repeat([]byte{0x11}, 32)
	ctx := Context{
		ProfileID:        "profile-1",
		Algorithm:        AlgorithmECDSA,
		Curve:            CurveSecp256k1,
		Scheme:           DerivationSchemeBIP32Secp256k1,
		AccountPath:      "m/44'/60'/0'",
		ChildPath:        "/0/15",
		FullPath:         "m/44'/60'/0'/0/15",
		DerivedPublicKey: validUncompressedSecp256k1Hex,
	}

	_, err := PrepareECDSASigningShare(share, chainCode, ctx)
	if !errors.Is(err, ErrDerivationContextMismatch) {
		t.Fatalf("expected ErrDerivationContextMismatch, got %v", err)
	}
}
