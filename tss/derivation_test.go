package tss

import (
	"bytes"
	"errors"
	"testing"
)

func TestPublicDerivationConstants(t *testing.T) {
	if AlgorithmECDSA != "ecdsa" {
		t.Fatalf("AlgorithmECDSA = %q", AlgorithmECDSA)
	}
	if AlgorithmEdDSA != "eddsa" {
		t.Fatalf("AlgorithmEdDSA = %q", AlgorithmEdDSA)
	}
	if CurveSecp256k1 != "secp256k1" {
		t.Fatalf("CurveSecp256k1 = %q", CurveSecp256k1)
	}
	if CurveEd25519 != "ed25519" {
		t.Fatalf("CurveEd25519 = %q", CurveEd25519)
	}
	if DerivationSchemeBIP32Secp256k1 != "bip32_secp256k1" {
		t.Fatalf("DerivationSchemeBIP32Secp256k1 = %q", DerivationSchemeBIP32Secp256k1)
	}
	if DerivationSchemeBIP32Public != "bip32_public" {
		t.Fatalf("DerivationSchemeBIP32Public = %q", DerivationSchemeBIP32Public)
	}
	if DerivationSchemeSLIP10Ed25519 != "slip10_ed25519" {
		t.Fatalf("DerivationSchemeSLIP10Ed25519 = %q", DerivationSchemeSLIP10Ed25519)
	}
	if PublicKeyFormatUncompressedHex != "uncompressed_hex" {
		t.Fatalf("PublicKeyFormatUncompressedHex = %q", PublicKeyFormatUncompressedHex)
	}
}

func TestSignSessionRequestValidateRequiresDerivationContext(t *testing.T) {
	req := SignSessionRequest{
		Session: SessionDescriptor{
			SessionID: "sign-1",
			OrgID:     "org-1",
			KeyID:     "key-1",
			Parties:   []string{"p1", "p2", "p3"},
			Threshold: 2,
			Algorithm: AlgorithmECDSA,
			Curve:     CurveSecp256k1,
		},
		LocalPartyID: "p1",
		Digest:       []byte{1, 2, 3},
		Transport:    noopTransport{},
	}

	err := req.Validate()
	if !errors.Is(err, ErrDerivationContextRequired) {
		t.Fatalf("expected ErrDerivationContextRequired, got %v", err)
	}
}

func TestDerivationErrorsPreserveErrorsIs(t *testing.T) {
	err := wrapPublicDerivationError(ErrInvalidDerivationContext, "bad context")
	if !errors.Is(err, ErrInvalidDerivationContext) {
		t.Fatalf("expected wrapper to preserve ErrInvalidDerivationContext, got %v", err)
	}
}

func TestDerivationContextHashV1DoesNotMutateInput(t *testing.T) {
	in := DerivationContext{
		ProfileID:   "profile-1",
		Algorithm:   "ECDSA",
		Curve:       "SECP256K1",
		Scheme:      DerivationSchemeBIP32Public,
		AccountPath: "m/44h/60h/0h",
		ChildPath:   "/0/15",
		FullPath:    "m/44'/60'/0'/0/15",
	}
	before := in
	if _, err := DerivationContextHashV1(in); err != nil {
		t.Fatalf("DerivationContextHashV1 returned error: %v", err)
	}
	if in != before {
		t.Fatalf("hash mutated input: before=%+v after=%+v", before, in)
	}
}

func TestDeriveECDSAChildPublicKeyKnownVector(t *testing.T) {
	ctx := validPublicECDSADerivationContext()
	accountPublicKey := "042f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6"
	chainCode := bytes.Repeat([]byte{0x11}, 32)

	got, err := DeriveECDSAChildPublicKey(accountPublicKey, chainCode, ctx)
	if err != nil {
		t.Fatalf("DeriveECDSAChildPublicKey returned error: %v", err)
	}

	want := "04697096f8cdd7e6c33c78b63a9a07fe94fcdcc5cc00a8087f013abcdc2de12b217fd91fdeff350c0da379f70ffcab88c5f33bf9d1bcb5eb70e56ab9a8a99347e7"
	if got != want {
		t.Fatalf("child public key mismatch\nwant: %s\n got: %s", want, got)
	}
}

func TestDeriveECDSAChildPublicKeyRejectsInvalidPath(t *testing.T) {
	ctx := validPublicECDSADerivationContext()
	ctx.ChildPath = "/0/01"
	ctx.FullPath = ""

	_, err := DeriveECDSAChildPublicKey(validAccountPublicKeyHex, bytes.Repeat([]byte{0x11}, 32), ctx)
	if !errors.Is(err, ErrDerivationPathInvalid) {
		t.Fatalf("expected ErrDerivationPathInvalid, got %v", err)
	}
}

func TestDeriveECDSAChildPublicKeyRejectsWrongChainCodeLength(t *testing.T) {
	_, err := DeriveECDSAChildPublicKey(validAccountPublicKeyHex, bytes.Repeat([]byte{0x11}, 31), validPublicECDSADerivationContext())
	if !errors.Is(err, ErrChainCodeInvalid) {
		t.Fatalf("expected ErrChainCodeInvalid, got %v", err)
	}
}

func TestDeriveECDSAChildPublicKeyRejectsDerivedPublicKeyMismatch(t *testing.T) {
	ctx := validPublicECDSADerivationContext()
	ctx.DerivedPublicKey = validAccountPublicKeyHex

	_, err := DeriveECDSAChildPublicKey(validAccountPublicKeyHex, bytes.Repeat([]byte{0x11}, 32), ctx)
	if !errors.Is(err, ErrDerivationContextMismatch) {
		t.Fatalf("expected ErrDerivationContextMismatch, got %v", err)
	}
}

const validAccountPublicKeyHex = "042f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6"

func validPublicECDSADerivationContext() DerivationContext {
	return DerivationContext{
		ProfileID:   "profile-1",
		Algorithm:   AlgorithmECDSA,
		Curve:       CurveSecp256k1,
		Scheme:      DerivationSchemeBIP32Secp256k1,
		AccountPath: "m/44'/60'/0'",
		ChildPath:   "/0/15",
		FullPath:    "m/44'/60'/0'/0/15",
	}
}
