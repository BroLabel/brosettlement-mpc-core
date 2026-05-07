package tss

import (
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
