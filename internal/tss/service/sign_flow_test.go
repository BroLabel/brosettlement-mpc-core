package service

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	corederivation "github.com/BroLabel/brosettlement-mpc-core/internal/tss/derivation"
	"github.com/bnb-chain/tss-lib/crypto"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

func validServiceDerivationContext() corederivation.Context {
	return corederivation.Context{
		ProfileID:   "profile-1",
		Algorithm:   corederivation.AlgorithmECDSA,
		Curve:       corederivation.CurveSecp256k1,
		Scheme:      corederivation.DerivationSchemeBIP32Secp256k1,
		AccountPath: "m/44'/60'/0'",
		ChildPath:   "/0/15",
		FullPath:    "m/44'/60'/0'/0/15",
	}
}

func newSecp256k1SigningShare(t *testing.T) ecdsakeygen.LocalPartySaveData {
	t.Helper()
	pub := crypto.ScalarBaseMult(tsslib.S256(), big.NewInt(5))
	xj := crypto.ScalarBaseMult(tsslib.S256(), big.NewInt(7))
	if pub == nil || xj == nil {
		t.Fatal("expected secp256k1 test points")
	}
	return ecdsakeygen.LocalPartySaveData{
		ECDSAPub: pub,
		BigXj:    []*crypto.ECPoint{xj},
	}
}

func newDerivedECDSAStubRunner(t *testing.T, keyID string) *stubRunner {
	t.Helper()
	share := newSecp256k1SigningShare(t)
	return &stubRunner{
		shareByKey: map[string]ecdsakeygen.LocalPartySaveData{
			keyID: share,
		},
		materialByKey: map[string]coreshares.ECDSAKeyMaterial{
			keyID: {
				Share:            share,
				ChainCode:        bytes.Repeat([]byte{0x11}, 32),
				PublicKeyFormat:  corederivation.PublicKeyFormatUncompressedHex,
				DerivationScheme: corederivation.DerivationSchemeBIP32Secp256k1,
			},
		},
	}
}

func shareReaderForMaterial(t *testing.T, material coreshares.ECDSAKeyMaterial) ShareReader {
	t.Helper()
	blob, err := coreshares.MarshalKeyMaterial(material)
	if err != nil {
		t.Fatalf("MarshalKeyMaterial() error = %v", err)
	}
	return staticShareReader{stored: &coreshares.StoredShare{Blob: blob}}
}

func TestRunSignSession_RequiresShareReaderBeforeRunnerStart(t *testing.T) {
	runner := newDerivedECDSAStubRunner(t, "key-1")
	hash, err := corederivation.HashV1(validServiceDerivationContext())
	if err != nil {
		t.Fatalf("HashV1 returned error: %v", err)
	}
	svc := New(runner, newTestLogger(), &stubLifecyclePool{}, nil, nil)

	err = svc.RunSignSession(context.Background(), SignInput{
		SessionID:             "sign-1",
		LocalPartyID:          "p1",
		OrgID:                 "org",
		KeyID:                 "key-1",
		Parties:               []string{"p1", "p2"},
		Digest:                []byte{1, 2, 3},
		Algorithm:             "ecdsa",
		Curve:                 "secp256k1",
		DerivationContext:     validServiceDerivationContext(),
		DerivationContextHash: hash,
		EmptyKeyErr:           errShareMissing,
	})
	if !errors.Is(err, ErrShareReaderRequired) {
		t.Fatalf("RunSignSession() error = %v, want ErrShareReaderRequired", err)
	}
	if runner.lastSignJob.SessionID != "" {
		t.Fatalf("runner started unexpectedly: %+v", runner.lastSignJob)
	}
}

func TestRunSignSession_PreparesDerivedECDSAShareLoadedByReader(t *testing.T) {
	runner := newDerivedECDSAStubRunner(t, "key-1")
	reader := shareReaderForMaterial(t, runner.materialByKey["key-1"])
	svc := New(runner, newTestLogger(), &stubLifecyclePool{}, reader, nil)
	hash, err := corederivation.HashV1(validServiceDerivationContext())
	if err != nil {
		t.Fatalf("HashV1() error = %v", err)
	}

	err = svc.RunSignSession(context.Background(), SignInput{
		SessionID:             "sign-1",
		LocalPartyID:          "p1",
		OrgID:                 "org",
		KeyID:                 "key-1",
		Parties:               []string{"p1", "p2"},
		Digest:                []byte{1, 2, 3},
		Algorithm:             "ecdsa",
		Curve:                 "secp256k1",
		DerivationContext:     validServiceDerivationContext(),
		DerivationContextHash: hash,
		EmptyKeyErr:           errShareMissing,
	})
	if err != nil {
		t.Fatalf("RunSignSession() error = %v", err)
	}
	if runner.lastSignJob.KeyDerivationDelta == nil {
		t.Fatal("runner did not receive the derived share")
	}
}

func TestRunSignSession_DerivationContextHashMismatchFailsBeforeRunnerStart(t *testing.T) {
	runner := newDerivedECDSAStubRunner(t, "key-1")
	svc := New(runner, newTestLogger(), &stubLifecyclePool{}, shareReaderForMaterial(t, runner.materialByKey["key-1"]), nil)

	err := svc.RunSignSession(context.Background(), SignInput{
		SessionID:             "sign-1",
		LocalPartyID:          "p1",
		OrgID:                 "org",
		KeyID:                 "key-1",
		Parties:               []string{"p1", "p2"},
		Digest:                []byte{1, 2, 3},
		Algorithm:             "ecdsa",
		Curve:                 "secp256k1",
		DerivationContext:     validServiceDerivationContext(),
		DerivationContextHash: "not-the-normalized-context-hash",
		EmptyKeyErr:           errShareMissing,
	})
	if !errors.Is(err, corederivation.ErrDerivationContextMismatch) {
		t.Fatalf("expected ErrDerivationContextMismatch, got %v", err)
	}
	if runner.lastSignJob.SessionID != "" {
		t.Fatalf("runner started unexpectedly: %+v", runner.lastSignJob)
	}
}

func TestRunSignSession_ReservedEdDSAReturnsUnsupportedBeforeRunnerStart(t *testing.T) {
	runner := &stubRunner{}
	svc := New(runner, newTestLogger(), &stubLifecyclePool{}, nil, nil)

	err := svc.RunSignSession(context.Background(), SignInput{
		SessionID:    "sign-eddsa",
		LocalPartyID: "p1",
		OrgID:        "org",
		KeyID:        "key-eddsa",
		Parties:      []string{"p1", "p2"},
		Digest:       []byte{1, 2, 3},
		Algorithm:    "eddsa",
		Curve:        "ed25519",
		DerivationContext: corederivation.Context{
			ProfileID:   "profile-1",
			Algorithm:   "eddsa",
			Curve:       "ed25519",
			Scheme:      "slip10_ed25519",
			AccountPath: "m/44'/501'/0'",
			ChildPath:   "/0/0",
			FullPath:    "m/44'/501'/0'/0/0",
		},
	})
	if !errors.Is(err, corederivation.ErrDerivedSigningUnsupported) {
		t.Fatalf("expected ErrDerivedSigningUnsupported, got %v", err)
	}
	if runner.lastSignJob.SessionID != "" {
		t.Fatalf("runner started unexpectedly: %+v", runner.lastSignJob)
	}
}
