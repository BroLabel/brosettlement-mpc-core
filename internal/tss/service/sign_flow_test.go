package service

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	corederivation "github.com/BroLabel/brosettlement-mpc-core/internal/tss/derivation"
	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
	"github.com/bnb-chain/tss-lib/crypto"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

func TestPrepareShareForSign_SkipsWhenStoreMissing(t *testing.T) {
	t.Parallel()

	runner := newECDSAStubRunner(t, "key-1")
	cleanup, err := prepareShareForSign(context.Background(), nil, runner, tssbnbrunner.SignJob{
		KeyID:     "key-1",
		OrgID:     "org",
		Algorithm: "ecdsa",
	}, errShareMissing, errShareMissing)
	if err != nil {
		t.Fatalf("prepareShareForSign returned error: %v", err)
	}
	cleanup()
	if len(runner.deletedKeys) != 0 {
		t.Fatalf("expected noop cleanup without store, got %+v", runner.deletedKeys)
	}
}

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

func TestRunSignSession_PreparesDerivedECDSAShareBeforeRunnerStart(t *testing.T) {
	runner := newDerivedECDSAStubRunner(t, "key-1")
	runner.requireShareForSign = true
	hash, err := corederivation.HashV1(validServiceDerivationContext())
	if err != nil {
		t.Fatalf("HashV1 returned error: %v", err)
	}
	svc := New(runner, newTestLogger(), &stubLifecyclePool{}, nil)

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
		MetadataMismatch:      errShareMissing,
	})
	if err != nil {
		t.Fatalf("RunSignSession returned error: %v", err)
	}
	if runner.lastSignJob.KeyDerivationDelta == nil {
		t.Fatal("expected runner sign job to receive key derivation delta")
	}
	if runner.lastSignJob.DerivationContextHash != hash {
		t.Fatalf("DerivationContextHash = %q", runner.lastSignJob.DerivationContextHash)
	}
}

func TestRunSignSession_MissingChainCodeFailsBeforeRunnerStart(t *testing.T) {
	runner := newDerivedECDSAStubRunner(t, "key-1")
	material := runner.materialByKey["key-1"]
	material.ChainCode = nil
	runner.materialByKey["key-1"] = material
	svc := New(runner, newTestLogger(), &stubLifecyclePool{}, nil)

	err := svc.RunSignSession(context.Background(), SignInput{
		SessionID:         "sign-1",
		LocalPartyID:      "p1",
		OrgID:             "org",
		KeyID:             "key-1",
		Parties:           []string{"p1", "p2"},
		Digest:            []byte{1, 2, 3},
		Algorithm:         "ecdsa",
		Curve:             "secp256k1",
		DerivationContext: validServiceDerivationContext(),
		EmptyKeyErr:       errShareMissing,
		MetadataMismatch:  errShareMissing,
	})
	if !errors.Is(err, corederivation.ErrChainCodeMissing) {
		t.Fatalf("expected ErrChainCodeMissing, got %v", err)
	}
	if runner.lastSignJob.SessionID != "" {
		t.Fatalf("runner started unexpectedly: %+v", runner.lastSignJob)
	}
}

func TestRunSignSession_DerivationContextHashMismatchFailsBeforeRunnerStart(t *testing.T) {
	runner := newDerivedECDSAStubRunner(t, "key-1")
	svc := New(runner, newTestLogger(), &stubLifecyclePool{}, nil)

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
		MetadataMismatch:      errShareMissing,
	})
	if !errors.Is(err, corederivation.ErrDerivationContextMismatch) {
		t.Fatalf("expected ErrDerivationContextMismatch, got %v", err)
	}
	if runner.lastSignJob.SessionID != "" {
		t.Fatalf("runner started unexpectedly: %+v", runner.lastSignJob)
	}
}

func TestRunSignSession_CurveMetadataMismatchFailsBeforeRunnerStart(t *testing.T) {
	runner := newDerivedECDSAStubRunner(t, "key-1")
	material := runner.materialByKey["key-1"]
	blob, err := coreshares.MarshalKeyMaterial(material)
	if err != nil {
		t.Fatalf("MarshalKeyMaterial returned error: %v", err)
	}
	store := staticShareStore{stored: &coreshares.StoredShare{
		Blob: blob,
		Meta: coreshares.ShareMeta{
			KeyID:     "key-1",
			OrgID:     "org",
			Algorithm: "ecdsa",
			Curve:     "p256",
		},
	}}
	svc := New(runner, newTestLogger(), &stubLifecyclePool{}, store)

	err = svc.RunSignSession(context.Background(), SignInput{
		SessionID:         "sign-1",
		LocalPartyID:      "p1",
		OrgID:             "org",
		KeyID:             "key-1",
		Parties:           []string{"p1", "p2"},
		Digest:            []byte{1, 2, 3},
		Algorithm:         "ecdsa",
		Curve:             "secp256k1",
		DerivationContext: validServiceDerivationContext(),
		EmptyKeyErr:       errShareMissing,
		MetadataMismatch:  errShareMissing,
	})
	if !errors.Is(err, errShareMissing) {
		t.Fatalf("expected metadata mismatch, got %v", err)
	}
	if runner.lastSignJob.SessionID != "" {
		t.Fatalf("runner started unexpectedly: %+v", runner.lastSignJob)
	}
}

func TestRunSignSession_ReservedEdDSAReturnsUnsupportedBeforeRunnerStart(t *testing.T) {
	runner := &stubRunner{}
	svc := New(runner, newTestLogger(), &stubLifecyclePool{}, nil)

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
