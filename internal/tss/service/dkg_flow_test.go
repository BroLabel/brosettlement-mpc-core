package service

import (
	"context"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

func validDKGMaterial() DKGDerivationMaterial {
	return DKGDerivationMaterial{
		ChainCode:        strings.Repeat("11", 32),
		DerivationScheme: "bip32_secp256k1",
	}
}

func newECDSASecp256k1StubRunner(t *testing.T, sessionID string) *stubRunner {
	t.Helper()
	share := newECDSATestShareWithCurve(t, tsslib.S256())
	return &stubRunner{
		shareByKey: map[string]ecdsakeygen.LocalPartySaveData{
			sessionID: share,
		},
	}
}

func TestRunDKGSession_UsesExternalPreParamsSourceWhenProvided(t *testing.T) {
	t.Parallel()

	runner := newECDSASecp256k1StubRunner(t, "session-1")
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	externalSource := &stubPreParamsSource{preParams: &ecdsakeygen.LocalPreParams{}}
	logger := newTestLogger()
	svc := New(runner, logger, internalPool, nil, externalSource)

	output, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:          "session-1",
		KeyID:              "session-1",
		LocalPartyID:       "p1",
		OrgID:              "org",
		Parties:            []string{"p1", "p2"},
		Threshold:          1,
		Algorithm:          "ecdsa",
		DerivationMaterial: validDKGMaterial(),
		MissingPub:         errMissingPublicKey,
		MissingAddr:        errMissingAddress,
	})
	if err != nil {
		t.Fatalf("RunDKGSession returned error: %v", err)
	}
	if output.KeyID != "session-1" || output.PublicKey == "" || output.Address == "" {
		t.Fatalf("expected populated ecdsa output, got %+v", output)
	}
	if runner.lastDKGJob.ECDSAPreParams != externalSource.preParams {
		t.Fatalf("expected external source preparams to be attached")
	}
	if externalSource.acquires != 1 {
		t.Fatalf("expected external source Acquire to be called once, got %d", externalSource.acquires)
	}
	if internalPool.acquires != 0 {
		t.Fatalf("expected internal pool Acquire not to be called, got %d", internalPool.acquires)
	}
}

func TestRunDKGSession_UsesInternalPoolWhenExternalPreParamsSourceMissing(t *testing.T) {
	t.Parallel()

	runner := newECDSASecp256k1StubRunner(t, "session-2")
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	logger := newTestLogger()
	svc := New(runner, logger, internalPool, nil)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:          "session-2",
		KeyID:              "session-2",
		LocalPartyID:       "p1",
		OrgID:              "org",
		Parties:            []string{"p1", "p2"},
		Threshold:          1,
		Algorithm:          "ecdsa",
		DerivationMaterial: validDKGMaterial(),
		MissingPub:         errMissingPublicKey,
		MissingAddr:        errMissingAddress,
	})
	if err != nil {
		t.Fatalf("RunDKGSession returned error: %v", err)
	}
	if out.KeyID != "session-2" || out.PublicKey == "" || out.Address == "" {
		t.Fatalf("expected populated ecdsa output, got %+v", out)
	}
	if runner.lastDKGJob.ECDSAPreParams != internalPool.preParams {
		t.Fatalf("expected internal pool preparams to be attached")
	}
	if internalPool.acquires != 1 {
		t.Fatalf("expected internal pool Acquire to be called once, got %d", internalPool.acquires)
	}
}

func TestRunDKGSession_ReturnsMissingPublicKeyError(t *testing.T) {
	runner := newECDSAStubRunnerWithoutPub(t, "session-1")
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(runner, logger, internalPool, nil)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:          "session-1",
		KeyID:              "session-1",
		LocalPartyID:       "p1",
		OrgID:              "org",
		Parties:            []string{"p1", "p2"},
		Threshold:          1,
		Algorithm:          "ecdsa",
		DerivationMaterial: validDKGMaterial(),
		MissingPub:         errMissingPublicKey,
		MissingAddr:        errMissingAddress,
	})
	if !errors.Is(err, errMissingPublicKey) {
		t.Fatalf("expected missing public key error, got %v", err)
	}
	if out != (DKGOutput{}) {
		t.Fatalf("expected zero output on error, got %+v", out)
	}
}

func TestRunDKGSession_ReturnsMissingPublicKeyForNonSecp256k1Share(t *testing.T) {
	runner := &stubRunner{
		shareByKey: map[string]ecdsakeygen.LocalPartySaveData{
			"session-1": newECDSATestShareWithCurve(t, elliptic.P224()),
		},
	}
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(runner, logger, internalPool, nil)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:          "session-1",
		KeyID:              "session-1",
		LocalPartyID:       "p1",
		OrgID:              "org",
		Parties:            []string{"p1", "p2"},
		Threshold:          1,
		Algorithm:          "ecdsa",
		DerivationMaterial: validDKGMaterial(),
		MissingPub:         errMissingPublicKey,
		MissingAddr:        errMissingAddress,
	})
	if !errors.Is(err, errMissingPublicKey) {
		t.Fatalf("expected missing public key error, got %v", err)
	}
	if out != (DKGOutput{}) {
		t.Fatalf("expected zero output on error, got %+v", out)
	}
}

func TestRunDKGSession_UsesExplicitECDSAKeyIDBeforeCleanup(t *testing.T) {
	runner := newECDSASecp256k1StubRunner(t, "session-1")
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(runner, logger, internalPool, nil)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:          "session-1",
		KeyID:              "key-1",
		LocalPartyID:       "p1",
		OrgID:              "org",
		Parties:            []string{"p1", "p2"},
		Threshold:          1,
		Algorithm:          "ecdsa",
		DerivationMaterial: validDKGMaterial(),
		MissingPub:         errMissingPublicKey,
		MissingAddr:        errMissingAddress,
	})
	if err != nil {
		t.Fatalf("RunDKGSession returned error: %v", err)
	}
	if out.KeyID != "key-1" {
		t.Fatalf("expected explicit key id, got %q", out.KeyID)
	}
	if out.PublicKey == "" || out.Address == "" {
		t.Fatalf("expected populated output, got %+v", out)
	}
	if len(runner.deletedKeys) != 0 {
		t.Fatalf("expected no cleanup without store, got %+v", runner.deletedKeys)
	}
}

func TestRunDKGSession_PersistsShareAfterOutputExtraction(t *testing.T) {
	runner := newECDSASecp256k1StubRunner(t, "session-1")
	store := &recordingShareStore{runner: runner, sessionID: "session-1"}
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(runner, logger, internalPool, store)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:          "session-1",
		KeyID:              "key-1",
		LocalPartyID:       "p1",
		OrgID:              "org",
		Parties:            []string{"p1", "p2"},
		Threshold:          1,
		Algorithm:          "ecdsa",
		DerivationMaterial: validDKGMaterial(),
		MissingPub:         errMissingPublicKey,
		MissingAddr:        errMissingAddress,
	})
	if err != nil {
		t.Fatalf("RunDKGSession returned error: %v", err)
	}
	if out.KeyID != "key-1" {
		t.Fatalf("expected explicit key id, got %q", out.KeyID)
	}
	if len(store.savedBlob) == 0 {
		t.Fatal("expected share to be persisted")
	}
	if store.savedKeyID != "key-1" {
		t.Fatalf("expected persisted key id key-1, got %q", store.savedKeyID)
	}
	if store.savedMeta.KeyID != "key-1" {
		t.Fatalf("expected persisted metadata key id key-1, got %q", store.savedMeta.KeyID)
	}
	wantEvents := []string{"export:session-1", "persist:key-1", "cleanup:session-1"}
	if !reflect.DeepEqual(runner.events, wantEvents) {
		t.Fatalf("expected events %v, got %v", wantEvents, runner.events)
	}
	if len(runner.deletedKeys) != 1 || runner.deletedKeys[0] != "session-1" {
		t.Fatalf("expected session share cleanup, got %+v", runner.deletedKeys)
	}
}

func TestRunDKGSession_PersistFailureKeepsRunnerShare(t *testing.T) {
	runner := newECDSASecp256k1StubRunner(t, "session-1")
	store := &failingShareStore{err: errPersistFailed}
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(runner, logger, internalPool, store)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:          "session-1",
		KeyID:              "key-1",
		LocalPartyID:       "p1",
		OrgID:              "org",
		Parties:            []string{"p1", "p2"},
		Threshold:          1,
		Algorithm:          "ecdsa",
		DerivationMaterial: validDKGMaterial(),
		MissingPub:         errMissingPublicKey,
		MissingAddr:        errMissingAddress,
	})
	if !errors.Is(err, errPersistFailed) {
		t.Fatalf("expected persist failure, got %v", err)
	}
	if out != (DKGOutput{}) {
		t.Fatalf("expected zero output on persist failure, got %+v", out)
	}
	if _, ok := runner.shareByKey["session-1"]; !ok {
		t.Fatal("expected runner share to remain after persist failure")
	}
	if len(runner.deletedKeys) != 0 {
		t.Fatalf("expected no cleanup on persist failure, got %+v", runner.deletedKeys)
	}
}

func TestRunDKGThenSign_NoStoreKeepsRunnerShare(t *testing.T) {
	runner := newECDSASecp256k1StubRunner(t, "key-1")
	runner.requireShareForSign = true
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(runner, logger, internalPool, nil)

	if _, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:          "key-1",
		KeyID:              "key-1",
		LocalPartyID:       "p1",
		OrgID:              "org",
		Parties:            []string{"p1", "p2"},
		Threshold:          1,
		Algorithm:          "ecdsa",
		DerivationMaterial: validDKGMaterial(),
		MissingPub:         errMissingPublicKey,
		MissingAddr:        errMissingAddress,
	}); err != nil {
		t.Fatalf("RunDKGSession returned error: %v", err)
	}
	if err := svc.RunSignSession(context.Background(), SignInput{
		SessionID:    "sign-1",
		KeyID:        "key-1",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Digest:       []byte{1, 2, 3},
		Algorithm:    "ecdsa",
	}); err != nil {
		t.Fatalf("expected in-memory sign to keep working, got %v", err)
	}
	if len(runner.deletedKeys) != 0 {
		t.Fatalf("expected no cleanup without store, got %+v", runner.deletedKeys)
	}
}

func TestRunDKGSession_EdDSAReturnsKeyIDOnly(t *testing.T) {
	runner := &stubRunner{}
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{}
	svc := New(runner, logger, internalPool, nil)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-eddsa",
		KeyID:        "key-eddsa",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "eddsa",
	})
	if err != nil {
		t.Fatalf("RunDKGSession returned error: %v", err)
	}
	if out != (DKGOutput{KeyID: "key-eddsa"}) {
		t.Fatalf("expected key-only eddsa output, got %+v", out)
	}
	if len(runner.exportedKeys) != 0 || len(runner.deletedKeys) != 0 {
		t.Fatalf("expected eddsa path to skip ecdsa share handling, got exports=%v deletes=%v", runner.exportedKeys, runner.deletedKeys)
	}
}

func TestRunDKGSession_ECDSAOutputIncludesSuppliedDerivationMaterial(t *testing.T) {
	chainCode := strings.Repeat("11", 32)
	runner := newECDSASecp256k1StubRunner(t, "session-1")
	store := &recordingShareStore{runner: runner, sessionID: "session-1"}
	svc := New(runner, newTestLogger(), &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}, store)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-1",
		LocalPartyID: "p1",
		OrgID:        "org",
		KeyID:        "key-1",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		Curve:        "secp256k1",
		DerivationMaterial: DKGDerivationMaterial{
			ChainCode:        chainCode,
			DerivationScheme: "bip32_secp256k1",
		},
		MissingPub:  errMissingPublicKey,
		MissingAddr: errMissingAddress,
	})
	if err != nil {
		t.Fatalf("RunDKGSession returned error: %v", err)
	}
	if out.KeyID != "key-1" {
		t.Fatalf("KeyID = %q", out.KeyID)
	}
	if out.ChainCode != chainCode {
		t.Fatalf("ChainCode = %q", out.ChainCode)
	}
	if out.PublicKeyFormat != "uncompressed_hex" {
		t.Fatalf("PublicKeyFormat = %q", out.PublicKeyFormat)
	}
	if out.DerivationScheme != "bip32_secp256k1" {
		t.Fatalf("DerivationScheme = %q", out.DerivationScheme)
	}
	material, err := coreshares.UnmarshalKeyMaterial(store.savedBlob)
	if err != nil {
		t.Fatalf("UnmarshalKeyMaterial returned error: %v", err)
	}
	if hex.EncodeToString(material.ChainCode) != chainCode {
		t.Fatalf("persisted chain code mismatch: %x", material.ChainCode)
	}
	if store.savedKeyID != "key-1" {
		t.Fatalf("persisted key id = %q", store.savedKeyID)
	}
	if store.savedMeta.Version != 2 {
		t.Fatalf("persisted metadata version = %d", store.savedMeta.Version)
	}
	if !store.savedMeta.ChainCodePresent {
		t.Fatal("expected persisted metadata to record chain code presence")
	}
	if store.savedMeta.PublicKeyFormat != "uncompressed_hex" {
		t.Fatalf("persisted metadata public key format = %q", store.savedMeta.PublicKeyFormat)
	}
	if store.savedMeta.DerivationScheme != "bip32_secp256k1" {
		t.Fatalf("persisted metadata derivation scheme = %q", store.savedMeta.DerivationScheme)
	}
}

func TestBuildECDSADKGOutput(t *testing.T) {
	t.Parallel()

	runner := newECDSASecp256k1StubRunner(t, "session-1")
	out, share, err := buildECDSADKGOutput(runner, DKGInput{
		SessionID:   "session-1",
		MissingPub:  errMissingPublicKey,
		MissingAddr: errMissingAddress,
	}, "key-1", normalizedDKGMaterial{
		ChainCode:    []byte(strings.Repeat("\x11", 32)),
		ChainCodeHex: strings.Repeat("11", 32),
		Scheme:       "bip32_secp256k1",
	})
	if err != nil {
		t.Fatalf("buildECDSADKGOutput returned error: %v", err)
	}
	if out.KeyID != "key-1" || out.PublicKey == "" || out.Address == "" {
		t.Fatalf("expected populated output, got %+v", out)
	}
	if reflect.DeepEqual(share, ecdsakeygen.LocalPartySaveData{}) {
		t.Fatal("expected returned share to be populated")
	}
}
