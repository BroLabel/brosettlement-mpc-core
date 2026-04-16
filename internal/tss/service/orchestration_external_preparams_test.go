package service

import (
	"context"
	"crypto/elliptic"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"reflect"
	"testing"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
	tssbnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/utils"
	coretransport "github.com/BroLabel/brosettlement-mpc-core/transport"
	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

var (
	errMissingPublicKey = errors.New("missing public key")
	errMissingAddress   = errors.New("missing address")
	errPersistFailed    = errors.New("persist failed")
	errShareMissing     = errors.New("share missing")
)

type stubRunner struct {
	lastDKGJob          tssbnbrunner.DKGJob
	lastSignJob         tssbnbrunner.SignJob
	shareByKey          map[string]ecdsakeygen.LocalPartySaveData
	exportedKeys        []string
	deletedKeys         []string
	events              []string
	requireShareForSign bool
	signatureExported   bool
}

func (r *stubRunner) ExportECDSAKeyShare(key string) (ecdsakeygen.LocalPartySaveData, error) {
	r.events = append(r.events, "export:"+key)
	r.exportedKeys = append(r.exportedKeys, key)
	share, ok := r.shareByKey[key]
	if !ok {
		return ecdsakeygen.LocalPartySaveData{}, errShareMissing
	}
	return share, nil
}

func (r *stubRunner) DeleteECDSAKeyShare(key string) {
	r.events = append(r.events, "cleanup:"+key)
	r.deletedKeys = append(r.deletedKeys, key)
	delete(r.shareByKey, key)
}

func (r *stubRunner) RunDKG(_ context.Context, job tssbnbrunner.DKGJob, _ coretransport.FrameTransport) error {
	r.lastDKGJob = job
	return nil
}

func (r *stubRunner) RunSign(_ context.Context, job tssbnbrunner.SignJob, _ coretransport.FrameTransport) error {
	r.lastSignJob = job
	if r.requireShareForSign {
		if _, ok := r.shareByKey[job.KeyID]; !ok {
			if _, ok := r.shareByKey[job.SessionID]; !ok {
				return errShareMissing
			}
		}
	}
	return nil
}

func (r *stubRunner) ExportECDSASignature(string) (common.SignatureData, error) {
	r.signatureExported = true
	return common.SignatureData{}, nil
}

func (r *stubRunner) ImportECDSAKeyShare(key string, data ecdsakeygen.LocalPartySaveData) {
	if r.shareByKey == nil {
		r.shareByKey = map[string]ecdsakeygen.LocalPartySaveData{}
	}
	r.shareByKey[key] = data
}

func (r *stubRunner) ECDSAAddress(string) (string, error) {
	return "", nil
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newECDSATestShare(t *testing.T) ecdsakeygen.LocalPartySaveData {
	t.Helper()
	pub := crypto.ScalarBaseMult(elliptic.P256(), big.NewInt(1))
	if pub == nil {
		t.Fatal("expected test public key point")
	}
	return ecdsakeygen.LocalPartySaveData{ECDSAPub: pub}
}

func newECDSATestShareWithCurve(t *testing.T, curve elliptic.Curve) ecdsakeygen.LocalPartySaveData {
	t.Helper()
	pub := crypto.ScalarBaseMult(curve, big.NewInt(1))
	if pub == nil {
		t.Fatal("expected test public key point")
	}
	return ecdsakeygen.LocalPartySaveData{ECDSAPub: pub}
}

func newECDSAStubRunner(t *testing.T, sessionID string) *stubRunner {
	t.Helper()
	share := newECDSATestShare(t)
	return &stubRunner{
		shareByKey: map[string]ecdsakeygen.LocalPartySaveData{
			sessionID: share,
		},
	}
}

func newECDSAStubRunnerWithoutPub(t *testing.T, sessionID string) *stubRunner {
	t.Helper()
	return &stubRunner{
		shareByKey: map[string]ecdsakeygen.LocalPartySaveData{
			sessionID: {},
		},
	}
}

type stubLifecyclePool struct {
	preParams *ecdsakeygen.LocalPreParams
	acquires  int
}

func (p *stubLifecyclePool) Acquire(context.Context) (*ecdsakeygen.LocalPreParams, error) {
	p.acquires++
	return p.preParams, nil
}

func (p *stubLifecyclePool) Size() int {
	return 0
}

func (p *stubLifecyclePool) Start(context.Context) error {
	return nil
}

func (p *stubLifecyclePool) Close() error {
	return nil
}

type stubPreParamsSource struct {
	preParams *ecdsakeygen.LocalPreParams
	acquires  int
}

func (s *stubPreParamsSource) Acquire(context.Context) (*ecdsakeygen.LocalPreParams, error) {
	s.acquires++
	return s.preParams, nil
}

type recordingShareStore struct {
	savedKeyID string
	savedBlob  []byte
	savedMeta  coreshares.ShareMeta
	runner     *stubRunner
	sessionID  string
}

func (s *recordingShareStore) SaveShare(_ context.Context, keyID string, blob []byte, meta coreshares.ShareMeta) error {
	s.runner.events = append(s.runner.events, "persist:"+keyID)
	if _, ok := s.runner.shareByKey[s.sessionID]; !ok {
		return errors.New("share cleaned before persist")
	}
	s.savedKeyID = keyID
	s.savedBlob = append([]byte(nil), blob...)
	s.savedMeta = meta
	return nil
}

func (s *recordingShareStore) LoadShare(context.Context, string) (*coreshares.StoredShare, error) {
	return nil, coreshares.ErrShareNotFound
}

type failingShareStore struct {
	err error
}

func (s *failingShareStore) SaveShare(context.Context, string, []byte, coreshares.ShareMeta) error {
	return s.err
}

func (s *failingShareStore) LoadShare(context.Context, string) (*coreshares.StoredShare, error) {
	return nil, coreshares.ErrShareNotFound
}

func TestRunDKGSession_UsesExternalPreParamsSourceWhenProvided(t *testing.T) {
	t.Parallel()

	runner := newECDSAStubRunner(t, "session-1")
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	externalSource := &stubPreParamsSource{preParams: &ecdsakeygen.LocalPreParams{}}
	logger := newTestLogger()
	svc := New(runner, logger, internalPool, nil, externalSource)

	output, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-1",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		MissingPub:   errMissingPublicKey,
		MissingAddr:  errMissingAddress,
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

	runner := newECDSAStubRunner(t, "session-2")
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	logger := newTestLogger()
	svc := New(runner, logger, internalPool, nil)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-2",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		MissingPub:   errMissingPublicKey,
		MissingAddr:  errMissingAddress,
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
		SessionID:    "session-1",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		MissingPub:   errMissingPublicKey,
		MissingAddr:  errMissingAddress,
	})
	if !errors.Is(err, errMissingPublicKey) {
		t.Fatalf("expected missing public key error, got %v", err)
	}
	if out != (DKGOutput{}) {
		t.Fatalf("expected zero output on error, got %+v", out)
	}
}

func TestRunDKGSession_ReturnsRawAddressDerivationError(t *testing.T) {
	runner := &stubRunner{
		shareByKey: map[string]ecdsakeygen.LocalPartySaveData{
			"session-1": newECDSATestShareWithCurve(t, elliptic.P224()),
		},
	}
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(runner, logger, internalPool, nil)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-1",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		MissingPub:   errMissingPublicKey,
		MissingAddr:  errMissingAddress,
	})
	if !errors.Is(err, tssbnbutils.ErrECDSAPubKeyUnavailable) {
		t.Fatalf("expected raw address derivation error, got %v", err)
	}
	if out != (DKGOutput{}) {
		t.Fatalf("expected zero output on error, got %+v", out)
	}
}

func TestRunDKGSession_NormalizesECDSAKeyIDToSessionIDBeforeCleanup(t *testing.T) {
	runner := newECDSAStubRunner(t, "session-1")
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(runner, logger, internalPool, nil)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-1",
		KeyID:        "key-1",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		MissingPub:   errMissingPublicKey,
		MissingAddr:  errMissingAddress,
	})
	if err != nil {
		t.Fatalf("RunDKGSession returned error: %v", err)
	}
	if out.KeyID != "session-1" {
		t.Fatalf("expected key id to normalize to session id, got %q", out.KeyID)
	}
	if out.PublicKey == "" || out.Address == "" {
		t.Fatalf("expected populated output, got %+v", out)
	}
	if len(runner.deletedKeys) != 0 {
		t.Fatalf("expected no cleanup without store, got %+v", runner.deletedKeys)
	}
}

func TestRunDKGSession_PersistsShareAfterOutputExtraction(t *testing.T) {
	runner := newECDSAStubRunner(t, "session-1")
	store := &recordingShareStore{runner: runner, sessionID: "session-1"}
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(runner, logger, internalPool, store)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-1",
		KeyID:        "key-1",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		MissingPub:   errMissingPublicKey,
		MissingAddr:  errMissingAddress,
	})
	if err != nil {
		t.Fatalf("RunDKGSession returned error: %v", err)
	}
	if out.KeyID != "session-1" {
		t.Fatalf("expected key id to normalize to session id, got %q", out.KeyID)
	}
	if len(store.savedBlob) == 0 {
		t.Fatal("expected share to be persisted")
	}
	if store.savedKeyID != "session-1" {
		t.Fatalf("expected persisted key id session-1, got %q", store.savedKeyID)
	}
	if store.savedMeta.KeyID != "session-1" {
		t.Fatalf("expected persisted metadata key id session-1, got %q", store.savedMeta.KeyID)
	}
	wantEvents := []string{"export:session-1", "persist:session-1", "cleanup:session-1"}
	if !reflect.DeepEqual(runner.events, wantEvents) {
		t.Fatalf("expected events %v, got %v", wantEvents, runner.events)
	}
	if len(runner.deletedKeys) != 1 || runner.deletedKeys[0] != "session-1" {
		t.Fatalf("expected session share cleanup, got %+v", runner.deletedKeys)
	}
}

func TestRunDKGSession_PersistFailureKeepsRunnerShare(t *testing.T) {
	runner := newECDSAStubRunner(t, "session-1")
	store := &failingShareStore{err: errPersistFailed}
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(runner, logger, internalPool, store)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-1",
		KeyID:        "key-1",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		MissingPub:   errMissingPublicKey,
		MissingAddr:  errMissingAddress,
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
	runner := newECDSAStubRunner(t, "key-1")
	runner.requireShareForSign = true
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(runner, logger, internalPool, nil)

	if _, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "key-1",
		KeyID:        "key-1",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		MissingPub:   errMissingPublicKey,
		MissingAddr:  errMissingAddress,
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

func TestBuildECDSADKGOutput(t *testing.T) {
	t.Parallel()

	runner := newECDSAStubRunner(t, "session-1")
	out, share, err := buildECDSADKGOutput(runner, DKGInput{
		SessionID:   "session-1",
		MissingPub:  errMissingPublicKey,
		MissingAddr: errMissingAddress,
	}, "key-1")
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
