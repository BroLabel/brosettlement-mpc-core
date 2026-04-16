package service

import (
	"context"
	"crypto/elliptic"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"testing"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
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
