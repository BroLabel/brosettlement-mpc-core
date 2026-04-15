package service

import (
	"context"
	"crypto/elliptic"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"testing"

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

func TestRunDKGSession_ReturnsOutputBeforeCleanup(t *testing.T) {
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
	if out.KeyID != "key-1" {
		t.Fatalf("expected key id key-1, got %q", out.KeyID)
	}
	if out.PublicKey == "" || out.Address == "" {
		t.Fatalf("expected populated output, got %+v", out)
	}
	if len(runner.deletedKeys) != 0 {
		t.Fatalf("expected no cleanup without store, got %+v", runner.deletedKeys)
	}
}
