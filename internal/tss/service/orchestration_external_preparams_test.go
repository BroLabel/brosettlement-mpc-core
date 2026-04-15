package service

import (
	"context"
	"io"
	"log/slog"
	"testing"

	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
	coretransport "github.com/BroLabel/brosettlement-mpc-core/transport"
	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type stubRunner struct {
	lastDKGJob tssbnbrunner.DKGJob
}

func (r *stubRunner) RunDKG(_ context.Context, job tssbnbrunner.DKGJob, _ coretransport.FrameTransport) error {
	r.lastDKGJob = job
	return nil
}

func (r *stubRunner) RunSign(context.Context, tssbnbrunner.SignJob, coretransport.FrameTransport) error {
	return nil
}

func (r *stubRunner) ExportECDSASignature(string) (common.SignatureData, error) {
	return common.SignatureData{}, nil
}

func (r *stubRunner) ExportECDSAKeyShare(string) (ecdsakeygen.LocalPartySaveData, error) {
	return ecdsakeygen.LocalPartySaveData{}, nil
}

func (r *stubRunner) ImportECDSAKeyShare(string, ecdsakeygen.LocalPartySaveData) {}

func (r *stubRunner) DeleteECDSAKeyShare(string) {}

func (r *stubRunner) ECDSAAddress(string) (string, error) {
	return "", nil
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

	runner := &stubRunner{}
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	externalSource := &stubPreParamsSource{preParams: &ecdsakeygen.LocalPreParams{}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := New(runner, logger, internalPool, nil, externalSource)

	_, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-1",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
	})
	if err != nil {
		t.Fatalf("RunDKGSession returned error: %v", err)
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

	runner := &stubRunner{}
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := New(runner, logger, internalPool, nil)

	_, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-2",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
	})
	if err != nil {
		t.Fatalf("RunDKGSession returned error: %v", err)
	}
	if runner.lastDKGJob.ECDSAPreParams != internalPool.preParams {
		t.Fatalf("expected internal pool preparams to be attached")
	}
	if internalPool.acquires != 1 {
		t.Fatalf("expected internal pool Acquire to be called once, got %d", internalPool.acquires)
	}
}
