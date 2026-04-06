package tss

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	bnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/support"
	"github.com/BroLabel/brosettlement-mpc-core/protocol"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type noopTransport struct{}

func (noopTransport) SendFrame(_ context.Context, _ protocol.Frame) error { return nil }

func (noopTransport) RecvFrame(_ context.Context) (protocol.Frame, error) {
	return protocol.Frame{}, errors.New("not implemented")
}

func TestDKGSessionRequestValidateRequiresTransport(t *testing.T) {
	req := DKGSessionRequest{
		Session: SessionDescriptor{
			SessionID: "session-1",
			OrgID:     "org-1",
			Parties:   []string{"p1", "p2", "p3"},
			Threshold: 2,
		},
		LocalPartyID: "p1",
	}

	err := req.Validate()
	if !errors.Is(err, ErrTransportRequired) {
		t.Fatalf("expected ErrTransportRequired, got %v", err)
	}
}

func TestSignSessionRequestValidateRequiresDigest(t *testing.T) {
	req := SignSessionRequest{
		Session: SessionDescriptor{
			SessionID: "session-1",
			OrgID:     "org-1",
			KeyID:     "key-1",
			Parties:   []string{"p1", "p2", "p3"},
			Threshold: 2,
		},
		LocalPartyID: "p1",
		Transport:    noopTransport{},
	}

	err := req.Validate()
	if !errors.Is(err, ErrDigestMissing) {
		t.Fatalf("expected ErrDigestMissing, got %v", err)
	}
}

func TestNewBnbServiceReturnsFacade(t *testing.T) {
	svc := NewBnbService(slog.Default())
	if svc == nil {
		t.Fatal("expected non-nil facade")
	}

	if got := svc.Snapshot(); got != (Snapshot{}) {
		t.Fatalf("expected zero-value snapshot, got %+v", got)
	}
}

type stubShareStore struct{}

func (stubShareStore) SaveShare(_ context.Context, _ string, _ []byte, _ coreshares.ShareMeta) error {
	return nil
}

func (stubShareStore) LoadShare(_ context.Context, _ string) (*coreshares.StoredShare, error) {
	return nil, ErrShareNotFound
}

func (stubShareStore) DisableShare(_ context.Context, _ string) error {
	return nil
}

type sourceStub struct {
	value *ecdsakeygen.LocalPreParams
	err   error
	calls int
}

func (s *sourceStub) Acquire(_ context.Context) (*ecdsakeygen.LocalPreParams, error) {
	s.calls++
	return s.value, s.err
}

func TestNewBnbServiceWithOptionsConfigShareStoreMetrics(t *testing.T) {
	cfg := PreParamsConfig{
		Enabled:             false,
		TargetSize:          2,
		MaxConcurrency:      1,
		GenerateTimeout:     time.Second,
		AcquireTimeout:      time.Second,
		RetryBackoff:        time.Millisecond,
		SyncFallbackOnEmpty: false,
		FileCacheEnabled:    false,
		FileCacheDir:        ".tmp/test",
	}
	store := stubShareStore{}

	svc := NewBnbService(
		slog.Default(),
		WithPreParamsConfig(cfg),
		WithShareStore(store),
		WithMetrics(bnbutils.NoopMetrics{}),
	)
	if svc == nil {
		t.Fatal("expected non-nil facade")
	}
}

func TestNewBnbServiceWithPreParamsSource(t *testing.T) {
	source := &sourceStub{value: &ecdsakeygen.LocalPreParams{}}

	svc := NewBnbService(slog.Default(), WithPreParamsSource(source))
	if svc == nil {
		t.Fatal("expected non-nil facade")
	}

	opts := buildServiceOptions(WithPreParamsSource(source))
	provider := newPreParamsProvider(slog.Default(), opts)
	if _, err := provider.Acquire(context.Background()); err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if source.calls != 1 {
		t.Fatalf("expected source Acquire() to be called once, got %d", source.calls)
	}
}

func TestNewBnbServiceCanCreateTwoServicesWithDifferentSources(t *testing.T) {
	sourceA := &sourceStub{value: &ecdsakeygen.LocalPreParams{}}
	sourceB := &sourceStub{value: &ecdsakeygen.LocalPreParams{}}

	svcA := NewBnbService(slog.Default(), WithPreParamsSource(sourceA))
	svcB := NewBnbService(slog.Default(), WithPreParamsSource(sourceB))
	if svcA == nil || svcB == nil {
		t.Fatal("expected both facades to be non-nil")
	}

	providerA := newPreParamsProvider(slog.Default(), buildServiceOptions(WithPreParamsSource(sourceA)))
	providerB := newPreParamsProvider(slog.Default(), buildServiceOptions(WithPreParamsSource(sourceB)))

	if _, err := providerA.Acquire(context.Background()); err != nil {
		t.Fatalf("providerA Acquire() error = %v", err)
	}
	if _, err := providerB.Acquire(context.Background()); err != nil {
		t.Fatalf("providerB Acquire() error = %v", err)
	}
	if sourceA.calls != 1 || sourceB.calls != 1 {
		t.Fatalf("expected isolated sources, got calls sourceA=%d sourceB=%d", sourceA.calls, sourceB.calls)
	}
}
