package tss

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
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
