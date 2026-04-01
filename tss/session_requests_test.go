package tss

import (
	"context"
	"errors"
	"testing"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
)

func TestDKGSessionRequestValidate(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		req := DKGSessionRequest{
			Session:      validSessionDescriptor(),
			LocalPartyID: "p1",
			Transport:    noopTransport{},
		}
		if err := req.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("invalid session descriptor", func(t *testing.T) {
		req := DKGSessionRequest{
			LocalPartyID: "p1",
			Transport:    noopTransport{},
		}
		if err := req.Validate(); !errors.Is(err, ErrInvalidSessionDescriptor) {
			t.Fatalf("Validate() error = %v, want %v", err, ErrInvalidSessionDescriptor)
		}
	})

	t.Run("missing local party id", func(t *testing.T) {
		req := DKGSessionRequest{
			Session:   validSessionDescriptor(),
			Transport: noopTransport{},
		}
		if err := req.Validate(); !errors.Is(err, ErrLocalPartyRequired) {
			t.Fatalf("Validate() error = %v, want %v", err, ErrLocalPartyRequired)
		}
	})

	t.Run("missing transport", func(t *testing.T) {
		req := DKGSessionRequest{
			Session:      validSessionDescriptor(),
			LocalPartyID: "p1",
		}
		if err := req.Validate(); !errors.Is(err, ErrTransportRequired) {
			t.Fatalf("Validate() error = %v, want %v", err, ErrTransportRequired)
		}
	})
}

func TestSignSessionRequestValidate(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		req := SignSessionRequest{
			Session:      validSessionDescriptor(),
			LocalPartyID: "p1",
			Digest:       []byte{0xaa},
			Transport:    noopTransport{},
		}
		if err := req.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("invalid session descriptor", func(t *testing.T) {
		req := SignSessionRequest{
			LocalPartyID: "p1",
			Digest:       []byte{0xaa},
			Transport:    noopTransport{},
		}
		if err := req.Validate(); !errors.Is(err, ErrInvalidSessionDescriptor) {
			t.Fatalf("Validate() error = %v, want %v", err, ErrInvalidSessionDescriptor)
		}
	})

	t.Run("missing local party id", func(t *testing.T) {
		req := SignSessionRequest{
			Session:   validSessionDescriptor(),
			Digest:    []byte{0xaa},
			Transport: noopTransport{},
		}
		if err := req.Validate(); !errors.Is(err, ErrLocalPartyRequired) {
			t.Fatalf("Validate() error = %v, want %v", err, ErrLocalPartyRequired)
		}
	})

	t.Run("missing key id", func(t *testing.T) {
		session := validSessionDescriptor()
		session.KeyID = ""
		req := SignSessionRequest{
			Session:      session,
			LocalPartyID: "p1",
			Digest:       []byte{0xaa},
			Transport:    noopTransport{},
		}
		if err := req.Validate(); !errors.Is(err, ErrKeyIDRequired) {
			t.Fatalf("Validate() error = %v, want %v", err, ErrKeyIDRequired)
		}
	})

	t.Run("missing digest", func(t *testing.T) {
		req := SignSessionRequest{
			Session:      validSessionDescriptor(),
			LocalPartyID: "p1",
			Transport:    noopTransport{},
		}
		if err := req.Validate(); !errors.Is(err, ErrDigestMissing) {
			t.Fatalf("Validate() error = %v, want %v", err, ErrDigestMissing)
		}
	})

	t.Run("missing transport", func(t *testing.T) {
		req := SignSessionRequest{
			Session:      validSessionDescriptor(),
			LocalPartyID: "p1",
			Digest:       []byte{0xaa},
		}
		if err := req.Validate(); !errors.Is(err, ErrTransportRequired) {
			t.Fatalf("Validate() error = %v, want %v", err, ErrTransportRequired)
		}
	})
}

func TestSignSessionRequestValidateRequiresDigest(t *testing.T) {
	req := SignSessionRequest{
		Session:      validSessionDescriptor(),
		LocalPartyID: "p1",
	}

	if err := req.Validate(); !errors.Is(err, ErrDigestMissing) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrDigestMissing)
	}
}

func validSessionDescriptor() protocol.SessionDescriptor {
	return protocol.SessionDescriptor{
		SessionID: "sess-1",
		OrgID:     "org-1",
		KeyID:     "key-1",
		Parties:   []string{"p1", "p2"},
		Threshold: 1,
		Algorithm: "ecdsa",
		Curve:     "secp256k1",
		Chain:     "bnb",
	}
}

type noopTransport struct{}

func (noopTransport) SendFrame(context.Context, protocol.Frame) error {
	return nil
}

func (noopTransport) RecvFrame(context.Context) (protocol.Frame, error) {
	return protocol.Frame{}, context.Canceled
}
