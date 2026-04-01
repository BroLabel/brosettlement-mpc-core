package tss

import (
	"errors"
	"strings"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
)

var (
	ErrInvalidSessionDescriptor = errors.New("invalid session descriptor")
	ErrLocalPartyRequired       = errors.New("local party id is required")
	ErrTransportRequired        = errors.New("transport is required")
	ErrKeyIDRequired            = errors.New("key id is required")
	ErrDigestMissing            = errors.New("digest is required")
)

type DKGSessionRequest struct {
	Session      protocol.SessionDescriptor
	LocalPartyID string
	Transport    Transport
}

type SignSessionRequest struct {
	Session      protocol.SessionDescriptor
	LocalPartyID string
	Digest       []byte
	Transport    Transport
}

func (r DKGSessionRequest) Validate() error {
	if !protocol.IsValidSessionDescriptor(r.Session) {
		return ErrInvalidSessionDescriptor
	}
	if strings.TrimSpace(r.LocalPartyID) == "" {
		return ErrLocalPartyRequired
	}
	if r.Transport == nil {
		return ErrTransportRequired
	}
	return nil
}

func (r SignSessionRequest) Validate() error {
	if !protocol.IsValidSessionDescriptor(r.Session) {
		return ErrInvalidSessionDescriptor
	}
	if strings.TrimSpace(r.LocalPartyID) == "" {
		return ErrLocalPartyRequired
	}
	if strings.TrimSpace(r.Session.KeyID) == "" {
		return ErrKeyIDRequired
	}
	if len(r.Digest) == 0 {
		return ErrDigestMissing
	}
	if r.Transport == nil {
		return ErrTransportRequired
	}
	return nil
}
