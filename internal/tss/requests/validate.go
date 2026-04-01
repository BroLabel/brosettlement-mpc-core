package requests

import (
	"errors"
	"strings"
)

type SessionDescriptor struct {
	SessionID string
	OrgID     string
	KeyID     string
	Parties   []string
	Threshold uint32
}

type DKGRequest struct {
	Session      SessionDescriptor
	LocalPartyID string
	HasTransport bool
}

type SignRequest struct {
	Session      SessionDescriptor
	LocalPartyID string
	Digest       []byte
	HasTransport bool
}

func IsValidSessionDescriptor(session SessionDescriptor) bool {
	if session.SessionID == "" || session.OrgID == "" {
		return false
	}
	if len(session.Parties) == 0 || session.Threshold == 0 {
		return false
	}
	return true
}

func ValidateDKG(req DKGRequest, invalidSessionErr, localPartyErr, transportErr error) error {
	switch {
	case !IsValidSessionDescriptor(req.Session):
		return invalidSessionErr
	case strings.TrimSpace(req.LocalPartyID) == "":
		return localPartyErr
	case !req.HasTransport:
		return transportErr
	default:
		return nil
	}
}

func ValidateSign(req SignRequest, invalidSessionErr, localPartyErr, keyIDErr, digestErr, transportErr error) error {
	switch {
	case !IsValidSessionDescriptor(req.Session):
		return invalidSessionErr
	case strings.TrimSpace(req.LocalPartyID) == "":
		return localPartyErr
	case strings.TrimSpace(req.Session.KeyID) == "":
		return keyIDErr
	case len(req.Digest) == 0:
		return digestErr
	case !req.HasTransport:
		return transportErr
	default:
		return nil
	}
}

var ErrUnexpectedNil = errors.New("unexpected nil")
