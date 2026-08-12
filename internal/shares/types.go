package shares

import (
	"context"
	"errors"
)

var (
	ErrShareNotFound       = errors.New("platform share not found")
	ErrInvalidSharePayload = errors.New("invalid platform share payload")
	ErrUnsupportedVersion  = errors.New("unsupported platform share version")
)

type StoredShare struct {
	Blob []byte
}

type ShareReader interface {
	LoadShare(ctx context.Context, keyID string) (*StoredShare, error)
}

type ShareWriter interface {
	SaveShare(ctx context.Context, in SaveShareInput) error
}

type SaveShareInput struct {
	SessionID                   string
	KeyID                       string
	LocalPartyID                string
	OpaqueDescriptorFingerprint []byte
	CodecBlob                   []byte
}
