package shares

import (
	"context"
	"errors"
)

var (
	ErrShareNotFound         = errors.New("platform share not found")
	ErrInvalidSharePayload   = errors.New("invalid platform share payload")
	ErrVaultUnavailable      = errors.New("vault unavailable")
	ErrVaultPermissionDenied = errors.New("vault permission denied")
	ErrVaultWriteFailed      = errors.New("vault write failed")
	ErrVaultReadFailed       = errors.New("vault read failed")
	ErrMetadataMismatch      = errors.New("platform share metadata mismatch")
	ErrUnsupportedVersion    = errors.New("unsupported platform share version")
)

type StoredShare struct {
	Blob []byte
	Meta ShareMeta
}

type Cipher interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
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
