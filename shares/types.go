package shares

import (
	"context"
	"errors"
)

var (
	ErrShareNotFound         = errors.New("platform share not found")
	ErrShareDisabled         = errors.New("platform share is disabled")
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

type KeyRef struct {
	KeyID string
	OrgID string
	Role  string
}

type ShareToSave struct {
	Ref       KeyRef
	Plaintext []byte
	Meta      ShareMeta
}

type LoadedShare struct {
	Ref       KeyRef
	Plaintext []byte
	Meta      ShareMeta
}

type Cipher interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

type Source interface {
	LoadShare(ctx context.Context, ref KeyRef) (*LoadedShare, error)
}

type Sink interface {
	SaveShare(ctx context.Context, in ShareToSave) error
}

type SourceSink interface {
	Source
	Sink
}

type Store interface {
	SaveShare(ctx context.Context, keyID string, blob []byte, meta ShareMeta) error
	LoadShare(ctx context.Context, keyID string) (*StoredShare, error)
	DisableShare(ctx context.Context, keyID string) error
}
