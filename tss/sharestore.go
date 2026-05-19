package tss

import (
	"context"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
)

const (
	ShareStatusActive   = coreshares.StatusActive
	ShareStatusDisabled = coreshares.StatusDisabled
)

var (
	ErrShareNotFound         = coreshares.ErrShareNotFound
	ErrShareDisabled         = coreshares.ErrShareDisabled
	ErrInvalidSharePayload   = coreshares.ErrInvalidSharePayload
	ErrVaultUnavailable      = coreshares.ErrVaultUnavailable
	ErrVaultPermissionDenied = coreshares.ErrVaultPermissionDenied
	ErrVaultWriteFailed      = coreshares.ErrVaultWriteFailed
	ErrVaultReadFailed       = coreshares.ErrVaultReadFailed
	ErrMetadataMismatch      = coreshares.ErrMetadataMismatch
	ErrUnsupportedVersion    = coreshares.ErrUnsupportedVersion
)

type StoredShare = coreshares.StoredShare
type ShareMeta = coreshares.ShareMeta
type ShareStore = coreshares.Store
type ECDSAKeyMaterial = coreshares.ECDSAKeyMaterial
type KeyMaterialMeta = coreshares.KeyMaterialMeta

func MarshalKeyMaterial(material ECDSAKeyMaterial) ([]byte, error) {
	return coreshares.MarshalKeyMaterial(material)
}

func UnmarshalKeyMaterial(blob []byte) (ECDSAKeyMaterial, error) {
	return coreshares.UnmarshalKeyMaterial(blob)
}

type ShareCipher interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}
