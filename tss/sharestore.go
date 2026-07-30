package tss

import (
	"context"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
)

var (
	ErrShareNotFound         = coreshares.ErrShareNotFound
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
type ShareReader = coreshares.ShareReader
type ShareWriter = coreshares.ShareWriter
type SaveShareInput = coreshares.SaveShareInput
type ECDSAKeyMaterial = coreshares.ECDSAKeyMaterial
type KeyMaterialMeta = coreshares.KeyMaterialMeta
type ECDSAKeyMaterialEvidence = coreshares.ECDSAKeyMaterialEvidence

func MarshalKeyMaterial(material ECDSAKeyMaterial) ([]byte, error) {
	return coreshares.MarshalKeyMaterial(material)
}

func UnmarshalKeyMaterial(blob []byte) (ECDSAKeyMaterial, error) {
	return coreshares.UnmarshalKeyMaterial(blob)
}

func InspectEncodedECDSAKeyMaterial(blob []byte) (ECDSAKeyMaterialEvidence, error) {
	return coreshares.InspectEncodedECDSAKeyMaterial(blob)
}

type ShareCipher interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}
