package tss

import coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"

var (
	ErrShareNotFound       = coreshares.ErrShareNotFound
	ErrInvalidSharePayload = coreshares.ErrInvalidSharePayload
	ErrMetadataMismatch    = coreshares.ErrMetadataMismatch
	ErrUnsupportedVersion  = coreshares.ErrUnsupportedVersion
)

type StoredShare = coreshares.StoredShare
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
