package runtime

import (
	"context"
	"crypto/elliptic"
	"encoding/hex"
	"strings"

	coreshares "brosettlement-mpc-signer/brosettlement-mpc-core/internal/shares"
	tssutils "brosettlement-mpc-signer/brosettlement-mpc-core/tss/utils"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type ShareStore interface {
	SaveShare(ctx context.Context, keyID string, blob []byte, meta coreshares.ShareMeta) error
	LoadShare(ctx context.Context, keyID string) (*coreshares.StoredShare, error)
}

type Runner interface {
	ExportECDSAKeyShare(key string) (ecdsakeygen.LocalPartySaveData, error)
	ImportECDSAKeyShare(key string, data ecdsakeygen.LocalPartySaveData)
	DeleteECDSAKeyShare(key string)
	ECDSAAddress(key string) (string, error)
}

type DKGPersistInput struct {
	SessionID         string
	OrgID             string
	Algorithm         string
	Curve             string
	EmptyKeyErr       error
	MissingPublicKey  error
	MissingAddressErr error
}

type SignPrepareInput struct {
	KeyID             string
	OrgID             string
	Algorithm         string
	EmptyKeyErr       error
	MetadataMismatch  error
}

func PersistShareAfterDKG(ctx context.Context, store ShareStore, runner Runner, in DKGPersistInput) error {
	keyID, err := tssutils.NormalizeKeyID(in.SessionID, in.EmptyKeyErr)
	if err != nil {
		return err
	}
	share, err := runner.ExportECDSAKeyShare(keyID)
	if err != nil {
		return err
	}
	defer runner.DeleteECDSAKeyShare(keyID)

	blob, err := coreshares.MarshalShare(share)
	if err == nil {
		defer tssutils.ZeroBytes(blob)
		err = store.SaveShare(ctx, keyID, blob, tssutils.DKGShareMeta(keyID, in.OrgID, in.Algorithm, in.Curve))
	}
	return err
}

func PrepareShareForSign(ctx context.Context, store ShareStore, runner Runner, in SignPrepareInput) (func(), error) {
	keyID, err := tssutils.NormalizeKeyID(in.KeyID, in.EmptyKeyErr)
	if err != nil {
		return nil, err
	}
	stored, err := store.LoadShare(ctx, keyID)
	if err == nil {
		err = ValidateLoadedMeta(keyID, in.OrgID, in.Algorithm, stored.Meta, in.MetadataMismatch)
	}
	if err != nil {
		return nil, err
	}
	share, err := coreshares.UnmarshalShare(stored.Blob)
	defer tssutils.ZeroBytes(stored.Blob)
	if err != nil {
		return nil, err
	}
	runner.ImportECDSAKeyShare(keyID, share)
	return func() {
		runner.DeleteECDSAKeyShare(keyID)
	}, nil
}

func EnsureDKGMetadata(runner Runner, sessionID string, missingPublicKeyErr, missingAddressErr error) error {
	share, err := runner.ExportECDSAKeyShare(sessionID)
	if err != nil {
		return err
	}
	if extractECDSAPublicKey(share) == "" {
		return missingPublicKeyErr
	}
	address, err := runner.ECDSAAddress(sessionID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(address) == "" {
		return missingAddressErr
	}
	return nil
}

func ValidateLoadedMeta(keyID, orgID, algorithm string, meta coreshares.ShareMeta, metadataMismatchErr error) error {
	if meta.KeyID != "" && meta.KeyID != keyID {
		return metadataMismatchErr
	}
	if orgID != "" && meta.OrgID != "" && meta.OrgID != orgID {
		return metadataMismatchErr
	}
	alg := strings.ToLower(strings.TrimSpace(algorithm))
	if alg == "" {
		alg = "ecdsa"
	}
	if meta.Algorithm != "" && !strings.EqualFold(meta.Algorithm, alg) {
		return metadataMismatchErr
	}
	return nil
}

func extractECDSAPublicKey(share ecdsakeygen.LocalPartySaveData) string {
	if share.ECDSAPub == nil {
		return ""
	}
	pub := share.ECDSAPub.ToECDSAPubKey()
	if pub == nil {
		return ""
	}
	marshaled := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	if len(marshaled) == 0 {
		return ""
	}
	return hex.EncodeToString(marshaled)
}
