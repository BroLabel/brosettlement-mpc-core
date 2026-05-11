package runtime

import (
	"context"
	"crypto/elliptic"
	"encoding/hex"
	"strings"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	corederivation "github.com/BroLabel/brosettlement-mpc-core/internal/tss/derivation"
	tssbnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/utils"
	tssutils "github.com/BroLabel/brosettlement-mpc-core/tss/utils"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type ShareStore interface {
	SaveShare(ctx context.Context, keyID string, blob []byte, meta coreshares.ShareMeta) error
	LoadShare(ctx context.Context, keyID string) (*coreshares.StoredShare, error)
}

type DKGPersistInput struct {
	KeyID            string
	OrgID            string
	Algorithm        string
	Curve            string
	ChainCode        []byte
	PublicKeyFormat  string
	DerivationScheme string
}

type DerivedECDSAOutput struct {
	PublicKey string
	Address   string
}

func PersistKeyMaterialAfterDKG(ctx context.Context, store ShareStore, share ecdsakeygen.LocalPartySaveData, in DKGPersistInput) error {
	blob, err := coreshares.MarshalKeyMaterial(coreshares.ECDSAKeyMaterial{
		Share:            share,
		ChainCode:        append([]byte(nil), in.ChainCode...),
		PublicKeyFormat:  in.PublicKeyFormat,
		DerivationScheme: in.DerivationScheme,
	})
	if err != nil {
		return err
	}
	defer tssutils.ZeroBytes(blob)
	return store.SaveShare(ctx, in.KeyID, blob, tssutils.DKGShareMeta(in.KeyID, in.OrgID, in.Algorithm, in.Curve, len(in.ChainCode) == 32, in.PublicKeyFormat, in.DerivationScheme))
}

func DeriveECDSAOutputFromShare(share ecdsakeygen.LocalPartySaveData, missingPublicKeyErr, missingAddressErr error) (DerivedECDSAOutput, error) {
	pub := extractECDSAPublicKey(share)
	if pub == "" {
		return DerivedECDSAOutput{}, missingPublicKeyErr
	}
	address, err := tssbnbutils.ECDSAAddressFromShare(share)
	if err != nil {
		return DerivedECDSAOutput{}, err
	}
	if strings.TrimSpace(address) == "" {
		return DerivedECDSAOutput{}, missingAddressErr
	}
	return DerivedECDSAOutput{
		PublicKey: pub,
		Address:   address,
	}, nil
}

func ValidateLoadedMeta(keyID, orgID, algorithm, curve string, meta coreshares.ShareMeta, metadataMismatchErr error) error {
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
	expectedCurve := strings.ToLower(strings.TrimSpace(curve))
	if expectedCurve == "" && alg == "ecdsa" {
		expectedCurve = corederivation.CurveSecp256k1
	}
	if meta.Curve != "" && !strings.EqualFold(meta.Curve, expectedCurve) {
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
