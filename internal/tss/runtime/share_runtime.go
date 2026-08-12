package runtime

import (
	"context"
	"crypto/elliptic"
	"encoding/hex"
	"strings"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	tssbnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/utils"
	tssutils "github.com/BroLabel/brosettlement-mpc-core/tss/utils"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type DKGPersistInput struct {
	SessionID                   string
	KeyID                       string
	LocalPartyID                string
	OpaqueDescriptorFingerprint []byte
	ChainCode                   []byte
	PublicKeyFormat             string
	DerivationScheme            string
}

type DerivedECDSAOutput struct {
	PublicKey string
	Address   string
}

func PersistKeyMaterialAfterDKG(ctx context.Context, writer coreshares.ShareWriter, share ecdsakeygen.LocalPartySaveData, in DKGPersistInput) error {
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
	return writer.SaveShare(ctx, coreshares.SaveShareInput{
		SessionID:                   in.SessionID,
		KeyID:                       in.KeyID,
		LocalPartyID:                in.LocalPartyID,
		OpaqueDescriptorFingerprint: append([]byte(nil), in.OpaqueDescriptorFingerprint...),
		CodecBlob:                   blob,
	})
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
