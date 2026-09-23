package runtime

import (
	"context"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
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
