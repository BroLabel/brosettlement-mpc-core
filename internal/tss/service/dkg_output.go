package service

import (
	"context"
	"errors"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	tssruntime "github.com/BroLabel/brosettlement-mpc-core/internal/tss/runtime"
	tssutils "github.com/BroLabel/brosettlement-mpc-core/tss/utils"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type DKGOutput struct {
	KeyID     string
	PublicKey string
	Address   string
}

type ReadDKGOutputInput struct {
	SessionID           string
	OrgID               string
	Algorithm           string
	Chain               string
	EmptyKeyErr         error
	MissingPublicKey    error
	MissingAddressErr   error
	MetadataMismatch    error
	UnsupportedAlgErr   error
	UnsupportedChainErr error
}

func (s *Service) ReadDKGOutput(ctx context.Context, in ReadDKGOutputInput) (DKGOutput, error) {
	if !tssutils.IsECDSA(in.Algorithm) {
		return DKGOutput{}, in.UnsupportedAlgErr
	}

	keyID, err := tssutils.NormalizeKeyID(in.SessionID, in.EmptyKeyErr)
	if err != nil {
		return DKGOutput{}, err
	}

	var share ecdsakeygen.LocalPartySaveData
	if s.shareStore != nil {
		stored, err := s.shareStore.LoadShare(ctx, keyID)
		if err != nil {
			return DKGOutput{}, err
		}
		if err := tssruntime.ValidateLoadedMeta(keyID, in.OrgID, in.Algorithm, stored.Meta, in.MetadataMismatch); err != nil {
			return DKGOutput{}, err
		}
		share, err = coreshares.UnmarshalShare(stored.Blob)
		tssutils.ZeroBytes(stored.Blob)
		if err != nil {
			return DKGOutput{}, err
		}
	} else {
		share, err = s.runner.ExportECDSAKeyShare(keyID)
		if err != nil {
			return DKGOutput{}, err
		}
	}

	publicKey, err := tssruntime.ExtractECDSAPublicKey(share)
	if err != nil {
		return DKGOutput{}, in.MissingPublicKey
	}
	address, err := tssruntime.ECDSAAddressFromShare(in.Chain, share)
	if errors.Is(err, tssruntime.ErrUnsupportedDKGOutputChain) {
		return DKGOutput{}, in.UnsupportedChainErr
	}
	if err != nil {
		return DKGOutput{}, in.MissingAddressErr
	}

	return DKGOutput{
		KeyID:     keyID,
		PublicKey: publicKey,
		Address:   address,
	}, nil
}
