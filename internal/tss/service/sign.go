package service

import (
	"context"
	"fmt"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	corederivation "github.com/BroLabel/brosettlement-mpc-core/internal/tss/derivation"
	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
	tssutils "github.com/BroLabel/brosettlement-mpc-core/tss/utils"
)

func prepareDerivedECDSASignJob(ctx context.Context, shareReader ShareReader, job tssbnbrunner.SignJob, in SignInput) (tssbnbrunner.SignJob, error) {
	if !tssutils.IsECDSA(job.Algorithm) {
		return job, corederivation.ErrDerivedSigningUnsupported
	}
	material, err := loadECDSAKeyMaterial(ctx, shareReader, in)
	if err != nil {
		return job, err
	}
	if len(material.ChainCode) != 32 {
		return job, corederivation.ErrChainCodeMissing
	}
	if material.DerivationScheme != corederivation.DerivationSchemeBIP32Secp256k1 {
		return job, fmt.Errorf("%w: stored scheme=%s", corederivation.ErrUnsupportedDerivationScheme, material.DerivationScheme)
	}
	if material.PublicKeyFormat != corederivation.PublicKeyFormatUncompressedHex {
		return job, fmt.Errorf("%w: stored public key format=%s", corederivation.ErrInvalidDerivationContext, material.PublicKeyFormat)
	}
	expectedHash, err := corederivation.HashV1(in.DerivationContext)
	if err != nil {
		return job, err
	}
	if in.DerivationContextHash == "" || in.DerivationContextHash != expectedHash {
		return job, fmt.Errorf("%w: context hash mismatch", corederivation.ErrDerivationContextMismatch)
	}
	prepared, err := corederivation.PrepareECDSASigningShare(material.Share, material.ChainCode, in.DerivationContext)
	if err != nil {
		return job, err
	}
	job.KeyShare = prepared.Share
	job.KeyDerivationDelta = prepared.KeyDerivationDelta
	job.DerivationContextHash = in.DerivationContextHash
	return job, nil
}

func loadECDSAKeyMaterial(ctx context.Context, shareReader ShareReader, in SignInput) (coreshares.ECDSAKeyMaterial, error) {
	keyID, err := tssutils.NormalizeKeyID(in.KeyID, in.EmptyKeyErr)
	if err != nil {
		return coreshares.ECDSAKeyMaterial{}, err
	}
	if shareReader == nil {
		return coreshares.ECDSAKeyMaterial{}, ErrShareReaderRequired
	}
	stored, err := shareReader.LoadShare(ctx, keyID)
	if err != nil {
		return coreshares.ECDSAKeyMaterial{}, err
	}
	defer tssutils.ZeroBytes(stored.Blob)
	return coreshares.UnmarshalKeyMaterial(stored.Blob)
}
