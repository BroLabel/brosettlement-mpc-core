package service

import (
	"context"
	"fmt"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	corederivation "github.com/BroLabel/brosettlement-mpc-core/internal/tss/derivation"
	tssruntime "github.com/BroLabel/brosettlement-mpc-core/internal/tss/runtime"
	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
	tssutils "github.com/BroLabel/brosettlement-mpc-core/tss/utils"
)

func prepareDerivedECDSASignJob(ctx context.Context, shareStore ShareStore, runner Runner, job tssbnbrunner.SignJob, in SignInput) (tssbnbrunner.SignJob, error) {
	if !tssutils.IsECDSA(job.Algorithm) {
		return job, corederivation.ErrDerivedSigningUnsupported
	}
	material, err := loadECDSAKeyMaterial(ctx, shareStore, runner, in)
	if err != nil {
		return job, err
	}
	if len(material.ChainCode) == 0 {
		return job, corederivation.ErrChainCodeMissing
	}
	if len(material.ChainCode) != 32 {
		return job, corederivation.ErrChainCodeInvalid
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

func loadECDSAKeyMaterial(ctx context.Context, shareStore ShareStore, runner Runner, in SignInput) (coreshares.ECDSAKeyMaterial, error) {
	keyID, err := tssutils.NormalizeKeyID(in.KeyID, in.EmptyKeyErr)
	if err != nil {
		return coreshares.ECDSAKeyMaterial{}, err
	}
	if shareStore == nil {
		return runner.ExportECDSAKeyMaterial(keyID)
	}
	stored, err := shareStore.LoadShare(ctx, keyID)
	if err == nil {
		err = tssruntime.ValidateLoadedMeta(keyID, in.OrgID, in.Algorithm, in.Curve, stored.Meta, in.MetadataMismatch)
	}
	if err != nil {
		return coreshares.ECDSAKeyMaterial{}, err
	}
	defer tssutils.ZeroBytes(stored.Blob)
	return coreshares.UnmarshalKeyMaterial(stored.Blob)
}

func prepareShareForSign(ctx context.Context, shareStore ShareStore, runner Runner, job tssbnbrunner.SignJob, emptyKeyErr, metadataMismatch error) (func(), error) {
	if shareStore == nil || !tssutils.IsECDSA(job.Algorithm) {
		return func() {}, nil
	}
	return tssruntime.PrepareShareForSign(ctx, shareStore, runner, tssruntime.SignPrepareInput{
		KeyID:            job.KeyID,
		OrgID:            job.OrgID,
		Algorithm:        job.Algorithm,
		EmptyKeyErr:      emptyKeyErr,
		MetadataMismatch: metadataMismatch,
	})
}
