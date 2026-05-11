package service

import (
	"context"
	"strings"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	corederivation "github.com/BroLabel/brosettlement-mpc-core/internal/tss/derivation"
	tssruntime "github.com/BroLabel/brosettlement-mpc-core/internal/tss/runtime"
	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
	tssutils "github.com/BroLabel/brosettlement-mpc-core/tss/utils"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

func buildDKGJob(in DKGInput) tssbnbrunner.DKGJob {
	return tssbnbrunner.DKGJob{
		SessionID:    in.SessionID,
		LocalPartyID: in.LocalPartyID,
		OrgID:        in.OrgID,
		Parties:      in.Parties,
		Threshold:    in.Threshold,
		Curve:        in.Curve,
		Algorithm:    in.Algorithm,
		Chain:        in.Chain,
	}
}

type normalizedDKGMaterial struct {
	ChainCode    []byte
	ChainCodeHex string
	Scheme       string
}

func normalizeDKGMaterial(in DKGInput) (normalizedDKGMaterial, error) {
	chainCode, scheme, err := corederivation.ValidateDKGMaterial(in.Algorithm, corederivation.DKGMaterial{
		ChainCode:        in.DerivationMaterial.ChainCode,
		DerivationScheme: in.DerivationMaterial.DerivationScheme,
	})
	if err != nil {
		return normalizedDKGMaterial{}, err
	}
	return normalizedDKGMaterial{
		ChainCode:    chainCode,
		ChainCodeHex: strings.ToLower(strings.TrimSpace(in.DerivationMaterial.ChainCode)),
		Scheme:       scheme,
	}, nil
}

func buildECDSADKGOutput(runner Runner, in DKGInput, keyID string, material normalizedDKGMaterial) (DKGOutput, ecdsakeygen.LocalPartySaveData, error) {
	share, err := runner.ExportTemporaryECDSADKGShare(in.SessionID)
	if err != nil {
		return DKGOutput{}, ecdsakeygen.LocalPartySaveData{}, err
	}
	publicKey, err := corederivation.EncodeECPointUncompressedSecp256k1(share.ECDSAPub)
	if err != nil {
		if in.MissingPub == nil {
			return DKGOutput{}, ecdsakeygen.LocalPartySaveData{}, err
		}
		return DKGOutput{}, ecdsakeygen.LocalPartySaveData{}, in.MissingPub
	}
	derived, err := tssruntime.DeriveECDSAOutputFromShare(share, in.MissingPub, in.MissingAddr)
	if err != nil {
		return DKGOutput{}, ecdsakeygen.LocalPartySaveData{}, err
	}
	return DKGOutput{
		KeyID:            keyID,
		PublicKey:        publicKey,
		Address:          derived.Address,
		ChainCode:        material.ChainCodeHex,
		PublicKeyFormat:  corederivation.PublicKeyFormatUncompressedHex,
		DerivationScheme: corederivation.DerivationSchemeBIP32Secp256k1,
	}, share, nil
}

func persistECDSAShareAfterDKG(ctx context.Context, shareStore ShareStore, runner Runner, sessionID string, job tssbnbrunner.DKGJob, keyID string, share ecdsakeygen.LocalPartySaveData, material normalizedDKGMaterial) error {
	if shareStore == nil {
		return nil
	}
	if err := tssruntime.PersistKeyMaterialAfterDKG(ctx, shareStore, share, tssruntime.DKGPersistInput{
		KeyID:            keyID,
		OrgID:            job.OrgID,
		Algorithm:        job.Algorithm,
		Curve:            job.Curve,
		ChainCode:        append([]byte(nil), material.ChainCode...),
		PublicKeyFormat:  corederivation.PublicKeyFormatUncompressedHex,
		DerivationScheme: material.Scheme,
	}); err != nil {
		return err
	}
	runner.DeleteTemporaryECDSADKGShare(sessionID)
	return nil
}

func importNoStoreECDSAKeyMaterial(runner Runner, shareStore ShareStore, keyID string, share ecdsakeygen.LocalPartySaveData, material normalizedDKGMaterial) {
	if shareStore != nil || len(material.ChainCode) != 32 {
		return
	}
	runner.ImportECDSAKeyMaterial(keyID, coreshares.ECDSAKeyMaterial{
		Share:            share,
		ChainCode:        append([]byte(nil), material.ChainCode...),
		PublicKeyFormat:  corederivation.PublicKeyFormatUncompressedHex,
		DerivationScheme: material.Scheme,
	})
}

func resolveDKGOutputKeyID(in DKGInput, algorithm string) (string, error) {
	if tssutils.IsECDSA(algorithm) {
		return tssutils.NormalizeKeyID(in.KeyID, in.EmptyKeyErr)
	}
	keyID := strings.TrimSpace(in.KeyID)
	if keyID == "" {
		return in.SessionID, nil
	}
	return keyID, nil
}
