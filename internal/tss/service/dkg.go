package service

import (
	"context"
	"strings"

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

func buildECDSADKGOutput(runner Runner, in DKGInput, keyID string) (DKGOutput, ecdsakeygen.LocalPartySaveData, error) {
	share, err := runner.ExportECDSAKeyShare(in.SessionID)
	if err != nil {
		return DKGOutput{}, ecdsakeygen.LocalPartySaveData{}, err
	}
	derived, err := tssruntime.DeriveECDSAOutputFromShare(share, in.MissingPub, in.MissingAddr)
	if err != nil {
		return DKGOutput{}, ecdsakeygen.LocalPartySaveData{}, err
	}
	return DKGOutput{
		KeyID:     keyID,
		PublicKey: derived.PublicKey,
		Address:   derived.Address,
	}, share, nil
}

func persistECDSAShareAfterDKG(ctx context.Context, shareStore ShareStore, runner Runner, sessionID string, job tssbnbrunner.DKGJob, keyID string, share ecdsakeygen.LocalPartySaveData) error {
	if shareStore == nil {
		return nil
	}
	if err := tssruntime.PersistShareAfterDKG(ctx, shareStore, share, tssruntime.DKGPersistInput{
		KeyID:     keyID,
		OrgID:     job.OrgID,
		Algorithm: job.Algorithm,
		Curve:     job.Curve,
	}); err != nil {
		return err
	}
	runner.DeleteECDSAKeyShare(sessionID)
	return nil
}

func normalizeDKGKeyID(sessionID, providedKeyID, algorithm string) string {
	if tssutils.IsECDSA(algorithm) {
		return sessionID
	}
	keyID := strings.TrimSpace(providedKeyID)
	if keyID == "" {
		return sessionID
	}
	return keyID
}
