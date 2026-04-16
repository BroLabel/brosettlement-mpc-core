package service

import (
	"context"
	"time"

	tsslogging "github.com/BroLabel/brosettlement-mpc-core/internal/tss/logging"
	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
	tssutils "github.com/BroLabel/brosettlement-mpc-core/tss/utils"
	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"log/slog"
)

type Service struct {
	runner          Runner
	logger          *slog.Logger
	preParamsPool   LifecyclePool
	preParamsSource PreParamsPool
	shareStore      ShareStore
}

func New(r Runner, logger *slog.Logger, pool LifecyclePool, shareStore ShareStore, externalSource ...PreParamsPool) *Service {
	if r == nil {
		panic(ErrNilRunner)
	}
	var source PreParamsPool
	if len(externalSource) > 0 {
		source = externalSource[0]
	}
	return &Service{
		runner:          r,
		logger:          logger,
		preParamsPool:   pool,
		preParamsSource: source,
		shareStore:      shareStore,
	}
}

func (s *Service) StartPreParamsPool(ctx context.Context) error {
	if s.preParamsPool == nil {
		return nil
	}
	return s.preParamsPool.Start(ctx)
}

func (s *Service) StopPreParamsPool() error {
	if s.preParamsPool == nil {
		return nil
	}
	return s.preParamsPool.Close()
}

func (s *Service) Snapshot() Snapshot {
	if s == nil || s.preParamsPool == nil {
		return Snapshot{}
	}
	var provider SnapshotProvider
	if details, ok := s.preParamsPool.(SnapshotProvider); ok {
		provider = details
	}
	return BuildSnapshot(s.preParamsPool, provider)
}

func (s *Service) RunDKGSession(ctx context.Context, in DKGInput) (DKGOutput, error) {
	job := buildDKGJob(in)
	keyID := normalizeDKGKeyID(in.SessionID, in.KeyID, job.Algorithm)

	tsslogging.LogSessionStart(s.logger, "dkg", in.SessionID, in.OrgID, keyID, in.LocalPartyID)
	started := time.Now()
	logEnd := func(err error) {
		tsslogging.LogSessionEnd(s.logger, "dkg", in.SessionID, in.OrgID, keyID, in.LocalPartyID, started, err)
	}
	err := AttachPreParams(ctx, ResolvePreParamsSource(s.preParamsSource, s.preParamsPool), &job, tssutils.IsECDSA(job.Algorithm))
	if err != nil {
		logEnd(err)
		return DKGOutput{}, err
	}
	if err = s.runner.RunDKG(ctx, job, in.Transport); err != nil {
		logEnd(err)
		return DKGOutput{}, err
	}
	if !tssutils.IsECDSA(job.Algorithm) {
		logEnd(nil)
		return DKGOutput{KeyID: keyID}, nil
	}

	output, share, err := buildECDSADKGOutput(s.runner, in, keyID)
	if err != nil {
		logEnd(err)
		return DKGOutput{}, err
	}
	if err = persistECDSAShareAfterDKG(ctx, s.shareStore, s.runner, in.SessionID, job, keyID, share); err != nil {
		logEnd(err)
		return DKGOutput{}, err
	}
	logEnd(nil)
	return output, nil
}

func (s *Service) RunSignSession(ctx context.Context, in SignInput) error {
	job := tssbnbrunner.SignJob{
		SessionID:    in.SessionID,
		LocalPartyID: in.LocalPartyID,
		OrgID:        in.OrgID,
		KeyID:        in.KeyID,
		Parties:      in.Parties,
		Digest:       append([]byte(nil), in.Digest...),
		Algorithm:    in.Algorithm,
		Chain:        in.Chain,
	}

	tsslogging.LogSessionStart(s.logger, "sign", in.SessionID, in.OrgID, in.KeyID, in.LocalPartyID)
	started := time.Now()
	cleanup, err := prepareShareForSign(ctx, s.shareStore, s.runner, job, in.EmptyKeyErr, in.MetadataMismatch)
	if err == nil {
		defer cleanup()
		err = s.runner.RunSign(ctx, job, in.Transport)
	}
	if err == nil {
		_, err = s.runner.ExportECDSASignature(in.SessionID)
	}
	tsslogging.LogSessionEnd(s.logger, "sign", in.SessionID, in.OrgID, in.KeyID, in.LocalPartyID, started, err)
	return err
}

func (s *Service) ExportECDSASignature(key string) (common.SignatureData, error) {
	return s.runner.ExportECDSASignature(key)
}

func (s *Service) ExportECDSAKeyShare(key string) (ecdsakeygen.LocalPartySaveData, error) {
	return s.runner.ExportECDSAKeyShare(key)
}

func (s *Service) ImportECDSAKeyShare(key string, data ecdsakeygen.LocalPartySaveData) {
	s.runner.ImportECDSAKeyShare(key, data)
}

func (s *Service) DeleteECDSAKeyShare(key string) {
	s.runner.DeleteECDSAKeyShare(key)
}

func (s *Service) ECDSAAddress(key string) (string, error) {
	return s.runner.ECDSAAddress(key)
}
