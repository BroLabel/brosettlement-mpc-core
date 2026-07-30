package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	tsslogging "github.com/BroLabel/brosettlement-mpc-core/internal/tss/logging"
	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
	tssutils "github.com/BroLabel/brosettlement-mpc-core/tss/utils"
	"github.com/bnb-chain/tss-lib/common"
	"log/slog"
)

type Service struct {
	dkgMu           sync.Mutex
	activeDKGRuns   map[tssbnbrunner.DKGRunKey]struct{}
	runner          Runner
	logger          *slog.Logger
	preParamsPool   LifecyclePool
	preParamsSource PreParamsPool
	shareReader     ShareReader
	shareWriter     ShareWriter
}

func New(r Runner, logger *slog.Logger, pool LifecyclePool, shareReader ShareReader, shareWriter ShareWriter, externalSource ...PreParamsPool) *Service {
	if r == nil {
		panic(ErrNilRunner)
	}
	var source PreParamsPool
	if len(externalSource) > 0 {
		source = externalSource[0]
	}
	return &Service{
		activeDKGRuns:   make(map[tssbnbrunner.DKGRunKey]struct{}),
		runner:          r,
		logger:          logger,
		preParamsPool:   pool,
		preParamsSource: source,
		shareReader:     shareReader,
		shareWriter:     shareWriter,
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
	runKey := tssbnbrunner.DKGRunKey{SessionID: job.SessionID, LocalPartyID: job.LocalPartyID}
	if !s.beginDKGRun(runKey) {
		return DKGOutput{}, fmt.Errorf("%w: session=%s party=%s", ErrDuplicateDKGRun, runKey.SessionID, runKey.LocalPartyID)
	}
	defer s.endDKGRun(runKey)

	keyID, err := resolveDKGOutputKeyID(in, job.Algorithm)
	if err != nil {
		return DKGOutput{}, err
	}

	tsslogging.LogSessionStart(s.logger, "dkg", in.SessionID, in.OrgID, keyID, in.LocalPartyID)
	started := time.Now()
	logEnd := func(err error) {
		tsslogging.LogSessionEnd(s.logger, "dkg", in.SessionID, in.OrgID, keyID, in.LocalPartyID, started, err)
	}
	material, err := normalizeDKGMaterial(in)
	if err != nil {
		logEnd(err)
		return DKGOutput{}, err
	}
	err = AttachPreParams(ctx, ResolvePreParamsSource(s.preParamsSource, s.preParamsPool), &job, tssutils.IsECDSA(job.Algorithm))
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

	output, share, err := buildECDSADKGOutput(s.runner, in, keyID, material)
	if err != nil {
		logEnd(err)
		return DKGOutput{}, err
	}
	importNoStoreECDSAKeyMaterial(s.runner, s.shareWriter, keyID, share, material)
	if err = persistECDSAShareAfterDKG(ctx, s.shareWriter, s.runner, runKey, keyID, in.OpaqueDescriptorFingerprint, share, material); err != nil {
		logEnd(err)
		return DKGOutput{}, err
	}
	logEnd(nil)
	return output, nil
}

func (s *Service) beginDKGRun(key tssbnbrunner.DKGRunKey) bool {
	s.dkgMu.Lock()
	defer s.dkgMu.Unlock()
	if _, exists := s.activeDKGRuns[key]; exists {
		return false
	}
	s.activeDKGRuns[key] = struct{}{}
	return true
}

func (s *Service) endDKGRun(key tssbnbrunner.DKGRunKey) {
	s.dkgMu.Lock()
	delete(s.activeDKGRuns, key)
	s.dkgMu.Unlock()
}

func (s *Service) RunSignSession(ctx context.Context, in SignInput) error {
	job := tssbnbrunner.SignJob{
		SessionID:             in.SessionID,
		LocalPartyID:          in.LocalPartyID,
		OrgID:                 in.OrgID,
		KeyID:                 in.KeyID,
		Parties:               in.Parties,
		Digest:                append([]byte(nil), in.Digest...),
		Algorithm:             in.Algorithm,
		Chain:                 in.Chain,
		DerivationContextHash: in.DerivationContextHash,
	}

	tsslogging.LogSessionStart(s.logger, "sign", in.SessionID, in.OrgID, in.KeyID, in.LocalPartyID)
	started := time.Now()
	var err error
	job, err = prepareDerivedECDSASignJob(ctx, s.shareReader, s.runner, job, in)
	if err == nil {
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

func (s *Service) ECDSAAddress(key string) (string, error) {
	return s.runner.ECDSAAddress(key)
}
