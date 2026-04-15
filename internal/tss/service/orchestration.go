package service

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	tsslogging "github.com/BroLabel/brosettlement-mpc-core/internal/tss/logging"
	tssruntime "github.com/BroLabel/brosettlement-mpc-core/internal/tss/runtime"
	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
	coretransport "github.com/BroLabel/brosettlement-mpc-core/transport"
	tssutils "github.com/BroLabel/brosettlement-mpc-core/tss/utils"
	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

var ErrNilRunner = errors.New("runner is required")

type Runner interface {
	RunDKG(ctx context.Context, job tssbnbrunner.DKGJob, transport coretransport.FrameTransport) error
	RunSign(ctx context.Context, job tssbnbrunner.SignJob, transport coretransport.FrameTransport) error
	ExportECDSASignature(key string) (common.SignatureData, error)
	ExportECDSAKeyShare(key string) (ecdsakeygen.LocalPartySaveData, error)
	ImportECDSAKeyShare(key string, data ecdsakeygen.LocalPartySaveData)
	DeleteECDSAKeyShare(key string)
	ECDSAAddress(key string) (string, error)
}

type ShareStore interface {
	SaveShare(ctx context.Context, keyID string, blob []byte, meta coreshares.ShareMeta) error
	LoadShare(ctx context.Context, keyID string) (*coreshares.StoredShare, error)
}

type LifecyclePool interface {
	PreParamsPool
	Pool
	Start(ctx context.Context) error
	Close() error
}

type SnapshotPool interface {
	LifecyclePool
	SnapshotProvider
}

type Service struct {
	runner          Runner
	logger          *slog.Logger
	preParamsPool   LifecyclePool
	preParamsSource PreParamsPool
	shareStore      ShareStore
}

type DKGInput struct {
	SessionID    string
	LocalPartyID string
	OrgID        string
	KeyID        string
	Parties      []string
	Threshold    uint32
	Curve        string
	Algorithm    string
	Chain        string
	Transport    coretransport.FrameTransport
	EmptyKeyErr  error
	MissingPub   error
	MissingAddr  error
}

type SignInput struct {
	SessionID        string
	LocalPartyID     string
	OrgID            string
	KeyID            string
	Parties          []string
	Digest           []byte
	Algorithm        string
	Chain            string
	Transport        coretransport.FrameTransport
	EmptyKeyErr      error
	MetadataMismatch error
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
	job := tssbnbrunner.DKGJob{
		SessionID:    in.SessionID,
		LocalPartyID: in.LocalPartyID,
		OrgID:        in.OrgID,
		Parties:      in.Parties,
		Threshold:    in.Threshold,
		Curve:        in.Curve,
		Algorithm:    in.Algorithm,
		Chain:        in.Chain,
	}
	keyID := strings.TrimSpace(in.KeyID)
	if keyID == "" {
		keyID = in.SessionID
	}

	tsslogging.LogSessionStart(s.logger, "dkg", in.SessionID, in.OrgID, keyID, in.LocalPartyID)
	started := time.Now()
	var out DKGOutput
	err := AttachPreParams(ctx, ResolvePreParamsSource(s.preParamsSource, s.preParamsPool), &job, tssutils.IsECDSA(job.Algorithm))
	if err == nil {
		err = s.runner.RunDKG(ctx, job, in.Transport)
	}
	if err == nil && s.shareStore != nil && tssutils.IsECDSA(job.Algorithm) {
		err = tssruntime.PersistShareAfterDKG(ctx, s.shareStore, s.runner, tssruntime.DKGPersistInput{
			SessionID:         job.SessionID,
			OrgID:             job.OrgID,
			Algorithm:         job.Algorithm,
			Curve:             job.Curve,
			EmptyKeyErr:       in.EmptyKeyErr,
			MissingPublicKey:  in.MissingPub,
			MissingAddressErr: in.MissingAddr,
		})
	}
	if err == nil && tssutils.IsECDSA(job.Algorithm) {
		out, err = s.ReadDKGOutput(ctx, ReadDKGOutputInput{
			SessionID:           job.SessionID,
			OrgID:               job.OrgID,
			Algorithm:           job.Algorithm,
			Chain:               job.Chain,
			EmptyKeyErr:         in.EmptyKeyErr,
			MissingPublicKey:    in.MissingPub,
			MissingAddressErr:   in.MissingAddr,
			MetadataMismatch:    coreshares.ErrMetadataMismatch,
			UnsupportedAlgErr:   errors.New("unsupported dkg output algorithm"),
			UnsupportedChainErr: tssruntime.ErrUnsupportedDKGOutputChain,
		})
	}
	tsslogging.LogSessionEnd(s.logger, "dkg", in.SessionID, in.OrgID, keyID, in.LocalPartyID, started, err)
	return out, err
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
	cleanup, err := s.prepareShareForSign(ctx, job, in.EmptyKeyErr, in.MetadataMismatch)
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

func (s *Service) prepareShareForSign(ctx context.Context, job tssbnbrunner.SignJob, emptyKeyErr, metadataMismatch error) (func(), error) {
	if s.shareStore == nil || !tssutils.IsECDSA(job.Algorithm) {
		return func() {}, nil
	}
	return tssruntime.PrepareShareForSign(ctx, s.shareStore, s.runner, tssruntime.SignPrepareInput{
		KeyID:            job.KeyID,
		OrgID:            job.OrgID,
		Algorithm:        job.Algorithm,
		EmptyKeyErr:      emptyKeyErr,
		MetadataMismatch: metadataMismatch,
	})
}
