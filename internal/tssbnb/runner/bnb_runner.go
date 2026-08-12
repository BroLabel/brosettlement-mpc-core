package bnb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/flow"
	bnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/support"
	tssbnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/utils"
	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

var (
	ErrUnknownSenderParty       = bnbutils.ErrUnknownSenderParty
	ErrDuplicateFrame           = bnbutils.ErrDuplicateFrame
	ErrFrameTooLarge            = bnbutils.ErrFrameTooLarge
	ErrQueueFull                = bnbutils.ErrQueueFull
	ErrStalledProtocol          = bnbutils.ErrStalledProtocol
	ErrKeyShareNotFound         = bnbutils.ErrKeyShareNotFound
	ErrSignDigestRequired       = bnbutils.ErrSignDigestRequired
	ErrSignAlgorithmUnsupported = bnbutils.ErrSignAlgorithmUnsupported
)

// BnbRunner runs tss-lib protocol loops over abstract frame transport.
type BnbRunner struct {
	mu                      sync.RWMutex
	temporaryECDSADKGShares map[DKGRunKey]ecdsakeygen.LocalPartySaveData
	ecdsaSigs               map[string]*common.SignatureData
	logger                  *slog.Logger
	debug                   bool
	cfg                     tssbnbutils.RunnerConfig
	metrics                 bnbutils.Metrics
}

type Option func(*options)

type options struct {
	metrics bnbutils.Metrics
	cfg     tssbnbutils.RunnerConfig
}

func WithMetrics(metrics bnbutils.Metrics) Option {
	return func(opts *options) {
		opts.metrics = metrics
	}
}

func WithConfig(cfg tssbnbutils.RunnerConfig) Option {
	return func(opts *options) {
		opts.cfg = cfg
	}
}

func NewBnbRunner(logger *slog.Logger, opts ...Option) *BnbRunner {
	cfg := options{
		metrics: bnbutils.NoopMetrics{},
		cfg:     tssbnbutils.LoadRunnerConfigFromEnv(),
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&cfg)
	}

	if logger == nil {
		logger = slog.Default()
	}
	if cfg.metrics == nil {
		cfg.metrics = bnbutils.NoopMetrics{}
	}
	return &BnbRunner{
		temporaryECDSADKGShares: map[DKGRunKey]ecdsakeygen.LocalPartySaveData{},
		ecdsaSigs:               map[string]*common.SignatureData{},
		logger:                  logger,
		debug:                   bnbutils.IsTSSDebugEnabled(logger),
		cfg:                     cfg.cfg,
		metrics:                 cfg.metrics,
	}
}

func (r *BnbRunner) RunDKG(ctx context.Context, job DKGJob, transport Transport) error {
	runKey := DKGRunKey{SessionID: job.SessionID, LocalPartyID: job.LocalPartyID}
	return flow.RunDKG(ctx, flow.DKGRunInput{
		Job: flow.DKGRunJob{
			SessionID:      job.SessionID,
			LocalPartyID:   job.LocalPartyID,
			Parties:        job.Parties,
			Threshold:      job.Threshold,
			Curve:          job.Curve,
			Algorithm:      job.Algorithm,
			ECDSAPreParams: job.ECDSAPreParams,
		},
		Transport: transport,
		Logger:    r.logger,
		Debug:     r.debug,
		Config:    r.cfg,
		Metrics:   r.metrics,
		OnECDSAKeyShare: func(data ecdsakeygen.LocalPartySaveData) {
			r.setTemporaryECDSADKGShare(runKey, data)
		},
	})
}

func (r *BnbRunner) RunSign(ctx context.Context, job SignJob, transport Transport) error {
	keyShare := job.KeyShare
	if isZeroECDSAShare(keyShare) {
		return fmt.Errorf("%w: adjusted key share required", ErrKeyShareNotFound)
	}

	err := flow.RunSign(ctx, flow.SignRunInput{
		Job: flow.SignRunJob{
			SessionID:             job.SessionID,
			LocalPartyID:          job.LocalPartyID,
			KeyID:                 job.KeyID,
			Parties:               job.Parties,
			Digest:                job.Digest,
			Algorithm:             job.Algorithm,
			KeyDerivationDelta:    job.KeyDerivationDelta,
			DerivationContextHash: job.DerivationContextHash,
		},
		KeyShare:  keyShare,
		Transport: transport,
		Logger:    r.logger,
		Debug:     r.debug,
		Config:    r.cfg,
		Metrics:   r.metrics,
		OnSignature: func(sigData *common.SignatureData) {
			r.setECDSASignature(job.SessionID, sigData)
			if job.KeyID != "" {
				r.setECDSASignature(job.KeyID, sigData)
			}
		},
	})
	if err != nil {
		if errors.Is(err, flow.ErrSignDigestRequired) {
			return ErrSignDigestRequired
		}
		if errors.Is(err, flow.ErrSignAlgorithmUnsupported) {
			return ErrSignAlgorithmUnsupported
		}
	}
	return err
}

func (r *BnbRunner) ExportECDSASignature(key string) (common.SignatureData, error) {
	data, ok := r.getECDSASignature(key)
	if !ok || data == nil {
		return common.SignatureData{}, fmt.Errorf("ecdsa signature not found: key=%s", key)
	}
	return common.SignatureData{
		Signature:         append([]byte(nil), data.GetSignature()...),
		SignatureRecovery: append([]byte(nil), data.GetSignatureRecovery()...),
		R:                 append([]byte(nil), data.GetR()...),
		S:                 append([]byte(nil), data.GetS()...),
		M:                 append([]byte(nil), data.GetM()...),
	}, nil
}

func (r *BnbRunner) ExportTemporaryECDSADKGShare(key DKGRunKey) (ecdsakeygen.LocalPartySaveData, error) {
	data, ok := r.getTemporaryECDSADKGShare(key)
	if !ok {
		return ecdsakeygen.LocalPartySaveData{}, fmt.Errorf("%w: session=%s party=%s", ErrKeyShareNotFound, key.SessionID, key.LocalPartyID)
	}
	return data, nil
}

func (r *BnbRunner) DeleteTemporaryECDSADKGShare(key DKGRunKey) {
	if key.SessionID == "" || key.LocalPartyID == "" {
		return
	}
	r.mu.Lock()
	delete(r.temporaryECDSADKGShares, key)
	r.mu.Unlock()
}

func (r *BnbRunner) setTemporaryECDSADKGShare(key DKGRunKey, data ecdsakeygen.LocalPartySaveData) {
	if key.SessionID == "" || key.LocalPartyID == "" {
		return
	}
	r.mu.Lock()
	if r.temporaryECDSADKGShares == nil {
		r.temporaryECDSADKGShares = map[DKGRunKey]ecdsakeygen.LocalPartySaveData{}
	}
	r.temporaryECDSADKGShares[key] = data
	r.mu.Unlock()
}

func (r *BnbRunner) getTemporaryECDSADKGShare(key DKGRunKey) (ecdsakeygen.LocalPartySaveData, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	data, ok := r.temporaryECDSADKGShares[key]
	return data, ok
}

func (r *BnbRunner) setECDSASignature(key string, data *common.SignatureData) {
	if key == "" || data == nil {
		return
	}
	r.mu.Lock()
	r.ecdsaSigs[key] = cloneECDSASignature(data)
	r.mu.Unlock()
}

func (r *BnbRunner) getECDSASignature(key string) (*common.SignatureData, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	data, ok := r.ecdsaSigs[key]
	return data, ok
}

func isZeroECDSAShare(share ecdsakeygen.LocalPartySaveData) bool {
	return share.ECDSAPub == nil && len(share.BigXj) == 0 && len(share.Ks) == 0
}

func cloneECDSASignature(in *common.SignatureData) *common.SignatureData {
	if in == nil {
		return nil
	}
	return &common.SignatureData{
		Signature:         append([]byte(nil), in.GetSignature()...),
		SignatureRecovery: append([]byte(nil), in.GetSignatureRecovery()...),
		R:                 append([]byte(nil), in.GetR()...),
		S:                 append([]byte(nil), in.GetS()...),
		M:                 append([]byte(nil), in.GetM()...),
	}
}
