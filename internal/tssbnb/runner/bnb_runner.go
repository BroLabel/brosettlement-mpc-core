package bnb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"brosettlement-mpc-signer/brosettlement-mpc-core/internal/tssbnb/flow"
	tssbnbutils "brosettlement-mpc-signer/brosettlement-mpc-core/internal/tssbnb/utils"
	bnbutils "brosettlement-mpc-signer/brosettlement-mpc-core/internal/tssbnb/support"
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
	ErrECDSAPubKeyUnavailable   = bnbutils.ErrECDSAPubKeyUnavailable
)

// BnbRunner runs tss-lib protocol loops over abstract frame transport.
type BnbRunner struct {
	mu        sync.RWMutex
	ecdsaKeys map[string]ecdsakeygen.LocalPartySaveData
	ecdsaSigs map[string]*common.SignatureData
	logger    *slog.Logger
	debug     bool
	cfg       tssbnbutils.RunnerConfig
	metrics   bnbutils.Metrics
}

func NewBnbRunner(logger *slog.Logger) *BnbRunner {
	return newBnbRunner(logger, bnbutils.NoopMetrics{}, tssbnbutils.LoadRunnerConfigFromEnv())
}

func NewBnbRunnerWithMetrics(logger *slog.Logger, metrics bnbutils.Metrics) *BnbRunner {
	return newBnbRunner(logger, metrics, tssbnbutils.LoadRunnerConfigFromEnv())
}

func newBnbRunner(logger *slog.Logger, metrics bnbutils.Metrics, cfg tssbnbutils.RunnerConfig) *BnbRunner {
	if logger == nil {
		logger = slog.Default()
	}
	if metrics == nil {
		metrics = bnbutils.NoopMetrics{}
	}
	return &BnbRunner{
		ecdsaKeys: map[string]ecdsakeygen.LocalPartySaveData{},
		ecdsaSigs: map[string]*common.SignatureData{},
		logger:    logger,
		debug:     bnbutils.IsTSSDebugEnabled(logger),
		cfg:       cfg,
		metrics:   metrics,
	}
}

func (r *BnbRunner) RunDKG(ctx context.Context, job DKGJob, transport Transport) error {
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
			r.setECDSAKeyShare(job.SessionID, data)
		},
	})
}

func (r *BnbRunner) RunSign(ctx context.Context, job SignJob, transport Transport) error {
	keyShare, ok := r.getECDSAKeyShare(job.KeyID)
	if !ok {
		keyShare, ok = r.getECDSAKeyShare(job.SessionID)
	}
	if !ok {
		return fmt.Errorf("%w: key_id=%s session_id=%s", ErrKeyShareNotFound, job.KeyID, job.SessionID)
	}

	err := flow.RunSign(ctx, flow.SignRunInput{
		Job: flow.SignRunJob{
			SessionID:    job.SessionID,
			LocalPartyID: job.LocalPartyID,
			KeyID:        job.KeyID,
			Parties:      job.Parties,
			Digest:       job.Digest,
			Algorithm:    job.Algorithm,
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

func (r *BnbRunner) ExportECDSAKeyShare(key string) (ecdsakeygen.LocalPartySaveData, error) {
	data, ok := r.getECDSAKeyShare(key)
	if !ok {
		return ecdsakeygen.LocalPartySaveData{}, fmt.Errorf("%w: key=%s", ErrKeyShareNotFound, key)
	}
	return data, nil
}

func (r *BnbRunner) ImportECDSAKeyShare(key string, data ecdsakeygen.LocalPartySaveData) {
	r.setECDSAKeyShare(key, data)
}

func (r *BnbRunner) DeleteECDSAKeyShare(key string) {
	if key == "" {
		return
	}
	r.mu.Lock()
	delete(r.ecdsaKeys, key)
	r.mu.Unlock()
}

func (r *BnbRunner) ECDSAAddress(key string) (string, error) {
	share, ok := r.getECDSAKeyShare(key)
	if !ok {
		return "", fmt.Errorf("%w: key=%s", ErrKeyShareNotFound, key)
	}
	addr, err := tssbnbutils.ECDSAAddressFromShare(share)
	if errors.Is(err, tssbnbutils.ErrECDSAPubKeyUnavailable) {
		return "", ErrECDSAPubKeyUnavailable
	}
	return addr, err
}

func (r *BnbRunner) setECDSAKeyShare(key string, data ecdsakeygen.LocalPartySaveData) {
	if key == "" {
		return
	}
	r.mu.Lock()
	r.ecdsaKeys[key] = data
	r.mu.Unlock()
}

func (r *BnbRunner) getECDSAKeyShare(key string) (ecdsakeygen.LocalPartySaveData, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	data, ok := r.ecdsaKeys[key]
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
