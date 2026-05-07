package bnb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
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
	ErrECDSAPubKeyUnavailable   = bnbutils.ErrECDSAPubKeyUnavailable
)

// BnbRunner runs tss-lib protocol loops over abstract frame transport.
type BnbRunner struct {
	mu             sync.RWMutex
	ecdsaKeys      map[string]ecdsakeygen.LocalPartySaveData
	ecdsaMaterials map[string]coreshares.ECDSAKeyMaterial
	ecdsaSigs      map[string]*common.SignatureData
	logger         *slog.Logger
	debug          bool
	cfg            tssbnbutils.RunnerConfig
	metrics        bnbutils.Metrics
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
		ecdsaKeys:      map[string]ecdsakeygen.LocalPartySaveData{},
		ecdsaMaterials: map[string]coreshares.ECDSAKeyMaterial{},
		ecdsaSigs:      map[string]*common.SignatureData{},
		logger:         logger,
		debug:          bnbutils.IsTSSDebugEnabled(logger),
		cfg:            cfg.cfg,
		metrics:        cfg.metrics,
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

func (r *BnbRunner) ImportECDSAKeyMaterial(key string, material coreshares.ECDSAKeyMaterial) {
	if key == "" {
		return
	}
	r.mu.Lock()
	if r.ecdsaMaterials == nil {
		r.ecdsaMaterials = map[string]coreshares.ECDSAKeyMaterial{}
	}
	if r.ecdsaKeys == nil {
		r.ecdsaKeys = map[string]ecdsakeygen.LocalPartySaveData{}
	}
	r.ecdsaMaterials[key] = cloneECDSAKeyMaterial(material)
	r.ecdsaKeys[key] = material.Share
	r.mu.Unlock()
}

func (r *BnbRunner) ExportECDSAKeyMaterial(key string) (coreshares.ECDSAKeyMaterial, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	material, ok := r.ecdsaMaterials[key]
	if !ok {
		return coreshares.ECDSAKeyMaterial{}, fmt.Errorf("%w: key=%s", ErrKeyShareNotFound, key)
	}
	return cloneECDSAKeyMaterial(material), nil
}

func (r *BnbRunner) DeleteECDSAKeyShare(key string) {
	if key == "" {
		return
	}
	r.mu.Lock()
	delete(r.ecdsaKeys, key)
	delete(r.ecdsaMaterials, key)
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
	if r.ecdsaKeys == nil {
		r.ecdsaKeys = map[string]ecdsakeygen.LocalPartySaveData{}
	}
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

func isZeroECDSAShare(share ecdsakeygen.LocalPartySaveData) bool {
	return share.ECDSAPub == nil && len(share.BigXj) == 0 && len(share.Ks) == 0
}

func cloneECDSAKeyMaterial(in coreshares.ECDSAKeyMaterial) coreshares.ECDSAKeyMaterial {
	return coreshares.ECDSAKeyMaterial{
		Share:            in.Share,
		ChainCode:        append([]byte(nil), in.ChainCode...),
		PublicKeyFormat:  in.PublicKeyFormat,
		DerivationScheme: in.DerivationScheme,
	}
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
