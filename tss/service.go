package tss

import (
	"context"
	"errors"
	"log/slog"

	"github.com/BroLabel/brosettlement-mpc-core/internal/preparams"
	tssrequests "github.com/BroLabel/brosettlement-mpc-core/internal/tss/requests"
	tssservice "github.com/BroLabel/brosettlement-mpc-core/internal/tss/service"
	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
	bnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/support"
	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type Service struct {
	impl *tssservice.Service
}

type PreParamsSource interface {
	Acquire(ctx context.Context) (*ecdsakeygen.LocalPreParams, error)
}

type ServiceOption func(*serviceOptions)

type serviceOptions struct {
	preParamsConfig    PreParamsConfig
	hasPreParamsConfig bool
	shareStore         ShareStore
	metrics            bnbutils.Metrics
	preParamsSource    PreParamsSource
}

type SessionDescriptor struct {
	SessionID string
	OrgID     string
	KeyID     string
	Parties   []string
	Threshold uint32
	Algorithm string
	Curve     string
	Chain     string
}

type DKGSessionRequest struct {
	Session      SessionDescriptor
	LocalPartyID string
	Transport    Transport
}

type SignSessionRequest struct {
	Session      SessionDescriptor
	LocalPartyID string
	Digest       []byte
	Transport    Transport
}

type dkgJob = tssbnbrunner.DKGJob
type signJob = tssbnbrunner.SignJob
type runner = tssservice.Runner
type preParamsProvider = tssservice.LifecyclePool

type preParamsSnapshotProvider interface {
	Snapshot() preparams.Snapshot
}

type Snapshot = tssservice.Snapshot

var ErrNilRunner = tssservice.ErrNilRunner

var (
	ErrInvalidSessionDescriptor = errors.New("invalid session descriptor")
	ErrLocalPartyRequired       = errors.New("local party id is required")
	ErrTransportRequired        = errors.New("transport is required")
	ErrKeyIDRequired            = errors.New("key id is required")
	ErrDigestMissing            = errors.New("digest is required")
	ErrMissingDKGPublicKey      = errors.New("dkg result missing public key")
	ErrMissingDKGAddress        = errors.New("dkg result missing address")
)

func WithPreParamsConfig(cfg PreParamsConfig) ServiceOption {
	return func(opts *serviceOptions) {
		opts.preParamsConfig = cfg
		opts.hasPreParamsConfig = true
	}
}

func WithShareStore(store ShareStore) ServiceOption {
	return func(opts *serviceOptions) {
		opts.shareStore = store
	}
}

func WithMetrics(metrics bnbutils.Metrics) ServiceOption {
	return func(opts *serviceOptions) {
		opts.metrics = metrics
	}
}

func WithPreParamsSource(source PreParamsSource) ServiceOption {
	return func(opts *serviceOptions) {
		opts.preParamsSource = source
	}
}

func NewBnbService(logger *slog.Logger, opts ...ServiceOption) *Service {
	options := buildServiceOptions(opts...)
	pool := newPreParamsPool(logger, options)

	runnerOpts := make([]tssbnbrunner.Option, 0, 1)
	if options.metrics != nil {
		runnerOpts = append(runnerOpts, tssbnbrunner.WithMetrics(options.metrics))
	}
	return newService(
		tssbnbrunner.NewBnbRunner(logger, runnerOpts...),
		logger,
		pool,
		options.shareStore,
		options.preParamsSource,
	)
}

func buildServiceOptions(opts ...ServiceOption) serviceOptions {
	options := serviceOptions{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&options)
	}
	return options
}

func newPreParamsPool(logger *slog.Logger, opts serviceOptions) preParamsProvider {
	cfg := LoadPreParamsConfigFromEnv()
	if opts.hasPreParamsConfig {
		cfg = opts.preParamsConfig
	}
	return preparams.NewPool(logger, preparams.Config{
		Enabled:             cfg.Enabled,
		TargetSize:          cfg.TargetSize,
		MaxConcurrency:      cfg.MaxConcurrency,
		GenerateTimeout:     cfg.GenerateTimeout,
		AcquireTimeout:      cfg.AcquireTimeout,
		RetryBackoff:        cfg.RetryBackoff,
		SyncFallbackOnEmpty: cfg.SyncFallbackOnEmpty,
		FileCacheEnabled:    cfg.FileCacheEnabled,
		FileCacheDir:        cfg.FileCacheDir,
	})
}

func newService(r runner, logger *slog.Logger, pool preParamsProvider, shareStore ShareStore, source PreParamsSource) *Service {
	return &Service{
		impl: tssservice.New(r, logger, pool, shareStore, source),
	}
}

func (s *Service) StartPreParamsPool(ctx context.Context) error {
	return s.impl.StartPreParamsPool(ctx)
}

func (s *Service) StopPreParamsPool() error {
	return s.impl.StopPreParamsPool()
}

func (s *Service) Snapshot() Snapshot {
	return s.impl.Snapshot()
}

func (s *Service) RunDKGSession(ctx context.Context, req DKGSessionRequest) error {
	return s.impl.RunDKGSession(ctx, tssservice.DKGInput{
		SessionID:    req.Session.SessionID,
		LocalPartyID: req.LocalPartyID,
		OrgID:        req.Session.OrgID,
		KeyID:        req.Session.KeyID,
		Parties:      req.Session.Parties,
		Threshold:    req.Session.Threshold,
		Curve:        req.Session.Curve,
		Algorithm:    req.Session.Algorithm,
		Chain:        req.Session.Chain,
		Transport:    req.Transport,
		EmptyKeyErr:  ErrVaultWriteFailed,
		MissingPub:   ErrMissingDKGPublicKey,
		MissingAddr:  ErrMissingDKGAddress,
	})
}

func (s *Service) RunSignSession(ctx context.Context, req SignSessionRequest) error {
	return s.impl.RunSignSession(ctx, tssservice.SignInput{
		SessionID:        req.Session.SessionID,
		LocalPartyID:     req.LocalPartyID,
		OrgID:            req.Session.OrgID,
		KeyID:            req.Session.KeyID,
		Parties:          req.Session.Parties,
		Digest:           req.Digest,
		Algorithm:        req.Session.Algorithm,
		Chain:            req.Session.Chain,
		Transport:        req.Transport,
		EmptyKeyErr:      ErrShareNotFound,
		MetadataMismatch: ErrMetadataMismatch,
	})
}

func (s *Service) ExportECDSASignature(key string) (common.SignatureData, error) {
	return s.impl.ExportECDSASignature(key)
}

func (s *Service) ExportECDSAKeyShare(key string) (ecdsakeygen.LocalPartySaveData, error) {
	return s.impl.ExportECDSAKeyShare(key)
}

func (s *Service) ImportECDSAKeyShare(key string, data ecdsakeygen.LocalPartySaveData) error {
	s.impl.ImportECDSAKeyShare(key, data)
	return nil
}

func (s *Service) DeleteECDSAKeyShare(key string) {
	s.impl.DeleteECDSAKeyShare(key)
}

func (s *Service) ECDSAAddress(key string) (string, error) {
	return s.impl.ECDSAAddress(key)
}

func isValidSessionDescriptor(session SessionDescriptor) bool {
	return tssrequests.IsValidSessionDescriptor(tssrequests.SessionDescriptor{
		SessionID: session.SessionID,
		OrgID:     session.OrgID,
		KeyID:     session.KeyID,
		Parties:   session.Parties,
		Threshold: session.Threshold,
	})
}

func (r DKGSessionRequest) Validate() error {
	return tssrequests.ValidateDKG(tssrequests.DKGRequest{
		Session: tssrequests.SessionDescriptor{
			SessionID: r.Session.SessionID,
			OrgID:     r.Session.OrgID,
			KeyID:     r.Session.KeyID,
			Parties:   r.Session.Parties,
			Threshold: r.Session.Threshold,
		},
		LocalPartyID: r.LocalPartyID,
		HasTransport: r.Transport != nil,
	}, ErrInvalidSessionDescriptor, ErrLocalPartyRequired, ErrTransportRequired)
}

func (r SignSessionRequest) Validate() error {
	return tssrequests.ValidateSign(tssrequests.SignRequest{
		Session: tssrequests.SessionDescriptor{
			SessionID: r.Session.SessionID,
			OrgID:     r.Session.OrgID,
			KeyID:     r.Session.KeyID,
			Parties:   r.Session.Parties,
			Threshold: r.Session.Threshold,
		},
		LocalPartyID: r.LocalPartyID,
		Digest:       r.Digest,
		HasTransport: r.Transport != nil,
	}, ErrInvalidSessionDescriptor, ErrLocalPartyRequired, ErrKeyIDRequired, ErrDigestMissing, ErrTransportRequired)
}
