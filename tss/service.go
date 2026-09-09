package tss

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/BroLabel/brosettlement-mpc-core/internal/preparams"
	corederivation "github.com/BroLabel/brosettlement-mpc-core/internal/tss/derivation"
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
	shareReader        ShareReader
	shareWriter        ShareWriter
	metrics            bnbutils.Metrics
	preParamsSource    PreParamsSource
}

type SessionDescriptor = DKGSessionDescriptor

type DKGSessionDescriptor struct {
	SessionID string
	OrgID     string
	KeyID     string
	Parties   []string
	Threshold uint32
	Algorithm string
	Curve     string
}

type SignSessionDescriptor struct {
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
	Session                     DKGSessionDescriptor
	LocalPartyID                string
	OpaqueDescriptorFingerprint []byte
	DerivationMaterial          *DKGDerivationMaterial
	Transport                   Transport
}

type SignSessionRequest struct {
	Session           SignSessionDescriptor
	LocalPartyID      string
	Digest            []byte
	DerivationContext *DerivationContext
	Transport         Transport
}

type runner = tssservice.Runner
type preParamsProvider = tssservice.LifecyclePool

type Snapshot = tssservice.Snapshot
type DKGOutput = tssservice.DKGOutput

var (
	ErrNilRunner           = tssservice.ErrNilRunner
	ErrShareReaderRequired = tssservice.ErrShareReaderRequired
	ErrShareWriterRequired = tssservice.ErrShareWriterRequired
)

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

func WithShareReader(reader ShareReader) ServiceOption {
	return func(opts *serviceOptions) {
		opts.shareReader = reader
	}
}

func WithShareWriter(writer ShareWriter) ServiceOption {
	return func(opts *serviceOptions) {
		opts.shareWriter = writer
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
		options.shareReader,
		options.shareWriter,
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
		Enabled:               cfg.Enabled,
		TargetSize:            cfg.TargetSize,
		MaxConcurrency:        cfg.MaxConcurrency,
		GenerationParallelism: cfg.GenerationParallelism,
		GenerateTimeout:       cfg.GenerateTimeout,
		AcquireTimeout:        cfg.AcquireTimeout,
		RetryBackoff:          cfg.RetryBackoff,
		SyncFallbackOnEmpty:   cfg.SyncFallbackOnEmpty,
		AutoRefillOnAcquire:   cfg.AutoRefillOnAcquire,
		FileCacheEnabled:      cfg.FileCacheEnabled,
		FileCacheDir:          cfg.FileCacheDir,
	})
}

func newService(r runner, logger *slog.Logger, pool preParamsProvider, shareReader ShareReader, shareWriter ShareWriter, source PreParamsSource) *Service {
	return &Service{
		impl: tssservice.New(r, logger, pool, shareReader, shareWriter, source),
	}
}

func (s *Service) StartPreParamsPool(ctx context.Context) error {
	return s.impl.StartPreParamsPool(ctx)
}

func (s *Service) StopPreParamsPool() error {
	return s.impl.StopPreParamsPool()
}

// PausePreParamsRefill prevents new background pre-parameter generation jobs
// from starting. Generation already in flight is allowed to finish.
func (s *Service) PausePreParamsRefill() {
	if s == nil || s.impl == nil {
		return
	}
	s.impl.PausePreParamsRefill()
}

// ResumePreParamsRefill re-enables asynchronous pre-parameter generation.
func (s *Service) ResumePreParamsRefill() {
	if s == nil || s.impl == nil {
		return
	}
	s.impl.ResumePreParamsRefill()
}

func (s *Service) Snapshot() Snapshot {
	return s.impl.Snapshot()
}

// RunDKGSession returns only after all session-owned protocol, transport, result,
// and callback work has stopped, including on failure or context cancellation.
func (s *Service) RunDKGSession(ctx context.Context, req DKGSessionRequest) (DKGOutput, error) {
	if err := req.Validate(); err != nil {
		return DKGOutput{}, err
	}
	return s.impl.RunDKGSession(ctx, buildDKGInput(req))
}

func (s *Service) AcquireDKGPreParams(ctx context.Context) (DKGPreParamsHandle, error) {
	handle, err := s.impl.AcquireDKGPreParams(ctx)
	if err != nil {
		return nil, err
	}
	return &dkgPreParamsHandle{handle: handle}, nil
}

// RunDKGSessionWithPreParams has the same completion barrier as RunDKGSession.
func (s *Service) RunDKGSessionWithPreParams(ctx context.Context, req DKGSessionRequest, handle DKGPreParamsHandle) (DKGOutput, error) {
	if err := req.Validate(); err != nil {
		return DKGOutput{}, err
	}
	internalHandle, err := unwrapDKGPreParamsHandle(handle)
	if err != nil {
		return DKGOutput{}, err
	}
	return s.impl.RunDKGSessionWithPreParams(ctx, buildDKGInput(req), internalHandle)
}

func buildDKGInput(req DKGSessionRequest) tssservice.DKGInput {
	var material tssservice.DKGDerivationMaterial
	if req.DerivationMaterial != nil {
		material = tssservice.DKGDerivationMaterial{
			ChainCode:        req.DerivationMaterial.ChainCode,
			DerivationScheme: req.DerivationMaterial.DerivationScheme,
		}
	}
	return tssservice.DKGInput{
		SessionID:                   req.Session.SessionID,
		LocalPartyID:                req.LocalPartyID,
		OrgID:                       req.Session.OrgID,
		KeyID:                       req.Session.KeyID,
		OpaqueDescriptorFingerprint: append([]byte(nil), req.OpaqueDescriptorFingerprint...),
		Parties:                     req.Session.Parties,
		Threshold:                   req.Session.Threshold,
		Curve:                       req.Session.Curve,
		Algorithm:                   req.Session.Algorithm,
		DerivationMaterial:          material,
		Transport:                   req.Transport,
		EmptyKeyErr:                 ErrKeyIDRequired,
		MissingPub:                  ErrMissingDKGPublicKey,
		MissingAddr:                 ErrMissingDKGAddress,
	}
}

// RunSignSession returns only after all session-owned protocol, transport,
// result, and signature callback work has stopped, including on failure or
// context cancellation.
func (s *Service) RunSignSession(ctx context.Context, req SignSessionRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}
	normalized, err := NormalizeDerivationContext(*req.DerivationContext)
	if err != nil {
		return err
	}
	hash, err := DerivationContextHashV1(normalized)
	if err != nil {
		return err
	}
	return s.impl.RunSignSession(ctx, tssservice.SignInput{
		SessionID:             req.Session.SessionID,
		LocalPartyID:          req.LocalPartyID,
		OrgID:                 req.Session.OrgID,
		KeyID:                 req.Session.KeyID,
		Parties:               req.Session.Parties,
		Digest:                req.Digest,
		Algorithm:             req.Session.Algorithm,
		Curve:                 req.Session.Curve,
		Chain:                 req.Session.Chain,
		DerivationContext:     toCoreDerivationContext(normalized),
		DerivationContextHash: hash,
		Transport:             req.Transport,
		EmptyKeyErr:           ErrShareNotFound,
	})
}

func (s *Service) ExportECDSASignature(key string) (common.SignatureData, error) {
	return s.impl.ExportECDSASignature(key)
}

func (r DKGSessionRequest) Validate() error {
	err := tssrequests.ValidateDKG(tssrequests.DKGRequest{
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
	if err != nil {
		return err
	}
	algorithm := strings.ToLower(strings.TrimSpace(r.Session.Algorithm))
	if algorithm == "" {
		algorithm = AlgorithmECDSA
	}
	curve := strings.ToLower(strings.TrimSpace(r.Session.Curve))
	if curve == "" && algorithm == AlgorithmECDSA {
		curve = CurveSecp256k1
	}
	if (algorithm != AlgorithmECDSA || curve != CurveSecp256k1) &&
		(algorithm != AlgorithmEdDSA || curve != CurveEd25519) {
		return ErrUnsupportedAlgorithmCurve
	}
	if corederivation.IsECDSAAlgorithm(r.Session.Algorithm) && strings.TrimSpace(r.Session.KeyID) == "" {
		return ErrKeyIDRequired
	}
	_, _, err = corederivation.ValidateDKGMaterial(r.Session.Algorithm, corederivation.DKGMaterial{
		ChainCode:        derivationMaterialChainCode(r.DerivationMaterial),
		DerivationScheme: derivationMaterialScheme(r.DerivationMaterial),
	})
	return err
}

func derivationMaterialChainCode(material *DKGDerivationMaterial) string {
	if material == nil {
		return ""
	}
	return material.ChainCode
}

func derivationMaterialScheme(material *DKGDerivationMaterial) string {
	if material == nil {
		return ""
	}
	return material.DerivationScheme
}

func (r SignSessionRequest) Validate() error {
	err := tssrequests.ValidateSign(tssrequests.SignRequest{
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
	if err != nil {
		return err
	}
	if r.DerivationContext == nil {
		return ErrDerivationContextRequired
	}
	return validateDerivationContextForSession(*r.DerivationContext, r.Session)
}
