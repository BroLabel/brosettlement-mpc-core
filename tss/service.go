package tss

import (
	"context"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"time"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/shares"
	"github.com/BroLabel/brosettlement-mpc-core/tss/bnb"
	bnbutils "github.com/BroLabel/brosettlement-mpc-core/tss/bnb/utils"
	"github.com/BroLabel/brosettlement-mpc-core/tss/preparams"
	tssutils "github.com/BroLabel/brosettlement-mpc-core/tss/utils"

	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

// Service orchestrates TSS runtime execution through a pluggable Runner.
type Service struct {
	runner        Runner
	logger        *slog.Logger
	preParamsPool preParamsProvider
	shareStore    coreshares.Store
}

type preParamsProvider interface {
	Start(ctx context.Context) error
	Acquire(ctx context.Context) (*ecdsakeygen.LocalPreParams, error)
	Size() int
	Close() error
}

type preParamsSnapshotProvider interface {
	Snapshot() preparams.Snapshot
}

type Snapshot struct {
	PreParamsPoolSize          int
	PreParamsSyncFallbackCount uint64
	PreParamsAcquireWaitNanos  int64
}

var ErrNilRunner = errors.New("runner is required")

var (
	ErrMissingDKGPublicKey = errors.New("dkg result missing public key")
	ErrMissingDKGAddress   = errors.New("dkg result missing address")
)

func NewBnbService(logger *slog.Logger) *Service {
	return NewBnbServiceWithConfigAndShareStoreAndMetrics(
		logger,
		preparams.LoadConfigFromEnv(),
		nil,
		nil,
	)
}

func NewBnbServiceWithConfigAndShareStoreAndMetrics(logger *slog.Logger, cfg preparams.Config, shareStore coreshares.Store, metrics bnbutils.Metrics) *Service {
	pool := preparams.NewPool(logger, cfg)
	return NewServiceWithComponents(bnb.NewBnbRunnerWithMetrics(logger, metrics), logger, pool, shareStore)
}

func NewService(runner Runner, logger *slog.Logger) *Service {
	return NewServiceWithComponents(runner, logger, nil, nil)
}

func NewServiceWithPreParamsPool(runner Runner, logger *slog.Logger, pool preParamsProvider) *Service {
	return NewServiceWithComponents(runner, logger, pool, nil)
}

func NewServiceWithComponents(runner Runner, logger *slog.Logger, pool preParamsProvider, shareStore coreshares.Store) *Service {
	if runner == nil {
		panic(ErrNilRunner)
	}
	return &Service{
		runner:        runner,
		logger:        logger,
		preParamsPool: pool,
		shareStore:    shareStore,
	}
}

// StartPreParamsPool starts background pre-params warmup/refill workers.
func (s *Service) StartPreParamsPool(ctx context.Context) error {
	if s.preParamsPool == nil {
		return nil
	}
	return s.preParamsPool.Start(ctx)
}

// StopPreParamsPool stops background pre-params workers.
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

	snapshot := Snapshot{
		PreParamsPoolSize: s.preParamsPool.Size(),
	}
	if provider, ok := s.preParamsPool.(preParamsSnapshotProvider); ok {
		poolSnapshot := provider.Snapshot()
		snapshot.PreParamsSyncFallbackCount = poolSnapshot.SyncFallbackCount
		snapshot.PreParamsAcquireWaitNanos = poolSnapshot.AcquireWaitNanos
		if snapshot.PreParamsPoolSize == 0 {
			snapshot.PreParamsPoolSize = poolSnapshot.Size
		}
	}
	return snapshot
}

func (s *Service) RunDKGSession(ctx context.Context, req DKGSessionRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}

	job := DKGJob{
		SessionID:    req.Session.SessionID,
		LocalPartyID: req.LocalPartyID,
		OrgID:        req.Session.OrgID,
		Parties:      req.Session.Parties,
		Threshold:    req.Session.Threshold,
		Curve:        req.Session.Curve,
		Algorithm:    req.Session.Algorithm,
		Chain:        req.Session.Chain,
	}
	keyID := strings.TrimSpace(req.Session.KeyID)
	if keyID == "" {
		keyID = req.Session.SessionID
	}

	s.logSessionStart("dkg", req.Session.SessionID, req.Session.OrgID, keyID, req.LocalPartyID)
	started := time.Now()
	err := s.attachPreParams(ctx, &job)
	if err == nil {
		err = s.runner.RunDKG(ctx, job, req.Transport)
	}
	if err == nil && s.shareStore != nil && tssutils.IsECDSA(job.Algorithm) {
		err = s.persistShareAfterDKG(ctx, job)
	}
	if err == nil && tssutils.IsECDSA(job.Algorithm) {
		err = s.ensureDKGMetadata(keyID, req.Session.SessionID)
	}
	s.logSessionEnd("dkg", req.Session.SessionID, req.Session.OrgID, keyID, req.LocalPartyID, started, err)
	return err
}

func (s *Service) RunSignSession(ctx context.Context, req SignSessionRequest) (err error) {
	if err := req.Validate(); err != nil {
		return err
	}

	job := SignJob{
		SessionID:    req.Session.SessionID,
		LocalPartyID: req.LocalPartyID,
		OrgID:        req.Session.OrgID,
		KeyID:        req.Session.KeyID,
		Parties:      req.Session.Parties,
		Digest:       append([]byte(nil), req.Digest...),
		Algorithm:    req.Session.Algorithm,
		Chain:        req.Session.Chain,
	}

	s.logSessionStart("sign", req.Session.SessionID, req.Session.OrgID, req.Session.KeyID, req.LocalPartyID)
	started := time.Now()
	cleanup, err := s.prepareShareForSign(ctx, job)
	if err == nil {
		defer cleanup()
		err = s.runner.RunSign(ctx, job, req.Transport)
	}
	if err == nil {
		_, err = s.runner.ExportECDSASignature(req.Session.SessionID)
	}
	s.logSessionEnd("sign", req.Session.SessionID, req.Session.OrgID, req.Session.KeyID, req.LocalPartyID, started, err)
	return err
}

func (s *Service) ExportECDSASignature(key string) (common.SignatureData, error) {
	return s.runner.ExportECDSASignature(key)
}

func (s *Service) ExportECDSAKeyShare(key string) (ecdsakeygen.LocalPartySaveData, error) {
	return s.runner.ExportECDSAKeyShare(key)
}

func (s *Service) ImportECDSAKeyShare(key string, data ecdsakeygen.LocalPartySaveData) error {
	s.runner.ImportECDSAKeyShare(key, data)
	return nil
}

func (s *Service) DeleteECDSAKeyShare(key string) {
	s.runner.DeleteECDSAKeyShare(key)
}

func (s *Service) ECDSAAddress(key string) (string, error) {
	return s.runner.ECDSAAddress(key)
}

func (s *Service) persistShareAfterDKG(ctx context.Context, job DKGJob) error {
	keyID, err := tssutils.NormalizeKeyID(job.SessionID, coreshares.ErrVaultWriteFailed)
	if err != nil {
		return err
	}
	share, err := s.runner.ExportECDSAKeyShare(keyID)
	if err != nil {
		return err
	}
	defer s.runner.DeleteECDSAKeyShare(keyID)

	blob, err := coreshares.MarshalShare(share)
	if err == nil {
		defer zeroBytes(blob)
		err = s.shareStore.SaveShare(ctx, keyID, blob, tssutils.DKGShareMeta(keyID, job.OrgID, job.Algorithm, job.Curve))
	}
	return err
}

func (s *Service) prepareShareForSign(ctx context.Context, job SignJob) (func(), error) {
	if s.shareStore == nil || !tssutils.IsECDSA(job.Algorithm) {
		return func() {}, nil
	}

	keyID, err := tssutils.NormalizeKeyID(job.KeyID, coreshares.ErrShareNotFound)
	if err != nil {
		return nil, err
	}
	stored, err := s.shareStore.LoadShare(ctx, keyID)
	if err == nil {
		err = validateLoadedMeta(keyID, job.OrgID, job.Algorithm, stored.Meta)
	}
	if err != nil {
		return nil, err
	}
	share, err := coreshares.UnmarshalShare(stored.Blob)
	defer zeroBytes(stored.Blob)
	if err != nil {
		return nil, err
	}
	s.runner.ImportECDSAKeyShare(keyID, share)
	return func() {
		s.runner.DeleteECDSAKeyShare(keyID)
	}, nil
}

func (s *Service) ensureDKGMetadata(keyID, sessionID string) error {
	share, err := s.runner.ExportECDSAKeyShare(sessionID)
	if err != nil {
		return err
	}
	if extractECDSAPublicKey(share) == "" {
		return ErrMissingDKGPublicKey
	}
	address, err := s.runner.ECDSAAddress(sessionID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(address) == "" {
		return ErrMissingDKGAddress
	}
	return nil
}

func validateLoadedMeta(keyID, orgID, algorithm string, meta coreshares.ShareMeta) error {
	if meta.KeyID != "" && meta.KeyID != keyID {
		return coreshares.ErrMetadataMismatch
	}
	if orgID != "" && meta.OrgID != "" && meta.OrgID != orgID {
		return coreshares.ErrMetadataMismatch
	}
	alg := strings.ToLower(strings.TrimSpace(algorithm))
	if alg == "" {
		alg = "ecdsa"
	}
	if meta.Algorithm != "" && !strings.EqualFold(meta.Algorithm, alg) {
		return coreshares.ErrMetadataMismatch
	}
	return nil
}

func extractECDSAPublicKey(share ecdsakeygen.LocalPartySaveData) string {
	if share.ECDSAPub == nil {
		return ""
	}
	pub := share.ECDSAPub.ToECDSAPubKey()
	if pub == nil {
		return ""
	}
	marshaled := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	if len(marshaled) == 0 {
		return ""
	}
	return hex.EncodeToString(marshaled)
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func (s *Service) attachPreParams(ctx context.Context, job *DKGJob) error {
	if job == nil || s.preParamsPool == nil || job.ECDSAPreParams != nil || !tssutils.IsECDSA(job.Algorithm) {
		return nil
	}
	pre, err := s.preParamsPool.Acquire(ctx)
	if err != nil {
		return err
	}
	job.ECDSAPreParams = pre
	return nil
}

func (s *Service) logSessionStart(operation, sessionID, orgID, keyID, partyID string) {
	args := []any{
		"operation", operation,
		"session_id", sessionID,
		"org_id", orgID,
		"party_id", partyID,
	}
	if strings.TrimSpace(keyID) != "" {
		args = append(args, "key_id", keyID)
	}
	s.logger.Info("tss session start", args...)
}

func (s *Service) logSessionEnd(operation, sessionID, orgID, keyID, partyID string, started time.Time, err error) {
	result := "success"
	level := slog.LevelInfo
	if errors.Is(err, context.Canceled) {
		result = "canceled"
		level = slog.LevelDebug
	} else if errors.Is(err, context.DeadlineExceeded) {
		result = "timeout"
		level = slog.LevelWarn
	} else if err != nil {
		result = "error"
		level = slog.LevelError
	}

	args := []any{
		"operation", operation,
		"session_id", sessionID,
		"org_id", orgID,
		"party_id", partyID,
		"duration", time.Since(started),
		"result", result,
	}
	if strings.TrimSpace(keyID) != "" {
		args = append(args, "key_id", keyID)
	}
	if err != nil {
		args = append(args, "err", err)
	}
	s.logger.Log(context.Background(), level, "tss session end", args...)
}
