package flow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"brosettlement-mpc-signer/pkg/idgen"
	"github.com/BroLabel/brosettlement-mpc-core/tss/bnb/execution"
	bnbutils "github.com/BroLabel/brosettlement-mpc-core/tss/bnb/utils"
	tssutils "github.com/BroLabel/brosettlement-mpc-core/tss/utils"

	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	ecdsasigning "github.com/bnb-chain/tss-lib/ecdsa/signing"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

var (
	ErrSignDigestRequired       = errors.New("sign digest is required")
	ErrSignAlgorithmUnsupported = errors.New("sign supports only ecdsa")
)

type SignBuildInput struct {
	Digest   []byte
	Params   *tsslib.Parameters
	KeyShare ecdsakeygen.LocalPartySaveData
	OutCh    chan<- tsslib.Message
}

type SignBuildOutput struct {
	Party tsslib.Party
	End   <-chan *common.SignatureData
}

type SignRunJob struct {
	SessionID    string
	LocalPartyID string
	KeyID        string
	Parties      []string
	Digest       []byte
	Algorithm    string
}

type SignRunMetrics = bnbutils.Metrics

type SignRunInput struct {
	Job         SignRunJob
	KeyShare    ecdsakeygen.LocalPartySaveData
	Transport   execution.Transport
	Logger      *slog.Logger
	Debug       bool
	Config      tssutils.RunnerConfig
	Metrics     SignRunMetrics
	OnSignature func(*common.SignatureData)
}

func BuildSign(in SignBuildInput) SignBuildOutput {
	rawEndCh := make(chan *common.SignatureData, 1)

	tssEndCh := make(chan common.SignatureData, 1)
	msg := new(big.Int).SetBytes(in.Digest)
	party := ecdsasigning.NewLocalParty(msg, in.Params, in.KeyShare, in.OutCh, tssEndCh)
	go func() {
		defer close(rawEndCh)

		//nolint:govet // unavoidable boundary with tss-lib v1.5.0
		sig := <-tssEndCh
		rawEndCh <- cloneSignatureData(&sig)
	}()
	return SignBuildOutput{Party: party, End: rawEndCh}
}

func RunSign(ctx context.Context, in SignRunInput) error {
	logger := in.Logger
	if logger == nil {
		logger = slog.Default()
	}

	job := in.Job
	correlationID := idgen.New("corr")
	started := time.Now()
	if in.Metrics != nil {
		in.Metrics.IncSessionsStarted("sign")
	}
	logDebug(in.Debug, logger, "tss runner run sign start",
		"correlation_id", correlationID,
		"session_id", job.SessionID,
		"party_id", job.LocalPartyID,
		"key_id", job.KeyID,
		"digest_len", len(job.Digest),
		"deadline_remaining", tssutils.DeadlineRemaining(ctx),
		"tss_err_ch_available", false,
	)
	if len(job.Digest) == 0 {
		return ErrSignDigestRequired
	}
	if alg := strings.ToLower(strings.TrimSpace(job.Algorithm)); alg != "" && alg != "ecdsa" {
		return fmt.Errorf("%w: %s", ErrSignAlgorithmUnsupported, job.Algorithm)
	}

	execStarted := time.Now()
	exec, err := newSignExecution(job, in.KeyShare, logger, in.Debug, correlationID, in.Config, in.Metrics)
	if err != nil {
		logDebug(in.Debug, logger, "tss runner run sign done",
			"correlation_id", correlationID,
			"session_id", job.SessionID,
			"party_id", job.LocalPartyID,
			"duration", time.Since(started),
			"build_duration", time.Since(execStarted),
			"err", err,
		)
		return err
	}
	err = exec.Run(ctx, in.Transport)
	if err != nil {
		kind, _, _ := tssutils.ClassifyErr(err)
		if kind == "timeout" && in.Metrics != nil {
			in.Metrics.IncTimeouts("sign")
		}
		if in.Metrics != nil {
			in.Metrics.IncSessionsFailed("sign", kind)
		}
	} else {
		if sig := exec.Signature(); sig != nil && in.OnSignature != nil {
			in.OnSignature(sig)
		}
		if in.Metrics != nil {
			in.Metrics.IncSessionsSucceeded("sign")
			in.Metrics.ObserveSessionDuration("sign", time.Since(started))
		}
	}
	stats := exec.Stats()
	logDebug(in.Debug, logger, "tss runner run sign done",
		"correlation_id", correlationID,
		"session_id", job.SessionID,
		"party_id", job.LocalPartyID,
		"duration", time.Since(started),
		"frames_sent", stats.FramesSent,
		"frames_recv", stats.FramesRecv,
		"dedup_drops", stats.DedupDrops,
		"err", err,
	)
	return err
}

func newSignExecution(job SignRunJob, keyShare ecdsakeygen.LocalPartySaveData, logger *slog.Logger, debug bool, correlationID string, cfg tssutils.RunnerConfig, metrics SignRunMetrics) (*execution.ProtocolExecution, error) {
	params, partyIDs, _, err := tssutils.BuildParams(job.Parties, job.LocalPartyID, len(job.Parties), "", "ecdsa")
	if err != nil {
		return nil, err
	}

	outCh := make(chan tsslib.Message, len(job.Parties)*8)
	built := BuildSign(SignBuildInput{
		Digest:   job.Digest,
		Params:   params,
		KeyShare: keyShare,
		OutCh:    outCh,
	})
	return execution.New(execution.Params{
		SessionID:      job.SessionID,
		LocalPartyID:   job.LocalPartyID,
		CorrelationID:  correlationID,
		Stage:          "sign",
		Algorithm:      "ecdsa",
		Party:          built.Party,
		PartyIDs:       partyIDs,
		OutCh:          outCh,
		Logger:         logger,
		Debug:          debug,
		Config:         cfg,
		Metrics:        metrics,
		SignECDSAEndCh: built.End,
	}), nil
}

func cloneSignatureData(in *common.SignatureData) *common.SignatureData {
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
