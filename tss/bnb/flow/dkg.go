package flow

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"brosettlement-mpc-signer/pkg/idgen"
	"github.com/BroLabel/brosettlement-mpc-core/tss/bnb/execution"
	bnbutils "github.com/BroLabel/brosettlement-mpc-core/tss/bnb/utils"
	tssutils "github.com/BroLabel/brosettlement-mpc-core/tss/utils"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	eddsakeygen "github.com/bnb-chain/tss-lib/eddsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

type DKGBuildInput struct {
	Params    *tsslib.Parameters
	OutCh     chan<- tsslib.Message
	Algorithm string
	PreParams *ecdsakeygen.LocalPreParams
}

type DKGBuildOutput struct {
	Party    tsslib.Party
	ECDSAEnd <-chan ecdsakeygen.LocalPartySaveData
	Done     <-chan struct{}
}

type DKGRunJob struct {
	SessionID      string
	LocalPartyID   string
	Parties        []string
	Threshold      uint32
	Curve          string
	Algorithm      string
	ECDSAPreParams *ecdsakeygen.LocalPreParams
}

type DKGRunMetrics = bnbutils.Metrics

type DKGRunInput struct {
	Job             DKGRunJob
	Transport       execution.Transport
	Logger          *slog.Logger
	Debug           bool
	Config          tssutils.RunnerConfig
	Metrics         DKGRunMetrics
	OnECDSAKeyShare func(ecdsakeygen.LocalPartySaveData)
}

func BuildDKG(in DKGBuildInput) (DKGBuildOutput, error) {
	alg := strings.ToLower(strings.TrimSpace(in.Algorithm))
	if alg == "" || alg == "ecdsa" {
		endCh := make(chan ecdsakeygen.LocalPartySaveData, 1)
		return DKGBuildOutput{
			Party:    newECDSAKeygenParty(in.Params, in.OutCh, endCh, in.PreParams),
			ECDSAEnd: endCh,
		}, nil
	}
	if alg == "eddsa" {
		doneCh := make(chan struct{}, 1)
		endCh := make(chan eddsakeygen.LocalPartySaveData, 1)
		party := eddsakeygen.NewLocalParty(in.Params, in.OutCh, endCh)
		go waitDKGDoneEdDSA(endCh, doneCh)
		return DKGBuildOutput{Party: party, Done: doneCh}, nil
	}
	return DKGBuildOutput{}, fmt.Errorf("unsupported algorithm: %s", in.Algorithm)
}

func newECDSAKeygenParty(
	params *tsslib.Parameters,
	outCh chan<- tsslib.Message,
	endCh chan<- ecdsakeygen.LocalPartySaveData,
	preParams *ecdsakeygen.LocalPreParams,
) tsslib.Party {
	if preParams == nil {
		return ecdsakeygen.NewLocalParty(params, outCh, endCh)
	}
	return ecdsakeygen.NewLocalParty(params, outCh, endCh, *preParams)
}

func waitDKGDoneEdDSA(endCh <-chan eddsakeygen.LocalPartySaveData, doneCh chan<- struct{}) {
	<-endCh
	select {
	case doneCh <- struct{}{}:
	default:
	}
}

func RunDKG(ctx context.Context, in DKGRunInput) error {
	logger := in.Logger
	if logger == nil {
		logger = slog.Default()
	}

	job := in.Job
	correlationID := idgen.New("corr")
	started := time.Now()
	if in.Metrics != nil {
		in.Metrics.IncSessionsStarted("dkg")
	}
	tssThreshold, thresholdErr := tssutils.ToTSSLibThreshold(int(job.Threshold), len(job.Parties))
	logDebug(in.Debug, logger, "tss runner run dkg start",
		"correlation_id", correlationID,
		"session_id", job.SessionID,
		"party_id", job.LocalPartyID,
		"parties", strings.Join(job.Parties, ","),
		"threshold_m", job.Threshold,
		"threshold_t", tssThreshold,
		"threshold_err", thresholdErr,
		"preparams_provided", job.ECDSAPreParams != nil,
		"deadline_remaining", tssutils.DeadlineRemaining(ctx),
		"tss_err_ch_available", false,
	)
	if job.ECDSAPreParams != nil {
		_ = job.ECDSAPreParams.ValidateWithProof()
	}

	execStarted := time.Now()
	exec, err := newDKGExecution(job, logger, in.Debug, correlationID, in.Config, in.Metrics)
	if err != nil {
		logDebug(in.Debug, logger, "tss runner run dkg done",
			"correlation_id", correlationID,
			"session_id", job.SessionID,
			"party_id", job.LocalPartyID,
			"duration", time.Since(started),
			"build_duration", time.Since(execStarted),
			"err", err,
		)
		return err
	}
	if err = exec.Run(ctx, in.Transport); err != nil {
		kind, _, _ := tssutils.ClassifyErr(err)
		if kind == "timeout" && in.Metrics != nil {
			in.Metrics.IncTimeouts("dkg")
		}
		if in.Metrics != nil {
			in.Metrics.IncSessionsFailed("dkg", kind)
		}
	} else {
		if keyShare := exec.ECDSAKeyShare(); keyShare != nil && in.OnECDSAKeyShare != nil {
			in.OnECDSAKeyShare(*keyShare)
		}
		if in.Metrics != nil {
			in.Metrics.IncSessionsSucceeded("dkg")
			in.Metrics.ObserveSessionDuration("dkg", time.Since(started))
		}
	}
	stats := exec.Stats()
	logDebug(in.Debug, logger, "tss runner run dkg done",
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

func newDKGExecution(job DKGRunJob, logger *slog.Logger, debug bool, correlationID string, cfg tssutils.RunnerConfig, metrics DKGRunMetrics) (*execution.ProtocolExecution, error) {
	params, partyIDs, _, err := tssutils.BuildParams(job.Parties, job.LocalPartyID, int(job.Threshold), job.Curve, job.Algorithm)
	if err != nil {
		return nil, err
	}
	outCh := make(chan tsslib.Message, len(job.Parties)*8)
	built, err := BuildDKG(DKGBuildInput{
		Params:    params,
		OutCh:     outCh,
		Algorithm: job.Algorithm,
		PreParams: job.ECDSAPreParams,
	})
	if err != nil {
		return nil, err
	}
	return execution.New(execution.Params{
		SessionID:     job.SessionID,
		LocalPartyID:  job.LocalPartyID,
		CorrelationID: correlationID,
		Stage:         "dkg",
		Algorithm:     tssutils.NormalizeAlgorithm(job.Algorithm),
		Party:         built.Party,
		PartyIDs:      partyIDs,
		OutCh:         outCh,
		Logger:        logger,
		Debug:         debug,
		Config:        cfg,
		Metrics:       metrics,
		DKGECDSAEndCh: built.ECDSAEnd,
		DoneCh:        built.Done,
	}), nil
}

func logDebug(debug bool, logger *slog.Logger, msg string, args ...any) {
	if !debug {
		return
	}
	logger.Debug(msg, args...)
}
