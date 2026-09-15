package execution

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"

	corederivation "github.com/BroLabel/brosettlement-mpc-core/internal/tss/derivation"
	bnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/support"
	tssbnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/utils"
	"github.com/BroLabel/brosettlement-mpc-core/protocol"
	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	eddsakeygen "github.com/bnb-chain/tss-lib/eddsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

var (
	ErrUnknownSenderParty        = bnbutils.ErrUnknownSenderParty
	ErrDuplicateFrame            = bnbutils.ErrDuplicateFrame
	ErrFrameTooLarge             = bnbutils.ErrFrameTooLarge
	ErrQueueFull                 = bnbutils.ErrQueueFull
	ErrStalledProtocol           = bnbutils.ErrStalledProtocol
	ErrDerivationContextMismatch = corederivation.ErrDerivationContextMismatch
)

type Transport interface {
	SendFrame(ctx context.Context, frame protocol.Frame) error
	RecvFrame(ctx context.Context) (protocol.Frame, error)
}

type Params struct {
	SessionID             string
	LocalPartyID          string
	CorrelationID         string
	Stage                 string
	Algorithm             string
	DerivationContextHash string
	Party                 tsslib.Party
	PartyIDs              map[string]*tsslib.PartyID
	OutCh                 <-chan tsslib.Message
	Logger                *slog.Logger
	Debug                 bool
	Config                tssbnbutils.RunnerConfig
	Metrics               bnbutils.Metrics

	DKGECDSAEndCh  <-chan ecdsakeygen.LocalPartySaveData
	DKGEdDSAEndCh  <-chan eddsakeygen.LocalPartySaveData
	SignECDSAEndCh <-chan common.SignatureData
	DoneCh         <-chan struct{}
}

type StatsSnapshot struct {
	FramesSent uint64
	FramesRecv uint64
	DedupDrops uint64
}

type ProtocolExecution struct {
	sessionID             string
	localPartyID          string
	correlationID         string
	stage                 string
	algorithm             string
	derivationContextHash string
	party                 tsslib.Party
	partyIDs              map[string]*tsslib.PartyID
	outCh                 <-chan tsslib.Message
	logger                *slog.Logger
	debug                 bool
	cfg                   tssbnbutils.RunnerConfig
	metrics               bnbutils.Metrics

	dkgECDSAEndCh  <-chan ecdsakeygen.LocalPartySaveData
	dkgEdDSAEndCh  <-chan eddsakeygen.LocalPartySaveData
	signECDSAEndCh <-chan common.SignatureData
	doneCh         <-chan struct{}

	ecdsaKeyShare *ecdsakeygen.LocalPartySaveData
	signature     *common.SignatureData
	seq           uint64

	stats   *protocolStats
	deduper inboundDeduper

	protocolDoneFlag  atomic.Bool
	lastProgressNanos int64
	lastWarnNanos     int64
	lastMsgType       atomic.Value
	lastRecvSeq       atomic.Uint64
	lastSentSeq       atomic.Uint64
	lastRoundHint     atomic.Uint32
}

func New(p Params) *ProtocolExecution {
	return &ProtocolExecution{
		sessionID:             p.SessionID,
		localPartyID:          p.LocalPartyID,
		correlationID:         p.CorrelationID,
		stage:                 p.Stage,
		algorithm:             p.Algorithm,
		derivationContextHash: p.DerivationContextHash,
		party:                 p.Party,
		partyIDs:              p.PartyIDs,
		outCh:                 p.OutCh,
		logger:                p.Logger,
		debug:                 p.Debug,
		cfg:                   p.Config,
		metrics:               p.Metrics,
		dkgECDSAEndCh:         p.DKGECDSAEndCh,
		dkgEdDSAEndCh:         p.DKGEdDSAEndCh,
		signECDSAEndCh:        p.SignECDSAEndCh,
		doneCh:                p.DoneCh,
		stats:                 &protocolStats{},
		deduper: newTTLFrameDeduper(deduperConfig{
			TTL:           p.Config.DedupTTL,
			MaxEntries:    p.Config.DedupMaxEntries,
			MaxFrameBytes: p.Config.MaxFrameBytes,
		}),
	}
}

func (e *ProtocolExecution) Run(ctx context.Context, transport Transport) (err error) {
	rt := newSessionRuntime(ctx, e.cfg.InboundQueueCap+8)
	defer rt.Stop()

	terminalState := "failed"
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("tss protocol loop panic: %v", r)
			terminalState = "panic"
			args := []any{
				"correlation_id", e.correlationID,
				"session_id", e.sessionID,
				"party_id", e.localPartyID,
				"stage", e.stage,
				"panic", r,
			}
			if e.debug {
				args = append(args, "stacktrace", goroutineDump())
			}
			e.logger.Error("tss protocol loop panic", args...)
		}
		if e.debug {
			e.logger.Debug("tss protocol terminal state",
				"correlation_id", e.correlationID,
				"session_id", e.sessionID,
				"party_id", e.localPartyID,
				"stage", e.stage,
				"state", terminalState,
				"frames_sent", e.stats.Sent(),
				"frames_recv", e.stats.Recv(),
				"dedup_drops", e.stats.DedupDrops(),
				"err", err,
			)
		}
	}()

	e.markProgress("start", 0)
	e.startWorkers(rt, transport)

	rt.startWorkerWait()
	defer rt.StopAndWait()

	for {
		select {
		case <-ctx.Done():
			terminalState = "canceled"
			rt.StopAndWait()
			return ctx.Err()
		case ev := <-rt.Events:
			done, state, handleErr := e.handleEvent(ctx, ev)
			if !done {
				continue
			}
			groupErr := rt.StopAndWait()
			state, handleErr = e.finishTerminalEvent(state, handleErr, groupErr)
			terminalState = state
			err = handleErr
			return err
		case <-rt.workersDone:
			terminalState, err = e.handleGroupResult(rt.Wait())
			return err
		}
	}
}

func (e *ProtocolExecution) ECDSAKeyShare() *ecdsakeygen.LocalPartySaveData {
	return e.ecdsaKeyShare
}

func (e *ProtocolExecution) Signature() *common.SignatureData {
	return e.signature
}

func (e *ProtocolExecution) Stats() StatsSnapshot {
	return StatsSnapshot{
		FramesSent: e.stats.Sent(),
		FramesRecv: e.stats.Recv(),
		DedupDrops: e.stats.DedupDrops(),
	}
}

func (e *ProtocolExecution) startWorkers(rt *sessionRuntime, transport Transport) {
	rt.Group.Go(func() error { return e.runOutboundPump(rt, transport) })
	rt.Group.Go(func() error { return e.runWatchdog(rt.Ctx) })
	rt.Group.Go(func() error { return e.runRecvWorker(rt, transport) })
	rt.Group.Go(func() error { return e.runProtocolResultWorker(rt) })
	rt.Group.Go(func() error {
		if err := e.party.Start(); err != nil {
			return fmt.Errorf("tss party start failed: %w", err)
		}
		return nil
	})
}
