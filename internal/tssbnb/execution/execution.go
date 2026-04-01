package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"time"

	"github.com/BroLabel/brosettlement-mpc-core/internal/idgen"
	bnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/support"
	tssbnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/utils"
	"github.com/BroLabel/brosettlement-mpc-core/protocol"
	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

var (
	ErrUnknownSenderParty = bnbutils.ErrUnknownSenderParty
	ErrDuplicateFrame     = bnbutils.ErrDuplicateFrame
	ErrFrameTooLarge      = bnbutils.ErrFrameTooLarge
	ErrQueueFull          = bnbutils.ErrQueueFull
	ErrStalledProtocol    = bnbutils.ErrStalledProtocol
)

type Transport interface {
	SendFrame(ctx context.Context, frame protocol.Frame) error
	RecvFrame(ctx context.Context) (protocol.Frame, error)
}

type Params struct {
	SessionID     string
	LocalPartyID  string
	CorrelationID string
	Stage         string
	Algorithm     string
	Party         tsslib.Party
	PartyIDs      map[string]*tsslib.PartyID
	OutCh         <-chan tsslib.Message
	Logger        *slog.Logger
	Debug         bool
	Config        tssbnbutils.RunnerConfig
	Metrics       bnbutils.Metrics

	DKGECDSAEndCh  <-chan ecdsakeygen.LocalPartySaveData
	SignECDSAEndCh <-chan *common.SignatureData
	DoneCh         <-chan struct{}
}

type StatsSnapshot struct {
	FramesSent uint64
	FramesRecv uint64
	DedupDrops uint64
}

type ProtocolExecution struct {
	sessionID     string
	localPartyID  string
	correlationID string
	stage         string
	algorithm     string
	party         tsslib.Party
	partyIDs      map[string]*tsslib.PartyID
	outCh         <-chan tsslib.Message
	logger        *slog.Logger
	debug         bool
	cfg           tssbnbutils.RunnerConfig
	metrics       bnbutils.Metrics

	dkgECDSAEndCh  <-chan ecdsakeygen.LocalPartySaveData
	signECDSAEndCh <-chan *common.SignatureData
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
		sessionID:      p.SessionID,
		localPartyID:   p.LocalPartyID,
		correlationID:  p.CorrelationID,
		stage:          p.Stage,
		algorithm:      p.Algorithm,
		party:          p.Party,
		partyIDs:       p.PartyIDs,
		outCh:          p.OutCh,
		logger:         p.Logger,
		debug:          p.Debug,
		cfg:            p.Config,
		metrics:        p.Metrics,
		dkgECDSAEndCh:  p.DKGECDSAEndCh,
		signECDSAEndCh: p.SignECDSAEndCh,
		doneCh:         p.DoneCh,
		stats:          &protocolStats{},
		deduper: newTTLFrameDeduper(deduperConfig{
			TTL:           p.Config.DedupTTL,
			MaxEntries:    p.Config.DedupMaxEntries,
			MaxFrameBytes: p.Config.MaxFrameBytes,
		}),
	}
}

func (e *ProtocolExecution) Run(ctx context.Context, transport Transport) (err error) {
	rt := newSessionRuntime[protocolEvent](ctx, e.cfg.InboundQueueCap+8)
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

	groupErrCh := make(chan error, 1)
	go func() {
		groupErrCh <- rt.Group.Wait()
		close(groupErrCh)
	}()

	for {
		select {
		case <-ctx.Done():
			terminalState = "canceled"
			return ctx.Err()
		case ev := <-rt.Events:
			done, state, handleErr := e.handleEvent(ev)
			if !done {
				continue
			}
			terminalState = state
			err = handleErr
			rt.Stop()
			<-groupErrCh
			return err
		case groupErr := <-groupErrCh:
			terminalState, err = e.handleGroupResult(groupErr)
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

type protocolResult struct {
	ecdsaKeyShare *ecdsakeygen.LocalPartySaveData
	signature     *common.SignatureData
}

type protocolEventType int

const (
	eventInboundFrame protocolEventType = iota
	eventRecvError
	eventProtocolDone
)

type protocolEvent struct {
	typ    protocolEventType
	frame  protocol.Frame
	err    error
	result protocolResult
}

func (e *ProtocolExecution) startWorkers(rt *sessionRuntime[protocolEvent], transport Transport) {
	rt.Group.Go(func() error { return e.runOutboundPump(rt.Ctx, transport) })
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

func (e *ProtocolExecution) runRecvWorker(rt *sessionRuntime[protocolEvent], transport Transport) error {
	inboundCh := make(chan protocol.Frame, e.cfg.InboundQueueCap)
	recvErrCh := make(chan error, 1)
	go tssbnbutils.RecvLoop(
		rt.Ctx,
		transport.RecvFrame,
		inboundCh,
		recvErrCh,
		e.cfg.MaxFrameBytes,
		ErrFrameTooLarge,
		ErrQueueFull,
	)

	for {
		select {
		case <-rt.Ctx.Done():
			return nil
		case frame, ok := <-inboundCh:
			if !ok {
				return nil
			}
			if !rt.Emit(protocolEvent{typ: eventInboundFrame, frame: frame}) {
				return nil
			}
		case err := <-recvErrCh:
			if !rt.Emit(protocolEvent{typ: eventRecvError, err: err}) {
				return nil
			}
			return nil
		}
	}
}

func (e *ProtocolExecution) runProtocolResultWorker(rt *sessionRuntime[protocolEvent]) error {
	for {
		select {
		case <-rt.Ctx.Done():
			return nil
		case data := <-e.dkgECDSAEndCh:
			d := data
			rt.Emit(protocolEvent{typ: eventProtocolDone, result: protocolResult{ecdsaKeyShare: &d}})
			return nil
		case sig := <-e.signECDSAEndCh:
			rt.Emit(protocolEvent{typ: eventProtocolDone, result: protocolResult{signature: sig}})
			return nil
		case <-e.doneCh:
			rt.Emit(protocolEvent{typ: eventProtocolDone, result: protocolResult{}})
			return nil
		}
	}
}

func (e *ProtocolExecution) handleEvent(ev protocolEvent) (done bool, state string, err error) {
	switch ev.typ {
	case eventInboundFrame:
		e.stats.IncRecv()
		e.metrics.IncFramesRecv(e.stage)
		e.lastRecvSeq.Store(ev.frame.Seq)
		e.markProgress(ev.frame.MessageType, ev.frame.RoundHint)
		if err := e.handleIncoming(ev.frame); err != nil {
			return true, "failed", err
		}
		e.markProgress(ev.frame.MessageType, ev.frame.RoundHint)
		return false, "", nil
	case eventRecvError:
		return e.handleRecvError(ev.err)
	case eventProtocolDone:
		e.ecdsaKeyShare = ev.result.ecdsaKeyShare
		e.signature = ev.result.signature
		e.protocolDoneFlag.Store(true)
		return true, "success", nil
	default:
		return true, "failed", fmt.Errorf("unknown protocol event: %d", ev.typ)
	}
}

func (e *ProtocolExecution) handleGroupResult(groupErr error) (string, error) {
	if groupErr == nil {
		if e.protocolDoneFlag.Load() {
			return "success", nil
		}
		return "failed", io.ErrUnexpectedEOF
	}
	if errors.Is(groupErr, context.Canceled) {
		if e.protocolDoneFlag.Load() {
			return "success", nil
		}
		return "canceled", context.Canceled
	}
	if errors.Is(groupErr, ErrStalledProtocol) {
		return "stalled", groupErr
	}
	return "failed", groupErr
}

func (e *ProtocolExecution) handleRecvError(err error) (bool, string, error) {
	if err == nil {
		return true, "failed", fmt.Errorf("recv loop stopped before protocol end")
	}
	if errors.Is(err, context.Canceled) {
		if e.protocolDoneFlag.Load() {
			return true, "success", nil
		}
		return true, "canceled", context.Canceled
	}
	if errors.Is(err, ErrQueueFull) {
		e.metrics.IncQueueFull(e.stage)
		e.logger.Warn("tss inbound queue full",
			"correlation_id", e.correlationID,
			"session_id", e.sessionID,
			"party_id", e.localPartyID,
			"stage", e.stage,
		)
		return true, "failed", err
	}
	if errors.Is(err, ErrFrameTooLarge) {
		e.metrics.IncOversizedFrames(e.stage)
		e.logger.Warn("tss inbound oversized frame",
			"correlation_id", e.correlationID,
			"session_id", e.sessionID,
			"party_id", e.localPartyID,
			"stage", e.stage,
			"err", err,
		)
		return true, "failed", err
	}
	if errors.Is(err, io.EOF) {
		return true, "failed", fmt.Errorf("recv loop EOF before protocol end: %w", err)
	}
	return true, "failed", err
}

func (e *ProtocolExecution) runOutboundPump(ctx context.Context, transport Transport) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case msg, ok := <-e.outCh:
			if !ok {
				return nil
			}
			if err := e.forwardOutgoing(ctx, transport, msg); err != nil {
				if e.debug {
					e.logger.Debug("tss out pump send error",
						"correlation_id", e.correlationID,
						"session_id", e.sessionID,
						"party_id", e.localPartyID,
						"stage", e.stage,
						"msg_type", msg.Type(),
						"err", err,
					)
				}
				return err
			}
		}
	}
}

func (e *ProtocolExecution) markProgress(msgType string, roundHint uint32) {
	now := time.Now().UnixNano()
	atomic.StoreInt64(&e.lastProgressNanos, now)
	if msgType != "" {
		e.lastMsgType.Store(msgType)
	}
	if roundHint > 0 {
		e.lastRoundHint.Store(roundHint)
	}
}

func (e *ProtocolExecution) runWatchdog(ctx context.Context) error {
	ticker := time.NewTicker(e.cfg.WatchdogTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			last := time.Unix(0, atomic.LoadInt64(&e.lastProgressNanos))
			if last.IsZero() {
				continue
			}
			idle := time.Since(last)
			if idle >= e.cfg.StallWarn {
				lastWarn := time.Unix(0, atomic.LoadInt64(&e.lastWarnNanos))
				if lastWarn.IsZero() || time.Since(lastWarn) >= e.cfg.StallWarnEvery {
					atomic.StoreInt64(&e.lastWarnNanos, time.Now().UnixNano())
					msgType, _ := e.lastMsgType.Load().(string)
					e.logger.Warn("tss protocol stall warning",
						"correlation_id", e.correlationID,
						"session_id", e.sessionID,
						"party_id", e.localPartyID,
						"stage", e.stage,
						"idle", idle,
						"last_msg_type", msgType,
						"last_round_hint", e.lastRoundHint.Load(),
						"last_recv_seq", e.lastRecvSeq.Load(),
						"last_sent_seq", e.lastSentSeq.Load(),
					)
				}
			}
			if idle >= e.cfg.StallFail {
				e.metrics.IncStalls(e.stage)
				if e.debug {
					e.logger.Debug("tss protocol stalled; goroutine dump",
						"correlation_id", e.correlationID,
						"session_id", e.sessionID,
						"party_id", e.localPartyID,
						"stage", e.stage,
						"idle", idle,
						"stacktrace", goroutineDump(),
					)
				}
				return fmt.Errorf("%w: idle=%s", ErrStalledProtocol, idle)
			}
		}
	}
}

func (e *ProtocolExecution) shouldProcessInbound(frame protocol.Frame) (bool, error) {
	ok, err := e.deduper.ShouldAccept(frame)
	if isDuplicateErr(err) {
		e.stats.IncDedupDrop()
		e.metrics.IncDedupHits(e.stage)
		return false, ErrDuplicateFrame
	}
	if errors.Is(err, ErrFrameTooLarge) {
		e.metrics.IncOversizedFrames(e.stage)
		return false, err
	}
	return ok, err
}

func (e *ProtocolExecution) validateInbound(frame protocol.Frame) error {
	if frame.SessionID != e.sessionID {
		return io.EOF
	}
	if ok, err := e.shouldProcessInbound(frame); !ok {
		if errors.Is(err, ErrDuplicateFrame) {
			return nil
		}
		return err
	}
	return nil
}

func (e *ProtocolExecution) parseInbound(frame protocol.Frame) (tsslib.ParsedMessage, error) {
	from, ok := e.partyIDs[frame.FromParty]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownSenderParty, frame.FromParty)
	}
	parsedMsg, err := tsslib.ParseWireMessage(frame.Payload, from, frame.IsBroadcast())
	if err != nil {
		if e.debug {
			e.logger.Debug("tss protocol update parse failed",
				"correlation_id", e.correlationID,
				"session_id", frame.SessionID,
				"stage", e.stage,
				"party_id", e.localPartyID,
				"from_party", frame.FromParty,
				"err", err,
			)
		}
		return nil, fmt.Errorf("parse tss message: %w", err)
	}
	return parsedMsg, nil
}

func (e *ProtocolExecution) applyInbound(parsedMsg tsslib.ParsedMessage, fromParty string, sessionID string) error {
	updateOK, updateErr := e.party.Update(parsedMsg)
	if e.debug && (updateErr != nil || !updateOK) {
		e.logger.Debug("tss protocol update result",
			"correlation_id", e.correlationID,
			"session_id", sessionID,
			"party_id", e.localPartyID,
			"msg_type", parsedMsg.Type(),
			"from_party", fromParty,
			"ok", updateOK,
			"err", updateErr,
		)
	}
	if updateErr != nil {
		return fmt.Errorf("update tss state: %w", updateErr)
	}
	return nil
}

func (e *ProtocolExecution) handleIncoming(frame protocol.Frame) error {
	if err := e.validateInbound(frame); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, ErrDuplicateFrame) {
			return nil
		}
		return err
	}
	parsedMsg, err := e.parseInbound(frame)
	if err != nil {
		return err
	}
	return e.applyInbound(parsedMsg, frame.FromParty, frame.SessionID)
}

func (e *ProtocolExecution) forwardOutgoing(ctx context.Context, transport Transport, msg tsslib.Message) error {
	msgType := msg.Type()
	roundHint := inferRoundHint(msgType)
	payload, routing, err := msg.WireBytes()
	if err != nil {
		return fmt.Errorf("encode tss message: %w", err)
	}
	if len(payload) > e.cfg.MaxFrameBytes {
		e.metrics.IncOversizedFrames(e.stage)
		return fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, len(payload), e.cfg.MaxFrameBytes)
	}

	base := protocol.Frame{
		SessionID:     e.sessionID,
		Stage:         e.stage,
		MessageID:     idgen.New("msg"),
		Seq:           atomic.AddUint64(&e.seq, 1),
		Round:         0,
		RoundHint:     roundHint,
		Broadcast:     routing.IsBroadcast,
		Protocol:      e.algorithm,
		MessageType:   msgType,
		FromParty:     routing.From.Id,
		Payload:       payload,
		PayloadHash:   shortHash(payload),
		CorrelationID: e.correlationID,
		SentAt:        time.Now(),
	}

	if routing.IsBroadcast || len(routing.To) == 0 {
		if err := transport.SendFrame(ctx, base); err != nil {
			if e.debug {
				e.logger.Debug("tss transport send failed",
					"correlation_id", e.correlationID,
					"session_id", e.sessionID,
					"stage", e.stage,
					"party_id", e.localPartyID,
					"msg_type", msgType,
					"to_party", "",
					"err", err,
				)
			}
			return err
		}
		e.stats.IncSent()
		e.metrics.IncFramesSent(e.stage)
		e.lastSentSeq.Store(base.Seq)
		e.markProgress(msgType, roundHint)
		return nil
	}

	for _, to := range routing.To {
		frame := base
		frame.ToParty = to.Id
		if err := transport.SendFrame(ctx, frame); err != nil {
			if e.debug {
				e.logger.Debug("tss transport send failed",
					"correlation_id", e.correlationID,
					"session_id", e.sessionID,
					"stage", e.stage,
					"party_id", e.localPartyID,
					"msg_type", msgType,
					"to_party", frame.ToParty,
					"err", err,
				)
			}
			return err
		}
		e.stats.IncSent()
		e.metrics.IncFramesSent(e.stage)
		e.lastSentSeq.Store(frame.Seq)
		e.markProgress(msgType, roundHint)
	}
	return nil
}

func inferRoundHint(msgType string) uint32 {
	switch {
	case strings.Contains(msgType, "KGRound1Message"):
		return 1
	case strings.Contains(msgType, "KGRound2Message1"),
		strings.Contains(msgType, "KGRound2Message2"):
		return 2
	case strings.Contains(msgType, "KGRound3Message"):
		return 3
	case strings.Contains(msgType, "SignRound1Message"):
		return 1
	case strings.Contains(msgType, "SignRound2Message"):
		return 2
	case strings.Contains(msgType, "SignRound3Message"):
		return 3
	case strings.Contains(msgType, "SignRound4Message"):
		return 4
	case strings.Contains(msgType, "SignRound5Message"):
		return 5
	default:
		return 0
	}
}

func shortHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:8])
}

func goroutineDump() string {
	var buf bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&buf, 2); err == nil && buf.Len() > 0 {
		return buf.String()
	}
	size := 1 << 20
	bufBytes := make([]byte, size)
	n := runtime.Stack(bufBytes, true)
	if n > 0 {
		return string(bufBytes[:n])
	}
	return string(debug.Stack())
}
