package execution

import (
	"context"
	"errors"
	"fmt"
	"io"

	tssbnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/utils"
	"github.com/BroLabel/brosettlement-mpc-core/protocol"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

func (e *ProtocolExecution) runRecvWorker(rt *sessionRuntime, transport Transport) error {
	inboundCh := make(chan protocol.Frame, e.cfg.InboundQueueCap)
	recvErrCh := make(chan error, 1)
	recvLoopDone := make(chan struct{})
	go func() {
		defer close(recvLoopDone)
		tssbnbutils.RecvLoop(
			rt.Ctx,
			transport.RecvFrame,
			inboundCh,
			recvErrCh,
			e.cfg.MaxFrameBytes,
			ErrFrameTooLarge,
			ErrQueueFull,
		)
	}()
	defer func() { <-recvLoopDone }()

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
	if err := e.validateDerivationContextHash(frame); err != nil {
		return err
	}
	if ok, err := e.shouldProcessInbound(frame); !ok {
		return err
	}
	return nil
}

func (e *ProtocolExecution) validateDerivationContextHash(frame protocol.Frame) error {
	if e.stage != "sign" {
		return nil
	}
	if e.derivationContextHash == "" || frame.DerivationContextHash != e.derivationContextHash {
		return fmt.Errorf("%w: expected=%s got=%s", ErrDerivationContextMismatch, e.derivationContextHash, frame.DerivationContextHash)
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
