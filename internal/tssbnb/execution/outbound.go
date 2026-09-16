package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"github.com/BroLabel/brosettlement-mpc-core/internal/idgen"
	"github.com/BroLabel/brosettlement-mpc-core/protocol"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

type cancellationProvenanceTransport struct {
	Transport
	stopping                func() bool
	independentCancellation bool
}

func (t *cancellationProvenanceTransport) SendFrame(ctx context.Context, frame protocol.Frame) error {
	err := t.Transport.SendFrame(ctx, frame)
	if errors.Is(err, context.Canceled) && !t.stopping() {
		t.independentCancellation = true
	}
	return err
}

func (e *ProtocolExecution) runOutboundPump(rt *sessionRuntime, transport Transport) error {
	ctx := rt.Ctx
	outCh := e.outCh
	for {
		if ctx.Err() != nil {
			return rt.StopError()
		}
		select {
		case <-ctx.Done():
			return rt.StopError()
		// tss-lib enqueues the final frame before publishing the result.
		case sig := <-rt.signResult:
			return e.drainOutbound(rt, transport, protocolResult{signature: sig})
		case data, ok := <-e.dkgECDSAEndCh:
			if !ok {
				return io.ErrUnexpectedEOF
			}
			return e.drainOutbound(rt, transport, protocolResult{ecdsaKeyShare: &data})
		case msg, ok := <-outCh:
			if !ok {
				if e.signECDSAEndCh != nil {
					// Keep the result handoff alive after the final outbound frame.
					outCh = nil
					continue
				}
				select {
				case <-ctx.Done():
					return rt.StopError()
				case data, endOK := <-e.dkgECDSAEndCh:
					if endOK {
						return e.emitProtocolDone(rt, protocolResult{ecdsaKeyShare: &data})
					}
					return io.ErrUnexpectedEOF
				default:
				}
				return nil
			}
			if err := e.forwardProtocolMessage(rt, transport, msg); err != nil {
				return err
			}
		}
	}
}

// drainOutbound sends already-produced frames before publishing the result.
func (e *ProtocolExecution) drainOutbound(rt *sessionRuntime, transport Transport, result protocolResult) error {
	for {
		if rt.Ctx.Err() != nil {
			return rt.StopError()
		}
		select {
		case <-rt.Ctx.Done():
			return rt.StopError()
		case msg, ok := <-e.outCh:
			if !ok {
				return e.emitProtocolDone(rt, result)
			}
			if err := e.forwardProtocolMessage(rt, transport, msg); err != nil {
				return err
			}
		default:
			return e.emitProtocolDone(rt, result)
		}
	}
}

func (e *ProtocolExecution) emitProtocolDone(rt *sessionRuntime, result protocolResult) error {
	if rt.Ctx.Err() != nil {
		return rt.StopError()
	}
	if rt.Emit(protocolEvent{typ: eventProtocolDone, result: result}) {
		return nil
	}
	return rt.StopError()
}

func (e *ProtocolExecution) forwardProtocolMessage(rt *sessionRuntime, transport Transport, msg tsslib.Message) error {
	trackedTransport := &cancellationProvenanceTransport{
		Transport: transport,
		stopping:  rt.Stopping,
	}
	if err := e.forwardOutgoing(rt.Ctx, trackedTransport, msg); err != nil {
		ownerCanceled := errors.Is(err, context.Canceled) &&
			!trackedTransport.independentCancellation && rt.Stopping()
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
		if ownerCanceled {
			return nil
		}
		return err
	}
	return nil
}

type outboundFrameInput struct {
	messageType string
	roundHint   uint32
	broadcast   bool
	fromParty   string
	payload     []byte
}

func (e *ProtocolExecution) newOutboundBaseFrame(in outboundFrameInput) protocol.Frame {
	return protocol.Frame{
		SessionID:             e.sessionID,
		Stage:                 e.stage,
		MessageID:             idgen.New("msg"),
		Seq:                   atomic.AddUint64(&e.seq, 1),
		Round:                 0,
		RoundHint:             in.roundHint,
		Broadcast:             in.broadcast,
		Protocol:              e.algorithm,
		MessageType:           in.messageType,
		FromParty:             in.fromParty,
		Payload:               in.payload,
		PayloadHash:           shortHash(in.payload),
		DerivationContextHash: e.derivationContextHash,
		CorrelationID:         e.correlationID,
		SentAt:                time.Now(),
	}
}

func (e *ProtocolExecution) forwardOutgoing(ctx context.Context, transport Transport, msg tsslib.Message) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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

	base := e.newOutboundBaseFrame(outboundFrameInput{
		messageType: msgType,
		roundHint:   roundHint,
		broadcast:   routing.IsBroadcast,
		fromParty:   routing.From.Id,
		payload:     payload,
	})

	if routing.IsBroadcast || len(routing.To) == 0 {
		return e.sendFrame(ctx, transport, base)
	}

	for _, to := range routing.To {
		frame := base
		frame.ToParty = to.Id
		if err := e.sendFrame(ctx, transport, frame); err != nil {
			return err
		}
	}
	return nil
}

func (e *ProtocolExecution) sendFrame(ctx context.Context, transport Transport, frame protocol.Frame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := transport.SendFrame(ctx, frame); err != nil {
		if e.debug {
			e.logger.Debug("tss transport send failed",
				"correlation_id", e.correlationID,
				"session_id", e.sessionID,
				"stage", e.stage,
				"party_id", e.localPartyID,
				"msg_type", frame.MessageType,
				"to_party", frame.ToParty,
				"err", err,
			)
		}
		return err
	}
	e.stats.IncSent()
	e.metrics.IncFramesSent(e.stage)
	e.lastSentSeq.Store(frame.Seq)
	e.markProgress(frame.MessageType, frame.RoundHint)
	return nil
}

func inferRoundHint(msgType string) uint32 {
	messageName := msgType[strings.LastIndexByte(msgType, '.')+1:]
	switch messageName {
	case "KGRound1Message":
		return 1
	case "KGRound2Message1", "KGRound2Message2":
		return 2
	case "KGRound3Message":
		return 3
	case "SignRound1Message", "SignRound1Message1", "SignRound1Message2":
		return 1
	case "SignRound2Message":
		return 2
	case "SignRound3Message":
		return 3
	case "SignRound4Message":
		return 4
	case "SignRound5Message":
		return 5
	case "SignRound6Message":
		return 6
	case "SignRound7Message":
		return 7
	case "SignRound8Message":
		return 8
	case "SignRound9Message":
		return 9
	default:
		return 0
	}
}

func shortHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:8])
}
