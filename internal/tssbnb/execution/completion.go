package execution

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

// tss-lib may publish the sign terminal result before this runner observes the
// final outbound sign message. Delay terminal signaling briefly so the outbound
// pump can flush already-produced frames without changing DKG completion.
const signProtocolDoneGrace = 100 * time.Millisecond

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

func (e *ProtocolExecution) runProtocolResultWorker(rt *sessionRuntime) error {
	cases := []reflect.SelectCase{
		{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(rt.Ctx.Done())},
		{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(e.signECDSAEndCh)},
		{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(e.dkgEdDSAEndCh)},
		{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(e.doneCh)},
	}
	chosen, value, ok := reflect.Select(cases)
	switch chosen {
	case 0:
		return nil
	case 1:
		if !ok {
			return io.ErrUnexpectedEOF
		}
		sig := cloneSignatureDataValue(value)
		if !e.waitSignProtocolDoneGrace(rt.Ctx) {
			return nil
		}
		rt.Emit(protocolEvent{typ: eventProtocolDone, result: protocolResult{signature: sig}})
		return nil
	case 2, 3:
		if !ok {
			return io.ErrUnexpectedEOF
		}
		rt.Emit(protocolEvent{typ: eventProtocolDone, result: protocolResult{}})
		return nil
	default:
		return io.ErrUnexpectedEOF
	}
}

func cloneSignatureDataValue(value reflect.Value) *common.SignatureData {
	fieldBytes := func(name string) []byte {
		field := value.FieldByName(name)
		if !field.IsValid() || field.Kind() != reflect.Slice || field.Type().Elem().Kind() != reflect.Uint8 {
			return nil
		}
		return append([]byte(nil), field.Bytes()...)
	}
	return &common.SignatureData{
		Signature:         fieldBytes("Signature"),
		SignatureRecovery: fieldBytes("SignatureRecovery"),
		R:                 fieldBytes("R"),
		S:                 fieldBytes("S"),
		M:                 fieldBytes("M"),
	}
}

func (e *ProtocolExecution) waitSignProtocolDoneGrace(ctx context.Context) bool {
	timer := time.NewTimer(signProtocolDoneGrace)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (e *ProtocolExecution) handleEvent(ctx context.Context, ev protocolEvent) (done bool, state string, err error) {
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
		if err := ctx.Err(); err != nil {
			return true, "canceled", err
		}
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

func (e *ProtocolExecution) finishTerminalEvent(state string, eventErr, groupErr error) (string, error) {
	if state != "success" || eventErr != nil || groupErr == nil {
		return state, eventErr
	}
	e.ecdsaKeyShare = nil
	e.signature = nil
	e.protocolDoneFlag.Store(false)
	return e.handleGroupResult(groupErr)
}
