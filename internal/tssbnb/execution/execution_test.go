package execution

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	tssbnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/utils"
	"github.com/BroLabel/brosettlement-mpc-core/protocol"
	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

type testMetrics struct{}

func (testMetrics) IncSessionsStarted(string)                    {}
func (testMetrics) IncSessionsSucceeded(string)                  {}
func (testMetrics) IncSessionsFailed(string, string)             {}
func (testMetrics) IncStalls(string)                             {}
func (testMetrics) IncTimeouts(string)                           {}
func (testMetrics) IncDedupHits(string)                          {}
func (testMetrics) IncFramesSent(string)                         {}
func (testMetrics) IncFramesRecv(string)                         {}
func (testMetrics) IncQueueFull(string)                          {}
func (testMetrics) IncOversizedFrames(string)                    {}
func (testMetrics) ObserveSessionDuration(string, time.Duration) {}

type recvOnlyTransport struct {
	recv func(context.Context) (protocol.Frame, error)
}

func (m recvOnlyTransport) SendFrame(context.Context, protocol.Frame) error { return io.EOF }
func (m recvOnlyTransport) RecvFrame(ctx context.Context) (protocol.Frame, error) {
	return m.recv(ctx)
}

type sendOnlyTransport struct {
	send func(context.Context, protocol.Frame) error
}

func (m sendOnlyTransport) SendFrame(ctx context.Context, frame protocol.Frame) error {
	return m.send(ctx, frame)
}

func (sendOnlyTransport) RecvFrame(context.Context) (protocol.Frame, error) {
	return protocol.Frame{}, io.EOF
}

type testOutboundMessage struct {
	messageType string
	payload     []byte
	from        *tsslib.PartyID
}

func (m testOutboundMessage) Type() string                  { return m.messageType }
func (m testOutboundMessage) GetTo() []*tsslib.PartyID      { return nil }
func (m testOutboundMessage) GetFrom() *tsslib.PartyID      { return m.from }
func (m testOutboundMessage) IsBroadcast() bool             { return true }
func (m testOutboundMessage) IsToOldCommittee() bool        { return false }
func (m testOutboundMessage) IsToOldAndNewCommittees() bool { return false }
func (m testOutboundMessage) WireMsg() *tsslib.MessageWrapper {
	return nil
}
func (m testOutboundMessage) String() string { return m.messageType }
func (m testOutboundMessage) WireBytes() ([]byte, *tsslib.MessageRouting, error) {
	return append([]byte(nil), m.payload...), &tsslib.MessageRouting{
		From:        m.from,
		IsBroadcast: true,
	}, nil
}

func newTestOutboundMessage(payload string) tsslib.Message {
	return testOutboundMessage{
		messageType: "binance.tsslib.ecdsa.keygen.KGRound3Message",
		payload:     []byte(payload),
		from:        tsslib.NewPartyID("A", "A", big.NewInt(1)),
	}
}

func newTestDKGExecution(outCh <-chan tsslib.Message, endCh <-chan ecdsakeygen.LocalPartySaveData) *ProtocolExecution {
	return New(Params{
		SessionID:     "session-1",
		LocalPartyID:  "A",
		Stage:         "dkg",
		Algorithm:     "ecdsa",
		OutCh:         outCh,
		DKGECDSAEndCh: endCh,
		Logger:        slog.Default(),
		Config:        tssbnbutils.DefaultRunnerConfig(),
		Metrics:       testMetrics{},
	})
}

func waitForProtocolEvent(t *testing.T, events <-chan protocolEvent) protocolEvent {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for protocol event")
		return protocolEvent{}
	}
}

func assertNoProtocolEvent(t *testing.T, events <-chan protocolEvent) {
	t.Helper()
	select {
	case event := <-events:
		t.Fatalf("unexpected protocol event: %+v", event)
	case <-time.After(100 * time.Millisecond):
	}
}

func waitForPumpResult(t *testing.T, errCh <-chan error) error {
	t.Helper()
	select {
	case err := <-errCh:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for outbound pump to exit")
		return nil
	}
}

func assertDKGProtocolDone(t *testing.T, event protocolEvent, want ecdsakeygen.LocalPartySaveData) {
	t.Helper()
	if event.typ != eventProtocolDone {
		t.Fatalf("event type = %v, want eventProtocolDone", event.typ)
	}
	if event.result.ecdsaKeyShare == nil {
		t.Fatal("protocol done event has no ECDSA key share")
	}
	if !reflect.DeepEqual(*event.result.ecdsaKeyShare, want) {
		t.Fatalf("protocol done share = %+v, want %+v", *event.result.ecdsaKeyShare, want)
	}
}

func TestHandleEventDKGCompletionPrefersCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	exec := newTestDKGExecution(nil, nil)
	share := ecdsakeygen.LocalPartySaveData{
		LocalSecrets: ecdsakeygen.LocalSecrets{Xi: big.NewInt(42), ShareID: big.NewInt(7)},
	}

	done, state, err := exec.handleEvent(ctx, protocolEvent{
		typ:    eventProtocolDone,
		result: protocolResult{ecdsaKeyShare: &share},
	})

	if !done {
		t.Fatal("DKG cancellation was not terminal")
	}
	if state != "canceled" {
		t.Fatalf("terminal state = %q, want canceled", state)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("terminal error = %v, want context.Canceled", err)
	}
	if exec.ECDSAKeyShare() != nil {
		t.Fatal("ECDSA key share accepted after cancellation")
	}
	if exec.protocolDoneFlag.Load() {
		t.Fatal("protocol done flag set after cancellation")
	}
}

func TestDKGProtocolDoneWaitsForOutboundPump(t *testing.T) {
	t.Run("blocked_final_send", func(t *testing.T) {
		outCh := make(chan tsslib.Message, 2)
		endCh := make(chan ecdsakeygen.LocalPartySaveData, 1)
		share := ecdsakeygen.LocalPartySaveData{
			LocalSecrets: ecdsakeygen.LocalSecrets{Xi: big.NewInt(42), ShareID: big.NewInt(7)},
		}
		outCh <- newTestOutboundMessage("round3-first")
		outCh <- newTestOutboundMessage("round3-final")
		endCh <- share

		rt := newSessionRuntime[protocolEvent](context.Background(), 4)
		defer rt.Stop()
		secondSendEntered := make(chan struct{})
		releaseSecondSend := make(chan struct{})
		var mu sync.Mutex
		var frames []protocol.Frame
		sendCalls := 0
		transport := sendOnlyTransport{send: func(ctx context.Context, frame protocol.Frame) error {
			mu.Lock()
			sendCalls++
			call := sendCalls
			mu.Unlock()
			if call == 2 {
				close(secondSendEntered)
				select {
				case <-releaseSecondSend:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			mu.Lock()
			frames = append(frames, frame)
			mu.Unlock()
			return nil
		}}

		errCh := make(chan error, 1)
		go func() { errCh <- newTestDKGExecution(outCh, endCh).runOutboundPump(rt, transport) }()

		select {
		case <-secondSendEntered:
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for final Round 3 SendFrame entry")
		}
		assertNoProtocolEvent(t, rt.Events)
		close(releaseSecondSend)

		assertDKGProtocolDone(t, waitForProtocolEvent(t, rt.Events), share)
		if err := waitForPumpResult(t, errCh); err != nil {
			t.Fatalf("outbound pump returned error: %v", err)
		}
		mu.Lock()
		gotFrames := append([]protocol.Frame(nil), frames...)
		mu.Unlock()
		if len(gotFrames) != 2 {
			t.Fatalf("forwarded frame count = %d, want 2", len(gotFrames))
		}
		if string(gotFrames[0].Payload) != "round3-first" || string(gotFrames[1].Payload) != "round3-final" {
			t.Fatalf("forwarded payloads = %q, %q", gotFrames[0].Payload, gotFrames[1].Payload)
		}
		assertNoProtocolEvent(t, rt.Events)
	})

	t.Run("closed_outbound_after_result", func(t *testing.T) {
		outCh := make(chan tsslib.Message)
		endCh := make(chan ecdsakeygen.LocalPartySaveData, 1)
		share := ecdsakeygen.LocalPartySaveData{
			LocalSecrets: ecdsakeygen.LocalSecrets{Xi: big.NewInt(84), ShareID: big.NewInt(9)},
		}
		endCh <- share
		close(outCh)

		rt := newSessionRuntime[protocolEvent](context.Background(), 4)
		defer rt.Stop()
		errCh := make(chan error, 1)
		transport := sendOnlyTransport{send: func(context.Context, protocol.Frame) error { return nil }}
		go func() { errCh <- newTestDKGExecution(outCh, endCh).runOutboundPump(rt, transport) }()

		assertDKGProtocolDone(t, waitForProtocolEvent(t, rt.Events), share)
		if err := waitForPumpResult(t, errCh); err != nil {
			t.Fatalf("outbound pump returned error: %v", err)
		}
		assertNoProtocolEvent(t, rt.Events)
	})

	t.Run("final_send_error", func(t *testing.T) {
		finalSendErr := errors.New("final send failed")
		outCh := make(chan tsslib.Message, 2)
		endCh := make(chan ecdsakeygen.LocalPartySaveData, 1)
		outCh <- newTestOutboundMessage("round3-first")
		outCh <- newTestOutboundMessage("round3-final")
		endCh <- ecdsakeygen.LocalPartySaveData{
			LocalSecrets: ecdsakeygen.LocalSecrets{Xi: big.NewInt(126), ShareID: big.NewInt(11)},
		}

		rt := newSessionRuntime[protocolEvent](context.Background(), 4)
		defer rt.Stop()
		sendCalls := 0
		transport := sendOnlyTransport{send: func(context.Context, protocol.Frame) error {
			sendCalls++
			if sendCalls == 2 {
				return finalSendErr
			}
			return nil
		}}
		errCh := make(chan error, 1)
		go func() { errCh <- newTestDKGExecution(outCh, endCh).runOutboundPump(rt, transport) }()

		if err := waitForPumpResult(t, errCh); !errors.Is(err, finalSendErr) {
			t.Fatalf("outbound pump error = %v, want %v", err, finalSendErr)
		}
		assertNoProtocolEvent(t, rt.Events)
	})

	t.Run("cancellation", func(t *testing.T) {
		outCh := make(chan tsslib.Message, 1)
		endCh := make(chan ecdsakeygen.LocalPartySaveData, 1)
		outCh <- newTestOutboundMessage("round3-final")
		endCh <- ecdsakeygen.LocalPartySaveData{
			LocalSecrets: ecdsakeygen.LocalSecrets{Xi: big.NewInt(168), ShareID: big.NewInt(13)},
		}

		ctx, cancel := context.WithCancel(context.Background())
		rt := newSessionRuntime[protocolEvent](ctx, 4)
		defer rt.Stop()
		sendEntered := make(chan struct{})
		transport := sendOnlyTransport{send: func(ctx context.Context, _ protocol.Frame) error {
			close(sendEntered)
			<-ctx.Done()
			return ctx.Err()
		}}
		errCh := make(chan error, 1)
		go func() { errCh <- newTestDKGExecution(outCh, endCh).runOutboundPump(rt, transport) }()

		select {
		case <-sendEntered:
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for SendFrame entry")
		}
		cancel()
		if err := waitForPumpResult(t, errCh); !errors.Is(err, context.Canceled) {
			t.Fatalf("outbound pump error = %v, want context.Canceled", err)
		}
		assertNoProtocolEvent(t, rt.Events)
	})
}

func TestShouldProcessInboundDedup(t *testing.T) {
	exec := New(Params{
		Stage:   "dkg",
		Config:  tssbnbutils.DefaultRunnerConfig(),
		Metrics: testMetrics{},
	})
	frame := protocol.Frame{
		SessionID:   "s1",
		Stage:       "dkg",
		FromParty:   "p1",
		Seq:         7,
		Payload:     []byte("abc"),
		PayloadHash: shortHash([]byte("abc")),
	}
	exec.sessionID = "s1"
	ok, reason := exec.shouldProcessInbound(frame)
	if !ok || reason != nil {
		t.Fatalf("first frame should pass, got ok=%v reason=%v", ok, reason)
	}
	ok, reason = exec.shouldProcessInbound(frame)
	if ok || !errors.Is(reason, ErrDuplicateFrame) {
		t.Fatalf("duplicate should be dropped, got ok=%v reason=%v", ok, reason)
	}
}

func TestValidateInboundSignFrameRequiresMatchingDerivationContextHash(t *testing.T) {
	exec := New(Params{
		SessionID:             "s1",
		Stage:                 "sign",
		DerivationContextHash: strings.Repeat("a", 64),
		Config:                tssbnbutils.DefaultRunnerConfig(),
		Metrics:               testMetrics{},
	})

	for _, tc := range []struct {
		name string
		hash string
	}{
		{name: "missing"},
		{name: "mismatch", hash: strings.Repeat("b", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := exec.handleIncoming(protocol.Frame{
				SessionID:             "s1",
				Stage:                 "sign",
				FromParty:             "unknown-party",
				Seq:                   10,
				Payload:               []byte("not a tss message"),
				PayloadHash:           shortHash([]byte("not a tss message")),
				DerivationContextHash: tc.hash,
			})
			if !errors.Is(err, ErrDerivationContextMismatch) {
				t.Fatalf("expected ErrDerivationContextMismatch, got %v", err)
			}
		})
	}
}

func TestValidateInboundDKGFrameDoesNotRequireDerivationContextHash(t *testing.T) {
	exec := New(Params{
		SessionID: "s1",
		Stage:     "dkg",
		Config:    tssbnbutils.DefaultRunnerConfig(),
		Metrics:   testMetrics{},
	})

	err := exec.validateInbound(protocol.Frame{
		SessionID:   "s1",
		Stage:       "dkg",
		FromParty:   "p1",
		Seq:         1,
		Payload:     []byte("abc"),
		PayloadHash: shortHash([]byte("abc")),
	})
	if err != nil {
		t.Fatalf("DKG frame without derivation context hash should validate, got %v", err)
	}
}

func TestNewOutboundBaseFrameStampsDerivationContextHash(t *testing.T) {
	exec := New(Params{
		SessionID:             "s1",
		Stage:                 "sign",
		Algorithm:             "ecdsa",
		CorrelationID:         "corr-1",
		DerivationContextHash: strings.Repeat("a", 64),
		Config:                tssbnbutils.DefaultRunnerConfig(),
		Metrics:               testMetrics{},
	})

	frame := exec.newOutboundBaseFrame(outboundFrameInput{
		messageType: "SignRound1Message",
		roundHint:   1,
		broadcast:   true,
		fromParty:   "p1",
		payload:     []byte("payload"),
	})
	if frame.DerivationContextHash != strings.Repeat("a", 64) {
		t.Fatalf("DerivationContextHash = %q", frame.DerivationContextHash)
	}
	if frame.SessionID != "s1" || frame.Stage != "sign" || frame.Protocol != "ecdsa" {
		t.Fatalf("unexpected base frame: %+v", frame)
	}
}

func TestInferRoundHint(t *testing.T) {
	tests := []struct {
		messageType string
		want        uint32
	}{
		{messageType: "binance.tsslib.ecdsa.keygen.KGRound1Message", want: 1},
		{messageType: "binance.tsslib.ecdsa.keygen.KGRound2Message1", want: 2},
		{messageType: "binance.tsslib.ecdsa.keygen.KGRound2Message2", want: 2},
		{messageType: "binance.tsslib.ecdsa.keygen.KGRound3Message", want: 3},
		{messageType: "binance.tsslib.eddsa.signing.SignRound1Message", want: 1},
		{messageType: "binance.tsslib.ecdsa.signing.SignRound1Message1", want: 1},
		{messageType: "binance.tsslib.ecdsa.signing.SignRound1Message2", want: 1},
		{messageType: "binance.tsslib.ecdsa.signing.SignRound2Message", want: 2},
		{messageType: "binance.tsslib.ecdsa.signing.SignRound3Message", want: 3},
		{messageType: "binance.tsslib.ecdsa.signing.SignRound4Message", want: 4},
		{messageType: "binance.tsslib.ecdsa.signing.SignRound5Message", want: 5},
		{messageType: "binance.tsslib.ecdsa.signing.SignRound6Message", want: 6},
		{messageType: "binance.tsslib.ecdsa.signing.SignRound7Message", want: 7},
		{messageType: "binance.tsslib.ecdsa.signing.SignRound8Message", want: 8},
		{messageType: "binance.tsslib.ecdsa.signing.SignRound9Message", want: 9},
		{messageType: "binance.tsslib.ecdsa.signing.SignRound10Message", want: 0},
		{messageType: "unknown", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.messageType, func(t *testing.T) {
			if got := inferRoundHint(tt.messageType); got != tt.want {
				t.Fatalf("inferRoundHint(%q) = %d, want %d", tt.messageType, got, tt.want)
			}
		})
	}
}

func TestRecvLoopQueueFull(t *testing.T) {
	inbound := make(chan protocol.Frame, 1)
	inbound <- protocol.Frame{}
	errCh := make(chan error, 1)
	tr := recvOnlyTransport{recv: func(context.Context) (protocol.Frame, error) {
		return protocol.Frame{SessionID: "s", Payload: []byte("x")}, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tssbnbutils.RecvLoop(ctx, tr.RecvFrame, inbound, errCh, 1024, ErrFrameTooLarge, ErrQueueFull)
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrQueueFull) {
			t.Fatalf("expected ErrQueueFull, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting queue full error")
	}
}

func TestWatchdogStallFail(t *testing.T) {
	exec := New(Params{
		SessionID:    "s1",
		LocalPartyID: "p1",
		Stage:        "sign",
		Logger:       slog.Default(),
		Config: tssbnbutils.RunnerConfig{
			StallWarn:      50 * time.Millisecond,
			StallFail:      120 * time.Millisecond,
			WatchdogTick:   20 * time.Millisecond,
			StallWarnEvery: 50 * time.Millisecond,
		},
		Metrics: testMetrics{},
	})
	exec.markProgress("x", 1)
	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { errCh <- exec.runWatchdog(ctx) }()
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrStalledProtocol) {
			t.Fatalf("expected ErrStalledProtocol, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting watchdog stall")
	}
}

func TestRecvLoopCanceled(t *testing.T) {
	inbound := make(chan protocol.Frame, 1)
	errCh := make(chan error, 1)
	tr := recvOnlyTransport{recv: func(ctx context.Context) (protocol.Frame, error) {
		<-ctx.Done()
		return protocol.Frame{}, ctx.Err()
	}}
	ctx, cancel := context.WithCancel(context.Background())
	go tssbnbutils.RecvLoop(ctx, tr.RecvFrame, inbound, errCh, 1024, ErrFrameTooLarge, ErrQueueFull)
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting canceled error")
	}
}

func TestSignProtocolDoneWaitsGraceBeforeEmitting(t *testing.T) {
	endCh := make(chan *common.SignatureData, 1)
	exec := New(Params{
		SessionID:      "s1",
		LocalPartyID:   "co-signer",
		Stage:          "sign",
		SignECDSAEndCh: endCh,
		Config:         tssbnbutils.DefaultRunnerConfig(),
		Metrics:        testMetrics{},
	})

	rt := newSessionRuntime[protocolEvent](context.Background(), 4)
	defer rt.Stop()

	errCh := make(chan error, 1)
	go func() { errCh <- exec.runProtocolResultWorker(rt) }()
	endCh <- &common.SignatureData{Signature: []byte("sig")}

	select {
	case <-rt.Events:
		t.Fatal("protocol done emitted before sign grace elapsed")
	case <-time.After(signProtocolDoneGrace / 2):
	}

	select {
	case ev := <-rt.Events:
		if ev.typ != eventProtocolDone {
			t.Fatalf("event = %v, want eventProtocolDone", ev.typ)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting protocol done")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("runProtocolResultWorker returned err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting protocol result worker return")
	}
}
