package execution

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	tssbnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/utils"
	"github.com/BroLabel/brosettlement-mpc-core/protocol"
	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	ecdsasigning "github.com/bnb-chain/tss-lib/ecdsa/signing"
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

type panicRecvMetrics struct{ testMetrics }

func (panicRecvMetrics) IncFramesRecv(string) { panic("recv metric panic") }

type recvOnlyTransport struct {
	recv func(context.Context) (protocol.Frame, error)
}

func (m recvOnlyTransport) SendFrame(context.Context, protocol.Frame) error { return io.EOF }
func (m recvOnlyTransport) RecvFrame(ctx context.Context) (protocol.Frame, error) {
	return m.recv(ctx)
}

type gatedStartParty struct {
	tsslib.Party
	entered chan struct{}
	release <-chan struct{}
	err     *tsslib.Error
}

func (p *gatedStartParty) Start() *tsslib.Error {
	close(p.entered)
	<-p.release
	return p.err
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

type testTransport struct {
	send func(context.Context, protocol.Frame) error
	recv func(context.Context) (protocol.Frame, error)
}

func (m testTransport) SendFrame(ctx context.Context, frame protocol.Frame) error {
	return m.send(ctx, frame)
}

func (m testTransport) RecvFrame(ctx context.Context) (protocol.Frame, error) {
	return m.recv(ctx)
}

type gatedWriter struct {
	once    sync.Once
	entered chan struct{}
	release <-chan struct{}
}

func (w *gatedWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}

type testOutboundMessage struct {
	messageType string
	payload     []byte
	from        *tsslib.PartyID
	to          []*tsslib.PartyID
	broadcast   bool
	wireEntered chan struct{}
	wireRelease <-chan struct{}
}

func (m testOutboundMessage) Type() string                  { return m.messageType }
func (m testOutboundMessage) GetTo() []*tsslib.PartyID      { return m.to }
func (m testOutboundMessage) GetFrom() *tsslib.PartyID      { return m.from }
func (m testOutboundMessage) IsBroadcast() bool             { return m.broadcast }
func (m testOutboundMessage) IsToOldCommittee() bool        { return false }
func (m testOutboundMessage) IsToOldAndNewCommittees() bool { return false }
func (m testOutboundMessage) WireMsg() *tsslib.MessageWrapper {
	return nil
}
func (m testOutboundMessage) String() string { return m.messageType }
func (m testOutboundMessage) WireBytes() ([]byte, *tsslib.MessageRouting, error) {
	if m.wireEntered != nil {
		close(m.wireEntered)
		<-m.wireRelease
	}
	return append([]byte(nil), m.payload...), &tsslib.MessageRouting{
		From:        m.from,
		To:          m.to,
		IsBroadcast: m.broadcast,
	}, nil
}

func newTestOutboundMessage(payload string) tsslib.Message {
	return testOutboundMessage{
		messageType: "binance.tsslib.ecdsa.keygen.KGRound3Message",
		payload:     []byte(payload),
		from:        tsslib.NewPartyID("A", "A", big.NewInt(1)),
		broadcast:   true,
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

func waitForSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for %s", name)
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

func TestProtocolExecutionCancellationWaitsForPartyStart(t *testing.T) {
	releaseStart := make(chan struct{})
	startEntered := make(chan struct{})
	party := &gatedStartParty{entered: startEntered, release: releaseStart}
	exec := New(Params{
		SessionID:      "barrier",
		LocalPartyID:   "A",
		Stage:          "sign",
		Algorithm:      "ecdsa",
		Party:          party,
		OutCh:          make(chan tsslib.Message),
		SignECDSAEndCh: make(chan common.SignatureData),
		Logger:         slog.Default(),
		Config:         tssbnbutils.DefaultRunnerConfig(),
		Metrics:        testMetrics{},
	})

	ctx, cancel := context.WithCancel(context.Background())
	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- exec.Run(ctx, recvOnlyTransport{recv: func(ctx context.Context) (protocol.Frame, error) {
			<-ctx.Done()
			return protocol.Frame{}, ctx.Err()
		}})
	}()

	select {
	case <-startEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Party.Start entry")
	}
	cancel()
	select {
	case err := <-runErrCh:
		close(releaseStart)
		t.Fatalf("Run returned before Party.Start exited: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseStart)
	select {
	case err := <-runErrCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Run after Party.Start exit")
	}
}

func TestProtocolExecutionRecoveredFailureWaitsForPartyStart(t *testing.T) {
	releaseStart := make(chan struct{})
	party := &gatedStartParty{entered: make(chan struct{}), release: releaseStart}
	exec := New(Params{
		SessionID:      "panic-barrier",
		LocalPartyID:   "A",
		Stage:          "sign",
		Algorithm:      "ecdsa",
		Party:          party,
		OutCh:          make(chan tsslib.Message),
		SignECDSAEndCh: make(chan common.SignatureData),
		Logger:         slog.Default(),
		Config:         tssbnbutils.DefaultRunnerConfig(),
		Metrics:        panicRecvMetrics{},
	})

	frameReady := make(chan struct{})
	runErrCh := make(chan error, 1)
	go func() {
		first := true
		runErrCh <- exec.Run(context.Background(), recvOnlyTransport{recv: func(ctx context.Context) (protocol.Frame, error) {
			if first {
				first = false
				<-frameReady
				return protocol.Frame{}, nil
			}
			<-ctx.Done()
			return protocol.Frame{}, ctx.Err()
		}})
	}()
	select {
	case <-party.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Party.Start entry")
	}
	close(frameReady)
	select {
	case err := <-runErrCh:
		close(releaseStart)
		t.Fatalf("Run returned recovered failure before Party.Start exited: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseStart)
	select {
	case err := <-runErrCh:
		if err == nil || !strings.Contains(err.Error(), "recv metric panic") {
			t.Fatalf("Run error = %v, want recovered metric panic", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for recovered Run failure")
	}
}

func TestProtocolExecutionCancellationWaitsForRecvLoop(t *testing.T) {
	releaseStart := make(chan struct{})
	close(releaseStart)
	party := &gatedStartParty{entered: make(chan struct{}), release: releaseStart}
	exec := New(Params{
		SessionID:      "recv-barrier",
		LocalPartyID:   "A",
		Stage:          "sign",
		Algorithm:      "ecdsa",
		Party:          party,
		OutCh:          make(chan tsslib.Message),
		SignECDSAEndCh: make(chan common.SignatureData),
		Logger:         slog.Default(),
		Config:         tssbnbutils.DefaultRunnerConfig(),
		Metrics:        testMetrics{},
	})

	recvEntered := make(chan struct{})
	releaseRecv := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- exec.Run(ctx, recvOnlyTransport{recv: func(context.Context) (protocol.Frame, error) {
			close(recvEntered)
			<-releaseRecv
			return protocol.Frame{}, context.Canceled
		}})
	}()

	select {
	case <-recvEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for RecvFrame entry")
	}
	cancel()
	select {
	case err := <-runErrCh:
		close(releaseRecv)
		t.Fatalf("Run returned before RecvLoop exited: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseRecv)
	select {
	case err := <-runErrCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Run after RecvLoop exit")
	}
}

func TestProtocolExecutionRepeatedCancellationDoesNotLeakOrKeepSignature(t *testing.T) {
	before := runtime.NumGoroutine()
	for i := range 16 {
		releaseStart := make(chan struct{})
		close(releaseStart)
		party := &gatedStartParty{entered: make(chan struct{}), release: releaseStart}
		endCh := make(chan common.SignatureData, 1)
		exec := New(Params{
			SessionID:      fmt.Sprintf("cancel-race-%d", i),
			LocalPartyID:   "A",
			Stage:          "sign",
			Algorithm:      "ecdsa",
			Party:          party,
			OutCh:          make(chan tsslib.Message),
			SignECDSAEndCh: endCh,
			Logger:         slog.Default(),
			Config:         tssbnbutils.DefaultRunnerConfig(),
			Metrics:        testMetrics{},
		})

		ctx, cancel := context.WithCancel(context.Background())
		runErrCh := make(chan error, 1)
		go func() {
			runErrCh <- exec.Run(ctx, recvOnlyTransport{recv: func(ctx context.Context) (protocol.Frame, error) {
				<-ctx.Done()
				return protocol.Frame{}, ctx.Err()
			}})
		}()
		select {
		case <-party.entered:
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d: timeout waiting for Party.Start entry", i)
		}
		endCh <- common.SignatureData{Signature: []byte("late")}
		cancel()
		select {
		case err := <-runErrCh:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("iteration %d: Run error = %v, want context.Canceled", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d: timeout waiting for Run", i)
		}
		if exec.Signature() != nil {
			t.Fatalf("iteration %d: signature accepted after cancellation", i)
		}
	}
	runtime.Gosched()
	after := runtime.NumGoroutine()
	if after > before+2 {
		t.Fatalf("canceled executions grew goroutines from %d to %d", before, after)
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

func TestHandleEventSignCompletionPrefersCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	exec := New(Params{
		Stage:   "sign",
		Config:  tssbnbutils.DefaultRunnerConfig(),
		Metrics: testMetrics{},
	})
	signature := &common.SignatureData{Signature: []byte("late")}

	done, state, err := exec.handleEvent(ctx, protocolEvent{
		typ:    eventProtocolDone,
		result: protocolResult{signature: signature},
	})

	if !done {
		t.Fatal("SIGN cancellation was not terminal")
	}
	if state != "canceled" {
		t.Fatalf("terminal state = %q, want canceled", state)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("terminal error = %v, want context.Canceled", err)
	}
	if exec.Signature() != nil {
		t.Fatal("signature accepted after cancellation")
	}
	if exec.protocolDoneFlag.Load() {
		t.Fatal("protocol done flag set after cancellation")
	}
}

func TestTerminalDKGCompletionPrefersWorkerFailure(t *testing.T) {
	exec := newTestDKGExecution(nil, nil)
	share := ecdsakeygen.LocalPartySaveData{
		LocalSecrets: ecdsakeygen.LocalSecrets{Xi: big.NewInt(42), ShareID: big.NewInt(7)},
	}

	done, state, eventErr := exec.handleEvent(context.Background(), protocolEvent{
		typ:    eventProtocolDone,
		result: protocolResult{ecdsaKeyShare: &share},
	})
	if !done || state != "success" || eventErr != nil {
		t.Fatalf("DKG completion = (%t, %q, %v), want successful terminal event", done, state, eventErr)
	}

	state, err := exec.finishTerminalEvent(state, eventErr, ErrStalledProtocol)
	if state != "stalled" {
		t.Fatalf("terminal state = %q, want stalled", state)
	}
	if !errors.Is(err, ErrStalledProtocol) {
		t.Fatalf("terminal error = %v, want ErrStalledProtocol", err)
	}
	if exec.ECDSAKeyShare() != nil {
		t.Fatal("ECDSA key share remained accepted after worker failure")
	}
	if exec.protocolDoneFlag.Load() {
		t.Fatal("protocol done flag remained set after worker failure")
	}
}

func TestTerminalSignCompletionRejectsIndependentTransportCancellation(t *testing.T) {
	exec := New(Params{
		Stage:   "sign",
		Config:  tssbnbutils.DefaultRunnerConfig(),
		Metrics: testMetrics{},
	})
	signature := &common.SignatureData{Signature: []byte("candidate")}

	done, state, eventErr := exec.handleEvent(context.Background(), protocolEvent{
		typ:    eventProtocolDone,
		result: protocolResult{signature: signature},
	})
	if !done || state != "success" || eventErr != nil {
		t.Fatalf("SIGN completion = (%t, %q, %v), want successful terminal event", done, state, eventErr)
	}

	state, err := exec.finishTerminalEvent(state, eventErr, context.Canceled)
	if state == "success" || err == nil {
		t.Fatalf("terminal result = (%q, %v), want transport cancellation failure", state, err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("terminal error = %v, want context.Canceled", err)
	}
	if exec.Signature() != nil {
		t.Fatal("signature remained accepted after independent transport cancellation")
	}
	if exec.protocolDoneFlag.Load() {
		t.Fatal("protocol done flag remained set after independent transport cancellation")
	}
}

func TestProtocolExecutionTerminalEventRejectsIndependentTransportCancellation(t *testing.T) {
	releaseStart := make(chan struct{})
	close(releaseStart)
	party := &gatedStartParty{entered: make(chan struct{}), release: releaseStart}
	outCh := make(chan tsslib.Message, 1)
	outCh <- newTestOutboundMessage("transport-cancel")
	doneCh := make(chan struct{})
	logEntered := make(chan struct{})
	releaseLog := make(chan struct{})
	logger := slog.New(slog.NewTextHandler(&gatedWriter{
		entered: logEntered,
		release: releaseLog,
	}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	exec := New(Params{
		SessionID:    "terminal-transport-cancel",
		LocalPartyID: "A",
		Stage:        "sign",
		Algorithm:    "ecdsa",
		Party:        party,
		OutCh:        outCh,
		DoneCh:       doneCh,
		Logger:       logger,
		Debug:        true,
		Config:       tssbnbutils.DefaultRunnerConfig(),
		Metrics:      testMetrics{},
	})

	sendEntered := make(chan struct{})
	releaseSend := make(chan struct{})
	transport := testTransport{
		send: func(context.Context, protocol.Frame) error {
			close(sendEntered)
			<-releaseSend
			return context.Canceled
		},
		recv: func(ctx context.Context) (protocol.Frame, error) {
			<-ctx.Done()
			return protocol.Frame{}, ctx.Err()
		},
	}

	runErrCh := make(chan error, 1)
	go func() { runErrCh <- exec.Run(context.Background(), transport) }()
	waitForSignal(t, party.entered, "Party.Start entry")
	waitForSignal(t, sendEntered, "SendFrame entry")
	close(releaseSend)
	waitForSignal(t, logEntered, "independent transport cancellation log")

	doneSent := make(chan struct{})
	go func() {
		doneCh <- struct{}{}
		close(doneSent)
	}()
	waitForSignal(t, doneSent, "terminal result receive")

	deadline := time.After(2 * time.Second)
	for !exec.protocolDoneFlag.Load() {
		select {
		case err := <-runErrCh:
			close(releaseLog)
			t.Fatalf("Run returned before reconciling terminal event: %v", err)
		case <-deadline:
			close(releaseLog)
			t.Fatal("timeout waiting for terminal event reconciliation")
		default:
			runtime.Gosched()
		}
	}
	close(releaseLog)

	select {
	case err := <-runErrCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v, want independent context cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Run after independent transport cancellation")
	}
	if exec.protocolDoneFlag.Load() {
		t.Fatal("protocol done flag remained set after independent transport cancellation")
	}
}

func TestTerminalSignCompletionPrefersWorkerFailure(t *testing.T) {
	startErr := errors.New("start failed after sign result")
	releaseStart := make(chan struct{})
	party := &gatedStartParty{
		entered: make(chan struct{}),
		release: releaseStart,
		err:     tsslib.NewError(startErr, "sign", 1, nil),
	}
	endCh := make(chan common.SignatureData, 1)
	exec := New(Params{
		SessionID:      "sign-result-race",
		LocalPartyID:   "A",
		Stage:          "sign",
		Algorithm:      "ecdsa",
		Party:          party,
		OutCh:          make(chan tsslib.Message),
		SignECDSAEndCh: endCh,
		Logger:         slog.Default(),
		Config:         tssbnbutils.DefaultRunnerConfig(),
		Metrics:        testMetrics{},
	})

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- exec.Run(context.Background(), recvOnlyTransport{recv: func(ctx context.Context) (protocol.Frame, error) {
			<-ctx.Done()
			return protocol.Frame{}, ctx.Err()
		}})
	}()
	select {
	case <-party.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Party.Start entry")
	}
	endCh <- common.SignatureData{Signature: []byte("candidate")}
	deadline := time.After(2 * time.Second)
	for !exec.protocolDoneFlag.Load() {
		select {
		case <-deadline:
			close(releaseStart)
			t.Fatal("timeout waiting for SIGN result to become terminal")
		default:
			runtime.Gosched()
		}
	}
	close(releaseStart)

	select {
	case err := <-runErrCh:
		if !errors.Is(err, startErr) {
			t.Fatalf("Run error = %v, want worker failure %v", err, startErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Run after Party.Start failure")
	}
	if exec.Signature() != nil {
		t.Fatal("signature remained accepted after worker failure")
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

		rt := newSessionRuntime(context.Background(), 4)
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

		rt := newSessionRuntime(context.Background(), 4)
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

		rt := newSessionRuntime(context.Background(), 4)
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
		rt := newSessionRuntime(ctx, 4)
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

func TestOutboundTransportCancellationBeforeStopFails(t *testing.T) {
	outCh := make(chan tsslib.Message, 1)
	outCh <- newTestOutboundMessage("send")
	close(outCh)
	rt := newSessionRuntime(context.Background(), 1)
	defer rt.Stop()
	exec := newTestDKGExecution(outCh, nil)

	err := exec.runOutboundPump(rt, sendOnlyTransport{send: func(context.Context, protocol.Frame) error {
		return context.Canceled
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runOutboundPump error = %v, want context.Canceled", err)
	}
}

func TestForwardOutgoingCancellationDuringEncodingSkipsBroadcastSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	wireEntered := make(chan struct{})
	releaseWire := make(chan struct{})
	msg := testOutboundMessage{
		messageType: "binance.tsslib.ecdsa.keygen.KGRound3Message",
		payload:     []byte("broadcast"),
		from:        tsslib.NewPartyID("A", "A", big.NewInt(1)),
		broadcast:   true,
		wireEntered: wireEntered,
		wireRelease: releaseWire,
	}
	sendCalls := 0
	errCh := make(chan error, 1)
	go func() {
		errCh <- newTestDKGExecution(nil, nil).forwardOutgoing(ctx, sendOnlyTransport{
			send: func(context.Context, protocol.Frame) error {
				sendCalls++
				return nil
			},
		}, msg)
	}()

	waitForSignal(t, wireEntered, "WireBytes entry")
	cancel()
	close(releaseWire)
	if err := waitForPumpResult(t, errCh); !errors.Is(err, context.Canceled) {
		t.Fatalf("forwardOutgoing error = %v, want context.Canceled", err)
	}
	if sendCalls != 0 {
		t.Fatalf("SendFrame calls = %d, want 0 after cancellation during encoding", sendCalls)
	}
}

func TestForwardOutgoingCancellationDuringFirstRecipientSkipsRemainingRecipients(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	msg := testOutboundMessage{
		messageType: "binance.tsslib.ecdsa.keygen.KGRound3Message",
		payload:     []byte("p2p"),
		from:        tsslib.NewPartyID("A", "A", big.NewInt(1)),
		to: []*tsslib.PartyID{
			tsslib.NewPartyID("B", "B", big.NewInt(2)),
			tsslib.NewPartyID("C", "C", big.NewInt(3)),
		},
	}
	var sentTo []string
	err := newTestDKGExecution(nil, nil).forwardOutgoing(ctx, sendOnlyTransport{
		send: func(_ context.Context, frame protocol.Frame) error {
			sentTo = append(sentTo, frame.ToParty)
			if len(sentTo) == 1 {
				cancel()
			}
			return nil
		},
	}, msg)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("forwardOutgoing error = %v, want context.Canceled", err)
	}
	if len(sentTo) != 1 || sentTo[0] != "B" {
		t.Fatalf("sent recipients = %v, want only [B]", sentTo)
	}
}

func TestOutboundPumpRejectsReadyMessagesAfterCancellation(t *testing.T) {
	for i := range 64 {
		outCh := make(chan tsslib.Message, 1)
		outCh <- newTestOutboundMessage("late")
		ctx, cancel := context.WithCancel(context.Background())
		rt := newSessionRuntime(ctx, 1)
		cancel()
		sendCalls := 0
		exec := newTestDKGExecution(outCh, nil)

		err := exec.runOutboundPump(rt, sendOnlyTransport{send: func(context.Context, protocol.Frame) error {
			sendCalls++
			return nil
		}})
		rt.Stop()
		if sendCalls != 0 {
			t.Fatalf("iteration %d sent %d frame(s) after cancellation", i, sendCalls)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("iteration %d error = %v, want context.Canceled", i, err)
		}
	}
}

func TestDKGResultChannelClosedWithoutResultFails(t *testing.T) {
	outCh := make(chan tsslib.Message)
	endCh := make(chan ecdsakeygen.LocalPartySaveData)
	close(endCh)
	rt := newSessionRuntime(context.Background(), 1)
	defer rt.Stop()
	exec := newTestDKGExecution(outCh, endCh)

	err := exec.runOutboundPump(rt, sendOnlyTransport{send: func(context.Context, protocol.Frame) error {
		return nil
	}})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("runOutboundPump error = %v, want io.ErrUnexpectedEOF", err)
	}
}

type countingUpdateParty struct {
	tsslib.Party
	updates int
}

func (p *countingUpdateParty) Update(tsslib.ParsedMessage) (bool, *tsslib.Error) {
	p.updates++
	return true, nil
}

func TestHandleIncomingDoesNotApplyDuplicateFrame(t *testing.T) {
	sender := tsslib.NewPartyID("p1", "p1", big.NewInt(1))
	payload, _, err := ecdsasigning.NewSignRound3Message(sender, big.NewInt(42)).WireBytes()
	if err != nil {
		t.Fatal(err)
	}
	party := &countingUpdateParty{}
	exec := New(Params{
		SessionID:             "s1",
		Stage:                 "sign",
		DerivationContextHash: strings.Repeat("a", 64),
		Party:                 party,
		PartyIDs:              map[string]*tsslib.PartyID{"p1": sender},
		Config:                tssbnbutils.DefaultRunnerConfig(),
		Metrics:               testMetrics{},
	})
	frame := protocol.Frame{
		SessionID:             "s1",
		Stage:                 "sign",
		FromParty:             "p1",
		Seq:                   7,
		Broadcast:             true,
		Payload:               payload,
		DerivationContextHash: strings.Repeat("a", 64),
	}
	for i := 0; i < 2; i++ {
		if err := exec.handleIncoming(frame); err != nil {
			t.Fatalf("delivery %d: %v", i+1, err)
		}
	}
	if party.updates != 1 {
		t.Fatalf("duplicate frame applied to TSS: updates = %d, want 1", party.updates)
	}
	if got := exec.Stats().DedupDrops; got != 1 {
		t.Fatalf("dedup drops = %d, want 1", got)
	}
	frame.Seq++
	if err := exec.handleIncoming(frame); err != nil {
		t.Fatal(err)
	}
	if party.updates != 2 {
		t.Fatalf("new frame not applied to TSS: updates = %d, want 2", party.updates)
	}
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

func TestSignCompletionWaitsForOutboundDelivery(t *testing.T) {
	sendErr := errors.New("final SIGN send failed")
	for _, tc := range []struct {
		name    string
		wantErr error
	}{
		{name: "delayed_delivery"},
		{name: "final_send_error", wantErr: sendErr},
		{name: "cancellation", wantErr: context.Canceled},
		{name: "deadline", wantErr: context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			timeout := 2 * time.Second
			if tc.wantErr == context.DeadlineExceeded {
				timeout = 500 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			startReleased := make(chan struct{})
			close(startReleased)
			outCh := make(chan tsslib.Message, 2)
			for _, payload := range []string{"first", "final"} {
				msg := newTestOutboundMessage(payload).(testOutboundMessage)
				msg.messageType = "binance.tsslib.ecdsa.signing.SignRound9Message"
				outCh <- msg
			}
			endCh := make(chan common.SignatureData, 1)
			exec := New(Params{
				SessionID: "sign-drain", LocalPartyID: "A", Stage: "sign", Algorithm: "ecdsa",
				Party: &gatedStartParty{entered: make(chan struct{}), release: startReleased},
				OutCh: outCh, SignECDSAEndCh: endCh,
				Logger: slog.Default(), Config: tssbnbutils.DefaultRunnerConfig(), Metrics: testMetrics{},
			})
			sendEntered := make(chan struct{})
			releaseSend := make(chan struct{})
			var delivered []string
			transport := testTransport{
				send: func(ctx context.Context, frame protocol.Frame) error {
					if string(frame.Payload) == "first" {
						close(sendEntered)
						select {
						case <-releaseSend:
						case <-ctx.Done():
							return ctx.Err()
						}
					} else if tc.wantErr == sendErr {
						return sendErr
					}
					delivered = append(delivered, string(frame.Payload))
					return nil
				},
				recv: func(ctx context.Context) (protocol.Frame, error) {
					<-ctx.Done()
					return protocol.Frame{}, ctx.Err()
				},
			}
			errCh := make(chan error, 1)
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				errCh <- exec.Run(ctx, transport)
			}()
			t.Cleanup(func() { cancel(); <-joined })
			waitForSignal(t, sendEntered, "SIGN send entry")
			endCh <- common.SignatureData{Signature: []byte("sig")}
			select {
			case err := <-errCh:
				t.Fatalf("Run returned before outbound delivery: %v", err)
			case <-time.After(200 * time.Millisecond):
			}
			if tc.wantErr == context.Canceled {
				cancel()
			} else if tc.wantErr != context.DeadlineExceeded {
				close(releaseSend)
			}
			if err := waitForPumpResult(t, errCh); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Run error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				if exec.Signature() != nil {
					t.Fatal("signature accepted without successful outbound delivery")
				}
				return
			}
			if !reflect.DeepEqual(delivered, []string{"first", "final"}) {
				t.Fatalf("delivered = %v, want both queued frames in order", delivered)
			}
			if exec.Signature() == nil || string(exec.Signature().Signature) != "sig" {
				t.Fatal("signature missing after successful outbound delivery")
			}
		})
	}
}

func TestSignOutboundClosedWaitsForResult(t *testing.T) {
	outCh := make(chan tsslib.Message)
	close(outCh)
	exec := New(Params{
		OutCh: outCh, SignECDSAEndCh: make(chan common.SignatureData),
		Config: tssbnbutils.DefaultRunnerConfig(), Metrics: testMetrics{},
	})
	rt := newSessionRuntime(context.Background(), 1)
	errCh := make(chan error, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		errCh <- exec.runOutboundPump(rt, testTransport{})
	}()
	t.Cleanup(func() { rt.Stop(); <-joined })
	select {
	case err := <-errCh:
		t.Fatalf("outbound pump exited before the SIGN result: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	sig := &common.SignatureData{Signature: []byte("sig")}
	select {
	case rt.signResult <- sig:
	case <-time.After(2 * time.Second):
		t.Fatal("SIGN result handoff blocked")
	}
	if err := waitForPumpResult(t, errCh); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-rt.Events:
		if ev.typ != eventProtocolDone || ev.result.signature != sig {
			t.Fatalf("unexpected protocol event: %+v", ev)
		}
	default:
		t.Fatal("missing SIGN completion event")
	}
}

func TestSignResultChannelClosedWithoutResultFails(t *testing.T) {
	endCh := make(chan common.SignatureData)
	close(endCh)
	exec := New(Params{
		SessionID:      "s1",
		LocalPartyID:   "co-signer",
		Stage:          "sign",
		SignECDSAEndCh: endCh,
		Config:         tssbnbutils.DefaultRunnerConfig(),
		Metrics:        testMetrics{},
	})

	rt := newSessionRuntime(context.Background(), 4)
	defer rt.Stop()

	err := exec.runProtocolResultWorker(rt)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("runProtocolResultWorker error = %v, want io.ErrUnexpectedEOF", err)
	}
	select {
	case ev := <-rt.Events:
		t.Fatalf("unexpected protocol event: %+v", ev)
	default:
	}
}
