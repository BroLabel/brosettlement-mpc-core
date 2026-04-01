package execution

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	tssbnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/utils"
	"github.com/BroLabel/brosettlement-mpc-core/protocol"
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
