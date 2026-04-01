package adapters

import (
	"context"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
)

func TestChannelTransportSendFrameCallsSendFn(t *testing.T) {
	ctx := context.Background()
	want := protocol.Frame{SessionID: "session-1", Seq: 7}
	called := false

	transport := NewChannelTransport(nil, func(gotCtx context.Context, got protocol.Frame) error {
		called = true
		if gotCtx != ctx {
			t.Fatalf("expected same context, got different value")
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("unexpected frame: got %+v want %+v", got, want)
		}
		return nil
	})

	if err := transport.SendFrame(ctx, want); err != nil {
		t.Fatalf("SendFrame() error = %v", err)
	}
	if !called {
		t.Fatal("expected send function to be called")
	}
}

func TestChannelTransportRecvFrameReturnsInboundFrame(t *testing.T) {
	inbound := make(chan protocol.Frame, 1)
	want := protocol.Frame{SessionID: "session-2", Seq: 3}
	inbound <- want

	transport := NewChannelTransport(inbound, func(context.Context, protocol.Frame) error { return nil })

	got, err := transport.RecvFrame(context.Background())
	if err != nil {
		t.Fatalf("RecvFrame() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected frame: got %+v want %+v", got, want)
	}
}

func TestChannelTransportRecvFrameReturnsEOFWhenInboundClosed(t *testing.T) {
	inbound := make(chan protocol.Frame)
	close(inbound)

	transport := NewChannelTransport(inbound, func(context.Context, protocol.Frame) error { return nil })

	_, err := transport.RecvFrame(context.Background())
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestChannelTransportRecvFrameHonorsContextCancel(t *testing.T) {
	inbound := make(chan protocol.Frame)
	transport := NewChannelTransport(inbound, func(context.Context, protocol.Frame) error { return nil })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := transport.RecvFrame(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestChannelTransportRecvFrameUnblocksOnContextTimeout(t *testing.T) {
	inbound := make(chan protocol.Frame)
	transport := NewChannelTransport(inbound, func(context.Context, protocol.Frame) error { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := transport.RecvFrame(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded, got %v", err)
	}
}
