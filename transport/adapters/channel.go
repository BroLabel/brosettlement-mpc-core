package adapters

import (
	"context"
	"io"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
	"github.com/BroLabel/brosettlement-mpc-core/transport"
)

// ChannelTransport adapts frame channels into a shared FrameTransport contract.
type ChannelTransport struct {
	inbound <-chan protocol.Frame
	sendFn  func(context.Context, protocol.Frame) error
}

var _ transport.FrameTransport = (*ChannelTransport)(nil)

func NewChannelTransport(
	inbound <-chan protocol.Frame,
	sendFn func(context.Context, protocol.Frame) error,
) *ChannelTransport {
	return &ChannelTransport{
		inbound: inbound,
		sendFn:  sendFn,
	}
}

func (t *ChannelTransport) SendFrame(ctx context.Context, frame protocol.Frame) error {
	return t.sendFn(ctx, frame)
}

func (t *ChannelTransport) RecvFrame(ctx context.Context) (protocol.Frame, error) {
	select {
	case <-ctx.Done():
		return protocol.Frame{}, ctx.Err()
	case frame, ok := <-t.inbound:
		if !ok {
			return protocol.Frame{}, io.EOF
		}
		return frame, nil
	}
}
