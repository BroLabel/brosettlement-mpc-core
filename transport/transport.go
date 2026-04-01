package transport

import (
	"context"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
)

// FrameTransport is the minimal boundary for exchanging protocol frames.
type FrameTransport interface {
	SendFrame(ctx context.Context, frame protocol.Frame) error
	RecvFrame(ctx context.Context) (protocol.Frame, error)
}
