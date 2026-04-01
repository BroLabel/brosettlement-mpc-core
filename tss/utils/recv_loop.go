package utils

import (
	"context"
	"fmt"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
)

type RecvFrameFunc func(context.Context) (protocol.Frame, error)

func RecvLoop(
	ctx context.Context,
	recv RecvFrameFunc,
	inboundCh chan<- protocol.Frame,
	recvErrCh chan<- error,
	maxFrameBytes int,
	errFrameTooLarge error,
	errQueueFull error,
) {
	defer close(inboundCh)
	for {
		frame, err := recv(ctx)
		if err != nil {
			select {
			case recvErrCh <- err:
			default:
			}
			return
		}
		if len(frame.Payload) > maxFrameBytes {
			select {
			case recvErrCh <- fmt.Errorf("%w: %d > %d", errFrameTooLarge, len(frame.Payload), maxFrameBytes):
			default:
			}
			return
		}
		select {
		case <-ctx.Done():
			select {
			case recvErrCh <- ctx.Err():
			default:
			}
			return
		case inboundCh <- frame:
		default:
			select {
			case recvErrCh <- errQueueFull:
			default:
			}
			return
		}
	}
}
