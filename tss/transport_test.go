package tss

import (
	"context"
	"testing"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
)

type aliasTransport struct{}

func (aliasTransport) SendFrame(_ context.Context, _ protocol.Frame) error { return nil }

func (aliasTransport) RecvFrame(_ context.Context) (protocol.Frame, error) {
	return protocol.Frame{}, nil
}

func TestTransportAliasAcceptsFrameTransportImplementations(t *testing.T) {
	var _ Transport = aliasTransport{}
}
