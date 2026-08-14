package protocol_test

import (
	"testing"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
)

func TestFrameBroadcastCompatibility(t *testing.T) {
	frame := protocol.Frame{ToParty: ""}
	if !frame.IsBroadcast() {
		t.Fatal("expected empty to_party to be treated as broadcast")
	}
}
