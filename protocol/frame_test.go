package protocol_test

import (
	"strings"
	"testing"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
)

func TestFrameBroadcastCompatibility(t *testing.T) {
	frame := protocol.Frame{ToParty: ""}
	if !frame.IsBroadcast() {
		t.Fatal("expected empty to_party to be treated as broadcast")
	}
}

func TestFrameCarriesDerivationContextHash(t *testing.T) {
	frame := protocol.Frame{DerivationContextHash: strings.Repeat("a", 64)}
	if frame.DerivationContextHash != strings.Repeat("a", 64) {
		t.Fatalf("DerivationContextHash = %q", frame.DerivationContextHash)
	}
}
