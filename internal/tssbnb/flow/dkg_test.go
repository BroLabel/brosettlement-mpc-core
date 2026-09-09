package flow

import (
	"runtime"
	"testing"

	tssbnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/utils"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

func TestBuildEdDSADKGDoesNotStartDetachedResultBridge(t *testing.T) {
	params, _, _, err := tssbnbutils.BuildParams([]string{"A", "B"}, "A", 2, "ed25519", "eddsa")
	if err != nil {
		t.Fatalf("BuildParams() error = %v", err)
	}

	before := runtime.NumGoroutine()
	for range 16 {
		if _, err := BuildDKG(DKGBuildInput{
			Params:    params,
			OutCh:     make(chan tsslib.Message),
			Algorithm: "eddsa",
		}); err != nil {
			t.Fatalf("BuildDKG() error = %v", err)
		}
	}
	runtime.Gosched()
	after := runtime.NumGoroutine()
	if after > before+2 {
		t.Fatalf("BuildDKG() goroutines grew from %d to %d; detached result bridges remain", before, after)
	}
}
