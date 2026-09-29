package execution

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v3/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/v3/ecdsa/keygen"
	eddsakeygen "github.com/bnb-chain/tss-lib/v3/eddsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/v3/tss"
)

func TestCloneSignatureDataPointerOwnsBytes(t *testing.T) {
	input := &common.SignatureData{Signature: []byte{1}, SignatureRecovery: []byte{0}, R: []byte{2}, S: []byte{3}, M: []byte{0, 4}}
	got := cloneSignatureDataValue(reflect.ValueOf(input))
	input.Signature[0], input.SignatureRecovery[0] = 9, 9
	input.R[0], input.S[0], input.M[0] = 9, 9, 9
	if got == nil || got.Signature[0] != 1 || got.SignatureRecovery[0] != 0 || got.R[0] != 2 || got.S[0] != 3 || got.M[0] != 0 {
		t.Fatal("signature result aliases producer memory")
	}
}

// A missing library result must not reach the completion event consumed by the
// facade before it persists a DKG share or publishes a signature.
func TestDKGNilPointerNeverCompletes(t *testing.T) {
	for _, closedOutbound := range []bool{false, true} {
		t.Run(fmt.Sprintf("outbound_closed_%t", closedOutbound), func(t *testing.T) {
			end := make(chan *ecdsakeygen.LocalPartySaveData, 1)
			end <- nil
			out := make(chan tsslib.Message)
			if closedOutbound {
				close(out)
			}
			rt := newSessionRuntime(context.Background(), 1)
			defer rt.Stop()
			exec := newTestDKGExecution(out, end)
			if err := exec.runOutboundPump(rt, sendOnlyTransport{}); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("nil DKG result error = %v, want io.ErrUnexpectedEOF", err)
			}
			assertNoCompletion(t, rt, exec)
		})
	}
}

func TestPointerResultWorkerRejectsMissingResults(t *testing.T) {
	for _, algorithm := range []string{"sign", "eddsa"} {
		for _, closed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s_closed_%t", algorithm, closed), func(t *testing.T) {
				params := Params{}
				if algorithm == "sign" {
					end := make(chan *common.SignatureData, 1)
					if closed {
						close(end)
					} else {
						end <- nil
					}
					params.SignECDSAEndCh = end
				} else {
					end := make(chan *eddsakeygen.LocalPartySaveData, 1)
					if closed {
						close(end)
					} else {
						end <- nil
					}
					params.DKGEdDSAEndCh = end
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				rt := newSessionRuntime(ctx, 1)
				defer rt.Stop()
				exec := New(params)
				if err := exec.runProtocolResultWorker(rt); !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("missing pointer result error = %v, want io.ErrUnexpectedEOF", err)
				}
				assertNoCompletion(t, rt, exec)
			})
		}
	}
}

func assertNoCompletion(t *testing.T, rt *sessionRuntime, exec *ProtocolExecution) {
	t.Helper()
	select {
	case ev := <-rt.Events:
		t.Fatalf("unexpected completion event: %+v", ev)
	default:
	}
	if exec.ECDSAKeyShare() != nil || exec.Signature() != nil || exec.protocolDoneFlag.Load() {
		t.Fatal("missing result was accepted as success")
	}
}
