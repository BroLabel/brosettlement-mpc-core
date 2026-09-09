package flow

import (
	"bytes"
	"errors"
	"math/big"
	"runtime"
	"testing"
	"time"

	tssbnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/utils"
	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

func TestBuildSignRejectsNilKeyDerivationDelta(t *testing.T) {
	outCh := make(chan tsslib.Message, 1)
	_, err := BuildSign(SignBuildInput{
		Digest:   []byte{1, 2, 3},
		Params:   &tsslib.Parameters{},
		KeyShare: ecdsakeygen.LocalPartySaveData{},
		OutCh:    outCh,
	})
	if !errors.Is(err, ErrKeyDerivationDeltaRequired) {
		t.Fatalf("expected ErrKeyDerivationDeltaRequired, got %v", err)
	}
}

func TestSignBuildInputCarriesKeyDerivationDelta(t *testing.T) {
	in := SignBuildInput{KeyDerivationDelta: big.NewInt(42)}
	if in.KeyDerivationDelta.Sign() != 1 {
		t.Fatalf("unexpected delta: %v", in.KeyDerivationDelta)
	}
}

func TestBuildSignDoesNotStartDetachedResultBridge(t *testing.T) {
	params, _, _, err := tssbnbutils.BuildParams([]string{"A", "B"}, "A", 2, "", "ecdsa")
	if err != nil {
		t.Fatalf("BuildParams() error = %v", err)
	}
	share := ecdsakeygen.NewLocalPartySaveData(2)
	for i, partyID := range params.Parties().IDs() {
		share.Ks[i] = new(big.Int).Set(partyID.KeyInt())
	}

	before := runtime.NumGoroutine()
	for range 16 {
		if _, err := BuildSign(SignBuildInput{
			Digest:             []byte{1},
			Params:             params,
			KeyShare:           share,
			KeyDerivationDelta: big.NewInt(1),
			OutCh:              make(chan tsslib.Message),
		}); err != nil {
			t.Fatalf("BuildSign() error = %v", err)
		}
	}
	runtime.Gosched()
	after := runtime.NumGoroutine()
	if after > before+2 {
		t.Fatalf("BuildSign() goroutines grew from %d to %d; detached result bridges remain", before, after)
	}
}

func TestDeliverSignaturePreservesExactLeadingZeroDigest(t *testing.T) {
	digest := append([]byte{0}, bytes.Repeat([]byte{0x31}, 31)...)
	tssResult := &common.SignatureData{
		Signature:         []byte{0x10, 0x11},
		SignatureRecovery: []byte{0x20},
		R:                 []byte{0x30},
		S:                 []byte{0x40},
		M:                 bytes.Repeat([]byte{0x31}, 31),
	}
	wantInput := cloneSignatureFields(
		tssResult.Signature,
		tssResult.SignatureRecovery,
		tssResult.R,
		tssResult.S,
		tssResult.M,
	)
	var delivered *common.SignatureData

	err := deliverSignature(tssResult, digest, func(signature *common.SignatureData) {
		delivered = signature
	})
	if err != nil {
		t.Fatalf("deliverSignature() error = %v", err)
	}
	if delivered == nil {
		t.Fatal("deliverSignature() did not invoke callback")
	}
	if !bytes.Equal(delivered.GetM(), digest) {
		t.Fatalf("delivered digest = %x, want %x", delivered.GetM(), digest)
	}
	if !bytes.Equal(delivered.GetSignature(), tssResult.GetSignature()) ||
		!bytes.Equal(delivered.GetSignatureRecovery(), tssResult.GetSignatureRecovery()) ||
		!bytes.Equal(delivered.GetR(), tssResult.GetR()) ||
		!bytes.Equal(delivered.GetS(), tssResult.GetS()) {
		t.Fatal("deliverSignature() changed signature fields")
	}
	if !bytes.Equal(tssResult.GetM(), wantInput.GetM()) || len(tssResult.GetM()) != 31 {
		t.Fatal("deliverSignature() mutated the tss-lib result")
	}
	delivered.M[0] ^= 0xff
	if !bytes.Equal(tssResult.GetM(), wantInput.GetM()) || digest[0] != 0 {
		t.Fatal("delivered signature aliases an input buffer")
	}
}

func TestDeliverSignatureRejectsNumericallyDifferentDigest(t *testing.T) {
	tssResult := &common.SignatureData{M: []byte{0x02}}
	digest := []byte{0x00, 0x01}
	called := false

	err := deliverSignature(tssResult, digest, func(*common.SignatureData) {
		called = true
	})
	if !errors.Is(err, ErrSignDigestMismatch) {
		t.Fatalf("deliverSignature() error = %v, want ErrSignDigestMismatch", err)
	}
	if called {
		t.Fatal("deliverSignature() invoked callback for a mismatched digest")
	}
	if !bytes.Equal(tssResult.GetM(), []byte{0x02}) || !bytes.Equal(digest, []byte{0x00, 0x01}) {
		t.Fatal("deliverSignature() mutated mismatched inputs")
	}
}

func TestDeliverSignatureWaitsForCallback(t *testing.T) {
	digest := []byte{0x01}
	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	resultCh := make(chan error, 1)
	go func() {
		resultCh <- deliverSignature(&common.SignatureData{M: digest}, digest, func(*common.SignatureData) {
			close(callbackEntered)
			<-releaseCallback
		})
	}()

	select {
	case <-callbackEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for signature callback entry")
	}
	select {
	case err := <-resultCh:
		close(releaseCallback)
		t.Fatalf("deliverSignature() returned before callback exited: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseCallback)
	select {
	case err := <-resultCh:
		if err != nil {
			t.Fatalf("deliverSignature() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for deliverSignature() after callback exit")
	}
}
