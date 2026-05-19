package flow

import (
	"errors"
	"math/big"
	"testing"

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
