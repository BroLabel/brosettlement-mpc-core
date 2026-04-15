package tss

import (
	"errors"

	tssruntime "github.com/BroLabel/brosettlement-mpc-core/internal/tss/runtime"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type DKGOutput struct {
	KeyID     string
	PublicKey string
	Address   string
}

type ReadDKGOutputInput struct {
	SessionID string
	OrgID     string
	Algorithm string
	Chain     string
}

var (
	ErrDKGKeyIDMismatch              = errors.New("dkg key id must match session id")
	ErrUnsupportedDKGOutputAlgorithm = errors.New("dkg output algorithm is unsupported")
	ErrUnsupportedDKGOutputChain     = errors.New("dkg output chain is unsupported")
)

func ExtractECDSAPublicKey(share ecdsakeygen.LocalPartySaveData) (string, error) {
	got, err := tssruntime.ExtractECDSAPublicKey(share)
	if err != nil {
		return "", ErrMissingDKGPublicKey
	}
	return got, nil
}

func ECDSAAddressFromShare(chain string, share ecdsakeygen.LocalPartySaveData) (string, error) {
	got, err := tssruntime.ECDSAAddressFromShare(chain, share)
	if errors.Is(err, tssruntime.ErrUnsupportedDKGOutputChain) {
		return "", ErrUnsupportedDKGOutputChain
	}
	if err != nil {
		return "", ErrMissingDKGAddress
	}
	return got, nil
}
