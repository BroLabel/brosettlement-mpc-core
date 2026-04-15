package runtime

import (
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"strings"

	tssbnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/utils"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

var ErrUnsupportedDKGOutputChain = errors.New("dkg output chain is unsupported")

func NormalizeDKGOutputChain(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "tron", "tron-mainnet":
		return "tron", nil
	default:
		return "", ErrUnsupportedDKGOutputChain
	}
}

func ExtractECDSAPublicKey(share ecdsakeygen.LocalPartySaveData) (string, error) {
	if share.ECDSAPub == nil {
		return "", tssbnbutils.ErrECDSAPubKeyUnavailable
	}
	pub := share.ECDSAPub.ToECDSAPubKey()
	if pub == nil || pub.X == nil || pub.Y == nil || pub.Curve == nil {
		return "", tssbnbutils.ErrECDSAPubKeyUnavailable
	}

	marshaled := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	if len(marshaled) == 0 {
		return "", tssbnbutils.ErrECDSAPubKeyUnavailable
	}
	return hex.EncodeToString(marshaled), nil
}

func ECDSAAddressFromShare(chain string, share ecdsakeygen.LocalPartySaveData) (string, error) {
	normalized, err := NormalizeDKGOutputChain(chain)
	if err != nil {
		return "", err
	}
	switch normalized {
	case "tron":
		return tssbnbutils.ECDSAAddressFromShare(share)
	default:
		return "", ErrUnsupportedDKGOutputChain
	}
}
