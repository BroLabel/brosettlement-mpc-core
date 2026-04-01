package utils

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"

	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/sha3"
)

var ErrECDSAPubKeyUnavailable = errors.New("ecdsa public key is unavailable")

func ECDSAAddressFromShare(share ecdsakeygen.LocalPartySaveData) (string, error) {
	if share.ECDSAPub == nil {
		return "", ErrECDSAPubKeyUnavailable
	}
	pub := share.ECDSAPub.ToECDSAPubKey()
	if pub == nil || pub.X == nil || pub.Y == nil || pub.Curve == nil {
		return "", ErrECDSAPubKeyUnavailable
	}
	uncompressed := marshalUncompressedPubKey(pub)
	if len(uncompressed) != 65 {
		return "", ErrECDSAPubKeyUnavailable
	}
	pubHash := keccak256(uncompressed[1:])
	payload := make([]byte, 21)
	payload[0] = 0x41 // Tron mainnet address prefix
	copy(payload[1:], pubHash[12:])
	checksum := doubleSHA256(payload)
	withChecksum := make([]byte, 0, len(payload)+4)
	withChecksum = append(withChecksum, payload...)
	withChecksum = append(withChecksum, checksum[:4]...)
	return base58.Encode(withChecksum), nil
}

func doubleSHA256(in []byte) [32]byte {
	first := sha256.Sum256(in)
	return sha256.Sum256(first[:])
}

func marshalUncompressedPubKey(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.Curve == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	params := pub.Params()
	if params == nil {
		return nil
	}
	byteLen := (params.BitSize + 7) / 8
	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	if len(x) > byteLen || len(y) > byteLen {
		return nil
	}
	out := make([]byte, 1+2*byteLen)
	out[0] = 0x04
	copy(out[1+byteLen-len(x):1+byteLen], x)
	copy(out[1+2*byteLen-len(y):], y)
	return out
}

// keccak256 computes Keccak-256 (legacy, Ethereum/Tron style), not SHA3-256.
func keccak256(msg []byte) [32]byte {
	var out [32]byte
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(msg)
	h.Sum(out[:0])
	return out
}
