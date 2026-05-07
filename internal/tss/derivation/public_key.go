package derivation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"strings"

	tsscrypto "github.com/bnb-chain/tss-lib/crypto"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

func ValidateUncompressedSecp256k1Hex(input string) error {
	if input == "" {
		return nil
	}
	if strings.HasPrefix(input, "0x") || strings.ToLower(input) != input || len(input) != 130 {
		return fmt.Errorf("%w: derived_public_key is not canonical uncompressed hex", ErrInvalidDerivationContext)
	}

	decoded, err := hex.DecodeString(input)
	if err != nil || len(decoded) != 65 || decoded[0] != 0x04 {
		return fmt.Errorf("%w: derived_public_key is not SEC1 uncompressed", ErrInvalidDerivationContext)
	}

	curve := tsslib.S256()
	x, y := elliptic.Unmarshal(curve, decoded)
	if x == nil || y == nil || !curve.IsOnCurve(x, y) || (x.Sign() == 0 && y.Sign() == 0) {
		return fmt.Errorf("%w: derived_public_key is not on secp256k1", ErrInvalidDerivationContext)
	}
	return nil
}

func EncodeUncompressedSecp256k1(pub *ecdsa.PublicKey) string {
	curve := tsslib.S256()
	if pub == nil || pub.X == nil || pub.Y == nil || !curve.IsOnCurve(pub.X, pub.Y) {
		return ""
	}

	encoded := elliptic.Marshal(curve, pub.X, pub.Y)
	if len(encoded) != 65 {
		return ""
	}
	return hex.EncodeToString(encoded)
}

func EncodeECPointUncompressedSecp256k1(point *tsscrypto.ECPoint) (string, error) {
	if point == nil {
		return "", fmt.Errorf("%w: secp256k1 public key missing", ErrInvalidDerivationContext)
	}
	encoded := EncodeUncompressedSecp256k1(point.ToECDSAPubKey())
	if encoded == "" {
		return "", fmt.Errorf("%w: secp256k1 public key required", ErrInvalidDerivationContext)
	}
	return encoded, nil
}
