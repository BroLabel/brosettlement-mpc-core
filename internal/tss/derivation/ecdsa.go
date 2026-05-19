package derivation

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/ckd"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	ecdsasigning "github.com/bnb-chain/tss-lib/ecdsa/signing"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

type DKGMaterial struct {
	ChainCode        string
	DerivationScheme string
}

type ECDSAChildKey struct {
	PublicKey          *ecdsa.PublicKey
	PublicKeyHex       string
	KeyDerivationDelta *big.Int
}

type PreparedECDSASigningShare struct {
	Share              ecdsakeygen.LocalPartySaveData
	DerivedPublicKey   string
	KeyDerivationDelta *big.Int
}

func IsECDSAAlgorithm(algorithm string) bool {
	alg := strings.ToLower(strings.TrimSpace(algorithm))
	return alg == "" || alg == AlgorithmECDSA
}

func ParseChainCodeHex(input string) ([]byte, error) {
	if len(input) != 64 || strings.HasPrefix(input, "0x") || strings.ToLower(input) != input {
		return nil, fmt.Errorf("%w: chain_code must be 32-byte lowercase hex", ErrChainCodeInvalid)
	}
	decoded, err := hex.DecodeString(input)
	if err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("%w: chain_code must be 32-byte lowercase hex", ErrChainCodeInvalid)
	}
	return decoded, nil
}

func ValidateDKGMaterial(algorithm string, material DKGMaterial) ([]byte, string, error) {
	if !IsECDSAAlgorithm(algorithm) {
		return nil, "", nil
	}
	if strings.TrimSpace(material.ChainCode) == "" {
		return nil, "", ErrChainCodeMissing
	}
	scheme := strings.ToLower(strings.TrimSpace(material.DerivationScheme))
	if scheme != DerivationSchemeBIP32Secp256k1 {
		return nil, "", fmt.Errorf("%w: %s", ErrUnsupportedDerivationScheme, material.DerivationScheme)
	}
	chainCode, err := ParseChainCodeHex(material.ChainCode)
	if err != nil {
		return nil, "", err
	}
	return chainCode, scheme, nil
}

func ParseChildPath(raw string) ([]uint32, error) {
	_, indices, err := NormalizeChildPath(raw)
	return indices, err
}

func DeriveECDSAChildKey(accountPub *crypto.ECPoint, chainCode []byte, indices []uint32) (ECDSAChildKey, error) {
	if accountPub == nil {
		return ECDSAChildKey{}, fmt.Errorf("%w: account public key missing", ErrInvalidDerivationContext)
	}
	if len(chainCode) == 0 {
		return ECDSAChildKey{}, ErrChainCodeMissing
	}
	if len(chainCode) != 32 {
		return ECDSAChildKey{}, fmt.Errorf("%w: chain_code must be 32 bytes", ErrChainCodeInvalid)
	}

	curve := tsslib.S256()
	pub := accountPub.ToECDSAPubKey()
	if pub == nil || pub.X == nil || pub.Y == nil || !curve.IsOnCurve(pub.X, pub.Y) {
		return ECDSAChildKey{}, fmt.Errorf("%w: account public key invalid", ErrInvalidDerivationContext)
	}

	extendedParent := &ckd.ExtendedKey{
		PublicKey:  ecdsa.PublicKey{Curve: curve, X: pub.X, Y: pub.Y},
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  append([]byte(nil), chainCode...),
		ParentFP:   []byte{0, 0, 0, 0},
		Version:    []byte{0x04, 0x88, 0xad, 0xe4},
	}
	delta, child, err := ckd.DeriveChildKeyFromHierarchy(indices, extendedParent, curve.Params().N, curve)
	if err != nil {
		return ECDSAChildKey{}, fmt.Errorf("%w: %v", ErrDerivationPathInvalid, err)
	}

	childPub := &child.PublicKey
	return ECDSAChildKey{
		PublicKey:          childPub,
		PublicKeyHex:       EncodeUncompressedSecp256k1(childPub),
		KeyDerivationDelta: delta,
	}, nil
}

func DeriveECDSAChildKeyForContext(accountPub *crypto.ECPoint, chainCode []byte, ctx Context) (ECDSAChildKey, error) {
	normalized, err := NormalizeContext(ctx)
	if err != nil {
		return ECDSAChildKey{}, err
	}
	if normalized.Algorithm != AlgorithmECDSA || normalized.Curve != CurveSecp256k1 {
		return ECDSAChildKey{}, fmt.Errorf("%w: %s/%s", ErrUnsupportedAlgorithmCurve, normalized.Algorithm, normalized.Curve)
	}

	indices, err := ParseChildPath(normalized.ChildPath)
	if err != nil {
		return ECDSAChildKey{}, err
	}
	child, err := DeriveECDSAChildKey(accountPub, chainCode, indices)
	if err != nil {
		return ECDSAChildKey{}, err
	}
	if normalized.DerivedPublicKey != "" && normalized.DerivedPublicKey != child.PublicKeyHex {
		return ECDSAChildKey{}, fmt.Errorf("%w: derived_public_key mismatch", ErrDerivationContextMismatch)
	}
	return child, nil
}

func PrepareECDSASigningShare(share ecdsakeygen.LocalPartySaveData, chainCode []byte, ctx Context) (PreparedECDSASigningShare, error) {
	child, err := DeriveECDSAChildKeyForContext(share.ECDSAPub, chainCode, ctx)
	if err != nil {
		return PreparedECDSASigningShare{}, err
	}

	adjusted := cloneECDSAShareForDerivation(share)
	keys := []ecdsakeygen.LocalPartySaveData{adjusted}
	if err := ecdsasigning.UpdatePublicKeyAndAdjustBigXj(child.KeyDerivationDelta, keys, child.PublicKey, tsslib.S256()); err != nil {
		return PreparedECDSASigningShare{}, fmt.Errorf("%w: adjust share: %v", ErrInvalidDerivationContext, err)
	}
	adjusted = keys[0]

	return PreparedECDSASigningShare{
		Share:              adjusted,
		DerivedPublicKey:   child.PublicKeyHex,
		KeyDerivationDelta: child.KeyDerivationDelta,
	}, nil
}

func cloneECDSAShareForDerivation(share ecdsakeygen.LocalPartySaveData) ecdsakeygen.LocalPartySaveData {
	clone := share
	if share.BigXj != nil {
		clone.BigXj = append([]*crypto.ECPoint(nil), share.BigXj...)
	}
	return clone
}
