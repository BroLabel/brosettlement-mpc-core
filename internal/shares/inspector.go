package shares

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	tsscrypto "github.com/bnb-chain/tss-lib/crypto"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

const compressedSecp256k1PublicKeyLength = 33

// ECDSAKeyMaterialEvidence is the non-secret evidence derived from an
// encoded codec-v2 ECDSA key material blob.
type ECDSAKeyMaterialEvidence struct {
	CodecVersion     uint32
	AccountPublicKey []byte
	ChainCodeHash    [32]byte
}

// InspectEncodedECDSAKeyMaterial validates an encoded codec-v2 ECDSA key
// material blob and derives only non-secret, canonical public evidence from it.
func InspectEncodedECDSAKeyMaterial(blob []byte) (evidence ECDSAKeyMaterialEvidence, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			evidence = ECDSAKeyMaterialEvidence{}
			err = fmt.Errorf("%w: ECDSA material inspection failed", ErrInvalidSharePayload)
		}
	}()

	material, err := UnmarshalKeyMaterial(blob)
	if err != nil {
		return ECDSAKeyMaterialEvidence{}, err
	}
	defer clearBytes(material.ChainCode)

	if len(material.ChainCode) != sha256.Size {
		return ECDSAKeyMaterialEvidence{}, fmt.Errorf("%w: chain code length", ErrInvalidSharePayload)
	}

	publicKey, err := compressedSecp256k1PublicKey(material.Share.ECDSAPub)
	if err != nil {
		return ECDSAKeyMaterialEvidence{}, err
	}

	return ECDSAKeyMaterialEvidence{
		CodecVersion:     codecVersion,
		AccountPublicKey: publicKey,
		ChainCodeHash:    sha256.Sum256(material.ChainCode),
	}, nil
}

func compressedSecp256k1PublicKey(point *tsscrypto.ECPoint) ([]byte, error) {
	if point == nil {
		return nil, fmt.Errorf("%w: ECDSA public key missing", ErrInvalidSharePayload)
	}

	curve := tsslib.S256()
	x, y := point.X(), point.Y()
	if x == nil || y == nil || (x.Sign() == 0 && y.Sign() == 0) || !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("%w: ECDSA public key invalid", ErrInvalidSharePayload)
	}

	return encodeCompressedSecp256k1Point(x, y), nil
}

func encodeCompressedSecp256k1Point(x, y *big.Int) []byte {
	encoded := make([]byte, compressedSecp256k1PublicKeyLength)
	encoded[0] = 0x02 + byte(y.Bit(0))
	xBytes := x.Bytes()
	copy(encoded[len(encoded)-len(xBytes):], xBytes)
	return encoded
}
