package derivation

import (
	"encoding/hex"
	"fmt"
	"strings"
)

type DKGMaterial struct {
	ChainCode        string
	DerivationScheme string
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
