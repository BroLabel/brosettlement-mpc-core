package utils

import "strings"

// NormalizeAlgorithm normalizes algorithm names and applies the project default.
func NormalizeAlgorithm(algorithm string) string {
	alg := strings.ToLower(strings.TrimSpace(algorithm))
	if alg == "" {
		return "ecdsa"
	}
	return alg
}

// IsECDSA reports whether the algorithm is ECDSA or empty (default ECDSA).
func IsECDSA(algorithm string) bool {
	alg := strings.ToLower(strings.TrimSpace(algorithm))
	return alg == "" || alg == "ecdsa"
}

// ZeroBytes overwrites a byte slice in place.
func ZeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
