package derivation

import (
	"errors"
	"strings"
	"testing"
)

const validUncompressedSecp256k1Hex = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

func TestValidateUncompressedSecp256k1Hex(t *testing.T) {
	if err := ValidateUncompressedSecp256k1Hex(validUncompressedSecp256k1Hex); err != nil {
		t.Fatalf("expected valid key, got %v", err)
	}
}

func TestValidateUncompressedSecp256k1HexRejectsNonCanonicalEncodings(t *testing.T) {
	tests := []string{
		"02" + strings.Repeat("00", 32),
		strings.Repeat("00", 32),
		"0x" + validUncompressedSecp256k1Hex,
		strings.ToUpper(validUncompressedSecp256k1Hex),
		"04" + strings.Repeat("00", 64),
		"04" + strings.Repeat("11", 63),
		"TQ2kaddresslike",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			err := ValidateUncompressedSecp256k1Hex(input)
			if !errors.Is(err, ErrInvalidDerivationContext) {
				t.Fatalf("expected ErrInvalidDerivationContext, got %v", err)
			}
		})
	}
}
