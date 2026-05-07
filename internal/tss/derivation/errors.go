package derivation

import (
	"errors"
	"fmt"
)

var (
	ErrDerivationContextRequired   = errors.New("derivation context required")
	ErrInvalidDerivationContext    = errors.New("invalid derivation context")
	ErrUnsupportedDerivationScheme = errors.New("unsupported derivation scheme")
	ErrDerivationPathInvalid       = errors.New("derivation path invalid")
	ErrDerivationContextMismatch   = errors.New("derivation context mismatch")
	ErrChainCodeMissing            = errors.New("chain code missing")
	ErrChainCodeInvalid            = errors.New("chain code invalid")
	ErrDerivedSigningUnsupported   = errors.New("derived signing unsupported")
	ErrUnsupportedAlgorithmCurve   = errors.New("unsupported algorithm curve")
)

func Wrap(base error, msg string) error {
	if base == nil {
		return nil
	}
	if msg == "" {
		return base
	}
	return fmt.Errorf("%w: %s", base, msg)
}
