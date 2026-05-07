package tss

import (
	"fmt"

	corederivation "github.com/BroLabel/brosettlement-mpc-core/internal/tss/derivation"
)

const (
	AlgorithmECDSA = "ecdsa"
	AlgorithmEdDSA = "eddsa"

	CurveSecp256k1 = "secp256k1"
	CurveEd25519   = "ed25519"

	DerivationSchemeBIP32Secp256k1 = "bip32_secp256k1"
	DerivationSchemeBIP32Public    = "bip32_public"
	DerivationSchemeSLIP10Ed25519  = "slip10_ed25519"

	PublicKeyFormatUncompressedHex = "uncompressed_hex"
)

var (
	ErrDerivationContextRequired   = corederivation.ErrDerivationContextRequired
	ErrInvalidDerivationContext    = corederivation.ErrInvalidDerivationContext
	ErrUnsupportedDerivationScheme = corederivation.ErrUnsupportedDerivationScheme
	ErrDerivationPathInvalid       = corederivation.ErrDerivationPathInvalid
	ErrDerivationContextMismatch   = corederivation.ErrDerivationContextMismatch
	ErrChainCodeMissing            = corederivation.ErrChainCodeMissing
	ErrChainCodeInvalid            = corederivation.ErrChainCodeInvalid
	ErrDerivedSigningUnsupported   = corederivation.ErrDerivedSigningUnsupported
	ErrUnsupportedAlgorithmCurve   = corederivation.ErrUnsupportedAlgorithmCurve
)

type DerivationContext struct {
	ProfileID         string
	Chain             string
	Algorithm         string
	Curve             string
	Scheme            string
	AccountPath       string
	ChildPath         string
	FullPath          string
	AddressEncoding   string
	ExpectedAddress   string
	DerivedPublicKey  string
	Descriptor        string
	DescriptorVersion uint32
	ProfileVersion    uint32
}

type DKGDerivationMaterial struct {
	ChainCode        string
	DerivationScheme string
}

func wrapPublicDerivationError(base error, msg string) error {
	if base == nil {
		return nil
	}
	if msg == "" {
		return base
	}
	return fmt.Errorf("%w: %s", base, msg)
}
