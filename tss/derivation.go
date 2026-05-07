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

func NormalizeDerivationContext(in DerivationContext) (DerivationContext, error) {
	out, err := corederivation.NormalizeContext(toCoreDerivationContext(in))
	if err != nil {
		return DerivationContext{}, err
	}
	return fromCoreDerivationContext(out), nil
}

func validateDerivationContextForSession(ctx DerivationContext, session SessionDescriptor) error {
	normalized, err := corederivation.NormalizeContext(toCoreDerivationContext(ctx))
	if err != nil {
		return err
	}
	return corederivation.MatchSession(normalized, corederivation.Session{
		Algorithm: session.Algorithm,
		Curve:     session.Curve,
		Chain:     session.Chain,
	})
}

func toCoreDerivationContext(in DerivationContext) corederivation.Context {
	return corederivation.Context{
		ProfileID:         in.ProfileID,
		Chain:             in.Chain,
		Algorithm:         in.Algorithm,
		Curve:             in.Curve,
		Scheme:            in.Scheme,
		AccountPath:       in.AccountPath,
		ChildPath:         in.ChildPath,
		FullPath:          in.FullPath,
		AddressEncoding:   in.AddressEncoding,
		ExpectedAddress:   in.ExpectedAddress,
		DerivedPublicKey:  in.DerivedPublicKey,
		Descriptor:        in.Descriptor,
		DescriptorVersion: in.DescriptorVersion,
		ProfileVersion:    in.ProfileVersion,
	}
}

func fromCoreDerivationContext(in corederivation.Context) DerivationContext {
	return DerivationContext{
		ProfileID:         in.ProfileID,
		Chain:             in.Chain,
		Algorithm:         in.Algorithm,
		Curve:             in.Curve,
		Scheme:            in.Scheme,
		AccountPath:       in.AccountPath,
		ChildPath:         in.ChildPath,
		FullPath:          in.FullPath,
		AddressEncoding:   in.AddressEncoding,
		ExpectedAddress:   in.ExpectedAddress,
		DerivedPublicKey:  in.DerivedPublicKey,
		Descriptor:        in.Descriptor,
		DescriptorVersion: in.DescriptorVersion,
		ProfileVersion:    in.ProfileVersion,
	}
}
