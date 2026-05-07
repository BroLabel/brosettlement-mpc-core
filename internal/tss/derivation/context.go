package derivation

import (
	"fmt"
	"strings"
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

type Context struct {
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

type Session struct {
	Algorithm string
	Curve     string
	Chain     string
}

func NormalizeContext(in Context) (Context, error) {
	out := in
	out.ProfileID = strings.TrimSpace(out.ProfileID)
	out.Chain = strings.TrimSpace(out.Chain)
	out.Algorithm = strings.ToLower(strings.TrimSpace(out.Algorithm))
	out.Curve = strings.ToLower(strings.TrimSpace(out.Curve))
	out.Scheme = strings.ToLower(strings.TrimSpace(out.Scheme))

	if out.ProfileID == "" {
		return Context{}, fmt.Errorf("%w: profile_id is required", ErrInvalidDerivationContext)
	}
	if out.Algorithm == "" {
		out.Algorithm = AlgorithmECDSA
	}
	if out.Curve == "" && out.Algorithm == AlgorithmECDSA {
		out.Curve = CurveSecp256k1
	}

	switch out.Algorithm {
	case AlgorithmECDSA:
		return normalizeECDSAContext(out)
	case AlgorithmEdDSA:
		return normalizeEdDSAContext(out)
	default:
		return Context{}, fmt.Errorf("%w: algorithm=%s", ErrUnsupportedAlgorithmCurve, out.Algorithm)
	}
}

func MatchSession(ctx Context, session Session) error {
	nctx, err := NormalizeContext(ctx)
	if err != nil {
		return err
	}

	alg := strings.ToLower(strings.TrimSpace(session.Algorithm))
	if alg == "" {
		alg = AlgorithmECDSA
	}
	curve := strings.ToLower(strings.TrimSpace(session.Curve))
	if curve == "" && alg == AlgorithmECDSA {
		curve = CurveSecp256k1
	}

	if nctx.Algorithm != alg || nctx.Curve != curve {
		return fmt.Errorf("%w: context=%s/%s session=%s/%s", ErrUnsupportedAlgorithmCurve, nctx.Algorithm, nctx.Curve, alg, curve)
	}
	if nctx.Chain != "" && strings.TrimSpace(session.Chain) != "" && nctx.Chain != strings.TrimSpace(session.Chain) {
		return fmt.Errorf("%w: chain mismatch", ErrInvalidDerivationContext)
	}
	return nil
}
