package derivation

import (
	"errors"
	"testing"
)

func validECDSAContext() Context {
	return Context{
		ProfileID:   "profile-1",
		Chain:       "ethereum",
		Algorithm:   " ECDSA ",
		Curve:       " SECP256K1 ",
		Scheme:      "bip32_public",
		AccountPath: "m/44h/60H/0'",
		ChildPath:   "/0/15",
		FullPath:    "m/44'/60'/0'/0/15",
	}
}

func TestNormalizeContextCanonicalizesECDSAAliasAndPaths(t *testing.T) {
	got, err := NormalizeContext(validECDSAContext())
	if err != nil {
		t.Fatalf("NormalizeContext returned error: %v", err)
	}
	if got.Algorithm != AlgorithmECDSA {
		t.Fatalf("Algorithm = %q", got.Algorithm)
	}
	if got.Curve != CurveSecp256k1 {
		t.Fatalf("Curve = %q", got.Curve)
	}
	if got.Scheme != DerivationSchemeBIP32Secp256k1 {
		t.Fatalf("Scheme = %q", got.Scheme)
	}
	if got.AccountPath != "m/44'/60'/0'" {
		t.Fatalf("AccountPath = %q", got.AccountPath)
	}
	if got.ChildPath != "/0/15" {
		t.Fatalf("ChildPath = %q", got.ChildPath)
	}
	if got.FullPath != "m/44'/60'/0'/0/15" {
		t.Fatalf("FullPath = %q", got.FullPath)
	}
}

func TestNormalizeContextDoesNotMutateInput(t *testing.T) {
	in := validECDSAContext()
	original := in
	if _, err := NormalizeContext(in); err != nil {
		t.Fatalf("NormalizeContext returned error: %v", err)
	}
	if in != original {
		t.Fatalf("NormalizeContext mutated input: got %+v want %+v", in, original)
	}
}

func TestNormalizeContextRejectsBadECDSAInputs(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Context)
		want error
	}{
		{name: "missing profile", edit: func(c *Context) { c.ProfileID = "" }, want: ErrInvalidDerivationContext},
		{name: "missing account path", edit: func(c *Context) { c.AccountPath = "" }, want: ErrInvalidDerivationContext},
		{name: "absolute child path", edit: func(c *Context) { c.ChildPath = "m/0/15" }, want: ErrDerivationPathInvalid},
		{name: "hardened child apostrophe", edit: func(c *Context) { c.ChildPath = "/0/15'" }, want: ErrDerivationPathInvalid},
		{name: "hardened child h", edit: func(c *Context) { c.ChildPath = "/0h/15" }, want: ErrDerivationPathInvalid},
		{name: "extra child depth", edit: func(c *Context) { c.ChildPath = "/0/15/2" }, want: ErrDerivationPathInvalid},
		{name: "leading zero", edit: func(c *Context) { c.ChildPath = "/0/015" }, want: ErrDerivationPathInvalid},
		{name: "full path mismatch", edit: func(c *Context) { c.FullPath = "m/44'/60'/0'/0/16" }, want: ErrDerivationPathInvalid},
		{name: "unknown scheme", edit: func(c *Context) { c.Scheme = "bad_scheme" }, want: ErrUnsupportedDerivationScheme},
		{name: "unsupported curve", edit: func(c *Context) { c.Curve = "p256" }, want: ErrUnsupportedAlgorithmCurve},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := validECDSAContext()
			tt.edit(&ctx)
			_, err := NormalizeContext(ctx)
			if !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
		})
	}
}

func TestNormalizeContextAcceptsReservedEdDSAContext(t *testing.T) {
	got, err := NormalizeContext(Context{
		ProfileID:   "profile-1",
		Algorithm:   "EdDSA",
		Curve:       "Ed25519",
		Scheme:      DerivationSchemeSLIP10Ed25519,
		AccountPath: "m/44'/501'/0'",
		ChildPath:   "/0/1",
		FullPath:    "m/44'/501'/0'/0/1",
	})
	if err != nil {
		t.Fatalf("NormalizeContext returned error: %v", err)
	}
	if got.Algorithm != AlgorithmEdDSA || got.Curve != CurveEd25519 || got.Scheme != DerivationSchemeSLIP10Ed25519 {
		t.Fatalf("unexpected normalized EdDSA context: %+v", got)
	}
}
