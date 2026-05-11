# HD Derived Signing Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make profile-derived HD signing the only public signing mode, with upstream-supplied DKG chain code, strict public derivation context validation, child-key ECDSA signing, and derivation context hash binding on SIGN frames.

**Architecture:** Add a small internal derivation package that owns canonical context normalization, path parsing, secp256k1 public key encoding, chain-code validation, context hashing, and BIP32/KDD share adjustment. The public `tss` package maps public request structs into internal normalized runtime structs before calling the service, while the service persists and loads full ECDSA key material rather than share-only blobs. The TSS runner receives an already adjusted signing share plus the required key-derivation delta and starts only the `NewLocalPartyWithKDD` signing path.

**Tech Stack:** Go, `testing`, `errors.Is`, `encoding/gob`, `crypto/sha256`, manual canonical JSON payload assembly, `tss-lib v1.5.0`, `tss-lib/crypto/ckd`, `tss-lib/ecdsa/signing`, `protocol.Frame`, `go test`

---

## File Structure

- Create `internal/tss/derivation/errors.go`: internal sentinel errors re-exported by `tss` so internal packages can wrap errors without importing the public facade.
- Create `internal/tss/derivation/context.go`: normalized derivation context structs, algorithm/curve/scheme constants, context normalization, session matching, and EdDSA reserved-mode classification.
- Create `internal/tss/derivation/path.go`: account path parsing, `/change/index` child path parsing, full path canonical join, and non-hardened child index checks.
- Create `internal/tss/derivation/public_key.go`: canonical `uncompressed_hex` secp256k1 public key validation and encoding.
- Create `internal/tss/derivation/hash.go`: canonical `DerivationContextHashV1` payload assembly and SHA-256 hashing.
- Create `internal/tss/derivation/ecdsa.go`: chain-code parsing, BIP32 child public key derivation, derived public key commitment comparison, and runtime share adjustment.
- Create tests beside each new derivation file: `context_test.go`, `path_test.go`, `public_key_test.go`, `hash_test.go`, and `ecdsa_test.go`.
- Modify `tss/service.go`: public `DerivationContext`, `DKGDerivationMaterial`, constants, error aliases, request structs, validation, and normalized request mapping.
- Modify `internal/tss/service/types.go`: internal `DKGInput`, `DKGOutput`, and `SignInput` fields for derivation material, normalized context, context hash, adjusted share, and KDD.
- Modify `internal/tss/service/dkg.go`: validate DKG derivation material, include chain code/scheme/format in output, and persist full key material.
- Modify `internal/tss/service/sign.go`: load full key material, derive child signing material, reject unsupported modes before protocol start, and pass only adjusted runtime data into runner signing.
- Modify `internal/tss/runtime/share_runtime.go`: persist/load `ECDSAKeyMaterial`, validate material metadata, derive canonical account public key output, and zero key-material blobs.
- Modify `internal/shares/codec.go`, `internal/shares/types.go`, `internal/shares/metadata.go`, and tests: v2 key-material envelope, no v1 decode compatibility, and public compatibility wrappers.
- Modify `tss/sharestore.go`: public aliases for `ECDSAKeyMaterial`, `KeyMaterialMeta`, `MarshalKeyMaterial`, and `UnmarshalKeyMaterial`.
- Modify `internal/tssbnb/runner/types.go` and `internal/tssbnb/runner/bnb_runner.go`: keep in-memory `ECDSAKeyMaterial`, remove SIGN fallback from `KeyID` to `SessionID`, and pass KDD to flow.
- Modify `internal/tssbnb/flow/sign.go`: require `KeyDerivationDelta` and call only `ecdsasigning.NewLocalPartyWithKDD`.
- Modify `protocol/frame.go`: add `DerivationContextHash string`.
- Modify `internal/tssbnb/execution/execution.go`: attach context hash to outbound SIGN frames and reject missing/mismatched inbound SIGN hashes before parsing TSS payloads.
- Modify `README.md`: document derived signing mode, DKG activation responsibility, chain-code source, and unsupported EdDSA runtime signing.

---

### Task 1: Add Public Derivation Contract Skeleton

**Files:**
- Create: `internal/tss/derivation/errors.go`
- Create: `tss/derivation.go`
- Create: `tss/derivation_test.go`
- Modify: `tss/service.go`
- Test: `tss/derivation_test.go`
- Test: `tss/service_test.go`

- [x] **Step 1: Write the failing public contract tests**

Add these tests to `tss/derivation_test.go`.

```go
package tss

import (
	"errors"
	"testing"
)

func TestPublicDerivationConstants(t *testing.T) {
	if AlgorithmECDSA != "ecdsa" {
		t.Fatalf("AlgorithmECDSA = %q", AlgorithmECDSA)
	}
	if AlgorithmEdDSA != "eddsa" {
		t.Fatalf("AlgorithmEdDSA = %q", AlgorithmEdDSA)
	}
	if CurveSecp256k1 != "secp256k1" {
		t.Fatalf("CurveSecp256k1 = %q", CurveSecp256k1)
	}
	if CurveEd25519 != "ed25519" {
		t.Fatalf("CurveEd25519 = %q", CurveEd25519)
	}
	if DerivationSchemeBIP32Secp256k1 != "bip32_secp256k1" {
		t.Fatalf("DerivationSchemeBIP32Secp256k1 = %q", DerivationSchemeBIP32Secp256k1)
	}
	if DerivationSchemeBIP32Public != "bip32_public" {
		t.Fatalf("DerivationSchemeBIP32Public = %q", DerivationSchemeBIP32Public)
	}
	if DerivationSchemeSLIP10Ed25519 != "slip10_ed25519" {
		t.Fatalf("DerivationSchemeSLIP10Ed25519 = %q", DerivationSchemeSLIP10Ed25519)
	}
	if PublicKeyFormatUncompressedHex != "uncompressed_hex" {
		t.Fatalf("PublicKeyFormatUncompressedHex = %q", PublicKeyFormatUncompressedHex)
	}
}

func TestSignSessionRequestValidateRequiresDerivationContext(t *testing.T) {
	req := SignSessionRequest{
		Session: SessionDescriptor{
			SessionID: "sign-1",
			OrgID:     "org-1",
			KeyID:     "key-1",
			Parties:   []string{"p1", "p2", "p3"},
			Threshold: 2,
			Algorithm: AlgorithmECDSA,
			Curve:     CurveSecp256k1,
		},
		LocalPartyID: "p1",
		Digest:       []byte{1, 2, 3},
		Transport:    noopTransport{},
	}

	err := req.Validate()
	if !errors.Is(err, ErrDerivationContextRequired) {
		t.Fatalf("expected ErrDerivationContextRequired, got %v", err)
	}
}

func TestDerivationErrorsPreserveErrorsIs(t *testing.T) {
	err := wrapPublicDerivationError(ErrInvalidDerivationContext, "bad context")
	if !errors.Is(err, ErrInvalidDerivationContext) {
		t.Fatalf("expected wrapper to preserve ErrInvalidDerivationContext, got %v", err)
	}
}
```

- [x] **Step 2: Run tests to verify the contract is missing**

Run: `go test ./tss -run 'TestPublicDerivationConstants|TestSignSessionRequestValidateRequiresDerivationContext|TestDerivationErrorsPreserveErrorsIs' -count=1`

Expected: FAIL to compile because `DerivationContext`, derivation constants, public errors, and `wrapPublicDerivationError` do not exist.

- [x] **Step 3: Add internal sentinels and public aliases**

Create `internal/tss/derivation/errors.go`.

```go
package derivation

import (
	"errors"
	"fmt"
)

var (
	ErrDerivationContextRequired  = errors.New("derivation context required")
	ErrInvalidDerivationContext   = errors.New("invalid derivation context")
	ErrUnsupportedDerivationScheme = errors.New("unsupported derivation scheme")
	ErrDerivationPathInvalid      = errors.New("derivation path invalid")
	ErrDerivationContextMismatch  = errors.New("derivation context mismatch")
	ErrChainCodeMissing           = errors.New("chain code missing")
	ErrChainCodeInvalid           = errors.New("chain code invalid")
	ErrDerivedSigningUnsupported  = errors.New("derived signing unsupported")
	ErrUnsupportedAlgorithmCurve  = errors.New("unsupported algorithm curve")
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
```

Add the missing `fmt` import in the same file.

Create `tss/derivation.go`.

```go
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
	ErrDerivationContextRequired  = corederivation.ErrDerivationContextRequired
	ErrInvalidDerivationContext   = corederivation.ErrInvalidDerivationContext
	ErrUnsupportedDerivationScheme = corederivation.ErrUnsupportedDerivationScheme
	ErrDerivationPathInvalid      = corederivation.ErrDerivationPathInvalid
	ErrDerivationContextMismatch  = corederivation.ErrDerivationContextMismatch
	ErrChainCodeMissing           = corederivation.ErrChainCodeMissing
	ErrChainCodeInvalid           = corederivation.ErrChainCodeInvalid
	ErrDerivedSigningUnsupported  = corederivation.ErrDerivedSigningUnsupported
	ErrUnsupportedAlgorithmCurve  = corederivation.ErrUnsupportedAlgorithmCurve
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
```

- [x] **Step 4: Extend public request structs and nil-context validation**

Modify `tss/service.go`.

```go
type DKGSessionRequest struct {
	Session            SessionDescriptor
	LocalPartyID       string
	DerivationMaterial *DKGDerivationMaterial
	Transport          Transport
}

type SignSessionRequest struct {
	Session           SessionDescriptor
	LocalPartyID      string
	Digest            []byte
	DerivationContext *DerivationContext
	Transport         Transport
}
```

Update `SignSessionRequest.Validate()` so base validation still runs first, then hard-mode signing rejects a nil context.

```go
func (r SignSessionRequest) Validate() error {
	err := tssrequests.ValidateSign(tssrequests.SignRequest{
		Session: tssrequests.SessionDescriptor{
			SessionID: r.Session.SessionID,
			OrgID:     r.Session.OrgID,
			KeyID:     r.Session.KeyID,
			Parties:   r.Session.Parties,
			Threshold: r.Session.Threshold,
		},
		LocalPartyID: r.LocalPartyID,
		Digest:       r.Digest,
		HasTransport: r.Transport != nil,
	}, ErrInvalidSessionDescriptor, ErrLocalPartyRequired, ErrKeyIDRequired, ErrDigestMissing, ErrTransportRequired)
	if err != nil {
		return err
	}
	if r.DerivationContext == nil {
		return ErrDerivationContextRequired
	}
	return nil
}
```

- [x] **Step 5: Run tests to verify the skeleton passes**

Run: `go test ./tss -run 'TestPublicDerivationConstants|TestSignSessionRequestValidateRequiresDerivationContext|TestDerivationErrorsPreserveErrorsIs|TestSignSessionRequestValidateRequiresDigest' -count=1`

Expected: PASS.

- [x] **Step 6: Commit the public skeleton**

```bash
git add internal/tss/derivation/errors.go tss/derivation.go tss/derivation_test.go tss/service.go
git commit -m "feat: add derived signing public contract"
```

### Task 2: Normalize Derivation Context and Paths

**Files:**
- Create: `internal/tss/derivation/context.go`
- Create: `internal/tss/derivation/path.go`
- Create: `internal/tss/derivation/public_key.go`
- Create: `internal/tss/derivation/context_test.go`
- Create: `internal/tss/derivation/path_test.go`
- Create: `internal/tss/derivation/public_key_test.go`
- Modify: `tss/derivation.go`
- Test: `internal/tss/derivation`
- Test: `tss`

- [x] **Step 1: Write failing normalization tests**

Create `internal/tss/derivation/context_test.go`.

```go
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
```

Create `internal/tss/derivation/public_key_test.go`.

```go
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
```

- [x] **Step 2: Run tests to verify normalization is missing**

Run: `go test ./internal/tss/derivation ./tss -run 'TestNormalizeContext|TestValidateUncompressedSecp256k1Hex' -count=1`

Expected: FAIL because the internal derivation package and public normalization functions do not exist.

- [x] **Step 3: Implement internal context and path types**

Create `internal/tss/derivation/context.go`.

```go
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
```

Create `internal/tss/derivation/path.go`. Keep child paths exactly two unsigned decimal components and reject hardened markers before parsing numeric values.

```go
package derivation

import (
	"fmt"
	"strconv"
	"strings"
)

func normalizeECDSAContext(out Context) (Context, error) {
	if out.Curve != CurveSecp256k1 {
		return Context{}, fmt.Errorf("%w: ecdsa curve=%s", ErrUnsupportedAlgorithmCurve, out.Curve)
	}
	switch out.Scheme {
	case DerivationSchemeBIP32Public:
		out.Scheme = DerivationSchemeBIP32Secp256k1
	case DerivationSchemeBIP32Secp256k1:
	default:
		return Context{}, fmt.Errorf("%w: scheme=%s", ErrUnsupportedDerivationScheme, out.Scheme)
	}
	account, err := NormalizeAccountPath(out.AccountPath)
	if err != nil {
		return Context{}, err
	}
	child, _, err := NormalizeChildPath(out.ChildPath)
	if err != nil {
		return Context{}, err
	}
	full := CanonicalFullPath(account, child)
	if strings.TrimSpace(out.FullPath) != "" {
		got, err := NormalizeFullPath(out.FullPath)
		if err != nil {
			return Context{}, err
		}
		if got != full {
			return Context{}, fmt.Errorf("%w: full_path mismatch", ErrDerivationPathInvalid)
		}
	}
	if err := ValidateUncompressedSecp256k1Hex(out.DerivedPublicKey); err != nil {
		return Context{}, err
	}
	out.AccountPath = account
	out.ChildPath = child
	out.FullPath = full
	return out, nil
}

func normalizeEdDSAContext(out Context) (Context, error) {
	if out.Curve != CurveEd25519 {
		return Context{}, fmt.Errorf("%w: eddsa curve=%s", ErrUnsupportedAlgorithmCurve, out.Curve)
	}
	if out.Scheme != DerivationSchemeSLIP10Ed25519 {
		return Context{}, fmt.Errorf("%w: scheme=%s", ErrUnsupportedDerivationScheme, out.Scheme)
	}
	account, err := NormalizeAccountPath(out.AccountPath)
	if err != nil {
		return Context{}, err
	}
	child, _, err := NormalizeChildPath(out.ChildPath)
	if err != nil {
		return Context{}, err
	}
	full := CanonicalFullPath(account, child)
	if strings.TrimSpace(out.FullPath) != "" {
		got, err := NormalizeFullPath(out.FullPath)
		if err != nil {
			return Context{}, err
		}
		if got != full {
			return Context{}, fmt.Errorf("%w: full_path mismatch", ErrDerivationPathInvalid)
		}
	}
	out.AccountPath = account
	out.ChildPath = child
	out.FullPath = full
	return out, nil
}

func NormalizeAccountPath(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || s != "m" && !strings.HasPrefix(s, "m/") {
		return "", fmt.Errorf("%w: account_path=%q", ErrInvalidDerivationContext, raw)
	}
	if s == "m" {
		return "m", nil
	}
	parts := strings.Split(strings.TrimPrefix(s, "m/"), "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized, err := normalizeAccountPathComponent(part)
		if err != nil {
			return "", err
		}
		out = append(out, normalized)
	}
	return "m/" + strings.Join(out, "/"), nil
}

func normalizeAccountPathComponent(part string) (string, error) {
	if part == "" || strings.ContainsAny(part, " +-") {
		return "", fmt.Errorf("%w: account_path segment=%q", ErrInvalidDerivationContext, part)
	}
	hardened := strings.HasSuffix(part, "'") || strings.HasSuffix(part, "h") || strings.HasSuffix(part, "H")
	core := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(part, "'"), "h"), "H")
	if core == "" || strings.ContainsAny(core, "'hH") {
		return "", fmt.Errorf("%w: account_path segment=%q", ErrInvalidDerivationContext, part)
	}
	n, err := strconv.ParseUint(core, 10, 32)
	if err != nil || n >= 0x80000000 {
		return "", fmt.Errorf("%w: account_path segment=%q", ErrInvalidDerivationContext, part)
	}
	if hardened {
		n += 0x80000000
	}
	if n >= 0x80000000 {
		return strconv.FormatUint(n-0x80000000, 10) + "'", nil
	}
	return strconv.FormatUint(n, 10), nil
}

func NormalizeChildPath(raw string) (string, []uint32, error) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "m/") || !strings.HasPrefix(s, "/") {
		return "", nil, fmt.Errorf("%w: child_path=%q", ErrDerivationPathInvalid, raw)
	}
	parts := strings.Split(strings.TrimPrefix(s, "/"), "/")
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("%w: child_path=%q", ErrDerivationPathInvalid, raw)
	}
	indices := make([]uint32, 0, 2)
	for _, part := range parts {
		if strings.ContainsAny(part, "'hH +-") {
			return "", nil, fmt.Errorf("%w: child_path=%q", ErrDerivationPathInvalid, raw)
		}
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return "", nil, fmt.Errorf("%w: child_path=%q", ErrDerivationPathInvalid, raw)
		}
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil || n >= 0x80000000 {
			return "", nil, fmt.Errorf("%w: child_path=%q", ErrDerivationPathInvalid, raw)
		}
		indices = append(indices, uint32(n))
	}
	return "/" + strconv.FormatUint(uint64(indices[0]), 10) + "/" + strconv.FormatUint(uint64(indices[1]), 10), indices, nil
}

func NormalizeFullPath(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || s != "m" && !strings.HasPrefix(s, "m/") {
		return "", fmt.Errorf("%w: full_path=%q", ErrDerivationPathInvalid, raw)
	}
	parts := strings.Split(strings.TrimPrefix(s, "m/"), "/")
	if len(parts) < 3 {
		return "", fmt.Errorf("%w: full_path=%q", ErrDerivationPathInvalid, raw)
	}
	accountParts := parts[:len(parts)-2]
	childParts := parts[len(parts)-2:]
	account, err := NormalizeAccountPath("m/" + strings.Join(accountParts, "/"))
	if err != nil {
		return "", err
	}
	child, _, err := NormalizeChildPath("/" + strings.Join(childParts, "/"))
	if err != nil {
		return "", err
	}
	return CanonicalFullPath(account, child), nil
}

func CanonicalFullPath(accountPath, childPath string) string {
	return strings.TrimRight(accountPath, "/") + childPath
}
```

- [x] **Step 4: Implement canonical public key validation**

Create `internal/tss/derivation/public_key.go`.

```go
package derivation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"strings"

	tsscrypto "github.com/bnb-chain/tss-lib/crypto"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

func ValidateUncompressedSecp256k1Hex(input string) error {
	if input == "" {
		return nil
	}
	if strings.HasPrefix(input, "0x") || strings.ToLower(input) != input || len(input) != 130 {
		return fmt.Errorf("%w: derived_public_key is not canonical uncompressed hex", ErrInvalidDerivationContext)
	}
	decoded, err := hex.DecodeString(input)
	if err != nil || len(decoded) != 65 || decoded[0] != 0x04 {
		return fmt.Errorf("%w: derived_public_key is not SEC1 uncompressed", ErrInvalidDerivationContext)
	}
	x, y := elliptic.Unmarshal(tsslib.S256(), decoded)
	if x == nil || y == nil || !tsslib.S256().IsOnCurve(x, y) || (x.Sign() == 0 && y.Sign() == 0) {
		return fmt.Errorf("%w: derived_public_key is not on secp256k1", ErrInvalidDerivationContext)
	}
	return nil
}

func EncodeUncompressedSecp256k1(pub *ecdsa.PublicKey) string {
	if pub == nil || pub.X == nil || pub.Y == nil || pub.Curve != tsslib.S256() || !tsslib.S256().IsOnCurve(pub.X, pub.Y) {
		return ""
	}
	encoded := elliptic.Marshal(tsslib.S256(), pub.X, pub.Y)
	if len(encoded) != 65 {
		return ""
	}
	return hex.EncodeToString(encoded)
}

func EncodeECPointUncompressedSecp256k1(point *tsscrypto.ECPoint) (string, error) {
	if point == nil {
		return "", fmt.Errorf("%w: secp256k1 public key missing", ErrInvalidDerivationContext)
	}
	encoded := EncodeUncompressedSecp256k1(point.ToECDSAPubKey())
	if encoded == "" {
		return "", fmt.Errorf("%w: secp256k1 public key required", ErrInvalidDerivationContext)
	}
	return encoded, nil
}
```

- [x] **Step 5: Wire public normalization wrappers**

Modify `tss/derivation.go`.

```go
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
```

Update `SignSessionRequest.Validate()` to call `validateDerivationContextForSession(*r.DerivationContext, r.Session)` after the nil-context check.

- [x] **Step 6: Run normalization tests**

Run: `go test ./internal/tss/derivation ./tss -run 'TestNormalizeContext|TestValidateUncompressedSecp256k1Hex|TestSignSessionRequestValidate' -count=1`

Expected: PASS.

- [x] **Step 7: Commit normalization**

```bash
git add internal/tss/derivation/context.go internal/tss/derivation/path.go internal/tss/derivation/public_key.go internal/tss/derivation/context_test.go internal/tss/derivation/path_test.go internal/tss/derivation/public_key_test.go tss/derivation.go tss/service.go
git commit -m "feat: normalize derivation context"
```

### Task 3: Add Stable DerivationContextHashV1

**Files:**
- Create: `internal/tss/derivation/hash.go`
- Create: `internal/tss/derivation/hash_test.go`
- Modify: `tss/derivation.go`
- Test: `internal/tss/derivation`
- Test: `tss`

- [x] **Step 1: Write failing hash tests**

Create `internal/tss/derivation/hash_test.go`.

```go
package derivation

import (
	"bytes"
	"strings"
	"testing"
)

func TestHashV1UsesCanonicalPayloadAndDomain(t *testing.T) {
	ctx := Context{
		ProfileID:         "profile-1",
		Chain:             "ethereum",
		Algorithm:         "ECDSA",
		Curve:             "SECP256K1",
		Scheme:            "bip32_public",
		AccountPath:       "m/44h/60h/0h",
		ChildPath:         "/0/15",
		FullPath:          "m/44'/60'/0'/0/15",
		DescriptorVersion: 7,
		ProfileVersion:    3,
	}

	payload, err := CanonicalHashPayloadV1(ctx)
	if err != nil {
		t.Fatalf("CanonicalHashPayloadV1 returned error: %v", err)
	}
	wantPayload := `{"version":1,"profile_id":"profile-1","chain":"ethereum","algorithm":"ecdsa","curve":"secp256k1","scheme":"bip32_secp256k1","account_path":"m/44'/60'/0'","child_path":"/0/15","full_path":"m/44'/60'/0'/0/15","derived_public_key":"","descriptor_version":7,"profile_version":3}`
	if string(payload) != wantPayload {
		t.Fatalf("payload mismatch\nwant: %s\n got: %s", wantPayload, payload)
	}

	got, err := HashV1(ctx)
	if err != nil {
		t.Fatalf("HashV1 returned error: %v", err)
	}
	want := "5d5026f1babbfdb661523324c1255509aa4acee5f9096e3035a0d162e9c05d5c"
	if got != want {
		t.Fatalf("hash mismatch: want %s got %s", want, got)
	}
}

func TestHashV1IgnoresAddressAndDescriptorFields(t *testing.T) {
	base := validECDSAContext()
	changed := base
	changed.AddressEncoding = "bech32"
	changed.ExpectedAddress = "chain-specific-address"
	changed.Descriptor = "descriptor payload"

	hashA, err := HashV1(base)
	if err != nil {
		t.Fatalf("HashV1 base error: %v", err)
	}
	hashB, err := HashV1(changed)
	if err != nil {
		t.Fatalf("HashV1 changed error: %v", err)
	}
	if hashA != hashB {
		t.Fatalf("expected ignored fields to keep hash stable: %s != %s", hashA, hashB)
	}
}

func TestHashV1PayloadDoesNotHTMLEscapeStrings(t *testing.T) {
	ctx := validECDSAContext()
	ctx.ProfileID = "profile<&>" + string(rune(0x2028)) + string(rune(0x2029)) + string([]byte{0xc3, 0xa9})

	payload, err := CanonicalHashPayloadV1(ctx)
	if err != nil {
		t.Fatalf("CanonicalHashPayloadV1 returned error: %v", err)
	}
	got := string(payload)
	if !strings.Contains(got, `"profile_id":"profile<&>`) {
		t.Fatalf("expected unescaped profile id in payload, got %s", got)
	}
	if strings.Contains(got, `\u003c`) || strings.Contains(got, `\u003e`) || strings.Contains(got, `\u0026`) || strings.Contains(got, `\u2028`) || strings.Contains(got, `\u2029`) || strings.Contains(got, `\u00e9`) {
		t.Fatalf("payload contains non-shortest escapes: %s", got)
	}
	if !bytes.Contains(payload, []byte{0xe2, 0x80, 0xa8}) || !bytes.Contains(payload, []byte{0xe2, 0x80, 0xa9}) || !bytes.Contains(payload, []byte{0xc3, 0xa9}) {
		t.Fatalf("payload does not contain raw UTF-8 non-ASCII bytes: %x", payload)
	}
}

func TestHashV1ChangesOnCommitmentAndVersionFields(t *testing.T) {
	base := validECDSAContext()
	baseHash, err := HashV1(base)
	if err != nil {
		t.Fatalf("HashV1 base error: %v", err)
	}

	cases := []Context{base, base, base, base}
	cases[0].DerivedPublicKey = validUncompressedSecp256k1Hex
	cases[1].ProfileVersion = 99
	cases[2].DescriptorVersion = 99
	cases[3].ChildPath = "/0/16"

	for i, ctx := range cases {
		got, err := HashV1(ctx)
		if err != nil {
			t.Fatalf("HashV1 case %d error: %v", i, err)
		}
		if got == baseHash {
			t.Fatalf("case %d did not change hash", i)
		}
	}
}
```

- [x] **Step 2: Run tests to verify hash support is missing**

Run: `go test ./internal/tss/derivation ./tss -run 'TestHashV1|TestDerivationContextHashV1' -count=1`

Expected: FAIL because `HashV1`, `CanonicalHashPayloadV1`, and public `DerivationContextHashV1` are missing.

- [x] **Step 3: Implement ordered canonical hash payload**

Create `internal/tss/derivation/hash.go`.

```go
package derivation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"unicode/utf8"
)

const hashDomainV1 = "brosettlement.derivation_context.v1"
const jsonHex = "0123456789abcdef"

func CanonicalHashPayloadV1(in Context) ([]byte, error) {
	ctx, err := NormalizeContext(in)
	if err != nil {
		return nil, err
	}
	fields := []struct {
		name  string
		value string
	}{
		{"profile_id", ctx.ProfileID},
		{"chain", ctx.Chain},
		{"algorithm", ctx.Algorithm},
		{"curve", ctx.Curve},
		{"scheme", ctx.Scheme},
		{"account_path", ctx.AccountPath},
		{"child_path", ctx.ChildPath},
		{"full_path", ctx.FullPath},
		{"derived_public_key", ctx.DerivedPublicKey},
	}
	for _, field := range fields {
		if !utf8.ValidString(field.value) {
			return nil, fmt.Errorf("%w: %s is not valid utf-8", ErrInvalidDerivationContext, field.name)
		}
	}

	payload := make([]byte, 0, 256)
	payload = append(payload, `{"version":1`...)
	for _, field := range fields {
		payload = appendJSONStringField(payload, field.name, field.value)
	}
	payload = appendJSONUintField(payload, "descriptor_version", ctx.DescriptorVersion)
	payload = appendJSONUintField(payload, "profile_version", ctx.ProfileVersion)
	payload = append(payload, '}')
	return payload, nil
}

func HashV1(in Context) (string, error) {
	payload, err := CanonicalHashPayloadV1(in)
	if err != nil {
		return "", err
	}
	input := append([]byte(hashDomainV1+"\n"), payload...)
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:]), nil
}

func appendJSONStringField(dst []byte, name, value string) []byte {
	dst = append(dst, `,"`...)
	dst = append(dst, name...)
	dst = append(dst, `":`...)
	return appendJSONString(dst, value)
}

func appendJSONUintField(dst []byte, name string, value uint32) []byte {
	dst = append(dst, `,"`...)
	dst = append(dst, name...)
	dst = append(dst, `":`...)
	return strconv.AppendUint(dst, uint64(value), 10)
}

func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); i++ {
		esc := ""
		switch s[i] {
		case '\\':
			esc = `\\`
		case '"':
			esc = `\"`
		case '\b':
			esc = `\b`
		case '\f':
			esc = `\f`
		case '\n':
			esc = `\n`
		case '\r':
			esc = `\r`
		case '\t':
			esc = `\t`
		default:
			if s[i] < 0x20 {
				dst = append(dst, s[start:i]...)
				dst = append(dst, `\u00`...)
				dst = append(dst, jsonHex[s[i]>>4], jsonHex[s[i]&0x0f])
				start = i + 1
			}
			continue
		}
		dst = append(dst, s[start:i]...)
		dst = append(dst, esc...)
		start = i + 1
	}
	dst = append(dst, s[start:]...)
	dst = append(dst, '"')
	return dst
}
```

- [x] **Step 4: Add public hash wrapper without mutating input**

Modify `tss/derivation.go`.

```go
func DerivationContextHashV1(in DerivationContext) (string, error) {
	return corederivation.HashV1(toCoreDerivationContext(in))
}
```

Add this test to `tss/derivation_test.go`.

```go
func TestDerivationContextHashV1DoesNotMutateInput(t *testing.T) {
	in := DerivationContext{
		ProfileID:   "profile-1",
		Algorithm:   "ECDSA",
		Curve:       "SECP256K1",
		Scheme:      DerivationSchemeBIP32Public,
		AccountPath: "m/44h/60h/0h",
		ChildPath:   "/0/15",
		FullPath:    "m/44'/60'/0'/0/15",
	}
	before := in
	if _, err := DerivationContextHashV1(in); err != nil {
		t.Fatalf("DerivationContextHashV1 returned error: %v", err)
	}
	if in != before {
		t.Fatalf("hash mutated input: before=%+v after=%+v", before, in)
	}
}
```

- [x] **Step 5: Run hash tests**

Run: `go test ./internal/tss/derivation ./tss -run 'TestHashV1|TestDerivationContextHashV1' -count=1`

Expected: PASS.

- [x] **Step 6: Commit hash binding primitive**

```bash
git add internal/tss/derivation/hash.go internal/tss/derivation/hash_test.go tss/derivation.go tss/derivation_test.go
git commit -m "feat: add derivation context hash"
```

### Task 4: Replace Share-Only Codec With V2 Key Material

**Files:**
- Modify: `internal/shares/codec.go`
- Modify: `internal/shares/metadata.go`
- Modify: `internal/shares/codec_test.go`
- Modify: `tss/sharestore.go`
- Test: `internal/shares`
- Test: `tss`

- [x] **Step 1: Write failing key-material codec tests**

Update `internal/shares/codec_test.go`.

```go
func TestMarshalUnmarshalKeyMaterialRoundTrip(t *testing.T) {
	original := ECDSAKeyMaterial{
		Share:            ecdsakeygen.LocalPartySaveData{},
		ChainCode:        bytes.Repeat([]byte{0x11}, 32),
		PublicKeyFormat:  "uncompressed_hex",
		DerivationScheme: "bip32_secp256k1",
	}

	blob, err := MarshalKeyMaterial(original)
	if err != nil {
		t.Fatalf("MarshalKeyMaterial() err = %v", err)
	}

	decoded, err := UnmarshalKeyMaterial(blob)
	if err != nil {
		t.Fatalf("UnmarshalKeyMaterial() err = %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Fatalf("decoded material mismatch: want %+v got %+v", original, decoded)
	}
}

func TestUnmarshalKeyMaterialRejectsLegacyV1ShareBlob(t *testing.T) {
	type legacyShareEnvelope struct {
		Version uint32
		Share   ecdsakeygen.LocalPartySaveData
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(legacyShareEnvelope{
		Version: 1,
		Share:   ecdsakeygen.LocalPartySaveData{},
	}); err != nil {
		t.Fatalf("gob encode err = %v", err)
	}

	_, err := UnmarshalKeyMaterial(buf.Bytes())
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
	}
}

func TestShareWrappersUseV2Envelope(t *testing.T) {
	blob, err := MarshalShare(ecdsakeygen.LocalPartySaveData{})
	if err != nil {
		t.Fatalf("MarshalShare() err = %v", err)
	}
	if _, err := UnmarshalShare(blob); err != nil {
		t.Fatalf("UnmarshalShare() err = %v", err)
	}
	if _, err := UnmarshalKeyMaterial(blob); err != nil {
		t.Fatalf("expected share wrapper blob to be v2 material, got %v", err)
	}
}
```

- [x] **Step 2: Run tests to verify key-material codec is missing**

Run: `go test ./internal/shares ./tss -run 'TestMarshalUnmarshalKeyMaterial|TestUnmarshalKeyMaterialRejectsLegacyV1ShareBlob|TestShareWrappersUseV2Envelope' -count=1`

Expected: FAIL because `ECDSAKeyMaterial`, `MarshalKeyMaterial`, and `UnmarshalKeyMaterial` do not exist.

- [x] **Step 3: Implement v2 material envelope**

Modify `internal/shares/codec.go`.

```go
const codecVersion uint32 = 2

type ECDSAKeyMaterial struct {
	Share            ecdsakeygen.LocalPartySaveData
	ChainCode        []byte
	PublicKeyFormat  string
	DerivationScheme string
}

type KeyMaterialMeta struct {
	ChainCode        []byte
	PublicKeyFormat  string
	DerivationScheme string
}

type shareEnvelope struct {
	Version uint32
	Share   ecdsakeygen.LocalPartySaveData
	Meta    KeyMaterialMeta
}

func MarshalKeyMaterial(material ECDSAKeyMaterial) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(shareEnvelope{
		Version: codecVersion,
		Share:   material.Share,
		Meta: KeyMaterialMeta{
			ChainCode:        append([]byte(nil), material.ChainCode...),
			PublicKeyFormat:  material.PublicKeyFormat,
			DerivationScheme: material.DerivationScheme,
		},
	}); err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidSharePayload, err)
	}
	return buf.Bytes(), nil
}

func UnmarshalKeyMaterial(blob []byte) (ECDSAKeyMaterial, error) {
	var env shareEnvelope
	if err := gob.NewDecoder(bytes.NewReader(blob)).Decode(&env); err != nil {
		return ECDSAKeyMaterial{}, fmt.Errorf("%w: decode: %v", ErrInvalidSharePayload, err)
	}
	if env.Version != codecVersion {
		return ECDSAKeyMaterial{}, fmt.Errorf("%w: got=%d expected=%d", ErrUnsupportedVersion, env.Version, codecVersion)
	}
	return ECDSAKeyMaterial{
		Share:            env.Share,
		ChainCode:        append([]byte(nil), env.Meta.ChainCode...),
		PublicKeyFormat:  env.Meta.PublicKeyFormat,
		DerivationScheme: env.Meta.DerivationScheme,
	}, nil
}

func MarshalShare(share ecdsakeygen.LocalPartySaveData) ([]byte, error) {
	return MarshalKeyMaterial(ECDSAKeyMaterial{Share: share})
}

func UnmarshalShare(blob []byte) (ecdsakeygen.LocalPartySaveData, error) {
	material, err := UnmarshalKeyMaterial(blob)
	if err != nil {
		return ecdsakeygen.LocalPartySaveData{}, err
	}
	return material.Share, nil
}
```

- [x] **Step 4: Add metadata diagnostics and public aliases**

Modify `internal/shares/metadata.go`.

```go
type ShareMeta struct {
	KeyID             string
	OrgID             string
	Algorithm         string
	Curve             string
	CreatedAt         time.Time
	Version           uint32
	Status            string
	ChainCodePresent  bool
	PublicKeyFormat   string
	DerivationScheme  string
}
```

Modify `tss/sharestore.go`.

```go
type ECDSAKeyMaterial = coreshares.ECDSAKeyMaterial
type KeyMaterialMeta = coreshares.KeyMaterialMeta

func MarshalKeyMaterial(material ECDSAKeyMaterial) ([]byte, error) {
	return coreshares.MarshalKeyMaterial(material)
}

func UnmarshalKeyMaterial(blob []byte) (ECDSAKeyMaterial, error) {
	return coreshares.UnmarshalKeyMaterial(blob)
}
```

- [x] **Step 5: Run codec tests**

Run: `go test ./internal/shares ./tss -run 'TestMarshalUnmarshal|TestUnmarshalShare|TestShareWrappersUseV2Envelope' -count=1`

Expected: PASS.

- [x] **Step 6: Commit key-material codec**

```bash
git add internal/shares/codec.go internal/shares/metadata.go internal/shares/codec_test.go tss/sharestore.go
git commit -m "feat: store ecdsa key material envelope"
```

### Task 5: Require DKG Derivation Material and Persist Chain Code

**Files:**
- Modify: `tss/service.go`
- Modify: `tss/service_test.go`
- Create: `internal/tss/derivation/ecdsa.go`
- Modify: `internal/tss/service/types.go`
- Modify: `internal/tss/service/dkg.go`
- Modify: `internal/tss/service/dkg_flow_test.go`
- Modify: `internal/tss/runtime/share_runtime.go`
- Modify: `tss/utils/share_helpers.go`
- Test: `tss`
- Test: `internal/tss/service`

- [x] **Step 1: Write failing DKG material tests**

Add public facade tests in `tss/service_test.go`.

```go
func TestDKGSessionRequestValidateRequiresECDSADerivationMaterial(t *testing.T) {
	req := DKGSessionRequest{
		Session: SessionDescriptor{
			SessionID: "dkg-1",
			OrgID:     "org-1",
			KeyID:     "key-1",
			Parties:   []string{"p1", "p2", "p3"},
			Threshold: 2,
			Algorithm: AlgorithmECDSA,
			Curve:     CurveSecp256k1,
		},
		LocalPartyID: "p1",
		Transport:    noopTransport{},
	}

	err := req.Validate()
	if !errors.Is(err, ErrChainCodeMissing) {
		t.Fatalf("expected ErrChainCodeMissing, got %v", err)
	}
}

func TestDKGSessionRequestValidateRejectsMalformedChainCode(t *testing.T) {
	req := validDKGRequestWithMaterial()
	req.DerivationMaterial.ChainCode = "0x11"

	err := req.Validate()
	if !errors.Is(err, ErrChainCodeInvalid) {
		t.Fatalf("expected ErrChainCodeInvalid, got %v", err)
	}
}

func TestDKGSessionRequestValidateRequiresECDSAKeyID(t *testing.T) {
	req := validDKGRequestWithMaterial()
	req.Session.KeyID = ""

	err := req.Validate()
	if !errors.Is(err, ErrKeyIDRequired) {
		t.Fatalf("expected ErrKeyIDRequired, got %v", err)
	}
}

func validDKGRequestWithMaterial() DKGSessionRequest {
	return DKGSessionRequest{
		Session: SessionDescriptor{
			SessionID: "dkg-1",
			OrgID:     "org-1",
			KeyID:     "key-1",
			Parties:   []string{"p1", "p2", "p3"},
			Threshold: 2,
			Algorithm: AlgorithmECDSA,
			Curve:     CurveSecp256k1,
		},
		LocalPartyID: "p1",
		DerivationMaterial: &DKGDerivationMaterial{
			ChainCode:        strings.Repeat("11", 32),
			DerivationScheme: DerivationSchemeBIP32Secp256k1,
		},
		Transport: noopTransport{},
	}
}
```

Add service tests in `internal/tss/service/dkg_flow_test.go`.

```go
func TestRunDKGSession_ECDSAOutputIncludesSuppliedDerivationMaterial(t *testing.T) {
	chainCode := strings.Repeat("11", 32)
	runner := newECDSAStubRunner(t, "session-1")
	store := &recordingShareStore{runner: runner, sessionID: "session-1"}
	svc := New(runner, newTestLogger(), &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}, store)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-1",
		LocalPartyID: "p1",
		OrgID:        "org",
		KeyID:        "key-1",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		Curve:        "secp256k1",
		DerivationMaterial: DKGDerivationMaterial{
			ChainCode:        chainCode,
			DerivationScheme: "bip32_secp256k1",
		},
		MissingPub:  errMissingPublicKey,
		MissingAddr: errMissingAddress,
	})
	if err != nil {
		t.Fatalf("RunDKGSession returned error: %v", err)
	}
	if out.KeyID != "key-1" {
		t.Fatalf("KeyID = %q", out.KeyID)
	}
	if out.ChainCode != chainCode {
		t.Fatalf("ChainCode = %q", out.ChainCode)
	}
	if out.PublicKeyFormat != "uncompressed_hex" {
		t.Fatalf("PublicKeyFormat = %q", out.PublicKeyFormat)
	}
	if out.DerivationScheme != "bip32_secp256k1" {
		t.Fatalf("DerivationScheme = %q", out.DerivationScheme)
	}
	material, err := coreshares.UnmarshalKeyMaterial(store.savedBlob)
	if err != nil {
		t.Fatalf("UnmarshalKeyMaterial returned error: %v", err)
	}
	if hex.EncodeToString(material.ChainCode) != chainCode {
		t.Fatalf("persisted chain code mismatch: %x", material.ChainCode)
	}
	if store.savedKeyID != "key-1" {
		t.Fatalf("persisted key id = %q", store.savedKeyID)
	}
}
```

- [x] **Step 2: Run DKG tests to verify material flow is missing**

Run: `go test ./tss ./internal/tss/service -run 'TestDKGSessionRequestValidate|TestRunDKGSession_ECDSAOutputIncludesSuppliedDerivationMaterial' -count=1`

Expected: FAIL because DKG derivation material is not validated, not passed internally, not included in `DKGOutput`, and not persisted.

- [x] **Step 3: Add DKG material to public and internal inputs**

Modify `internal/tss/service/types.go`.

```go
type DKGDerivationMaterial struct {
	ChainCode        string
	DerivationScheme string
}

type DKGInput struct {
	SessionID          string
	LocalPartyID       string
	OrgID              string
	KeyID              string
	Parties            []string
	Threshold          uint32
	Curve              string
	Algorithm          string
	Chain              string
	DerivationMaterial DKGDerivationMaterial
	Transport          coretransport.FrameTransport
	EmptyKeyErr        error
	MissingPub         error
	MissingAddr        error
}

type DKGOutput struct {
	KeyID            string
	PublicKey        string
	Address          string
	ChainCode        string
	PublicKeyFormat  string
	DerivationScheme string
}
```

Modify public `RunDKGSession` mapping in `tss/service.go` to validate first and copy material.

```go
if err := req.Validate(); err != nil {
	return DKGOutput{}, err
}
var material tssservice.DKGDerivationMaterial
if req.DerivationMaterial != nil {
	material = tssservice.DKGDerivationMaterial{
		ChainCode:        req.DerivationMaterial.ChainCode,
		DerivationScheme: req.DerivationMaterial.DerivationScheme,
	}
}
```

Include `DerivationMaterial: material` and `EmptyKeyErr: ErrKeyIDRequired` in the `tssservice.DKGInput` passed to `s.impl.RunDKGSession`.

- [x] **Step 4: Validate chain code and scheme at the boundary**

Create `internal/tss/derivation/ecdsa.go` with `ValidateDKGMaterial` and `ParseChainCodeHex`.

```go
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
```

Wire the public request validation in `tss/service.go`. This is required so `DKGSessionRequest.Validate()` returns typed derivation errors before the public facade calls the internal service. Add the `strings` import in this file.

```go
func (r DKGSessionRequest) Validate() error {
	err := tssrequests.ValidateDKG(tssrequests.DKGRequest{
		Session: tssrequests.SessionDescriptor{
			SessionID: r.Session.SessionID,
			OrgID:     r.Session.OrgID,
			KeyID:     r.Session.KeyID,
			Parties:   r.Session.Parties,
			Threshold: r.Session.Threshold,
		},
		LocalPartyID: r.LocalPartyID,
		HasTransport: r.Transport != nil,
	}, ErrInvalidSessionDescriptor, ErrLocalPartyRequired, ErrTransportRequired)
	if err != nil {
		return err
	}
	if corederivation.IsECDSAAlgorithm(r.Session.Algorithm) && strings.TrimSpace(r.Session.KeyID) == "" {
		return ErrKeyIDRequired
	}
	_, _, err = corederivation.ValidateDKGMaterial(r.Session.Algorithm, corederivation.DKGMaterial{
		ChainCode:        derivationMaterialChainCode(r.DerivationMaterial),
		DerivationScheme: derivationMaterialScheme(r.DerivationMaterial),
	})
	return err
}

func derivationMaterialChainCode(material *DKGDerivationMaterial) string {
	if material == nil {
		return ""
	}
	return material.ChainCode
}

func derivationMaterialScheme(material *DKGDerivationMaterial) string {
	if material == nil {
		return ""
	}
	return material.DerivationScheme
}
```

Wire the internal service boundary in `internal/tss/service/dkg.go`. This protects direct internal callers and gives the DKG flow parsed bytes plus canonical scheme before protocol start.

```go
type normalizedDKGMaterial struct {
	ChainCode    []byte
	ChainCodeHex string
	Scheme       string
}

func normalizeDKGMaterial(in DKGInput) (normalizedDKGMaterial, error) {
	chainCode, scheme, err := corederivation.ValidateDKGMaterial(in.Algorithm, corederivation.DKGMaterial{
		ChainCode:        in.DerivationMaterial.ChainCode,
		DerivationScheme: in.DerivationMaterial.DerivationScheme,
	})
	if err != nil {
		return normalizedDKGMaterial{}, err
	}
	return normalizedDKGMaterial{
		ChainCode:    chainCode,
		ChainCodeHex: strings.ToLower(strings.TrimSpace(in.DerivationMaterial.ChainCode)),
		Scheme:       scheme,
	}, nil
}
```

Update `Service.RunDKGSession` so DKG material is validated after logging is initialized and before `AttachPreParams` or `runner.RunDKG`. Pass the normalized material into output construction and persistence.

```go
func (s *Service) RunDKGSession(ctx context.Context, in DKGInput) (DKGOutput, error) {
	job := buildDKGJob(in)
	keyID, err := resolveDKGOutputKeyID(in, job.Algorithm)
	if err != nil {
		return DKGOutput{}, err
	}

	tsslogging.LogSessionStart(s.logger, "dkg", in.SessionID, in.OrgID, keyID, in.LocalPartyID)
	started := time.Now()
	logEnd := func(err error) {
		tsslogging.LogSessionEnd(s.logger, "dkg", in.SessionID, in.OrgID, keyID, in.LocalPartyID, started, err)
	}
	material, err := normalizeDKGMaterial(in)
	if err != nil {
		logEnd(err)
		return DKGOutput{}, err
	}
	err = AttachPreParams(ctx, ResolvePreParamsSource(s.preParamsSource, s.preParamsPool), &job, tssutils.IsECDSA(job.Algorithm))
	if err != nil {
		logEnd(err)
		return DKGOutput{}, err
	}
	if err = s.runner.RunDKG(ctx, job, in.Transport); err != nil {
		logEnd(err)
		return DKGOutput{}, err
	}
	if !tssutils.IsECDSA(job.Algorithm) {
		logEnd(nil)
		return DKGOutput{KeyID: keyID}, nil
	}

	output, share, err := buildECDSADKGOutput(s.runner, in, keyID, material)
	if err != nil {
		logEnd(err)
		return DKGOutput{}, err
	}
	if err = persistECDSAShareAfterDKG(ctx, s.shareStore, s.runner, in.SessionID, job, keyID, share, material); err != nil {
		logEnd(err)
		return DKGOutput{}, err
	}
	logEnd(nil)
	return output, nil
}
```

Replace the old ECDSA behavior that normalized `KeyID` to `SessionID`. ECDSA DKG output and persisted material must use the DKG intent key id; only non-ECDSA DKG may fall back to `SessionID` when the caller omitted a key id.

```go
func resolveDKGOutputKeyID(in DKGInput, algorithm string) (string, error) {
	if tssutils.IsECDSA(algorithm) {
		return tssutils.NormalizeKeyID(in.KeyID, in.EmptyKeyErr)
	}
	keyID := strings.TrimSpace(in.KeyID)
	if keyID == "" {
		return in.SessionID, nil
	}
	return keyID, nil
}
```

Update `persistECDSAShareAfterDKG` to pass full material into runtime persistence.

```go
func persistECDSAShareAfterDKG(ctx context.Context, shareStore ShareStore, runner Runner, sessionID string, job tssbnbrunner.DKGJob, keyID string, share ecdsakeygen.LocalPartySaveData, material normalizedDKGMaterial) error {
	if shareStore == nil {
		return nil
	}
	if err := tssruntime.PersistKeyMaterialAfterDKG(ctx, shareStore, share, tssruntime.DKGPersistInput{
		KeyID:            keyID,
		OrgID:            job.OrgID,
		Algorithm:        job.Algorithm,
		Curve:            job.Curve,
		ChainCode:        append([]byte(nil), material.ChainCode...),
		PublicKeyFormat:  corederivation.PublicKeyFormatUncompressedHex,
		DerivationScheme: material.Scheme,
	}); err != nil {
		return err
	}
	runner.DeleteECDSAKeyShare(sessionID)
	return nil
}
```

- [x] **Step 5: Persist key material after successful DKG**

Modify `internal/tss/runtime/share_runtime.go`.

```go
type DKGPersistInput struct {
	KeyID            string
	OrgID            string
	Algorithm        string
	Curve            string
	ChainCode        []byte
	PublicKeyFormat  string
	DerivationScheme string
}

func PersistKeyMaterialAfterDKG(ctx context.Context, store ShareStore, share ecdsakeygen.LocalPartySaveData, in DKGPersistInput) error {
	blob, err := coreshares.MarshalKeyMaterial(coreshares.ECDSAKeyMaterial{
		Share:            share,
		ChainCode:        append([]byte(nil), in.ChainCode...),
		PublicKeyFormat:  in.PublicKeyFormat,
		DerivationScheme: in.DerivationScheme,
	})
	if err != nil {
		return err
	}
	defer tssutils.ZeroBytes(blob)
	return store.SaveShare(ctx, in.KeyID, blob, tssutils.DKGShareMeta(in.KeyID, in.OrgID, in.Algorithm, in.Curve, len(in.ChainCode) == 32, in.PublicKeyFormat, in.DerivationScheme))
}
```

Update `tss/utils/share_helpers.go` so `DKGShareMeta` accepts the new diagnostic fields and sets `Version: 2`.

- [x] **Step 6: Include supplied chain code in DKG output**

Modify `internal/tss/service/dkg.go`.

```go
func buildECDSADKGOutput(runner Runner, in DKGInput, keyID string, material normalizedDKGMaterial) (DKGOutput, ecdsakeygen.LocalPartySaveData, error) {
	share, err := runner.ExportECDSAKeyShare(in.SessionID)
	if err != nil {
		return DKGOutput{}, ecdsakeygen.LocalPartySaveData{}, err
	}
	publicKey, err := corederivation.EncodeECPointUncompressedSecp256k1(share.ECDSAPub)
	if err != nil {
		if in.MissingPub == nil {
			return DKGOutput{}, ecdsakeygen.LocalPartySaveData{}, err
		}
		return DKGOutput{}, ecdsakeygen.LocalPartySaveData{}, in.MissingPub
	}
	derived, err := tssruntime.DeriveECDSAOutputFromShare(share, in.MissingPub, in.MissingAddr)
	if err != nil {
		return DKGOutput{}, ecdsakeygen.LocalPartySaveData{}, err
	}
	return DKGOutput{
		KeyID:            keyID,
		PublicKey:        publicKey,
		Address:          derived.Address,
		ChainCode:        material.ChainCodeHex,
		PublicKeyFormat:  corederivation.PublicKeyFormatUncompressedHex,
		DerivationScheme: corederivation.DerivationSchemeBIP32Secp256k1,
	}, share, nil
}
```

Do not reuse the current `derived.PublicKey` field for the output contract; it can be produced from a non-secp256k1 curve. The output public key must come from `corederivation.EncodeECPointUncompressedSecp256k1`.

- [x] **Step 7: Run DKG material tests**

Run: `go test ./tss ./internal/tss/service ./internal/tss/runtime -run 'TestDKGSessionRequestValidate|TestRunDKGSession_ECDSAOutputIncludesSuppliedDerivationMaterial|TestRunDKGSession_EdDSAReturnsKeyIDOnly' -count=1`

Expected: PASS.

- [x] **Step 8: Commit DKG material flow**

```bash
git add tss/service.go tss/service_test.go internal/tss/derivation/ecdsa.go internal/tss/service/types.go internal/tss/service/dkg.go internal/tss/service/dkg_flow_test.go internal/tss/runtime/share_runtime.go tss/utils/share_helpers.go
git commit -m "feat: persist dkg derivation material"
```

### Task 6: Implement BIP32 Child Derivation and Share Adjustment

**Files:**
- Modify: `internal/tss/derivation/ecdsa.go`
- Create: `internal/tss/derivation/ecdsa_test.go`
- Modify: `internal/tss/runtime/share_runtime.go`
- Test: `internal/tss/derivation`
- Test: `internal/tss/runtime`

- [x] **Step 1: Write failing BIP32 and KDD tests**

Create `internal/tss/derivation/ecdsa_test.go`.

```go
package derivation

import (
	"bytes"
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/bnb-chain/tss-lib/crypto"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

func testShareWithBigXj(t *testing.T) ecdsakeygen.LocalPartySaveData {
	t.Helper()
	pub := crypto.ScalarBaseMult(tsslib.S256(), big.NewInt(5))
	xj := crypto.ScalarBaseMult(tsslib.S256(), big.NewInt(7))
	return ecdsakeygen.LocalPartySaveData{
		ECDSAPub: pub,
		BigXj:    []*crypto.ECPoint{xj},
	}
}

func TestParseChildPath(t *testing.T) {
	got, err := ParseChildPath("/0/15")
	if err != nil {
		t.Fatalf("ParseChildPath returned error: %v", err)
	}
	want := []uint32{0, 15}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v got %v", want, got)
	}
}

func TestDeriveECDSAChildKeyReturnsCanonicalPublicKeyAndDelta(t *testing.T) {
	share := testShareWithBigXj(t)
	chainCode := bytes.Repeat([]byte{0x11}, 32)

	out, err := DeriveECDSAChildKey(share.ECDSAPub, chainCode, []uint32{0, 15})
	if err != nil {
		t.Fatalf("DeriveECDSAChildKey returned error: %v", err)
	}
	if out.KeyDerivationDelta == nil || out.KeyDerivationDelta.Sign() <= 0 {
		t.Fatalf("missing positive key derivation delta: %+v", out.KeyDerivationDelta)
	}
	if err := ValidateUncompressedSecp256k1Hex(out.PublicKeyHex); err != nil {
		t.Fatalf("derived public key is not canonical: %v", err)
	}
	if out.PublicKey == nil || out.PublicKey.Curve != tsslib.S256() {
		t.Fatalf("unexpected child public key: %+v", out.PublicKey)
	}
}

func TestPrepareECDSASigningShareDoesNotMutateOriginal(t *testing.T) {
	share := testShareWithBigXj(t)
	originalPub := EncodeUncompressedSecp256k1(share.ECDSAPub.ToECDSAPubKey())
	originalBigXj := share.BigXj[0]
	chainCode := bytes.Repeat([]byte{0x11}, 32)
	ctx := Context{
		ProfileID:   "profile-1",
		Algorithm:   AlgorithmECDSA,
		Curve:       CurveSecp256k1,
		Scheme:      DerivationSchemeBIP32Secp256k1,
		AccountPath: "m/44'/60'/0'",
		ChildPath:   "/0/15",
		FullPath:    "m/44'/60'/0'/0/15",
	}

	prepared, err := PrepareECDSASigningShare(share, chainCode, ctx)
	if err != nil {
		t.Fatalf("PrepareECDSASigningShare returned error: %v", err)
	}
	if prepared.KeyDerivationDelta == nil {
		t.Fatal("expected key derivation delta")
	}
	if EncodeUncompressedSecp256k1(share.ECDSAPub.ToECDSAPubKey()) != originalPub {
		t.Fatal("original ECDSAPub was mutated")
	}
	if share.BigXj[0] != originalBigXj {
		t.Fatal("original BigXj pointer was replaced")
	}
	if EncodeUncompressedSecp256k1(prepared.Share.ECDSAPub.ToECDSAPubKey()) == originalPub {
		t.Fatal("expected adjusted share public key to differ from account public key")
	}
}

func TestPrepareECDSASigningShareRejectsDerivedPublicKeyMismatch(t *testing.T) {
	share := testShareWithBigXj(t)
	chainCode := bytes.Repeat([]byte{0x11}, 32)
	ctx := Context{
		ProfileID:        "profile-1",
		Algorithm:        AlgorithmECDSA,
		Curve:            CurveSecp256k1,
		Scheme:           DerivationSchemeBIP32Secp256k1,
		AccountPath:      "m/44'/60'/0'",
		ChildPath:        "/0/15",
		FullPath:         "m/44'/60'/0'/0/15",
		DerivedPublicKey: validUncompressedSecp256k1Hex,
	}

	_, err := PrepareECDSASigningShare(share, chainCode, ctx)
	if !errors.Is(err, ErrDerivationContextMismatch) {
		t.Fatalf("expected ErrDerivationContextMismatch, got %v", err)
	}
}
```

- [x] **Step 2: Run tests to verify derivation runtime is missing**

Run: `go test ./internal/tss/derivation -run 'TestParseChildPath|TestDeriveECDSAChildKey|TestPrepareECDSASigningShare' -count=1`

Expected: FAIL because `ParseChildPath`, `DeriveECDSAChildKey`, and `PrepareECDSASigningShare` are missing.

- [x] **Step 3: Implement child derivation using tss-lib CKD**

Modify `internal/tss/derivation/ecdsa.go`.

```go
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

func ParseChildPath(raw string) ([]uint32, error) {
	_, indices, err := NormalizeChildPath(raw)
	return indices, err
}

func DeriveECDSAChildKey(accountPub *crypto.ECPoint, chainCode []byte, indices []uint32) (ECDSAChildKey, error) {
	if accountPub == nil {
		return ECDSAChildKey{}, fmt.Errorf("%w: account public key missing", ErrInvalidDerivationContext)
	}
	if len(chainCode) != 32 {
		return ECDSAChildKey{}, ErrChainCodeMissing
	}
	pub := accountPub.ToECDSAPubKey()
	if pub == nil || pub.X == nil || pub.Y == nil || !tsslib.S256().IsOnCurve(pub.X, pub.Y) {
		return ECDSAChildKey{}, fmt.Errorf("%w: account public key invalid", ErrInvalidDerivationContext)
	}
	extendedParent := &ckd.ExtendedKey{
		PublicKey: ecdsa.PublicKey{Curve: tsslib.S256(), X: pub.X, Y: pub.Y},
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  append([]byte(nil), chainCode...),
		ParentFP:   []byte{0, 0, 0, 0},
		Version:    []byte{0x04, 0x88, 0xad, 0xe4},
	}
	delta, child, err := ckd.DeriveChildKeyFromHierarchy(indices, extendedParent, tsslib.S256().Params().N, tsslib.S256())
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
```

- [x] **Step 4: Implement share-copy adjustment**

Add to `internal/tss/derivation/ecdsa.go`.

```go
func PrepareECDSASigningShare(share ecdsakeygen.LocalPartySaveData, chainCode []byte, ctx Context) (PreparedECDSASigningShare, error) {
	normalized, err := NormalizeContext(ctx)
	if err != nil {
		return PreparedECDSASigningShare{}, err
	}
	if normalized.Algorithm != AlgorithmECDSA || normalized.Curve != CurveSecp256k1 {
		return PreparedECDSASigningShare{}, fmt.Errorf("%w: %s/%s", ErrUnsupportedAlgorithmCurve, normalized.Algorithm, normalized.Curve)
	}
	indices, err := ParseChildPath(normalized.ChildPath)
	if err != nil {
		return PreparedECDSASigningShare{}, err
	}
	child, err := DeriveECDSAChildKey(share.ECDSAPub, chainCode, indices)
	if err != nil {
		return PreparedECDSASigningShare{}, err
	}
	if normalized.DerivedPublicKey != "" && normalized.DerivedPublicKey != child.PublicKeyHex {
		return PreparedECDSASigningShare{}, fmt.Errorf("%w: derived_public_key mismatch", ErrDerivationContextMismatch)
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
```

`cloneECDSAShareForDerivation` must copy the `BigXj` slice before calling `UpdatePublicKeyAndAdjustBigXj`; the ECPoint values themselves are immutable for this operation because tss-lib replaces slice elements with adjusted points.

- [x] **Step 5: Run derivation runtime tests**

Run: `go test ./internal/tss/derivation -run 'TestParseChildPath|TestDeriveECDSAChildKey|TestPrepareECDSASigningShare' -count=1`

Expected: PASS.

- [x] **Step 6: Commit derivation runtime**

```bash
git add internal/tss/derivation/ecdsa.go internal/tss/derivation/ecdsa_test.go internal/tss/runtime/share_runtime.go
git commit -m "feat: derive ecdsa child signing material"
```

### Task 7: Wire Derived Signing Through Service

**Files:**
- Modify: `internal/tss/service/types.go`
- Modify: `internal/tss/service/sign.go`
- Modify: `internal/tss/service/service.go`
- Modify: `internal/tss/service/sign_flow_test.go`
- Modify: `internal/tss/service/service_testkit_test.go`
- Modify: `internal/tss/runtime/share_runtime.go`
- Modify: `internal/tssbnb/runner/bnb_runner.go`
- Modify: `tss/service.go`
- Modify: `tss/service_test.go`
- Test: `internal/tss/service`
- Test: `tss`

- [x] **Step 1: Write failing service-level derived signing tests**

Update `internal/tss/service/sign_flow_test.go`.

```go
func validServiceDerivationContext() corederivation.Context {
	return corederivation.Context{
		ProfileID:   "profile-1",
		Algorithm:   corederivation.AlgorithmECDSA,
		Curve:       corederivation.CurveSecp256k1,
		Scheme:      corederivation.DerivationSchemeBIP32Secp256k1,
		AccountPath: "m/44'/60'/0'",
		ChildPath:   "/0/15",
		FullPath:    "m/44'/60'/0'/0/15",
	}
}

func newSecp256k1SigningShare(t *testing.T) ecdsakeygen.LocalPartySaveData {
	t.Helper()
	pub := crypto.ScalarBaseMult(tsslib.S256(), big.NewInt(5))
	xj := crypto.ScalarBaseMult(tsslib.S256(), big.NewInt(7))
	if pub == nil || xj == nil {
		t.Fatal("expected secp256k1 test points")
	}
	return ecdsakeygen.LocalPartySaveData{
		ECDSAPub: pub,
		BigXj:    []*crypto.ECPoint{xj},
	}
}

func newDerivedECDSAStubRunner(t *testing.T, keyID string) *stubRunner {
	t.Helper()
	share := newSecp256k1SigningShare(t)
	return &stubRunner{
		shareByKey: map[string]ecdsakeygen.LocalPartySaveData{
			keyID: share,
		},
		materialByKey: map[string]coreshares.ECDSAKeyMaterial{
			keyID: {
				Share:            share,
				ChainCode:        bytes.Repeat([]byte{0x11}, 32),
				PublicKeyFormat:  corederivation.PublicKeyFormatUncompressedHex,
				DerivationScheme: corederivation.DerivationSchemeBIP32Secp256k1,
			},
		},
	}
}

func TestRunSignSession_PreparesDerivedECDSAShareBeforeRunnerStart(t *testing.T) {
	runner := newDerivedECDSAStubRunner(t, "key-1")
	runner.requireShareForSign = true
	hash, err := corederivation.HashV1(validServiceDerivationContext())
	if err != nil {
		t.Fatalf("HashV1 returned error: %v", err)
	}
	svc := New(runner, newTestLogger(), &stubLifecyclePool{}, nil)

	err = svc.RunSignSession(context.Background(), SignInput{
		SessionID:             "sign-1",
		LocalPartyID:          "p1",
		OrgID:                 "org",
		KeyID:                 "key-1",
		Parties:               []string{"p1", "p2"},
		Digest:                []byte{1, 2, 3},
		Algorithm:             "ecdsa",
		Curve:                 "secp256k1",
		DerivationContext:     validServiceDerivationContext(),
		DerivationContextHash: hash,
		EmptyKeyErr:           errShareMissing,
		MetadataMismatch:      errShareMissing,
	})
	if err != nil {
		t.Fatalf("RunSignSession returned error: %v", err)
	}
	if runner.lastSignJob.KeyDerivationDelta == nil {
		t.Fatal("expected runner sign job to receive key derivation delta")
	}
	if runner.lastSignJob.DerivationContextHash != hash {
		t.Fatalf("DerivationContextHash = %q", runner.lastSignJob.DerivationContextHash)
	}
}

func TestRunSignSession_MissingChainCodeFailsBeforeRunnerStart(t *testing.T) {
	runner := newDerivedECDSAStubRunner(t, "key-1")
	material := runner.materialByKey["key-1"]
	material.ChainCode = nil
	runner.materialByKey["key-1"] = material
	svc := New(runner, newTestLogger(), &stubLifecyclePool{}, nil)

	err := svc.RunSignSession(context.Background(), SignInput{
		SessionID:         "sign-1",
		LocalPartyID:      "p1",
		OrgID:             "org",
		KeyID:             "key-1",
		Parties:           []string{"p1", "p2"},
		Digest:            []byte{1, 2, 3},
		Algorithm:         "ecdsa",
		Curve:             "secp256k1",
		DerivationContext: validServiceDerivationContext(),
		EmptyKeyErr:       errShareMissing,
		MetadataMismatch:  errShareMissing,
	})
	if !errors.Is(err, corederivation.ErrChainCodeMissing) {
		t.Fatalf("expected ErrChainCodeMissing, got %v", err)
	}
	if runner.lastSignJob.SessionID != "" {
		t.Fatalf("runner started unexpectedly: %+v", runner.lastSignJob)
	}
}

func TestRunSignSession_CurveMetadataMismatchFailsBeforeRunnerStart(t *testing.T) {
	runner := newDerivedECDSAStubRunner(t, "key-1")
	material := runner.materialByKey["key-1"]
	blob, err := coreshares.MarshalKeyMaterial(material)
	if err != nil {
		t.Fatalf("MarshalKeyMaterial returned error: %v", err)
	}
	store := staticShareStore{stored: &coreshares.StoredShare{
		Blob: blob,
		Meta: coreshares.ShareMeta{
			KeyID:     "key-1",
			OrgID:     "org",
			Algorithm: "ecdsa",
			Curve:     "p256",
		},
	}}
	svc := New(runner, newTestLogger(), &stubLifecyclePool{}, store)

	err = svc.RunSignSession(context.Background(), SignInput{
		SessionID:         "sign-1",
		LocalPartyID:      "p1",
		OrgID:             "org",
		KeyID:             "key-1",
		Parties:           []string{"p1", "p2"},
		Digest:            []byte{1, 2, 3},
		Algorithm:         "ecdsa",
		Curve:             "secp256k1",
		DerivationContext: validServiceDerivationContext(),
		EmptyKeyErr:       errShareMissing,
		MetadataMismatch:  errShareMissing,
	})
	if !errors.Is(err, errShareMissing) {
		t.Fatalf("expected metadata mismatch, got %v", err)
	}
	if runner.lastSignJob.SessionID != "" {
		t.Fatalf("runner started unexpectedly: %+v", runner.lastSignJob)
	}
}

func TestRunSignSession_ReservedEdDSAReturnsUnsupportedBeforeRunnerStart(t *testing.T) {
	runner := &stubRunner{}
	svc := New(runner, newTestLogger(), &stubLifecyclePool{}, nil)

	err := svc.RunSignSession(context.Background(), SignInput{
		SessionID:    "sign-eddsa",
		LocalPartyID: "p1",
		OrgID:        "org",
		KeyID:        "key-eddsa",
		Parties:      []string{"p1", "p2"},
		Digest:       []byte{1, 2, 3},
		Algorithm:    "eddsa",
		Curve:        "ed25519",
		DerivationContext: corederivation.Context{
			ProfileID:   "profile-1",
			Algorithm:   "eddsa",
			Curve:       "ed25519",
			Scheme:      "slip10_ed25519",
			AccountPath: "m/44'/501'/0'",
			ChildPath:   "/0/0",
			FullPath:    "m/44'/501'/0'/0/0",
		},
	})
	if !errors.Is(err, corederivation.ErrDerivedSigningUnsupported) {
		t.Fatalf("expected ErrDerivedSigningUnsupported, got %v", err)
	}
	if runner.lastSignJob.SessionID != "" {
		t.Fatalf("runner started unexpectedly: %+v", runner.lastSignJob)
	}
}
```

- [x] **Step 2: Run tests to verify service sign flow is still root-signing shaped**

Run: `go test ./internal/tss/service ./tss -run 'TestRunSignSession_|TestSignSessionRequestValidateRequiresDerivationContext' -count=1`

Expected: FAIL because `SignInput` has no derivation context, runner stubs have no key-material export, and signing does not derive or adjust the share.

- [x] **Step 3: Extend service and runner interfaces**

Modify `internal/tss/service/types.go`.

```go
type Runner interface {
	RunDKG(ctx context.Context, job tssbnbrunner.DKGJob, transport coretransport.FrameTransport) error
	RunSign(ctx context.Context, job tssbnbrunner.SignJob, transport coretransport.FrameTransport) error
	ExportECDSASignature(key string) (common.SignatureData, error)
	ExportECDSAKeyShare(key string) (ecdsakeygen.LocalPartySaveData, error)
	ExportECDSAKeyMaterial(key string) (coreshares.ECDSAKeyMaterial, error)
	ImportECDSAKeyShare(key string, data ecdsakeygen.LocalPartySaveData)
	ImportECDSAKeyMaterial(key string, material coreshares.ECDSAKeyMaterial)
	DeleteECDSAKeyShare(key string)
	ECDSAAddress(key string) (string, error)
}

type SignInput struct {
	SessionID             string
	LocalPartyID          string
	OrgID                 string
	KeyID                 string
	Parties               []string
	Digest                []byte
	Algorithm             string
	Curve                 string
	Chain                 string
	DerivationContext     corederivation.Context
	DerivationContextHash string
	Transport             coretransport.FrameTransport
	EmptyKeyErr           error
	MetadataMismatch      error
}
```

Update `internal/tss/service/service_testkit_test.go` so `stubRunner` satisfies the expanded interface.

```go
type stubRunner struct {
	lastDKGJob          tssbnbrunner.DKGJob
	lastSignJob         tssbnbrunner.SignJob
	shareByKey          map[string]ecdsakeygen.LocalPartySaveData
	materialByKey       map[string]coreshares.ECDSAKeyMaterial
	exportedKeys        []string
	deletedKeys         []string
	events              []string
	requireShareForSign bool
	signatureExported   bool
}

func (r *stubRunner) ExportECDSAKeyMaterial(key string) (coreshares.ECDSAKeyMaterial, error) {
	r.events = append(r.events, "export-material:"+key)
	if material, ok := r.materialByKey[key]; ok {
		return material, nil
	}
	return coreshares.ECDSAKeyMaterial{}, errShareMissing
}

func (r *stubRunner) ImportECDSAKeyMaterial(key string, material coreshares.ECDSAKeyMaterial) {
	if r.materialByKey == nil {
		r.materialByKey = map[string]coreshares.ECDSAKeyMaterial{}
	}
	if r.shareByKey == nil {
		r.shareByKey = map[string]ecdsakeygen.LocalPartySaveData{}
	}
	r.materialByKey[key] = material
	r.shareByKey[key] = material.Share
}

type staticShareStore struct {
	stored *coreshares.StoredShare
	err    error
}

func (s staticShareStore) SaveShare(context.Context, string, []byte, coreshares.ShareMeta) error {
	return nil
}

func (s staticShareStore) LoadShare(context.Context, string) (*coreshares.StoredShare, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.stored, nil
}
```

Update production `internal/tssbnb/runner/bnb_runner.go` in the same task so `NewBnbService` still compiles after the service `Runner` interface expands.

```go
type BnbRunner struct {
	mu             sync.RWMutex
	ecdsaKeys      map[string]ecdsakeygen.LocalPartySaveData
	ecdsaMaterials map[string]coreshares.ECDSAKeyMaterial
	ecdsaSigs      map[string]*common.SignatureData
	logger         *slog.Logger
	debug          bool
	cfg            tssbnbutils.RunnerConfig
	metrics        bnbutils.Metrics
}

// In NewBnbRunner:
return &BnbRunner{
	ecdsaKeys:      map[string]ecdsakeygen.LocalPartySaveData{},
	ecdsaMaterials: map[string]coreshares.ECDSAKeyMaterial{},
	ecdsaSigs:      map[string]*common.SignatureData{},
	logger:         logger,
	debug:          bnbutils.IsTSSDebugEnabled(logger),
	cfg:            cfg.cfg,
	metrics:        cfg.metrics,
}

func (r *BnbRunner) ImportECDSAKeyMaterial(key string, material coreshares.ECDSAKeyMaterial) {
	if key == "" {
		return
	}
	r.mu.Lock()
	if r.ecdsaMaterials == nil {
		r.ecdsaMaterials = map[string]coreshares.ECDSAKeyMaterial{}
	}
	if r.ecdsaKeys == nil {
		r.ecdsaKeys = map[string]ecdsakeygen.LocalPartySaveData{}
	}
	r.ecdsaMaterials[key] = material
	r.ecdsaKeys[key] = material.Share
	r.mu.Unlock()
}

func (r *BnbRunner) ExportECDSAKeyMaterial(key string) (coreshares.ECDSAKeyMaterial, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if material, ok := r.ecdsaMaterials[key]; ok {
		return material, nil
	}
	return coreshares.ECDSAKeyMaterial{}, fmt.Errorf("%w: key=%s", ErrKeyShareNotFound, key)
}

func (r *BnbRunner) DeleteECDSAKeyShare(key string) {
	if key == "" {
		return
	}
	r.mu.Lock()
	delete(r.ecdsaKeys, key)
	delete(r.ecdsaMaterials, key)
	r.mu.Unlock()
}
```

- [x] **Step 4: Load full material and prepare adjusted share**

Modify `internal/tss/service/sign.go`.

```go
func prepareDerivedECDSASignJob(ctx context.Context, shareStore ShareStore, runner Runner, job tssbnbrunner.SignJob, in SignInput) (tssbnbrunner.SignJob, error) {
	if !tssutils.IsECDSA(job.Algorithm) {
		return job, corederivation.ErrDerivedSigningUnsupported
	}
	material, err := loadECDSAKeyMaterial(ctx, shareStore, runner, in)
	if err != nil {
		return job, err
	}
	if len(material.ChainCode) != 32 {
		return job, corederivation.ErrChainCodeMissing
	}
	if material.DerivationScheme != corederivation.DerivationSchemeBIP32Secp256k1 {
		return job, fmt.Errorf("%w: stored scheme=%s", corederivation.ErrUnsupportedDerivationScheme, material.DerivationScheme)
	}
	if material.PublicKeyFormat != corederivation.PublicKeyFormatUncompressedHex {
		return job, fmt.Errorf("%w: stored public key format=%s", corederivation.ErrInvalidDerivationContext, material.PublicKeyFormat)
	}
	prepared, err := corederivation.PrepareECDSASigningShare(material.Share, material.ChainCode, in.DerivationContext)
	if err != nil {
		return job, err
	}
	job.KeyShare = prepared.Share
	job.KeyDerivationDelta = prepared.KeyDerivationDelta
	job.DerivationContextHash = in.DerivationContextHash
	return job, nil
}
```

Update `Service.RunSignSession` so it calls `prepareDerivedECDSASignJob` before starting the runner and uses the prepared job.

```go
func (s *Service) RunSignSession(ctx context.Context, in SignInput) error {
	job := tssbnbrunner.SignJob{
		SessionID:             in.SessionID,
		LocalPartyID:          in.LocalPartyID,
		OrgID:                 in.OrgID,
		KeyID:                 in.KeyID,
		Parties:               in.Parties,
		Digest:                append([]byte(nil), in.Digest...),
		Algorithm:             in.Algorithm,
		Chain:                 in.Chain,
		DerivationContextHash: in.DerivationContextHash,
	}

	tsslogging.LogSessionStart(s.logger, "sign", in.SessionID, in.OrgID, in.KeyID, in.LocalPartyID)
	started := time.Now()
	var err error
	job, err = prepareDerivedECDSASignJob(ctx, s.shareStore, s.runner, job, in)
	if err == nil {
		err = s.runner.RunSign(ctx, job, in.Transport)
	}
	if err == nil {
		_, err = s.runner.ExportECDSASignature(in.SessionID)
	}
	tsslogging.LogSessionEnd(s.logger, "sign", in.SessionID, in.OrgID, in.KeyID, in.LocalPartyID, started, err)
	return err
}
```

Add `loadECDSAKeyMaterial` in the same file. Store-backed signing decodes the v2 key-material envelope after metadata validation. No-store signing must read full material from the runner, not a share-only fallback.

```go
func loadECDSAKeyMaterial(ctx context.Context, shareStore ShareStore, runner Runner, in SignInput) (coreshares.ECDSAKeyMaterial, error) {
	keyID, err := tssutils.NormalizeKeyID(in.KeyID, in.EmptyKeyErr)
	if err != nil {
		return coreshares.ECDSAKeyMaterial{}, err
	}
	if shareStore == nil {
		return runner.ExportECDSAKeyMaterial(keyID)
	}
	stored, err := shareStore.LoadShare(ctx, keyID)
	if err == nil {
		err = tssruntime.ValidateLoadedMeta(keyID, in.OrgID, in.Algorithm, in.Curve, stored.Meta, in.MetadataMismatch)
	}
	if err != nil {
		return coreshares.ECDSAKeyMaterial{}, err
	}
	defer tssutils.ZeroBytes(stored.Blob)
	return coreshares.UnmarshalKeyMaterial(stored.Blob)
}
```

Update `internal/tss/runtime/share_runtime.go` so store metadata validation includes curve when the store provides it.

```go
func ValidateLoadedMeta(keyID, orgID, algorithm, curve string, meta coreshares.ShareMeta, metadataMismatchErr error) error {
	if meta.KeyID != "" && meta.KeyID != keyID {
		return metadataMismatchErr
	}
	if orgID != "" && meta.OrgID != "" && meta.OrgID != orgID {
		return metadataMismatchErr
	}
	alg := strings.ToLower(strings.TrimSpace(algorithm))
	if alg == "" {
		alg = "ecdsa"
	}
	if meta.Algorithm != "" && !strings.EqualFold(meta.Algorithm, alg) {
		return metadataMismatchErr
	}
	expectedCurve := strings.ToLower(strings.TrimSpace(curve))
	if expectedCurve == "" && alg == "ecdsa" {
		expectedCurve = corederivation.CurveSecp256k1
	}
	if meta.Curve != "" && !strings.EqualFold(meta.Curve, expectedCurve) {
		return metadataMismatchErr
	}
	return nil
}
```

Add `corederivation` to the runtime imports for `CurveSecp256k1`.

Update `Service.RunDKGSession` now that `Runner` can carry full key material. After `buildECDSADKGOutput` succeeds and before store cleanup, import full material into the runner when `shareStore == nil` so no-store DKG followed by SIGN keeps the chain code.

```go
func importNoStoreECDSAKeyMaterial(runner Runner, shareStore ShareStore, keyID string, share ecdsakeygen.LocalPartySaveData, material normalizedDKGMaterial) {
	if shareStore != nil || len(material.ChainCode) != 32 {
		return
	}
	runner.ImportECDSAKeyMaterial(keyID, coreshares.ECDSAKeyMaterial{
		Share:            share,
		ChainCode:        append([]byte(nil), material.ChainCode...),
		PublicKeyFormat:  corederivation.PublicKeyFormatUncompressedHex,
		DerivationScheme: material.Scheme,
	})
}
```

In `Service.RunDKGSession`, insert the no-store import immediately after successful ECDSA output construction and before persistence cleanup.

```go
output, share, err := buildECDSADKGOutput(s.runner, in, keyID, material)
if err != nil {
	logEnd(err)
	return DKGOutput{}, err
}
importNoStoreECDSAKeyMaterial(s.runner, s.shareStore, keyID, share, material)
if err = persistECDSAShareAfterDKG(ctx, s.shareStore, s.runner, in.SessionID, job, keyID, share, material); err != nil {
	logEnd(err)
	return DKGOutput{}, err
}
```

This keeps no-store integration tests working without allowing share-only derived signing.

- [x] **Step 5: Normalize and hash at the public boundary**

Modify `tss/service.go` public `RunSignSession`.

```go
if err := req.Validate(); err != nil {
	return err
}
normalized, err := NormalizeDerivationContext(*req.DerivationContext)
if err != nil {
	return err
}
hash, err := DerivationContextHashV1(normalized)
if err != nil {
	return err
}
return s.impl.RunSignSession(ctx, tssservice.SignInput{
	SessionID:             req.Session.SessionID,
	LocalPartyID:          req.LocalPartyID,
	OrgID:                 req.Session.OrgID,
	KeyID:                 req.Session.KeyID,
	Parties:               req.Session.Parties,
	Digest:                req.Digest,
	Algorithm:             req.Session.Algorithm,
	Curve:                 req.Session.Curve,
	Chain:                 req.Session.Chain,
	DerivationContext:     toCoreDerivationContext(normalized),
	DerivationContextHash: hash,
	Transport:             req.Transport,
	EmptyKeyErr:           ErrShareNotFound,
	MetadataMismatch:      ErrMetadataMismatch,
})
```

- [x] **Step 6: Run service derived signing tests**

Run: `go test ./internal/tss/service ./tss -run 'TestRunSignSession_|TestSignSessionRequestValidate|TestDerivationContextHashV1' -count=1`

Expected: PASS.

- [x] **Step 7: Commit service signing boundary**

```bash
git add internal/tss/service/types.go internal/tss/service/sign.go internal/tss/service/service.go internal/tss/service/sign_flow_test.go internal/tss/service/service_testkit_test.go internal/tss/runtime/share_runtime.go internal/tssbnb/runner/bnb_runner.go tss/service.go tss/service_test.go
git commit -m "feat: require derived signing material"
```

### Task 8: Force KDD Signing Path in Runner and Flow

**Files:**
- Modify: `internal/tssbnb/runner/types.go`
- Modify: `internal/tssbnb/runner/bnb_runner.go`
- Modify: `internal/tssbnb/runner/bnb_runner_test.go`
- Modify: `internal/tssbnb/flow/sign.go`
- Create: `internal/tssbnb/flow/sign_test.go`
- Test: `internal/tssbnb/flow`
- Test: `internal/tssbnb/runner`

- [x] **Step 1: Write failing KDD guard tests**

Create `internal/tssbnb/flow/sign_test.go`.

```go
package flow

import (
	"errors"
	"math/big"
	"testing"

	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

func TestBuildSignRejectsNilKeyDerivationDelta(t *testing.T) {
	outCh := make(chan tsslib.Message, 1)
	_, err := BuildSign(SignBuildInput{
		Digest:   []byte{1, 2, 3},
		Params:   &tsslib.Parameters{},
		KeyShare: ecdsakeygen.LocalPartySaveData{},
		OutCh:    outCh,
	})
	if !errors.Is(err, ErrKeyDerivationDeltaRequired) {
		t.Fatalf("expected ErrKeyDerivationDeltaRequired, got %v", err)
	}
}

func TestSignBuildInputCarriesKeyDerivationDelta(t *testing.T) {
	in := SignBuildInput{KeyDerivationDelta: big.NewInt(42)}
	if in.KeyDerivationDelta.Sign() != 1 {
		t.Fatalf("unexpected delta: %v", in.KeyDerivationDelta)
	}
}
```

Add runner guard tests in `internal/tssbnb/runner/bnb_runner_test.go`.

```go
func TestRunSignDoesNotFallbackFromKeyIDToSessionID(t *testing.T) {
	runner := NewBnbRunner(slog.Default())
	runner.ImportECDSAKeyShare("session-1", ecdsakeygen.LocalPartySaveData{})

	err := runner.RunSign(context.Background(), SignJob{
		SessionID:             "session-1",
		KeyID:                 "key-1",
		Parties:               []string{"p1", "p2"},
		Digest:                []byte{1, 2, 3},
		Algorithm:             "ecdsa",
		KeyDerivationDelta:    big.NewInt(1),
		DerivationContextHash: strings.Repeat("a", 64),
	}, nil)
	if !errors.Is(err, ErrKeyShareNotFound) {
		t.Fatalf("expected ErrKeyShareNotFound, got %v", err)
	}
}

func TestRunSignRejectsMissingAdjustedKeyShare(t *testing.T) {
	runner := NewBnbRunner(slog.Default())
	runner.ImportECDSAKeyShare("key-1", ecdsakeygen.LocalPartySaveData{})

	err := runner.RunSign(context.Background(), SignJob{
		SessionID:             "sign-1",
		KeyID:                 "key-1",
		Parties:               []string{"p1", "p2"},
		Digest:                []byte{1, 2, 3},
		Algorithm:             "ecdsa",
		KeyDerivationDelta:    big.NewInt(1),
		DerivationContextHash: strings.Repeat("a", 64),
	}, nil)
	if !errors.Is(err, ErrKeyShareNotFound) {
		t.Fatalf("expected ErrKeyShareNotFound, got %v", err)
	}
}
```

- [x] **Step 2: Run tests to verify current flow still allows nil KDD and fallback**

Run: `go test ./internal/tssbnb/flow ./internal/tssbnb/runner -run 'TestBuildSignRejectsNilKeyDerivationDelta|TestRunSignDoesNotFallbackFromKeyIDToSessionID|TestRunSignRejectsMissingAdjustedKeyShare' -count=1`

Expected: FAIL because `BuildSign` has no error return and `BnbRunner.RunSign` can still read an unadjusted in-memory share.

- [x] **Step 3: Require KDD in flow**

Modify `internal/tssbnb/flow/sign.go`.

```go
var ErrKeyDerivationDeltaRequired = errors.New("key derivation delta is required")

type SignBuildInput struct {
	Digest             []byte
	Params             *tsslib.Parameters
	KeyShare           ecdsakeygen.LocalPartySaveData
	KeyDerivationDelta *big.Int
	OutCh              chan<- tsslib.Message
}

func BuildSign(in SignBuildInput) (SignBuildOutput, error) {
	if in.KeyDerivationDelta == nil {
		return SignBuildOutput{}, ErrKeyDerivationDeltaRequired
	}
	rawEndCh := make(chan *common.SignatureData, 1)
	tssEndCh := make(chan common.SignatureData, 1)
	msg := new(big.Int).SetBytes(in.Digest)
	party := ecdsasigning.NewLocalPartyWithKDD(msg, in.Params, in.KeyShare, in.KeyDerivationDelta, in.OutCh, tssEndCh)
	go func() {
		defer close(rawEndCh)
		sig := <-tssEndCh
		rawEndCh <- cloneSignatureData(&sig)
	}()
	return SignBuildOutput{Party: party, End: rawEndCh}, nil
}
```

Update `SignRunJob` and `newSignExecution` in `internal/tssbnb/flow/sign.go` so the required KDD and context hash actually reach `BuildSign` and execution params.

```go
type SignRunJob struct {
	SessionID             string
	LocalPartyID          string
	KeyID                 string
	Parties               []string
	Digest                []byte
	Algorithm             string
	KeyDerivationDelta    *big.Int
	DerivationContextHash string
}

func newSignExecution(job SignRunJob, keyShare ecdsakeygen.LocalPartySaveData, logger *slog.Logger, debug bool, correlationID string, cfg tssbnbutils.RunnerConfig, metrics SignRunMetrics) (*execution.ProtocolExecution, error) {
	params, partyIDs, _, err := tssbnbutils.BuildParams(job.Parties, job.LocalPartyID, len(job.Parties), "", "ecdsa")
	if err != nil {
		return nil, err
	}

	outCh := make(chan tsslib.Message, len(job.Parties)*8)
	built, err := BuildSign(SignBuildInput{
		Digest:             job.Digest,
		Params:             params,
		KeyShare:           keyShare,
		KeyDerivationDelta: job.KeyDerivationDelta,
		OutCh:              outCh,
	})
	if err != nil {
		return nil, err
	}
	return execution.New(execution.Params{
		SessionID:             job.SessionID,
		LocalPartyID:          job.LocalPartyID,
		CorrelationID:         correlationID,
		Stage:                 "sign",
		Algorithm:             "ecdsa",
		DerivationContextHash: job.DerivationContextHash,
		Party:                 built.Party,
		PartyIDs:              partyIDs,
		OutCh:                 outCh,
		Logger:                logger,
		Debug:                 debug,
		Config:                cfg,
		Metrics:               metrics,
		SignECDSAEndCh:        built.End,
	}), nil
}
```

- [x] **Step 4: Remove runner fallback and pass adjusted share**

Modify `internal/tssbnb/runner/types.go`.

```go
type SignJob struct {
	SessionID             string
	LocalPartyID          string
	OrgID                 string
	KeyID                 string
	Parties               []string
	Digest                []byte
	Algorithm             string
	Chain                 string
	KeyShare              ecdsakeygen.LocalPartySaveData
	KeyDerivationDelta    *big.Int
	DerivationContextHash string
}
```

Modify `BnbRunner.RunSign` so it requires the already adjusted `job.KeyShare` supplied by the service. Do not read signing shares from the in-memory map during SIGN.

```go
keyShare := job.KeyShare
if isZeroECDSAShare(keyShare) {
	return fmt.Errorf("%w: adjusted key share required", ErrKeyShareNotFound)
}

err := flow.RunSign(ctx, flow.SignRunInput{
	Job: flow.SignRunJob{
		SessionID:             job.SessionID,
		LocalPartyID:          job.LocalPartyID,
		KeyID:                 job.KeyID,
		Parties:               job.Parties,
		Digest:                job.Digest,
		Algorithm:             job.Algorithm,
		KeyDerivationDelta:    job.KeyDerivationDelta,
		DerivationContextHash: job.DerivationContextHash,
	},
	KeyShare:  keyShare,
	Transport: transport,
	Logger:    r.logger,
	Debug:     r.debug,
	Config:    r.cfg,
	Metrics:   r.metrics,
	OnSignature: func(sigData *common.SignatureData) {
		r.setECDSASignature(job.SessionID, sigData)
		if job.KeyID != "" {
			r.setECDSASignature(job.KeyID, sigData)
		}
	},
})
```

Do not query `job.SessionID` or `job.KeyID` for signing shares in `RunSign`; the service must derive and pass the adjusted runtime share.

Add this helper in `internal/tssbnb/runner/bnb_runner.go` so an explicitly supplied adjusted share is used even when the runner has no in-memory share entry.

```go
func isZeroECDSAShare(share ecdsakeygen.LocalPartySaveData) bool {
	return share.ECDSAPub == nil && len(share.BigXj) == 0 && len(share.Ks) == 0
}
```

- [x] **Step 5: Add in-memory key material helpers**

Modify `internal/tssbnb/runner/bnb_runner.go`.

```go
type BnbRunner struct {
	mu             sync.RWMutex
	ecdsaKeys      map[string]ecdsakeygen.LocalPartySaveData
	ecdsaMaterials map[string]coreshares.ECDSAKeyMaterial
	ecdsaSigs      map[string]*common.SignatureData
	logger         *slog.Logger
	debug          bool
	cfg            tssbnbutils.RunnerConfig
	metrics        bnbutils.Metrics
}

// In NewBnbRunner:
return &BnbRunner{
	ecdsaKeys:      map[string]ecdsakeygen.LocalPartySaveData{},
	ecdsaMaterials: map[string]coreshares.ECDSAKeyMaterial{},
	ecdsaSigs:      map[string]*common.SignatureData{},
	logger:         logger,
	debug:          bnbutils.IsTSSDebugEnabled(logger),
	cfg:            cfg.cfg,
	metrics:        cfg.metrics,
}

func (r *BnbRunner) ImportECDSAKeyMaterial(key string, material coreshares.ECDSAKeyMaterial) {
	if key == "" {
		return
	}
	r.mu.Lock()
	if r.ecdsaMaterials == nil {
		r.ecdsaMaterials = map[string]coreshares.ECDSAKeyMaterial{}
	}
	if r.ecdsaKeys == nil {
		r.ecdsaKeys = map[string]ecdsakeygen.LocalPartySaveData{}
	}
	r.ecdsaMaterials[key] = material
	r.ecdsaKeys[key] = material.Share
	r.mu.Unlock()
}

func (r *BnbRunner) ExportECDSAKeyMaterial(key string) (coreshares.ECDSAKeyMaterial, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	material, ok := r.ecdsaMaterials[key]
	if ok {
		return material, nil
	}
	return coreshares.ECDSAKeyMaterial{}, fmt.Errorf("%w: key=%s", ErrKeyShareNotFound, key)
}
```

- [x] **Step 6: Run flow and runner tests**

Run: `go test ./internal/tssbnb/flow ./internal/tssbnb/runner -run 'TestBuildSign|TestSignBuildInput|TestRunSign|TestNewBnbRunner' -count=1`

Expected: PASS.

- [x] **Step 7: Commit KDD-only signing path**

```bash
git add internal/tssbnb/runner/types.go internal/tssbnb/runner/bnb_runner.go internal/tssbnb/runner/bnb_runner_test.go internal/tssbnb/flow/sign.go internal/tssbnb/flow/sign_test.go
git commit -m "feat: force kdd signing path"
```

### Task 9: Bind Derivation Context Hash to SIGN Frames

**Files:**
- Modify: `protocol/frame.go`
- Modify: `protocol/frame_test.go`
- Modify: `internal/tssbnb/execution/execution.go`
- Modify: `internal/tssbnb/execution/execution_test.go`
- Modify: `internal/tssbnb/flow/sign.go`
- Test: `protocol`
- Test: `internal/tssbnb/execution`

- [x] **Step 1: Write failing frame hash tests**

Update `protocol/frame_test.go`.

```go
func TestFrameCarriesDerivationContextHash(t *testing.T) {
	frame := protocol.Frame{DerivationContextHash: strings.Repeat("a", 64)}
	if frame.DerivationContextHash != strings.Repeat("a", 64) {
		t.Fatalf("DerivationContextHash = %q", frame.DerivationContextHash)
	}
}
```

Update `internal/tssbnb/execution/execution_test.go`.

```go
func TestValidateInboundSignFrameRequiresMatchingDerivationContextHash(t *testing.T) {
	exec := New(Params{
		SessionID:             "s1",
		Stage:                 "sign",
		DerivationContextHash: strings.Repeat("a", 64),
		Config:                tssbnbutils.DefaultRunnerConfig(),
		Metrics:               testMetrics{},
	})

	err := exec.validateInbound(protocol.Frame{
		SessionID:             "s1",
		Stage:                 "sign",
		FromParty:             "p1",
		Seq:                   1,
		Payload:               []byte("abc"),
		PayloadHash:           shortHash([]byte("abc")),
		DerivationContextHash: strings.Repeat("b", 64),
	})
	if !errors.Is(err, ErrDerivationContextMismatch) {
		t.Fatalf("expected ErrDerivationContextMismatch, got %v", err)
	}
}
```

Add an outbound base-frame test in `internal/tssbnb/execution/execution_test.go`.

```go
func TestNewOutboundBaseFrameStampsDerivationContextHash(t *testing.T) {
	exec := New(Params{
		SessionID:             "s1",
		Stage:                 "sign",
		Algorithm:             "ecdsa",
		CorrelationID:         "corr-1",
		DerivationContextHash: strings.Repeat("a", 64),
		Config:                tssbnbutils.DefaultRunnerConfig(),
		Metrics:               testMetrics{},
	})

	frame := exec.newOutboundBaseFrame(outboundFrameInput{
		messageType: "SignRound1Message",
		roundHint:  1,
		broadcast:  true,
		fromParty:  "p1",
		payload:    []byte("payload"),
	})
	if frame.DerivationContextHash != strings.Repeat("a", 64) {
		t.Fatalf("DerivationContextHash = %q", frame.DerivationContextHash)
	}
	if frame.SessionID != "s1" || frame.Stage != "sign" || frame.Protocol != "ecdsa" {
		t.Fatalf("unexpected base frame: %+v", frame)
	}
}
```

- [x] **Step 2: Run tests to verify frame binding is missing**

Run: `go test ./protocol ./internal/tssbnb/execution -run 'TestFrameCarriesDerivationContextHash|TestValidateInboundSignFrameRequiresMatchingDerivationContextHash' -count=1`

Expected: FAIL because `protocol.Frame` and execution params do not carry the field.

- [x] **Step 3: Add frame field and execution params**

Modify `protocol/frame.go`.

```go
type Frame struct {
	SessionID             string
	Stage                 string
	OrgID                 string
	MessageID             string
	Seq                   uint64
	Round                 uint32
	RoundHint             uint32
	Broadcast             bool
	Protocol              string
	MessageType           string
	PayloadHash           string
	DerivationContextHash string
	FromParty             string
	ToParty               string
	Payload               []byte
	CorrelationID         string
	SentAt                time.Time
}
```

Modify `internal/tssbnb/execution/execution.go` `Params` and `ProtocolExecution`.

```go
type Params struct {
	SessionID             string
	LocalPartyID          string
	CorrelationID         string
	Stage                 string
	Algorithm             string
	DerivationContextHash string
	Party                 tsslib.Party
	PartyIDs              map[string]*tsslib.PartyID
	OutCh                 <-chan tsslib.Message
	Logger                *slog.Logger
	Debug                 bool
	Config                tssbnbutils.RunnerConfig
	Metrics               bnbutils.Metrics
	DKGECDSAEndCh         <-chan ecdsakeygen.LocalPartySaveData
	SignECDSAEndCh        <-chan *common.SignatureData
	DoneCh                <-chan struct{}
}
```

In the same file, add the runtime field and constructor assignment. Without this, inbound validation and outbound stamping will read an empty expected hash.

```diff
 type ProtocolExecution struct {
     sessionID     string
     localPartyID  string
     correlationID string
     stage         string
     algorithm     string
+    derivationContextHash string
     party         tsslib.Party
     partyIDs      map[string]*tsslib.PartyID
     outCh         <-chan tsslib.Message
@@
 func New(p Params) *ProtocolExecution {
     return &ProtocolExecution{
         sessionID:      p.SessionID,
         localPartyID:   p.LocalPartyID,
         correlationID:  p.CorrelationID,
         stage:          p.Stage,
         algorithm:      p.Algorithm,
+        derivationContextHash: p.DerivationContextHash,
         party:          p.Party,
         partyIDs:       p.PartyIDs,
         outCh:          p.OutCh,
```

- [x] **Step 4: Validate inbound and stamp outbound SIGN frames**

Add internal error alias in `execution.go`.

```go
var ErrDerivationContextMismatch = corederivation.ErrDerivationContextMismatch
```

Modify inbound validation.

```go
func (e *ProtocolExecution) validateDerivationContextHash(frame protocol.Frame) error {
	if e.stage != "sign" {
		return nil
	}
	if e.derivationContextHash == "" || frame.DerivationContextHash != e.derivationContextHash {
		return fmt.Errorf("%w: expected=%s got=%s", ErrDerivationContextMismatch, e.derivationContextHash, frame.DerivationContextHash)
	}
	return nil
}
```

Call this after session-id validation and before `parseInbound`.

Add a small outbound base-frame helper and use it from `forwardOutgoing`.

```go
type outboundFrameInput struct {
	messageType string
	roundHint   uint32
	broadcast   bool
	fromParty   string
	payload     []byte
}

func (e *ProtocolExecution) newOutboundBaseFrame(in outboundFrameInput) protocol.Frame {
	return protocol.Frame{
		SessionID:             e.sessionID,
		Stage:                 e.stage,
		MessageID:             idgen.New("msg"),
		Seq:                   atomic.AddUint64(&e.seq, 1),
		Round:                 0,
		RoundHint:             in.roundHint,
		Broadcast:             in.broadcast,
		Protocol:              e.algorithm,
		MessageType:           in.messageType,
		FromParty:             in.fromParty,
		Payload:               in.payload,
		PayloadHash:           shortHash(in.payload),
		DerivationContextHash: e.derivationContextHash,
		CorrelationID:         e.correlationID,
		SentAt:                time.Now(),
	}
}
```

In `forwardOutgoing`, replace the inline `protocol.Frame{...}` construction with:

```go
base := e.newOutboundBaseFrame(outboundFrameInput{
	messageType: msgType,
	roundHint:   roundHint,
	broadcast:   routing.IsBroadcast,
	fromParty:   routing.From.Id,
	payload:     payload,
})
```

- [x] **Step 5: Pass hash from sign flow into execution**

Modify `internal/tssbnb/flow/sign.go` `SignRunJob` and `newSignExecution` to carry `DerivationContextHash` into `execution.Params`.

```go
DerivationContextHash: job.DerivationContextHash,
```

- [x] **Step 6: Run frame hash tests**

Run: `go test ./protocol ./internal/tssbnb/execution ./internal/tssbnb/flow -run 'TestFrameCarriesDerivationContextHash|TestValidateInboundSignFrameRequiresMatchingDerivationContextHash|TestBuildSign' -count=1`

Expected: PASS.

- [x] **Step 7: Commit frame hash binding**

```bash
git add protocol/frame.go protocol/frame_test.go internal/tssbnb/execution/execution.go internal/tssbnb/execution/execution_test.go internal/tssbnb/flow/sign.go
git commit -m "feat: bind derivation context hash to sign frames"
```

### Task 10: Update End-to-End Tests and Documentation

**Files:**
- Modify: `internal/tss/service/dkg_flow_test.go`
- Modify: `internal/tss/service/sign_flow_test.go`
- Modify: `tss/service_test.go`
- Modify: `README.md`
- Test: all Go packages

- [x] **Step 1: Update existing ECDSA tests to use derivation material and context**

Change all ECDSA DKG service tests that call `RunDKGSession` to include the same deterministic chain code.

```go
DerivationMaterial: DKGDerivationMaterial{
	ChainCode:        strings.Repeat("11", 32),
	DerivationScheme: corederivation.DerivationSchemeBIP32Secp256k1,
},
```

Change all successful ECDSA signing tests to include a normalized context and the matching hash.

```go
ctx := validServiceDerivationContext()
hash, err := corederivation.HashV1(ctx)
if err != nil {
	t.Fatalf("HashV1 returned error: %v", err)
}
in.DerivationContext = ctx
in.DerivationContextHash = hash
```

Update the no-store DKG-then-SIGN regression to assert that DKG imported full key material into the runner, not only a share.

```go
material, ok := runner.materialByKey["key-1"]
if !ok {
	t.Fatal("expected no-store DKG to keep full key material in runner")
}
if len(material.ChainCode) != 32 {
	t.Fatalf("expected stored chain code, got %d bytes", len(material.ChainCode))
}
```

- [x] **Step 2: Add negative public SIGN regression tests**

Add these tests to `tss/service_test.go`.

```go
func TestRunSignSessionRejectsNilDerivationContextBeforeInternalService(t *testing.T) {
	svc := NewBnbService(slog.Default())
	err := svc.RunSignSession(context.Background(), SignSessionRequest{
		Session: SessionDescriptor{
			SessionID: "sign-1",
			OrgID:     "org-1",
			KeyID:     "key-1",
			Parties:   []string{"p1", "p2", "p3"},
			Threshold: 2,
			Algorithm: AlgorithmECDSA,
			Curve:     CurveSecp256k1,
		},
		LocalPartyID: "p1",
		Digest:       []byte{1, 2, 3},
		Transport:    noopTransport{},
	})
	if !errors.Is(err, ErrDerivationContextRequired) {
		t.Fatalf("expected ErrDerivationContextRequired, got %v", err)
	}
}

func TestRunSignSessionRejectsInvalidDerivationContextBeforeInternalService(t *testing.T) {
	svc := NewBnbService(slog.Default())
	ctx := DerivationContext{
		ProfileID:   "profile-1",
		Algorithm:   AlgorithmECDSA,
		Curve:       CurveSecp256k1,
		Scheme:      DerivationSchemeBIP32Secp256k1,
		AccountPath: "m/44'/60'/0'",
		ChildPath:   "/0/015",
		FullPath:    "m/44'/60'/0'/0/015",
	}
	err := svc.RunSignSession(context.Background(), SignSessionRequest{
		Session: SessionDescriptor{
			SessionID: "sign-1",
			OrgID:     "org-1",
			KeyID:     "key-1",
			Parties:   []string{"p1", "p2", "p3"},
			Threshold: 2,
			Algorithm: AlgorithmECDSA,
			Curve:     CurveSecp256k1,
		},
		LocalPartyID:      "p1",
		Digest:            []byte{1, 2, 3},
		DerivationContext: &ctx,
		Transport:         noopTransport{},
	})
	if !errors.Is(err, ErrDerivationPathInvalid) {
		t.Fatalf("expected ErrDerivationPathInvalid, got %v", err)
	}
}
```

- [x] **Step 3: Update README public behavior**

Add this section to `README.md`.

```markdown
## Derived Signing

Public SIGN requests require `tss.DerivationContext`.
ECDSA secp256k1 signing signs the requested non-hardened BIP32 child key.
Root or account-key signing is intentionally unsupported through the public SIGN API.

ECDSA DKG creates account-level key material and requires upstream-supplied `tss.DKGDerivationMaterial`.
The upstream orchestration layer must generate one 32-byte chain code per ECDSA DKG intent and pass the byte-identical value to every participant.
Core validates and persists that chain code after successful DKG; SIGN requests never carry chain code.

Core returns local DKG output.
Key activation is an upstream orchestration responsibility and must compare matching outputs from the complete required participant set before activating a key.

Core normalizes and hashes the signing derivation context with `tss.DerivationContextHashV1`.
SIGN frames carry that hash so peers fail closed when they are using different profile/path commitments.

Core does not store derivation profiles, prove profile or account-path ownership, compute chain-specific child addresses, or validate `ExpectedAddress`.
EdDSA derivation values are reserved in the public contract, but derived EdDSA signing returns `tss.ErrDerivedSigningUnsupported` in this scope.
```

- [x] **Step 4: Run targeted package tests**

Run: `go test ./tss ./internal/shares ./internal/tss/derivation ./internal/tss/runtime ./internal/tss/service ./internal/tssbnb/flow ./internal/tssbnb/runner ./internal/tssbnb/execution ./protocol -count=1`

Expected: PASS.

- [x] **Step 5: Run full test suite**

Run: `go test ./... -count=1`

Expected: PASS.

- [x] **Step 6: Commit tests and docs**

```bash
git add internal/tss/service/dkg_flow_test.go internal/tss/service/sign_flow_test.go tss/service_test.go README.md
git commit -m "test: cover derived signing contract"
```

---

## Self-Review Checklist

- Public SIGN hard mode is covered by Task 1, Task 2, Task 3, Task 7, and Task 10.
- Public `DerivationContext`, `NormalizeDerivationContext`, and `DerivationContextHashV1` are covered by Task 1 through Task 3.
- Canonical ECDSA public key format is covered by Task 2 and used by Task 6.
- Upstream-supplied DKG chain code is covered by Task 5.
- DKG output chain code, public key format, and derivation scheme are covered by Task 5.
- ECDSA DKG output and persistence use the DKG intent `KeyID`, not `SessionID`, in Task 5.
- Public and internal DKG material validation are both wired before protocol start in Task 5.
- No-store DKG keeps full `ECDSAKeyMaterial` in the runner before derived signing in Task 7 and Task 10.
- Canonical hash payloads use a manual ordered encoder and test raw UTF-8 for `<`, `>`, `&`, U+2028, U+2029, and non-ASCII bytes in Task 3.
- Concrete helper implementations for path normalization, context conversions, share cloning, material loading, and zero-share detection are included in Task 2, Task 6, Task 7, and Task 8.
- Store-backed signing validates loaded metadata key id, org id, algorithm, and curve in Task 7.
- Service derived-signing tests use secp256k1 shares with `BigXj`, not P-256 shares, in Task 7.
- DKG output public keys are encoded through secp256k1 validation, not reused from generic runtime output, in Task 5.
- V2 full key material persistence and v1 rejection are covered by Task 4.
- BIP32 child derivation, adjusted share copy, and KDD delta are covered by Task 6.
- Service-level pre-protocol failure for missing chain code, mismatched derived public key, and unsupported EdDSA is covered by Task 7.
- `NewLocalPartyWithKDD` as the only signing construction path is covered by Task 8.
- Removal of `KeyID` to `SessionID` signing fallback is covered by Task 8.
- `DerivationContextHash` is stored on `ProtocolExecution` and used on outbound and inbound SIGN frames in Task 9.
- README updates and full verification are covered by Task 10.

## Execution Status

Implemented on branch `feat-hd-wallets`. Checklist entries are marked complete to keep the plan aligned with the current code state.

Post-implementation cleanup removed public share-only APIs and dead internal share-only persistence/sign-loading helpers. Historical snippets above that mention `MarshalShare`, `UnmarshalShare`, `ImportECDSAKeyShare`, or service-level ECDSA share import/export are superseded by the current key-material-only implementation. Internal DKG-only share access is intentionally named `ExportTemporaryECDSADKGShare`, `DeleteTemporaryECDSADKGShare`, and `temporaryECDSADKGShares`.
