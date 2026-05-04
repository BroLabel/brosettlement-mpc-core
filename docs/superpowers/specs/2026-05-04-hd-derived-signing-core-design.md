# HD Derived Signing Core Design

## Goal

`brosettlement-mpc-core` must support profile-derived HD signing as the only public signing mode.
ECDSA secp256k1 signing must derive and sign the requested non-hardened BIP32 child key in this scope.
EdDSA Ed25519 derivation is reserved in the public contract, but runtime support remains explicitly unsupported.

The central invariant is:

```text
All public SIGN requests require DerivationContext.
Root/account-key signing is intentionally unsupported.
No fallback to root signing is allowed.
All derivation failures happen before protocol start.
```

DKG still creates account-level key material. That material is used only as the parent for child derivation:

```text
account public key + account chain code -> child public key -> child signing
```

## Current Context

The current public `tss` package exposes `SessionDescriptor`, `DKGSessionRequest`, `SignSessionRequest`, and `DKGOutput`.
`SignSessionRequest` currently carries `key_id`, `algorithm`, `digest`, `parties`, and `transport`, but no derivation context.
The internal service loads an ECDSA share by `key_id` and passes `LocalPartySaveData` directly into `tss-lib` signing.

`tss-lib v1.5.0` already has HD support for ECDSA signing:

- `crypto/ckd` derives non-hardened BIP32 child public keys and returns the accumulated `IL` delta.
- `ecdsa/signing.UpdatePublicKeyAndAdjustBigXj` demonstrates the required share adjustment.
- `ecdsa/signing.NewLocalPartyWithKDD` accepts the key derivation delta.

The correct ECDSA HD flow must do both operations:

1. Derive `IL` / `keyDerivationDelta`.
2. Sign with a child-adjusted copy of `LocalPartySaveData` and pass the same delta to `NewLocalPartyWithKDD`.

Passing only the delta is not sufficient.

## Public Contract

Add a universal public derivation context to package `tss`.
The type is intentionally not ECDSA-specific and does not contain chain code.
Chain code is key-bound DKG metadata, not request input.

```go
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
```

Extend `SignSessionRequest`:

```go
type SignSessionRequest struct {
    Session           SessionDescriptor
    LocalPartyID      string
    Digest            []byte
    DerivationContext *DerivationContext
    Transport         Transport
}
```

`SignSessionRequest.Validate()` must not mutate the request.
Normalization is a separate boundary:

```go
func NormalizeDerivationContext(in DerivationContext) (DerivationContext, error)
```

The public service copies and normalizes the derivation context before passing it into internal runtime objects.
The normalized runtime copy uses canonical paths, lower-case algorithm/curve values, and canonical scheme names.

Add public constants:

```go
const (
    AlgorithmECDSA = "ecdsa"
    AlgorithmEdDSA = "eddsa"

    CurveSecp256k1 = "secp256k1"
    CurveEd25519   = "ed25519"

    DerivationSchemeBIP32Secp256k1 = "bip32_secp256k1"
    DerivationSchemeBIP32Public    = "bip32_public" // deprecated alias, normalized at boundary
    DerivationSchemeSLIP10Ed25519  = "slip10_ed25519"
)
```

The only canonical ECDSA runtime scheme is `bip32_secp256k1`.
`bip32_public` may be accepted as a deprecated alias by `NormalizeDerivationContext`, but must be normalized before runtime.

Add typed public errors:

```go
var (
    ErrDerivationContextRequired = errors.New("derivation context required")
    ErrInvalidDerivationContext  = errors.New("invalid derivation context")
    ErrUnsupportedDerivationScheme = errors.New("unsupported derivation scheme")
    ErrDerivationPathInvalid     = errors.New("derivation path invalid")
    ErrDerivationContextMismatch = errors.New("derivation context mismatch")
    ErrChainCodeMissing          = errors.New("chain code missing")
    ErrDerivedSigningUnsupported = errors.New("derived signing unsupported")
    ErrUnsupportedAlgorithmCurve = errors.New("unsupported algorithm curve")
)
```

All wrappers must preserve `errors.Is` behavior for downstream mapping in `mpc-signer` and `mpc-co-signer`.

## Signing Validation Boundary

`SignSessionRequest.Validate()` must enforce hard mode:

1. Existing base validation still applies: valid session descriptor, local party id, non-empty key id, non-empty digest, and transport.
2. `DerivationContext` is required. A nil context returns `ErrDerivationContextRequired`.
3. The context must be structurally valid before runtime starts.

For ECDSA secp256k1:

- `ProfileID` must be non-empty.
- `Algorithm` and `Curve` in context must match the session algorithm and curve after normalization.
- `Chain`, when set in both context and session, must match.
- `Scheme` must be `bip32_secp256k1` or deprecated alias `bip32_public`.
- Runtime receives only canonical `bip32_secp256k1`.
- `ChildPath` must be canonical relative `/change/index`.
- `ChildPath` must not contain hardened markers: `'`, `h`, `H`, or index values `>= 0x80000000`.
- `ChildPath` must not be absolute, such as `m/...`.
- `FullPath`, if supplied, must equal the canonical join of `AccountPath` and `ChildPath` after parsing and normalization.
- `DerivedPublicKey`, if supplied, must be a structurally valid public key encoding and later match the derived child public key.
- `ExpectedAddress` is carried as a commitment/audit field only. Core does not compute or verify chain-specific addresses.

For EdDSA:

- recognized reserved algorithm/curve/scheme values can pass structural validation;
- runtime always returns `ErrDerivedSigningUnsupported` in this scope;
- unknown schemes return `ErrUnsupportedDerivationScheme`.

If derivation cannot be applied, signing must fail before protocol start.

## DKG Output

Extend `DKGOutput`:

```go
type DKGOutput struct {
    KeyID            string
    PublicKey        string
    Address          string
    ChainCode        string
    PublicKeyFormat  string
    DerivationScheme string
}
```

For ECDSA secp256k1:

- `PublicKey` is the account-level uncompressed public key hex.
- `Address` remains for compatibility with the current output contract, but address encoding is not a core responsibility for child keys.
- `ChainCode` is required and must be 32-byte hex.
- `PublicKeyFormat` should be `uncompressed_hex`.
- `DerivationScheme` should be `bip32_secp256k1`.

The chain code is generated by core after successful ECDSA DKG and before persistence.
It is cryptographically random 32-byte key metadata created in the same lifecycle as the MPC share.
It is not extracted from `tss-lib LocalPartySaveData`, because that structure does not contain BIP32 chain code.
It is never accepted from a signing request.

For EdDSA DKG, the output remains key-only in this scope:

```go
DKGOutput{KeyID: keyID}
```

No EdDSA chain code is generated until a separate EdDSA derivation implementation exists.

## Share And Store Lifecycle

Core must persist enough key-bound metadata to derive child keys later.
Introduce an internal key material type:

```go
type ECDSAKeyMaterial struct {
    Share            ecdsakeygen.LocalPartySaveData
    ChainCode        []byte
    PublicKeyFormat  string
    DerivationScheme string
}
```

The encrypted share blob should store share material and chain code together.
`ShareMeta` may include diagnostics such as `ChainCodePresent`, `PublicKeyFormat`, and `DerivationScheme`, but must not duplicate the chain code if metadata can be logged or stored separately.

Update the share envelope version:

```go
const codecVersion uint32 = 2

type shareEnvelope struct {
    Version uint32
    Share   ecdsakeygen.LocalPartySaveData
    Meta    KeyMaterialMeta
}

type KeyMaterialMeta struct {
    ChainCode        []byte
    PublicKeyFormat  string
    DerivationScheme string
}
```

Keep legacy decode hygiene:

- v1 blobs may decode into share-only key material with empty metadata;
- v1 blobs are not valid signing targets;
- signing with derivation context and missing chain code returns `ErrChainCodeMissing`;
- old share compatibility exists only for diagnostics/import handling, not for successful signing.

Add new codec APIs while retaining wrappers where useful:

```go
func MarshalKeyMaterial(material ECDSAKeyMaterial) ([]byte, error)
func UnmarshalKeyMaterial(blob []byte) (ECDSAKeyMaterial, error)
```

`MarshalShare` and `UnmarshalShare` can remain compatibility wrappers for existing callers.
New DKG persistence and derived signing paths should use key material APIs.

The in-memory runner store should also store `ECDSAKeyMaterial`, not only `LocalPartySaveData`.
Existing share import/export helpers can remain wrappers around the material store.
Derived signing must load full key material and reject missing chain code.

The child-adjusted `LocalPartySaveData` used for signing is a runtime copy only.
It must never be persisted.

## ECDSA Derived Signing Runtime

The runtime flow for ECDSA secp256k1 is:

1. Public `RunSignSession` validates the request. A nil context returns `ErrDerivationContextRequired`.
2. The public boundary normalizes and copies the context with `NormalizeDerivationContext`.
3. Internal service loads `ECDSAKeyMaterial` by `KeyID`.
4. If the material has no 32-byte chain code, return `ErrChainCodeMissing`.
5. Validate context against runtime metadata: algorithm, curve, scheme, chain, account path, child path, and full path.
6. Extract the account public key from stored `LocalPartySaveData.ECDSAPub`.
7. Derive the child public key and accumulated `IL` delta from account public key, chain code, and child indices.
8. If `DerivedPublicKey` is supplied, compare it with the derived child public key. Mismatch returns `ErrDerivationContextMismatch`.
9. Copy the stored share.
10. Adjust the copied share to the child public key:
    - set copied `ECDSAPub` to the derived child public key;
    - add `IL*G` to every copied `BigXj[j]`.
11. Start signing with the adjusted copy and `keyDerivationDelta = IL`.

`ExpectedAddress` remains commitment-only. It is carried for audit/logging and downstream policy, but core does not compute addresses.
Production `mpc-signer` should pass `DerivedPublicKey` as a commitment, even though core may sign after successful derivation if it is absent.

## Path Parsing And BIP32 Derivation

Add a focused internal parser, for example under `internal/tss/derivation`.
It must not include chain-specific address logic.

`AccountPath` rules:

- absolute path starting with `m`;
- may contain hardened components;
- canonical apostrophe form, for example `m/44'/60'/0'`;
- used only for metadata and canonical join validation;
- core does not perform hardened derivation from seed or private root material.

`ChildPath` rules for the first production scope:

```text
/change/index
```

- exactly two decimal components;
- must start with `/`;
- must not start with `m/`;
- no hardened markers;
- each component must be `uint32 < 0x80000000`;
- no empty segments, whitespace, `+`, `-`, leading zeros except literal `0`, or extended depth.

The canonical child path is always `/change/index`.

`FullPath`, when supplied, is parsed and compared by components:

```text
canonical(full_path) == canonical_join(account_path, child_path)
```

Example:

```text
AccountPath: m/44'/60'/0'
ChildPath:  /0/15
FullPath:   m/44'/60'/0'/0/15
```

Use `tss-lib` `crypto/ckd` for non-hardened BIP32 derivation.
For multi-level `/change/index`, use the accumulated delta returned by `DeriveChildKeyFromHierarchy`.
Any CKD invalid-child result should be wrapped so `errors.Is(err, ErrDerivationPathInvalid)` succeeds.

## KDD Integration

`flow.SignBuildInput` gains a required derivation delta:

```go
type SignBuildInput struct {
    Digest             []byte
    Params             *tsslib.Parameters
    KeyShare           ecdsakeygen.LocalPartySaveData
    KeyDerivationDelta *big.Int
    OutCh              chan<- tsslib.Message
}
```

The public SIGN flow must call only:

```go
ecdsasigning.NewLocalPartyWithKDD(msg, params, adjustedShare, keyDerivationDelta, outCh, endCh)
```

It must not call `ecdsasigning.NewLocalParty`.

Guardrails:

- `BuildSign` requires `KeyDerivationDelta != nil`.
- Derived signing prepares an adjusted share copy before `BuildSign`.
- Protocol start is forbidden until derivation succeeds.
- Runner signing must not fall back from `KeyID` to `SessionID`.
- No successful public SIGN path exists without derivation context.

## Derivation Context Binding

Core should compute a stable hash of the normalized derivation context, for example `DerivationContextHash`.
The hash belongs to core transport/frame metadata, not inside the `tss-lib` payload.

If `protocol.Frame` does not already have a suitable metadata field, add:

```go
DerivationContextHash string
```

Outbound sign frames must include the hash.
Inbound sign frames must include the same hash.
Missing or mismatched hashes return `ErrDerivationContextMismatch` before the TSS message is passed to `party.Update`.

This change must be propagated symmetrically through signer/co-signer transports.
It prevents two parties from accidentally running the protocol with different profile/path commitments.

## Error Handling

All derivation errors must occur before `party.Start()` or before `party.Update()` for inbound messages.

Error mapping:

- missing `DerivationContext` -> `ErrDerivationContextRequired`
- malformed required fields/profile/path/full path -> `ErrInvalidDerivationContext` or `ErrDerivationPathInvalid`
- unknown scheme -> `ErrUnsupportedDerivationScheme`
- reserved EdDSA algorithm/curve/scheme -> `ErrDerivedSigningUnsupported`
- ECDSA with unsupported curve -> `ErrUnsupportedAlgorithmCurve`
- stored key material has no 32-byte chain code -> `ErrChainCodeMissing`
- `DerivedPublicKey` mismatch -> `ErrDerivationContextMismatch`
- frame `DerivationContextHash` missing or mismatch -> `ErrDerivationContextMismatch`
- CKD invalid child result -> `ErrDerivationPathInvalid`

No invalid or unsupported derivation request may start root/account-key signing.

## Tests

Public contract and validation:

- `SignSessionRequest` without context returns `ErrDerivationContextRequired`.
- valid ECDSA context `/0/15` passes normalization.
- `bip32_public` normalizes to `bip32_secp256k1`.
- hardened child path rejects.
- absolute child path rejects.
- child path with extra depth rejects.
- leading-zero child segment rejects.
- wrong algorithm/curve rejects.
- chain mismatch rejects when both sides set chain.
- full path mismatch rejects after canonical join.
- unknown scheme returns `ErrUnsupportedDerivationScheme`.
- reserved EdDSA context structurally validates, runtime returns `ErrDerivedSigningUnsupported`.

DKG/share lifecycle:

- ECDSA `DKGOutput` includes non-empty 32-byte hex `ChainCode`.
- ECDSA `DKGOutput.DerivationScheme == "bip32_secp256k1"`.
- `PublicKeyFormat == "uncompressed_hex"`.
- persisted key material includes chain code.
- loaded key material round-trips share and chain code.
- v1 share blob can decode for diagnostics but signing with context returns `ErrChainCodeMissing`.
- EdDSA DKG does not create chain code and remains runtime-unsupported for derived signing.

BIP32/KDD unit tests:

- parse `/0/15` into indices `[0, 15]`.
- derive child public key from account public key and chain code using known BIP32 vectors where possible.
- accumulated delta matches `ckd.DeriveChildKeyFromHierarchy`.
- adjusted share copy changes `ECDSAPub` and `BigXj` but does not mutate original stored share.
- derived public key commitment mismatch returns `ErrDerivationContextMismatch`.

Signing/runtime:

- ECDSA signing with valid context uses the KDD build path and succeeds in the existing in-memory multi-party integration test.
- signature verifies against expected child public key, not account public key.
- missing chain code fails before protocol start.
- invalid context fails before protocol start.
- `DerivationContextHash` mismatch on inbound frame fails before `party.Update`.
- unsupported EdDSA derived signing returns `ErrDerivedSigningUnsupported`.
- no successful public SIGN test uses nil context.
- negative nil-context public SIGN test verifies `ErrDerivationContextRequired`.
- builder-level guard verifies `BuildSign` rejects nil `KeyDerivationDelta`.

Downstream tests expected in companion repositories:

- `mpc-signer` passes normalized context into core.
- `mpc-co-signer` builds the same context from monolith intent payload.
- relay/HTTP/protobuf frame mappings preserve `DerivationContextHash`.

## Documentation Updates

Update README or package docs to state:

- DKG produces account-level public key and chain code.
- SIGN always signs a derived child key.
- root/account-key signing is intentionally unsupported.
- core does not store derivation profiles.
- core does not perform chain-specific address encoding.
- `ExpectedAddress` is commitment-only in core.
- ECDSA secp256k1 `bip32_secp256k1` is implemented.
- `bip32_public` is a deprecated alias normalized at the boundary.
- EdDSA Ed25519/SLIP-10 is reserved in contract but runtime unsupported.

## Non-Goals

Core must not:

- perform chain-specific address encoding;
- store derivation profiles;
- depend on `mpc-signer`, `mpc-co-signer`, or monolith concepts;
- accept chain code from signing requests;
- sign the account/root key through the public SIGN flow;
- silently fall back to root signing when derivation is invalid or unsupported;
- persist child-adjusted key shares.

## Rollout Notes

This design intentionally assumes no production backward compatibility requirement for root signing.
All successful signing integrations must provide derivation context.

Companion changes are required in:

- `mpc-signer`: persist chain code from DKG output, require sign profile/path/address context, pass normalized context to core.
- `mpc-co-signer`: require derivation context in monolith intent payload and pass it to core.
- monolith: include immutable derivation context in signing intents.
- relay transports/protobuf/HTTP mappings: preserve `DerivationContextHash`.
