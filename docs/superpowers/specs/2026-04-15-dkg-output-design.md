# DKG Output Design

## Summary

The core service must provide a reliable way to obtain `DKGOutput { KeyID, PublicKey, Address }` after a successful ECDSA DKG run, including when `shareStore` is configured and the in-memory runner share is deleted after persistence.

`RunDKGSession` is the primary contract and should return `DKGOutput` directly on success. `ReadDKGOutput` is a recovery, replay, and fallback path that reconstructs the same output from the same source-of-truth selection rules.

The result-building logic stays inside core. External callers such as `mpc-co-signer` must not parse share blobs, derive public keys or addresses, or import anything from `internal/...`.

## Problem

Today, post-run DKG result access is not reliable because the service still depends on runner-held state after `RunDKG`.

When `shareStore != nil`, the DKG flow persists the ECDSA share and then clears the runner-held key share. Any post-run access pattern that depends on `ExportECDSAKeyShare(sessionID)` or `ECDSAAddress(sessionID)` can therefore fail even though DKG completed successfully and the persisted share is valid.

This creates an invalid contract for downstream callers. The core service must own both source selection and derivation of DKG output.

## Goals

- Add a public `DKGOutput` type to core.
- Make `RunDKGSession` return `DKGOutput` on successful ECDSA DKG.
- Add `ReadDKGOutput` as a recovery and replay API.
- Ensure both APIs use the same internal builder and the same source-selection rules.
- Use persisted share as the only source of truth when `shareStore != nil`.
- Use runner state as the source of truth only when `shareStore == nil`.
- Keep share parsing and derivation logic inside core.
- Avoid any public dependency on `internal/...`.

## Non-Goals

- Redesign share storage format.
- Persist a second copy of derived DKG output alongside the share.
- Move derivation logic into `mpc-co-signer`.
- Add fallback logic from persisted share to runner state when `shareStore != nil`.

## Public API Changes

Add a public output type:

```go
type DKGOutput struct {
    KeyID     string
    PublicKey string
    Address   string
}
```

Make DKG return the output directly:

```go
RunDKGSession(ctx context.Context, req DKGSessionRequest) (DKGOutput, error)
```

Add a recovery and replay API with metadata-validation context:

```go
type ReadDKGOutputInput struct {
    SessionID string
    OrgID     string
    Algorithm string
}

ReadDKGOutput(ctx context.Context, in ReadDKGOutputInput) (DKGOutput, error)
```

Add public share-derivation helpers in the `tss` package:

```go
ExtractECDSAPublicKey(share ecdsakeygen.LocalPartySaveData) (string, error)
ECDSAAddressFromShare(share ecdsakeygen.LocalPartySaveData) (string, error)
```

These helpers expose reusable derivation primitives but do not embed orchestration semantics such as `sessionID -> keyID` mapping or source selection.

## Design

### Single DKG Output Builder

Introduce a single internal builder in the service/orchestration layer that is responsible for:

- deriving `KeyID` as `NormalizeKeyID(sessionID)`
- choosing the correct source of truth
- validating share metadata when reading persisted data
- deriving `PublicKey` and `Address`
- mapping missing or invalid data to the expected public errors

This builder is the only place where `sessionID`, source selection, and metadata validation come together.

### Source Selection Rules

The builder must be deterministic:

- if `shareStore != nil`, always read from persisted share
- if `shareStore == nil`, read from runner state

There is no fallback between these sources. In particular, when `shareStore != nil`, the builder must not silently fall back to runner memory. This guarantees that the primary path and recovery path use the same source of truth and prevents hidden dependence on runner-held state.

### Persisted Share Path

When `shareStore != nil`, the builder:

1. Normalizes `keyID` from `sessionID`.
2. Loads the stored share by `keyID`.
3. Validates share metadata against `orgID` and `algorithm`.
4. Unmarshals the share blob.
5. Derives `PublicKey` and `Address` from the unmarshaled share.
6. Returns `DKGOutput`.

The metadata validation must use the same semantic contract already used by the sign flow. A metadata mismatch returns `ErrMetadataMismatch`.

### Runner-State Path

When `shareStore == nil`, the builder:

1. Normalizes `keyID` from `sessionID`.
2. Reads the in-memory share from the runner by `keyID`.
3. Derives `PublicKey` and `Address` from that share.
4. Returns `DKGOutput`.

No persisted-share validation occurs on this path because the share store is not in use.

## DKG Flow

For successful ECDSA DKG:

- `RunDKGSession` executes DKG as it does today.
- If `shareStore != nil`, it persists the share and clears the runner-held share.
- It then calls the single builder and returns the resulting `DKGOutput`.

For successful ECDSA DKG without share persistence:

- `RunDKGSession` executes DKG.
- It calls the single builder, which reads the in-memory runner share.
- It returns `DKGOutput`.

The existing separate `EnsureDKGMetadata(...)` post-run check should be removed or folded into the builder so there is no second, competing post-DKG contract.

## Read Path

`ReadDKGOutput` is not the primary success path. It exists for:

- recovery after a successful DKG
- replay by callers that need to re-read DKG output later
- deterministic fallback semantics owned by core

Its source selection must match `RunDKGSession` exactly:

- persisted share only when `shareStore != nil`
- runner state only when `shareStore == nil`

`SessionID` is the primary identifier and the source of `KeyID`. `OrgID` and `Algorithm` exist to validate persisted-share metadata before returning a result.

## Error Semantics

The following mappings should be preserved and made explicit:

- missing public key maps to `ErrMissingDKGPublicKey`
- missing or empty address maps to `ErrMissingDKGAddress`
- persisted-share metadata mismatch maps to `ErrMetadataMismatch`
- missing share maps to a typed not-found error
- corrupt share blob maps to `ErrInvalidSharePayload`
- unsupported share version maps to `ErrUnsupportedVersion`

If public derivation helpers need additional internal errors, they should map those errors at the service boundary so callers of `RunDKGSession` and `ReadDKGOutput` see stable public errors.

## Implementation Notes

- Reuse the existing `NormalizeKeyID` helper for `KeyID` derivation.
- Reuse the existing metadata validation logic for persisted-share reads.
- Lift ECDSA public-key extraction into public `tss` API instead of leaving it in `internal/tss/runtime`.
- Lift ECDSA address derivation from share into public `tss` API instead of leaving it only in `internal/tssbnb/utils`.
- Keep blob parsing and share unmarshaling inside core service flow and public core helpers, not in callers.

## Testing

Add tests for:

- successful `RunDKGSession` with `shareStore != nil`, proving the output builder reads persisted share and does not depend on runner state after persistence and cleanup
- successful `RunDKGSession` with `shareStore == nil`, proving the output is built from runner state
- successful `ReadDKGOutput` with `shareStore != nil`
- metadata mismatch on persisted share returning `ErrMetadataMismatch`
- missing share returning a typed not-found error
- corrupt share blob returning `ErrInvalidSharePayload`
- unsupported share version returning `ErrUnsupportedVersion`
- no regression in sign flow when persisted share is loaded for signing
- targeted public-helper tests for `ExtractECDSAPublicKey` and `ECDSAAddressFromShare`

## Risks And Mitigations

Risk: hidden fallback to runner state in `shareStore != nil` mode would reintroduce the original contract ambiguity.
Mitigation: builder tests must explicitly fail if the implementation reads runner state in persisted-share mode.

Risk: public helper expansion could accidentally expose orchestration behavior.
Mitigation: expose only derivation primitives, not a public builder that mixes derivation with `sessionID` semantics.

Risk: error mapping could diverge between primary and recovery paths.
Mitigation: both paths must call the same builder and assert on the same test expectations.

## Decision

Adopt a single internal DKG output builder inside core. Make `RunDKGSession` return `DKGOutput` as the primary contract. Add `ReadDKGOutput` with `SessionID`, `OrgID`, and `Algorithm` as the recovery and replay contract. Use persisted share as the sole source of truth when `shareStore != nil`, and runner state only when `shareStore == nil`.
