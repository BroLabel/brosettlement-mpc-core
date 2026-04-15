# DKG Output Design

## Summary

The core service must provide a reliable way to obtain `DKGOutput { KeyID, PublicKey, Address }` after a successful ECDSA DKG run, including when `shareStore` is configured and the in-memory runner share is deleted after persistence.

`RunDKGSession` is the primary contract and should return `DKGOutput` directly on success for ECDSA DKG. `ReadDKGOutput` is a recovery, replay, and fallback path that reconstructs the same output from the same source-of-truth selection rules.

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

## Scope

This design is ECDSA-specific.

`DKGOutput` is defined only for the ECDSA path described in the problem statement. `RunDKGSession` continues to execute non-ECDSA DKG exactly as it does today, but output derivation is not attempted for those algorithms and the method returns a zero-value `DKGOutput` together with the underlying DKG execution result.

If core later needs derived post-DKG output for another algorithm, that behavior should be designed explicitly instead of being inferred from the ECDSA contract in this document.

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

For ECDSA DKG, `req.Session.SessionID` is the only canonical source of `KeyID`. `req.Session.KeyID` does not participate in persistence, lookup, or output derivation.

For ECDSA DKG, `req.Session.KeyID` must therefore be either empty or equal to `req.Session.SessionID` after normalization. A mismatch is an invalid request and should fail validation instead of being tolerated silently.

For non-ECDSA algorithms, `RunDKGSession` returns the existing DKG execution result and a zero-value `DKGOutput`. No post-DKG output derivation is attempted on that path.

Add a recovery and replay API with metadata-validation context:

```go
type ReadDKGOutputInput struct {
    SessionID string
    OrgID     string
    Algorithm string
    Chain     string
}

ReadDKGOutput(ctx context.Context, in ReadDKGOutputInput) (DKGOutput, error)
```

`ReadDKGOutput` is an ECDSA-only recovery and replay API. For non-ECDSA algorithms, it must fail with a typed public unsupported-algorithm error instead of returning a zero-value `DKGOutput`.

Add public share-derivation helpers in the `tss` package:

```go
ExtractECDSAPublicKey(share ecdsakeygen.LocalPartySaveData) (string, error)
ECDSAAddressFromShare(chain string, share ecdsakeygen.LocalPartySaveData) (string, error)
```

These helpers expose reusable derivation primitives but do not embed orchestration semantics such as `sessionID -> keyID` mapping or source selection.

`Chain` is an explicit address-derivation selector, not part of persisted-share identity. In this scope, the only canonical supported value is `tron`.

For backward compatibility with current behavior, the derivation contract must normalize `""`, `tron`, and `tron-mainnet` case-insensitively to canonical `tron`. Any other value must return a typed public unsupported-chain error instead of silently defaulting to some address format.

## Design

### Single DKG Output Builder

Introduce a single internal builder in the service/orchestration layer that is responsible for:

- deriving `KeyID` as `NormalizeKeyID(sessionID)`
- treating `SessionID`, not request `KeyID`, as the canonical ECDSA identity
- choosing the correct source of truth
- validating share metadata when reading persisted data
- carrying chain context into address derivation
- deriving `PublicKey` and `Address`
- mapping missing or invalid data to the expected public errors

This builder is the only place where `sessionID`, source selection, and metadata validation come together.

It is also the only place that should normalize chain aliases before address derivation.

### Source Selection Rules

The builder must be deterministic:

- if `shareStore != nil`, always read from persisted share
- if `shareStore == nil`, read from runner state

There is no fallback between these sources. In particular, when `shareStore != nil`, the builder must not silently fall back to runner memory. This guarantees that the primary path and recovery path use the same source of truth and prevents hidden dependence on runner-held state.

When `shareStore == nil`, the builder still uses runner state deterministically, but that source is inherently ephemeral. Recovery and replay semantics on that path are therefore best-effort rather than durable.

### Persisted Share Path

When `shareStore != nil`, the builder:

1. Normalizes `keyID` from `sessionID`.
2. Loads the stored share by `keyID`.
3. Validates share metadata against `orgID` and `algorithm`.
4. Unmarshals the share blob.
5. Derives `PublicKey` and chain-specific `Address` from the unmarshaled share.
6. Returns `DKGOutput`.

The metadata validation must use the same semantic contract already used by the sign flow. A metadata mismatch returns `ErrMetadataMismatch`.

`Chain` is not part of this metadata validation. In the current design, persisted share identity is defined by `keyID`, `orgID`, and `algorithm`, while `Chain` only selects how `Address` is derived from the same ECDSA key material.

### Runner-State Path

When `shareStore == nil`, the builder:

1. Normalizes `keyID` from `sessionID`.
2. Reads the in-memory share from the runner by `keyID`.
3. Derives `PublicKey` and chain-specific `Address` from that share.
4. Returns `DKGOutput`.

No persisted-share validation occurs on this path because the share store is not in use.

## DKG Flow

For successful ECDSA DKG:

- `RunDKGSession` executes DKG as it does today.
- It treats `SessionID` as the canonical ECDSA key identity and rejects mismatched `req.Session.KeyID` during request validation.
- If `shareStore != nil`, it persists the share and clears the runner-held share.
- It then calls the single builder and returns the resulting `DKGOutput`.

For successful ECDSA DKG without share persistence:

- `RunDKGSession` executes DKG.
- It calls the single builder, which reads the in-memory runner share.
- It returns `DKGOutput`.

The existing separate `EnsureDKGMetadata(...)` post-run check should be removed or folded into the builder so there is no second, competing post-DKG contract.

For successful non-ECDSA DKG:

- `RunDKGSession` preserves the existing DKG execution behavior.
- It does not attempt to construct `DKGOutput`.
- It returns a zero-value `DKGOutput` and the DKG execution result.

### Partial-Success Semantics

For ECDSA, `RunDKGSession` performs two logical stages:

1. execute DKG and commit any resulting share state
2. build `DKGOutput` from the selected source of truth

If stage 1 succeeds but stage 2 fails, `RunDKGSession` returns an error even though DKG itself has already completed successfully. In that case the caller must treat the error as an output-readback failure, not as evidence that the DKG session should be re-run.

The supported recovery path for that situation is `ReadDKGOutput(...)` with the same session context. Callers should use it to re-read the persisted or in-memory result rather than starting a second DKG for the same logical session.

This recovery guidance is durable only when `shareStore != nil`. When `shareStore == nil`, `ReadDKGOutput(...)` is only a best-effort follow-up path while the relevant runner state is still present in the same process lifetime.

## Read Path

`ReadDKGOutput` is not the primary success path. It exists for:

- recovery after a successful DKG
- replay by callers that need to re-read DKG output later
- deterministic fallback semantics owned by core

Its source selection must match `RunDKGSession` exactly:

- persisted share only when `shareStore != nil`
- runner state only when `shareStore == nil`

For non-ECDSA algorithms, `ReadDKGOutput` must return the typed public unsupported-algorithm error without touching persisted share or runner state.

`SessionID` is the primary identifier and the source of `KeyID`. `OrgID` and `Algorithm` exist to validate persisted-share metadata before returning a result. `Chain` exists because `Address` derivation is chain-dependent and must not silently assume a hard-coded address format, but it is not part of persisted-share metadata identity in this design.

When `shareStore != nil`, this API is a durable recovery/replay mechanism because the source of truth is persisted share. When `shareStore == nil`, it is only a best-effort same-process read path and is not guaranteed to survive runner cleanup or process restart.

## Error Semantics

The following mappings should be preserved and made explicit:

- missing public key maps to `ErrMissingDKGPublicKey`
- missing or empty address maps to `ErrMissingDKGAddress`
- persisted-share metadata mismatch maps to `ErrMetadataMismatch`
- missing share maps to a typed not-found error
- corrupt share blob maps to `ErrInvalidSharePayload`
- unsupported share version maps to `ErrUnsupportedVersion`
- non-ECDSA `ReadDKGOutput` maps to a typed public unsupported-algorithm error
- unsupported chain maps to a typed public unsupported-chain error
- non-ECDSA DKG does not produce derived `DKGOutput`; callers receive a zero-value output and the normal DKG execution result

If public derivation helpers need additional internal errors, they should map those errors at the service boundary so callers of `RunDKGSession` and `ReadDKGOutput` see stable public errors.

## Implementation Notes

- Reuse the existing `NormalizeKeyID` helper for `KeyID` derivation.
- Extend ECDSA DKG request validation so `SessionDescriptor.KeyID`, when present, must match canonical `SessionID` semantics instead of creating an alternate lookup key.
- Reuse the existing metadata validation logic for persisted-share reads.
- Lift ECDSA public-key extraction into public `tss` API instead of leaving it in `internal/tss/runtime`.
- Lift ECDSA address derivation from share into public `tss` API instead of leaving it only in `internal/tssbnb/utils`.
- Thread `Chain` through the ECDSA output builder and public address helper so address derivation remains explicit and deterministic.
- Centralize chain normalization in one helper so `RunDKGSession`, `ReadDKGOutput`, and public derivation helpers all interpret aliases identically.
- Do not add `Chain` to persisted share metadata in this scope; chain influences address derivation only.
- Keep blob parsing and share unmarshaling inside core service flow and public core helpers, not in callers.

## Testing

Add tests for:

- successful `RunDKGSession` with `shareStore != nil`, proving the output builder reads persisted share and does not depend on runner state after persistence and cleanup
- successful `RunDKGSession` with `shareStore == nil`, proving the output is built from runner state
- successful `ReadDKGOutput` with `shareStore != nil`
- ECDSA DKG request validation rejects mismatched `SessionID` and `SessionDescriptor.KeyID`
- successful non-ECDSA `RunDKGSession`, proving it returns a zero-value `DKGOutput` and does not invoke the ECDSA output builder
- non-ECDSA `ReadDKGOutput`, proving it returns the typed unsupported-algorithm error and does not invoke persisted-share or runner reads
- metadata mismatch on persisted share returning `ErrMetadataMismatch`
- missing share returning a typed not-found error
- corrupt share blob returning `ErrInvalidSharePayload`
- unsupported share version returning `ErrUnsupportedVersion`
- chain normalization coverage for `""`, `tron`, and `tron-mainnet`, proving all aliases produce the same canonical derivation behavior
- unsupported chain returning the typed public error rather than a silently defaulted address format
- partial-success behavior where DKG completes but `RunDKGSession` returns an output-readback error and `ReadDKGOutput` is the documented recovery step
- `ReadDKGOutput` with `shareStore == nil` succeeds while runner state is present and fails once runner state is cleared, documenting the best-effort limitation
- no regression in sign flow when persisted share is loaded for signing
- targeted public-helper tests for `ExtractECDSAPublicKey` and `ECDSAAddressFromShare`

## Risks And Mitigations

Risk: hidden fallback to runner state in `shareStore != nil` mode would reintroduce the original contract ambiguity.
Mitigation: builder tests must explicitly fail if the implementation reads runner state in persisted-share mode.

Risk: public helper expansion could accidentally expose orchestration behavior.
Mitigation: expose only derivation primitives, not a public builder that mixes derivation with `sessionID` semantics.

Risk: error mapping could diverge between primary and recovery paths.
Mitigation: both paths must call the same builder and assert on the same test expectations.

Risk: callers may treat output-readback failure as DKG failure and accidentally re-run the same logical session.
Mitigation: document partial-success semantics explicitly and require recovery through `ReadDKGOutput(...)`.

Risk: address derivation could silently lock the API to one chain format.
Mitigation: carry `Chain` explicitly through read/output derivation contracts, define the supported canonical values, and test alias normalization.

Risk: ambiguous `SessionDescriptor.KeyID` could create divergence between persisted lookup and readback identity.
Mitigation: make `SessionID` canonical for ECDSA and reject mismatched request `KeyID` values during validation.

Risk: callers may assume `ReadDKGOutput` is a durable recovery mechanism even when `shareStore == nil`.
Mitigation: document that runner-backed recovery is best-effort only and cover loss-of-runner-state behavior in tests.

## Decision

Adopt a single internal DKG output builder inside core for ECDSA. Make `RunDKGSession` return `DKGOutput` as the primary ECDSA contract and return a zero-value output for non-ECDSA algorithms. Add `ReadDKGOutput` with `SessionID`, `OrgID`, `Algorithm`, and `Chain` as the ECDSA recovery and replay contract, returning a typed unsupported-algorithm error for non-ECDSA inputs. Use persisted share as the sole durable source of truth when `shareStore != nil`, and runner state only as a best-effort same-process source when `shareStore == nil`.
