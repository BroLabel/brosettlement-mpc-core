# Module Independence Design

## Goal

Prepare `github.com/BroLabel/brosettlement-mpc-core` for external consumption via `go get` with a small, stable public surface.

The module should be usable by downstream repositories through these public packages only:

- `protocol`
- `transport`
- `tss`

Everything under `internal/` is implementation detail and must not be documented or treated as stable API.

## Success Criteria

- A clean checkout builds and tests with `go test ./...` without `replace` directives.
- No source file imports the old module path `brosettlement-mpc-signer/brosettlement-mpc-core/...`.
- README documents only the real public packages and includes a working integration example.
- Public `tss` entrypoints are covered by facade-level tests so internal refactors do not silently break consumers.
- The repository is ready for semantic version tagging.

## Non-Goals

- Publishing additional public packages beyond `protocol`, `transport`, and `tss`.
- Exposing `internal/*` helpers as supported extension points.
- Reworking the protocol design or changing the intended runtime behavior of DKG/sign flows unless required for module independence.

## Current Gaps

### Broken self-containment

The repository still contains imports that point at the historical module path instead of the current canonical path. This prevents the module from compiling as an independent repository.

### Public API drift

The documentation still refers to packages that are no longer public, especially share-related packages that were moved under `internal/`.

### Weak facade protection

Most tests now live under `internal/`, while the public `tss` package has little or no direct coverage. That leaves the exported facade vulnerable to breakage during future internal refactors.

## Target Architecture

### Public surface

`protocol`
: defines wire-level frame contracts shared by peers.

`transport`
: defines the minimal transport boundary used by public consumers.

`tss`
: exposes the high-level service API, share-store-facing helpers, transport alias, and pre-params configuration intended for downstream use.

### Internal surface

`internal/preparams`
: pre-parameter pool implementation.

`internal/shares`
: share serialization and persistence internals.

`internal/tss`
: request validation, orchestration, runtime state, and logging internals behind the public `tss.Service`.

`internal/tssbnb`
: concrete BNB-backed TSS runner implementation and supporting utilities.

`internal/idgen`
: internal helper for correlation and message identifiers.

## Implementation Approach

### 1. Restore independent module compilation

- Replace every remaining import that uses `brosettlement-mpc-signer/brosettlement-mpc-core/...` with `github.com/BroLabel/brosettlement-mpc-core/...`.
- Verify there are no lingering references in public or internal packages.
- Run module-wide tests from a clean dependency graph.

### 2. Align documentation with the real public API

- Rewrite README package list to mention only `protocol`, `transport`, and `tss`.
- Replace outdated compatibility notes about no-longer-external dependencies.
- Add a small working example that uses the current public `tss` facade rather than removed packages.
- State explicitly that `internal/*` is not public API.

### 3. Protect the public facade

- Add tests in the public `tss` package for:
  - request validation behavior
  - pre-params config defaults and env loading
  - share codec facade helpers
  - service wiring that can be exercised without reaching internal implementation details directly
- Keep implementation-specific behavior tests under `internal/`, but use public tests to lock the exported contract.

### 4. Final release readiness pass

- Confirm `go test ./...` passes.
- Confirm `README`, `go.mod`, and package layout match the intended public surface.
- Create a first semantic version tag after the code is stable.

## Error Handling and Compatibility

- Any user-visible errors currently exposed by `tss` should keep their names and meanings unless a change is required to make the facade internally consistent.
- Internal package moves must not require downstream import changes as long as consumers stay within `protocol`, `transport`, and `tss`.
- If a helper is needed by downstream code and is currently only available through `internal/*`, it must be re-exposed intentionally through `tss` rather than by widening the public package set accidentally.

## Testing Strategy

- Use `go test ./...` as the repository readiness gate.
- Keep focused package-level tests for public packages.
- Use public facade tests to validate exported contracts and internal tests to validate implementation details.
- Prefer simple constructor and validation tests over brittle white-box assertions.

## Risks

- Import-path cleanup may reveal circular dependencies introduced during the facade refactor.
- Some aliases in `tss` may expose more internal structure than intended and may need reshaping rather than direct re-export.
- README updates can easily drift again if public-package boundaries are not made explicit in the code review checklist.

## Recommended Rollout

1. Fix import paths and get the repository compiling again.
2. Update README to match the actual public API.
3. Add facade-level tests in `tss`.
4. Run the full verification gate.
5. Tag the first external-consumer release.
