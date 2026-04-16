# Internal TSS Service Layout Design

## Summary

Improve readability and navigation inside `internal/tss/service` without changing its package boundary. The package remains `service`, but files are regrouped so each file has a single clear ownership area that is visible from its name.

This is an internal code-organization refactor only. It does not introduce new subpackages, new public APIs, or behavioral changes in DKG/sign execution.

## Goals

- Keep `internal/tss/service` as a single Go package.
- Make it easier to find orchestration, flow-specific logic, preparams helpers, and snapshot logic by filename alone.
- Reduce the amount of unrelated code co-located in the current `orchestration.go`.
- Preserve the current runtime behavior and package-level interfaces.

## Non-Goals

- No new subpackages under `internal/tss/service`.
- No changes to the public `tss` package layout.
- No protocol or lifecycle behavior changes.
- No opportunistic cleanup outside file layout and ownership clarity.

## Current Problem

`internal/tss/service` already has the right conceptual split, but the file layout does not expose it clearly enough:

- `orchestration.go` mixes the core `Service` type, constructor, lifecycle helpers, DKG flow, and sign flow.
- preparams and snapshot helpers live in `state.go`, whose name does not communicate their role.
- DKG and sign helpers already exist in dedicated files, but their entrypoints still live in the orchestration file.

The result is that readers still need to open the largest file first and scan through unrelated responsibilities before finding the code path they want.

## Target Layout

The package stays `internal/tss/service`, with these files:

- `service.go`
  - `Service`
  - constructor and shared dependency fields
  - preparams pool lifecycle methods
- `types.go`
  - `Runner`
  - `ShareStore`
  - `LifecyclePool`
  - `SnapshotPool`
  - `DKGInput`
  - `DKGOutput`
  - `SignInput`
  - package errors that describe constructor requirements
- `dkg_flow.go`
  - `RunDKGSession`
  - `buildDKGJob`
  - `buildECDSADKGOutput`
  - `persistECDSAShareAfterDKG`
  - `normalizeDKGKeyID`
- `sign_flow.go`
  - `RunSignSession`
  - `prepareShareForSign`
- `preparams.go`
  - `Pool`
  - `SnapshotProvider`
  - `PreParamsPool`
  - `ResolvePreParamsSource`
  - `AttachPreParams`
- `snapshot.go`
  - `Snapshot`
  - `BuildSnapshot`

## Design Rules

- File names should communicate responsibility, not implementation history.
- Entry-point methods should live with the helpers they orchestrate when that improves locality.
- Shared structural types should be separated from flow logic so readers can inspect interfaces without scrolling through runtime behavior.
- Keep private helpers close to the flow they support unless they are reused across multiple flows.

## Behavioral Expectations

- `RunDKGSession` and `RunSignSession` keep the same signatures and behavior.
- `New`, `StartPreParamsPool`, `StopPreParamsPool`, and `Snapshot` keep the same behavior.
- No import graph changes are expected outside `internal/tss/service` because package paths stay the same.

## Testing

Use existing tests as the regression gate for this refactor. No new behavior-specific tests are required unless file movement exposes an existing gap.

Primary verification:

- targeted package tests that cover `tss` and `internal/tss/service` call paths
- repository test run if the targeted pass is clean and inexpensive enough

## Risks

- Moving types between files can accidentally create duplicate declarations or stale references if not done mechanically.
- A file split that is too granular could make navigation worse rather than better.
- Renaming `state.go` must avoid implying semantic changes where only organization changed.

## Recommendation

Implement the single-package layout refactor now and defer any subpackage split until the package grows enough that filename-based grouping stops being sufficient.
