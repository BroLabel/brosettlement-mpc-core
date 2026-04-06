# PreParams Source Injection For TSS Service

## Summary

Replace the current public constructor split with a single option-based `tss.NewBnbService` API that can accept an external preparams source for DKG. When a source is supplied, the service acquires preparams from that source. When no source is supplied, the service preserves the current behavior by using the internal preparams pool.

This keeps preparams storage, file rotation, and PoC-specific orchestration outside core while making it possible to construct multiple services with different preparams inputs.

## Goals

- Add a public `PreParamsSource` interface for DKG preparams acquisition.
- Allow `tss.NewBnbService` to accept an optional external preparams source.
- Preserve the current default runtime behavior when no source is provided.
- Allow two independently constructed services to use different preparams sources without interference.
- Keep PoC-specific logic, file paths, and storage policy decisions outside core.
- Remove the legacy expanded constructor and make `NewBnbService` the only public constructor.
- Remove the similar internal expanded constructor pair in `internal/tssbnb/runner`.

## Non-Goals

- No `p1` or `p2` logic in core.
- No new internal cache policy model such as `ephemeral` or `persistent`.
- No refactor of preparams pool internals beyond what is required to share a small abstraction.
- No change to DKG/sign protocol semantics outside preparams sourcing.

## Public API

`tss` exposes:

```go
type PreParamsSource interface {
    Acquire(ctx context.Context) (*ecdsakeygen.LocalPreParams, error)
}
```

`tss` uses a single constructor entrypoint:

```go
func NewBnbService(logger *slog.Logger, opts ...ServiceOption) *Service
```

Supported options in this change:

```go
func WithPreParamsSource(source PreParamsSource) ServiceOption
func WithPreParamsConfig(cfg PreParamsConfig) ServiceOption
func WithShareStore(store ShareStore) ServiceOption
func WithMetrics(metrics bnbutils.Metrics) ServiceOption
```

The legacy `NewBnbServiceWithConfigAndShareStoreAndMetrics` constructor is removed in favor of this single option-based API.

## Legacy Constructor Audit

This repository currently has one public legacy-style expanded constructor pattern in scope for cleanup:

- `tss.NewBnbServiceWithConfigAndShareStoreAndMetrics`

There is also a similar pair under `internal/*` that is included in this cleanup:

- `internal/tssbnb/runner.NewBnbRunner`
- `internal/tssbnb/runner.NewBnbRunnerWithMetrics`

The internal runner constructors should be consolidated to a single option-based entrypoint as well so the service and runner layers follow the same construction model.

Planned internal runner API shape:

```go
func NewBnbRunner(logger *slog.Logger, opts ...Option) *BnbRunner
```

Supported runner options in this change:

```go
func WithMetrics(metrics bnbutils.Metrics) Option
func WithConfig(cfg tssbnbutils.RunnerConfig) Option
```

`NewBnbRunnerWithMetrics` is removed.

## Internal Design

The existing internal `Acquire(ctx)` abstraction already matches the desired external preparams source shape closely. The implementation should reuse that shape instead of introducing a second internal protocol.

The public service keeps separate references for:

- the internal lifecycle-managed preparams pool
- the optional external preparams source

The DKG path selects a provider in this order:

1. If an external preparams source is configured, call `Acquire(ctx)` on it.
2. Otherwise, use the existing internal preparams pool behavior.

Only the internal pool participates in service lifecycle methods:

- `StartPreParamsPool`
- `StopPreParamsPool`
- `Snapshot`

Supplying an external preparams source does not change lifecycle ownership. Core consumes the source but does not manage its storage, generation, or cleanup strategy.

The `tss` service constructor should build the internal runner through the new option-based runner API, passing metrics through a runner option instead of selecting a dedicated constructor.

## Behavioral Rules

- ECDSA DKG continues attaching preparams before starting the runner.
- If a DKG job already has preparams attached, no new acquisition occurs.
- If an external source is set, it is used even if the internal pool also exists.
- If no external source is set, behavior remains unchanged.
- Sign flows are unaffected.

## Error Handling

- Any `Acquire(ctx)` error from the external source is returned from DKG setup exactly as pool acquisition errors are today.
- Context cancellation and timeout behavior remain driven by the caller's context or by the existing internal pool when it is used.

## Testing

Add tests covering:

- service with external source uses that source for DKG preparams
- service without external source continues using the existing pool path
- two services can be created with different sources and acquire independently
- default `NewBnbService(logger)` preserves current behavior when no options are supplied
- option-based construction can provide config, share store, and metrics after removal of the legacy constructor
- internal runner default construction preserves current behavior when no options are supplied
- internal runner can be constructed with metrics via an option after removal of `NewBnbRunnerWithMetrics`

## Risks

- Removing the legacy constructor is a breaking public API change for callers using it directly.
- Option precedence must be explicit and stable, especially when both pool config and external source are present.
- Snapshot and lifecycle behavior must continue to describe the internal pool only, otherwise metrics semantics become ambiguous.
- The internal runner option names should avoid confusion with the public service option types.
