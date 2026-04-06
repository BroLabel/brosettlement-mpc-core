# PreParams Source Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add external preparams source injection to `tss.NewBnbService`, preserve default internal pool behavior, and remove legacy expanded constructors in both `tss` and `internal/tssbnb/runner`.

**Architecture:** Convert both service and runner construction to option-based APIs. The public `tss` layer accepts an optional `PreParamsSource` and passes metrics/share-store/config through options, while the internal service keeps separate references for the lifecycle-managed pool and the optional external source. DKG attaches preparams from the external source when present and otherwise falls back to the existing pool.

**Tech Stack:** Go, `testing`, `tss-lib`, `slog`

---

### Task 1: Lock Public Service Constructor Shape

**Files:**
- Modify: `tss/service_test.go`
- Modify: `tss/service.go`
- Test: `tss/service_test.go`

- [ ] **Step 1: Write the failing tests**

```go
func TestNewBnbServiceReturnsFacadeWithoutOptions(t *testing.T) {
	svc := NewBnbService(slog.Default())
	if svc == nil {
		t.Fatal("expected non-nil facade")
	}
}

func TestNewBnbServiceAcceptsOptionalConfigShareStoreAndMetrics(t *testing.T) {
	store := newStubShareStore()
	metrics := &stubMetrics{}

	svc := NewBnbService(
		slog.Default(),
		WithPreParamsConfig(PreParamsConfig{Enabled: false, TargetSize: 1, MaxConcurrency: 1}),
		WithShareStore(store),
		WithMetrics(metrics),
	)
	if svc == nil {
		t.Fatal("expected non-nil facade")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `GOCACHE=/tmp/go-build go test ./tss -run 'TestNewBnbServiceReturnsFacadeWithoutOptions|TestNewBnbServiceAcceptsOptionalConfigShareStoreAndMetrics' -count=1`
Expected: FAIL with unknown `WithPreParamsConfig` / `WithShareStore` / `WithMetrics` symbols or mismatched `NewBnbService` signature.

- [ ] **Step 3: Write minimal implementation**

```go
type ServiceOption func(*serviceOptions)

type serviceOptions struct {
	preParamsConfig *PreParamsConfig
	shareStore      ShareStore
	metrics         bnbutils.Metrics
	preParamsSource PreParamsSource
}

func WithPreParamsConfig(cfg PreParamsConfig) ServiceOption {
	cfg = normalizePreParamsConfig(cfg)
	return func(o *serviceOptions) {
		o.preParamsConfig = &cfg
	}
}

func WithShareStore(store ShareStore) ServiceOption {
	return func(o *serviceOptions) {
		o.shareStore = store
	}
}

func WithMetrics(metrics bnbutils.Metrics) ServiceOption {
	return func(o *serviceOptions) {
		o.metrics = metrics
	}
}

func NewBnbService(logger *slog.Logger, opts ...ServiceOption) *Service {
	options := applyServiceOptions(opts)
	cfg := LoadPreParamsConfigFromEnv()
	if options.preParamsConfig != nil {
		cfg = *options.preParamsConfig
	}
	pool := preparams.NewPool(logger, preparams.Config{ /* map cfg fields */ })
	runner := tssbnbrunner.NewBnbRunner(logger, tssbnbrunner.WithMetrics(options.metrics))
	return newService(runner, logger, pool, options.shareStore, options.preParamsSource)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `GOCACHE=/tmp/go-build go test ./tss -run 'TestNewBnbServiceReturnsFacadeWithoutOptions|TestNewBnbServiceAcceptsOptionalConfigShareStoreAndMetrics' -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tss/service.go tss/service_test.go
git commit -m "refactor: switch tss service to option-based constructor"
```

### Task 2: Add Public External PreParams Source Option

**Files:**
- Modify: `tss/service.go`
- Modify: `tss/service_test.go`
- Test: `tss/service_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestNewBnbServiceAcceptsPreParamsSourceOption(t *testing.T) {
	source := &stubPreParamsSource{}

	svc := NewBnbService(slog.Default(), WithPreParamsSource(source))
	if svc == nil {
		t.Fatal("expected non-nil facade")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOCACHE=/tmp/go-build go test ./tss -run TestNewBnbServiceAcceptsPreParamsSourceOption -count=1`
Expected: FAIL with unknown `PreParamsSource` or `WithPreParamsSource`.

- [ ] **Step 3: Write minimal implementation**

```go
type PreParamsSource interface {
	Acquire(ctx context.Context) (*ecdsakeygen.LocalPreParams, error)
}

func WithPreParamsSource(source PreParamsSource) ServiceOption {
	return func(o *serviceOptions) {
		o.preParamsSource = source
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `GOCACHE=/tmp/go-build go test ./tss -run TestNewBnbServiceAcceptsPreParamsSourceOption -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tss/service.go tss/service_test.go
git commit -m "feat: add public preparams source option"
```

### Task 3: Route DKG Through External Source When Present

**Files:**
- Modify: `internal/tss/service/orchestration.go`
- Modify: `internal/tss/service/state.go`
- Modify: `tss/service.go`
- Create: `internal/tss/service/orchestration_test.go`
- Test: `internal/tss/service/orchestration_test.go`

- [ ] **Step 1: Write the failing tests**

```go
func TestRunDKGSessionUsesExternalPreParamsSourceWhenConfigured(t *testing.T) {
	source := &stubPreParamsSource{result: &ecdsakeygen.LocalPreParams{}}
	runner := &stubRunner{}
	svc := New(runner, slog.Default(), &stubLifecyclePool{}, nil, source)

	err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID: "session-1",
		LocalPartyID: "p1",
		OrgID: "org-1",
		Parties: []string{"p1", "p2", "p3"},
		Threshold: 2,
		Algorithm: "ecdsa",
		Transport: stubTransport{},
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if source.calls != 1 {
		t.Fatalf("expected external source to be used once, got %d", source.calls)
	}
	if runner.lastDKGJob.ECDSAPreParams == nil {
		t.Fatal("expected DKG job to receive preparams from external source")
	}
}

func TestRunDKGSessionFallsBackToPoolWithoutExternalSource(t *testing.T) {
	pool := &stubLifecyclePool{result: &ecdsakeygen.LocalPreParams{}}
	runner := &stubRunner{}
	svc := New(runner, slog.Default(), pool, nil, nil)

	err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID: "session-1",
		LocalPartyID: "p1",
		OrgID: "org-1",
		Parties: []string{"p1", "p2", "p3"},
		Threshold: 2,
		Algorithm: "ecdsa",
		Transport: stubTransport{},
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if pool.calls != 1 {
		t.Fatalf("expected pool Acquire to be used once, got %d", pool.calls)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `GOCACHE=/tmp/go-build go test ./internal/tss/service -run 'TestRunDKGSessionUsesExternalPreParamsSourceWhenConfigured|TestRunDKGSessionFallsBackToPoolWithoutExternalSource' -count=1`
Expected: FAIL because `Service` does not yet accept/store an external source and `New` has the wrong signature.

- [ ] **Step 3: Write minimal implementation**

```go
type Service struct {
	runner           Runner
	logger           *slog.Logger
	preParamsPool    LifecyclePool
	preParamsSource  PreParamsPool
	shareStore       ShareStore
}

func New(r Runner, logger *slog.Logger, pool LifecyclePool, shareStore ShareStore, source PreParamsPool) *Service {
	// initialize fields
}

func (s *Service) dkgPreParamsProvider() PreParamsPool {
	if s.preParamsSource != nil {
		return s.preParamsSource
	}
	return s.preParamsPool
}

func (s *Service) RunDKGSession(ctx context.Context, in DKGInput) error {
	// ...
	err := AttachPreParams(ctx, s.dkgPreParamsProvider(), &job, tssutils.IsECDSA(job.Algorithm))
	// ...
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `GOCACHE=/tmp/go-build go test ./internal/tss/service -run 'TestRunDKGSessionUsesExternalPreParamsSourceWhenConfigured|TestRunDKGSessionFallsBackToPoolWithoutExternalSource' -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/tss/service/orchestration.go internal/tss/service/state.go internal/tss/service/orchestration_test.go tss/service.go
git commit -m "feat: use external preparams source for dkg"
```

### Task 4: Prove Service Isolation Across Different Sources

**Files:**
- Modify: `tss/service_test.go`
- Test: `tss/service_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestNewBnbServiceAllowsIndependentPreParamsSources(t *testing.T) {
	sourceA := &stubPreParamsSource{}
	sourceB := &stubPreParamsSource{}

	svcA := NewBnbService(slog.Default(), WithPreParamsSource(sourceA))
	svcB := NewBnbService(slog.Default(), WithPreParamsSource(sourceB))
	if svcA == nil || svcB == nil {
		t.Fatal("expected both services to be constructed")
	}
	if sourceA == sourceB {
		t.Fatal("expected distinct sources")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOCACHE=/tmp/go-build go test ./tss -run TestNewBnbServiceAllowsIndependentPreParamsSources -count=1`
Expected: FAIL only if constructor/options are still not wired correctly.

- [ ] **Step 3: Write minimal implementation**

```go
func applyServiceOptions(opts []ServiceOption) serviceOptions {
	var out serviceOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&out)
		}
	}
	return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `GOCACHE=/tmp/go-build go test ./tss -run TestNewBnbServiceAllowsIndependentPreParamsSources -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tss/service.go tss/service_test.go
git commit -m "test: cover independent service preparams sources"
```

### Task 5: Remove Legacy Runner Constructor

**Files:**
- Modify: `internal/tssbnb/runner/bnb_runner.go`
- Create: `internal/tssbnb/runner/bnb_runner_test.go`
- Test: `internal/tssbnb/runner/bnb_runner_test.go`

- [ ] **Step 1: Write the failing tests**

```go
func TestNewBnbRunnerSupportsMetricsOption(t *testing.T) {
	runner := NewBnbRunner(slog.Default(), WithMetrics(&stubMetrics{}))
	if runner == nil {
		t.Fatal("expected non-nil runner")
	}
}

func TestNewBnbRunnerUsesDefaultsWithoutOptions(t *testing.T) {
	runner := NewBnbRunner(slog.Default())
	if runner == nil {
		t.Fatal("expected non-nil runner")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `GOCACHE=/tmp/go-build go test ./internal/tssbnb/runner -run 'TestNewBnbRunnerSupportsMetricsOption|TestNewBnbRunnerUsesDefaultsWithoutOptions' -count=1`
Expected: FAIL because `NewBnbRunner` does not accept options and `WithMetrics` is not defined in this package.

- [ ] **Step 3: Write minimal implementation**

```go
type Option func(*options)

type options struct {
	metrics bnbutils.Metrics
	config  tssbnbutils.RunnerConfig
}

func WithMetrics(metrics bnbutils.Metrics) Option {
	return func(o *options) {
		o.metrics = metrics
	}
}

func WithConfig(cfg tssbnbutils.RunnerConfig) Option {
	return func(o *options) {
		o.config = cfg
	}
}

func NewBnbRunner(logger *slog.Logger, opts ...Option) *BnbRunner {
	options := applyOptions(opts)
	return newBnbRunner(logger, options.metrics, options.config)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `GOCACHE=/tmp/go-build go test ./internal/tssbnb/runner -run 'TestNewBnbRunnerSupportsMetricsOption|TestNewBnbRunnerUsesDefaultsWithoutOptions' -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/tssbnb/runner/bnb_runner.go internal/tssbnb/runner/bnb_runner_test.go
git commit -m "refactor: switch bnb runner to option-based constructor"
```

### Task 6: Update Construction Call Sites And Run Focused Verification

**Files:**
- Modify: `tss/service.go`
- Modify: `README.md`
- Test: `tss/service_test.go`
- Test: `internal/tss/service/orchestration_test.go`
- Test: `internal/tssbnb/runner/bnb_runner_test.go`

- [ ] **Step 1: Write the failing test or doc expectation**

```go
func TestNewBnbServiceDefaultSnapshotRemainsZeroValue(t *testing.T) {
	svc := NewBnbService(slog.Default())
	if got := svc.Snapshot(); got != (Snapshot{}) {
		t.Fatalf("expected zero-value snapshot, got %+v", got)
	}
}
```

Update `README.md` example to:

```go
_ = tss.NewBnbService(logger)
```

- [ ] **Step 2: Run focused verification**

Run: `GOCACHE=/tmp/go-build go test ./tss ./internal/tss/service ./internal/tssbnb/runner -count=1`
Expected: FAIL until all call sites and constructor signatures are aligned.

- [ ] **Step 3: Write minimal implementation**

```go
runner := tssbnbrunner.NewBnbRunner(logger, tssbnbrunner.WithMetrics(options.metrics))
return newService(runner, logger, pool, options.shareStore, options.preParamsSource)
```

Remove:

```go
func NewBnbServiceWithConfigAndShareStoreAndMetrics(...)
func NewBnbRunnerWithMetrics(...)
```

- [ ] **Step 4: Run focused verification**

Run: `GOCACHE=/tmp/go-build go test ./tss ./internal/tss/service ./internal/tssbnb/runner -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add README.md tss/service.go tss/service_test.go internal/tss/service/orchestration.go internal/tss/service/orchestration_test.go internal/tssbnb/runner/bnb_runner.go internal/tssbnb/runner/bnb_runner_test.go
git commit -m "feat: inject external preparams source into tss service"
```

### Task 7: Full Verification

**Files:**
- Test: `./tss`
- Test: `./internal/tss/service`
- Test: `./internal/tssbnb/runner`

- [ ] **Step 1: Run targeted package tests**

Run: `GOCACHE=/tmp/go-build go test ./tss ./internal/tss/service ./internal/tssbnb/runner -count=1`
Expected: PASS

- [ ] **Step 2: Run full repository verification**

Run: `GOCACHE=/tmp/go-build go test ./... -count=1`
Expected: PASS

- [ ] **Step 3: Commit final verification state**

```bash
git add tss/service.go tss/service_test.go internal/tss/service/orchestration.go internal/tss/service/orchestration_test.go internal/tss/service/state.go internal/tssbnb/runner/bnb_runner.go internal/tssbnb/runner/bnb_runner_test.go README.md docs/superpowers/specs/2026-04-06-preparams-source-design.md docs/superpowers/plans/2026-04-06-preparams-source-implementation.md
git commit -m "test: verify preparams source constructor cleanup"
```
