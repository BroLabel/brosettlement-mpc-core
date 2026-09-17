package preparams

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

func TestPoolAcquireSuccess(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TargetSize = 1
	cfg.MaxConcurrency = 1
	cfg.AcquireTimeout = 200 * time.Millisecond
	cfg.GenerateTimeout = 200 * time.Millisecond
	cfg.SyncFallbackOnEmpty = false

	pool := newPoolForTest(testLogger(), cfg,
		func(ctx context.Context) (*ecdsakeygen.LocalPreParams, error) {
			return &ecdsakeygen.LocalPreParams{}, nil
		},
		func(params *ecdsakeygen.LocalPreParams) bool { return params != nil },
	)
	defer func() { _ = pool.Close() }()
	if err := pool.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitFor(t, 500*time.Millisecond, func() bool { return pool.Size() > 0 })

	got, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if got == nil {
		t.Fatalf("Acquire() returned nil")
	}
}

func TestPoolTryAcquireReturnsImmediatelyWhenEmpty(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TargetSize = 1
	pool := newPoolForTest(testLogger(), cfg, nil, func(params *ecdsakeygen.LocalPreParams) bool { return params != nil })

	started := time.Now()
	_, err := pool.TryAcquire(context.Background())
	if !errors.Is(err, ErrPoolEmpty) {
		t.Fatalf("TryAcquire() error = %v, want ErrPoolEmpty", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("TryAcquire() blocked for %s", elapsed)
	}
}

func TestPoolTryAcquirePreservesDisabledPoolSynchronousGeneration(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	pool := newPoolForTest(
		testLogger(),
		cfg,
		func(context.Context) (*ecdsakeygen.LocalPreParams, error) { return &ecdsakeygen.LocalPreParams{}, nil },
		func(params *ecdsakeygen.LocalPreParams) bool { return params != nil },
	)

	got, err := pool.TryAcquire(context.Background())
	if err != nil || got == nil {
		t.Fatalf("TryAcquire() = (%v, %v), want generated pre-params", got, err)
	}
}

func TestPoolTryAcquireDoesNotConsumeWhenContextIsCanceled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TargetSize = 1
	cfg.MaxConcurrency = 1
	pool := newPoolForTest(
		testLogger(),
		cfg,
		func(context.Context) (*ecdsakeygen.LocalPreParams, error) { return &ecdsakeygen.LocalPreParams{}, nil },
		func(params *ecdsakeygen.LocalPreParams) bool { return params != nil },
	)
	defer func() { _ = pool.Close() }()
	if err := pool.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitFor(t, 500*time.Millisecond, func() bool { return pool.Size() == 1 })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := pool.TryAcquire(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("TryAcquire() error = %v, want context.Canceled", err)
	}
	if got := pool.Size(); got != 1 {
		t.Fatalf("pool size after canceled acquire = %d, want 1", got)
	}
}

func TestPoolWaitOnEmpty(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TargetSize = 1
	cfg.MaxConcurrency = 1
	cfg.AcquireTimeout = 60 * time.Millisecond
	cfg.SyncFallbackOnEmpty = false

	pool := newPoolForTest(testLogger(), cfg,
		func(ctx context.Context) (*ecdsakeygen.LocalPreParams, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(300 * time.Millisecond):
				return &ecdsakeygen.LocalPreParams{}, nil
			}
		},
		func(params *ecdsakeygen.LocalPreParams) bool { return params != nil },
	)
	defer func() { _ = pool.Close() }()
	if err := pool.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	_, err := pool.Acquire(context.Background())
	if err == nil {
		t.Fatalf("Acquire() expected timeout error")
	}
}

func TestPoolRefillAfterConsume(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TargetSize = 1
	cfg.MaxConcurrency = 1
	cfg.AcquireTimeout = 200 * time.Millisecond

	var generated atomic.Int32
	pool := newPoolForTest(testLogger(), cfg,
		func(ctx context.Context) (*ecdsakeygen.LocalPreParams, error) {
			generated.Add(1)
			return &ecdsakeygen.LocalPreParams{}, nil
		},
		func(params *ecdsakeygen.LocalPreParams) bool { return true },
	)
	defer func() { _ = pool.Close() }()
	if err := pool.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitFor(t, 500*time.Millisecond, func() bool {
		snapshot := pool.Snapshot()
		return snapshot.Size == 1 && snapshot.InFlight == 0
	})

	_, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	waitFor(t, 500*time.Millisecond, func() bool { return pool.Size() == 1 })
	if generated.Load() < 2 {
		t.Fatalf("expected refill generation, got %d", generated.Load())
	}
}

func TestPoolGenerationParallelismIsExplicitAndSupportsOne(t *testing.T) {
	originalGOMAXPROCS := runtime.GOMAXPROCS(1)
	t.Cleanup(func() {
		runtime.GOMAXPROCS(originalGOMAXPROCS)
	})

	cfg := DefaultConfig()
	cfg.GenerationParallelism = 1
	pool := NewPool(testLogger(), cfg)

	var gotParallelism atomic.Int32
	pool.generatePreParams = func(_ context.Context, parallelism int) (*ecdsakeygen.LocalPreParams, error) {
		gotParallelism.Store(int32(parallelism))
		return &ecdsakeygen.LocalPreParams{}, nil
	}

	if _, err := pool.defaultGenerator(context.Background()); err != nil {
		t.Fatalf("defaultGenerator() error = %v", err)
	}
	if got := gotParallelism.Load(); got != 1 {
		t.Fatalf("generation parallelism = %d, want explicit value 1", got)
	}
}

func TestPoolGenerationParallelismDoesNotFollowGOMAXPROCS(t *testing.T) {
	originalGOMAXPROCS := runtime.GOMAXPROCS(8)
	t.Cleanup(func() {
		runtime.GOMAXPROCS(originalGOMAXPROCS)
	})

	cfg := DefaultConfig()
	cfg.GenerationParallelism = 3
	pool := NewPool(testLogger(), cfg)

	var gotParallelism atomic.Int32
	pool.generatePreParams = func(_ context.Context, parallelism int) (*ecdsakeygen.LocalPreParams, error) {
		gotParallelism.Store(int32(parallelism))
		return &ecdsakeygen.LocalPreParams{}, nil
	}

	if _, err := pool.defaultGenerator(context.Background()); err != nil {
		t.Fatalf("defaultGenerator() error = %v", err)
	}
	if got := gotParallelism.Load(); got != 3 {
		t.Fatalf("generation parallelism = %d, want configured value 3", got)
	}
}

func TestPoolAcquireDoesNotTriggerRefillWhenDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TargetSize = 1
	cfg.MaxConcurrency = 1
	cfg.AutoRefillOnAcquire = false
	cfg.SyncFallbackOnEmpty = false

	var calls atomic.Int32
	unexpectedRefill := make(chan struct{}, 1)
	pool := newPoolForTest(testLogger(), cfg,
		func(ctx context.Context) (*ecdsakeygen.LocalPreParams, error) {
			if calls.Add(1) > 1 {
				unexpectedRefill <- struct{}{}
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return &ecdsakeygen.LocalPreParams{}, nil
		},
		func(params *ecdsakeygen.LocalPreParams) bool { return params != nil },
	)
	defer func() { _ = pool.Close() }()

	if err := pool.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitFor(t, 500*time.Millisecond, func() bool { return pool.Size() == 1 })
	if _, err := pool.Acquire(context.Background()); err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}

	select {
	case <-unexpectedRefill:
		t.Fatal("Acquire() started a refill while AutoRefillOnAcquire was disabled")
	case <-time.After(2200 * time.Millisecond):
	}
	if snapshot := pool.Snapshot(); snapshot.InFlight != 0 || snapshot.GenerationsSuccess != 1 {
		t.Fatalf("snapshot after acquire = %+v, want no refill transition", snapshot)
	}
}

func TestPoolRefillPauseDuringTwoActiveRuntimesAndIdempotentResume(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TargetSize = 2
	cfg.MaxConcurrency = 1
	cfg.AutoRefillOnAcquire = false
	cfg.SyncFallbackOnEmpty = false

	var calls atomic.Int32
	pool := newPoolForTest(testLogger(), cfg,
		func(context.Context) (*ecdsakeygen.LocalPreParams, error) {
			calls.Add(1)
			return &ecdsakeygen.LocalPreParams{}, nil
		},
		func(params *ecdsakeygen.LocalPreParams) bool { return params != nil },
	)
	defer func() { _ = pool.Close() }()

	if err := pool.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitFor(t, 500*time.Millisecond, func() bool {
		snapshot := pool.Snapshot()
		return snapshot.Size == 2 && snapshot.InFlight == 0
	})

	const pauses = 16
	var pauseWG sync.WaitGroup
	pauseWG.Add(pauses)
	for i := 0; i < pauses; i++ {
		go func() {
			defer pauseWG.Done()
			pool.PauseRefill()
		}()
	}
	pauseWG.Wait()
	if _, err := pool.Acquire(context.Background()); err != nil {
		t.Fatalf("Acquire() B error = %v", err)
	}
	if _, err := pool.Acquire(context.Background()); err != nil {
		t.Fatalf("Acquire() C error = %v", err)
	}
	pool.signalRefill()

	select {
	case <-time.After(100 * time.Millisecond):
		if got := calls.Load(); got != 2 {
			t.Fatalf("generation calls while two runtimes active = %d, want 2", got)
		}
	}
	paused := pool.Snapshot()
	if !paused.RefillPaused {
		t.Fatalf("paused refill state = %+v, want paused", paused)
	}
	if paused.Size != 0 || paused.InFlight != 0 || paused.GenerationsSuccess != 2 {
		t.Fatalf("paused generation metrics = %+v, want empty idle pool", paused)
	}

	const resumes = 16
	var wg sync.WaitGroup
	wg.Add(resumes)
	for i := 0; i < resumes; i++ {
		go func() {
			defer wg.Done()
			pool.ResumeRefill()
		}()
	}
	wg.Wait()
	waitFor(t, 500*time.Millisecond, func() bool {
		snapshot := pool.Snapshot()
		return snapshot.Size == 2 && snapshot.InFlight == 0
	})

	resumed := pool.Snapshot()
	if resumed.RefillPaused {
		t.Fatalf("resumed refill state = %+v, want active", resumed)
	}
	if resumed.GenerationsSuccess != 4 || calls.Load() != 4 {
		t.Fatalf("generation transitions after resume = success:%d calls:%d, want 4:4",
			resumed.GenerationsSuccess, calls.Load())
	}
}

func TestPoolPauseRefillAllowsExistingGenerationToFinish(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TargetSize = 2
	cfg.MaxConcurrency = 1

	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	pool := newPoolForTest(testLogger(), cfg,
		func(context.Context) (*ecdsakeygen.LocalPreParams, error) {
			if calls.Add(1) == 1 {
				close(started)
				<-release
			}
			return &ecdsakeygen.LocalPreParams{}, nil
		},
		func(params *ecdsakeygen.LocalPreParams) bool { return params != nil },
	)
	defer func() { _ = pool.Close() }()

	if err := pool.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	<-started
	pool.PauseRefill()
	close(release)

	waitFor(t, 500*time.Millisecond, func() bool {
		snapshot := pool.Snapshot()
		return snapshot.Size == 1 && snapshot.InFlight == 0
	})
	snapshot := pool.Snapshot()
	if !snapshot.RefillPaused || snapshot.GenerationsSuccess != 1 || snapshot.GenerationsFailed != 0 {
		t.Fatalf("snapshot after in-flight completion = %+v", snapshot)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("generation calls after pausing an in-flight fill = %d, want 1", got)
	}
}

func TestPoolCloseStopsWorkers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TargetSize = 2
	cfg.MaxConcurrency = 2

	pool := newPoolForTest(testLogger(), cfg,
		func(ctx context.Context) (*ecdsakeygen.LocalPreParams, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		func(params *ecdsakeygen.LocalPreParams) bool { return true },
	)
	if err := pool.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := pool.Acquire(context.Background()); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("Acquire() err = %v, want ErrPoolClosed", err)
	}
	if snapshot := pool.Snapshot(); snapshot.AcquireCount != 0 || snapshot.AcquireFailedCount != 1 {
		t.Fatalf("closed acquire metrics = success:%d failed:%d, want 0:1", snapshot.AcquireCount, snapshot.AcquireFailedCount)
	}
}

func TestPoolCloseDoesNotCountCanceledGenerationAsFailure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TargetSize = 1
	cfg.MaxConcurrency = 1

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	started := make(chan struct{})
	pool := newPoolForTest(logger, cfg,
		func(ctx context.Context) (*ecdsakeygen.LocalPreParams, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
		func(params *ecdsakeygen.LocalPreParams) bool { return true },
	)

	if err := pool.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	<-started
	if err := pool.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	snapshot := pool.Snapshot()
	if snapshot.GenerationsFailed != 0 {
		t.Fatalf("GenerationsFailed = %d, want 0", snapshot.GenerationsFailed)
	}
	if strings.Contains(logs.String(), "preparams generation failed") {
		t.Fatalf("unexpected generation failure log: %s", logs.String())
	}
}

func TestPoolGenerationErrorRetry(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TargetSize = 1
	cfg.MaxConcurrency = 1
	cfg.RetryBackoff = 10 * time.Millisecond
	cfg.AcquireTimeout = 500 * time.Millisecond
	cfg.SyncFallbackOnEmpty = false

	var attempts atomic.Int32
	pool := newPoolForTest(testLogger(), cfg,
		func(ctx context.Context) (*ecdsakeygen.LocalPreParams, error) {
			if attempts.Add(1) < 3 {
				return nil, errors.New("boom")
			}
			return &ecdsakeygen.LocalPreParams{}, nil
		},
		func(params *ecdsakeygen.LocalPreParams) bool { return true },
	)
	defer func() { _ = pool.Close() }()
	if err := pool.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	_, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if attempts.Load() < 3 {
		t.Fatalf("attempts = %d, want >=3", attempts.Load())
	}
}

func TestPoolAcquireWithoutStartFallsBackImmediately(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TargetSize = 1
	cfg.MaxConcurrency = 1
	cfg.AcquireTimeout = 200 * time.Millisecond
	cfg.SyncFallbackOnEmpty = true

	var calls atomic.Int32
	pool := newPoolForTest(testLogger(), cfg,
		func(ctx context.Context) (*ecdsakeygen.LocalPreParams, error) {
			calls.Add(1)
			return &ecdsakeygen.LocalPreParams{}, nil
		},
		func(params *ecdsakeygen.LocalPreParams) bool { return params != nil },
	)
	defer func() { _ = pool.Close() }()

	started := time.Now()
	got, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if got == nil {
		t.Fatal("Acquire() returned nil")
	}
	if calls.Load() != 1 {
		t.Fatalf("generator calls = %d, want 1", calls.Load())
	}
	if elapsed := time.Since(started); elapsed >= cfg.AcquireTimeout/2 {
		t.Fatalf("Acquire() took %s, want immediate fallback without waiting for timeout %s", elapsed, cfg.AcquireTimeout)
	}
}

func TestPoolConcurrentAcquire(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TargetSize = 3
	cfg.MaxConcurrency = 2
	cfg.AcquireTimeout = 300 * time.Millisecond
	cfg.SyncFallbackOnEmpty = true

	pool := newPoolForTest(testLogger(), cfg,
		func(ctx context.Context) (*ecdsakeygen.LocalPreParams, error) {
			return &ecdsakeygen.LocalPreParams{}, nil
		},
		func(params *ecdsakeygen.LocalPreParams) bool { return true },
	)
	defer func() { _ = pool.Close() }()
	if err := pool.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	const n = 8
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := pool.Acquire(context.Background())
			errCh <- err
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("Acquire() error = %v", err)
		}
	}
}

func TestPoolDurableAcquireOrdersValidationBeforeUnlinkAndDirectorySync(t *testing.T) {
	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "fake-material.gob")
	if err := os.WriteFile(cachePath, []byte("non-secret-test-material"), 0o600); err != nil {
		t.Fatalf("write cache entry: %v", err)
	}

	var events []string
	fs := &recordingCacheFS{
		cacheFS: newOSCacheFS(),
		onRemove: func(path string) {
			if path == cachePath {
				events = append(events, "unlink")
			}
		},
		onSyncDir: func(path string) {
			if path == cacheDir {
				events = append(events, "directory-sync")
			}
		},
	}
	pool := newPoolForTest(testLogger(), acquireTestConfig(cacheDir), nil,
		func(params *ecdsakeygen.LocalPreParams) bool {
			events = append(events, "validate")
			return params != nil
		},
	)
	pool.fs = fs
	pool.runCtx = context.Background()
	pool.ch <- item{params: &ecdsakeygen.LocalPreParams{}, cachePath: cachePath}

	got, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if got == nil {
		t.Fatal("Acquire() returned nil")
	}
	if want := []string{"validate", "unlink", "directory-sync"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	if _, err := os.Stat(cachePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache entry still exists or stat failed unexpectedly: %v", err)
	}
	snapshot := pool.Snapshot()
	if snapshot.AcquireCount != 1 || snapshot.AcquireFailedCount != 0 {
		t.Fatalf("acquire metrics = success:%d failed:%d, want 1:0", snapshot.AcquireCount, snapshot.AcquireFailedCount)
	}
}

func TestPoolAcquireFailuresNeverReturnOrRequeueMaterial(t *testing.T) {
	unlinkErr := errors.New("unlink unavailable")
	syncErr := errors.New("directory sync unavailable")

	tests := []struct {
		name       string
		cacheFile  bool
		cachePath  bool
		validate   bool
		removeErr  error
		syncDirErr error
		wantErr    error
	}{
		{name: "validation", cacheFile: true, cachePath: true, validate: false, wantErr: ErrInvalidCachedPreParams},
		{name: "missing cache binding", validate: true, wantErr: ErrCachePathRequired},
		{name: "missing", cachePath: true, validate: true, wantErr: os.ErrNotExist},
		{name: "unlink", cacheFile: true, cachePath: true, validate: true, removeErr: unlinkErr, wantErr: unlinkErr},
		{name: "directory sync", cacheFile: true, cachePath: true, validate: true, syncDirErr: syncErr, wantErr: syncErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			cachePath := filepath.Join(cacheDir, "fake-material.gob")
			if tt.cacheFile {
				if err := os.WriteFile(cachePath, []byte("non-secret-test-material"), 0o600); err != nil {
					t.Fatalf("write cache entry: %v", err)
				}
			}

			fs := &recordingCacheFS{
				cacheFS:   newOSCacheFS(),
				removeErr: tt.removeErr,
				syncDirErr: func(path string) error {
					if path == cacheDir {
						return tt.syncDirErr
					}
					return nil
				},
			}
			pool := newPoolForTest(testLogger(), acquireTestConfig(cacheDir), nil,
				func(params *ecdsakeygen.LocalPreParams) bool {
					return tt.validate && params != nil
				},
			)
			pool.fs = fs
			pool.runCtx = context.Background()
			queuedPath := ""
			if tt.cachePath {
				queuedPath = cachePath
			}
			pool.ch <- item{params: &ecdsakeygen.LocalPreParams{}, cachePath: queuedPath}

			got, err := pool.Acquire(context.Background())
			if got != nil {
				t.Fatal("Acquire() returned material on failure")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Acquire() error = %v, want %v", err, tt.wantErr)
			}
			if pool.Size() != 0 {
				t.Fatalf("pool size = %d, want failed entry permanently dequeued", pool.Size())
			}
			snapshot := pool.Snapshot()
			if snapshot.AcquireCount != 0 || snapshot.AcquireFailedCount != 1 {
				t.Fatalf("acquire metrics = success:%d failed:%d, want 0:1", snapshot.AcquireCount, snapshot.AcquireFailedCount)
			}
		})
	}
}

func acquireTestConfig(cacheDir string) Config {
	cfg := DefaultConfig()
	cfg.TargetSize = 1
	cfg.MaxConcurrency = 1
	cfg.AcquireTimeout = 20 * time.Millisecond
	cfg.SyncFallbackOnEmpty = false
	cfg.FileCacheEnabled = true
	cfg.FileCacheDir = cacheDir
	return cfg
}
