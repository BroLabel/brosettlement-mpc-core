package preparams

import (
	"context"
	"errors"
	"io"
	"log/slog"
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
	waitFor(t, 500*time.Millisecond, func() bool { return pool.Size() == 1 })

	_, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	waitFor(t, 500*time.Millisecond, func() bool { return pool.Size() == 1 })
	if generated.Load() < 2 {
		t.Fatalf("expected refill generation, got %d", generated.Load())
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
