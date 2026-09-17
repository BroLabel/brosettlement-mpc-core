package preparams

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	tssutils "github.com/BroLabel/brosettlement-mpc-core/tss/utils"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/google/uuid"
)

var ErrPoolClosed = errors.New("preparams pool is closed")
var ErrPoolEmpty = errors.New("preparams pool is empty")

type Generator func(ctx context.Context) (*ecdsakeygen.LocalPreParams, error)
type Validator func(params *ecdsakeygen.LocalPreParams) bool

type Snapshot struct {
	Size               int
	InFlight           int32
	GenerationsSuccess uint64
	GenerationsFailed  uint64
	AcquireCount       uint64
	AcquireFailedCount uint64
	AcquireWaitNanos   int64
	PoolEmptyCount     uint64
	SyncFallbackCount  uint64
	LastGenerateNanos  int64
	RefillPaused       bool
}

type item struct {
	params    *ecdsakeygen.LocalPreParams
	cachePath string
}

type Pool struct {
	cfg    Config
	logger *slog.Logger

	ch chan item

	gen               Generator
	validate          Validator
	fs                cacheFS
	generatePreParams func(context.Context, int) (*ecdsakeygen.LocalPreParams, error)

	runCtx context.Context
	cancel context.CancelFunc

	startOnce sync.Once
	startErr  error
	closeOnce sync.Once
	wg        sync.WaitGroup

	refillCh chan struct{}
	refillMu sync.Mutex

	closed       atomic.Bool
	refillPaused atomic.Bool

	inFlight          atomic.Int32
	generationsOK     atomic.Uint64
	generationsFailed atomic.Uint64
	acquires          atomic.Uint64
	acquireFailed     atomic.Uint64
	acquireWaitNanos  atomic.Int64
	poolEmpty         atomic.Uint64
	syncFallback      atomic.Uint64
	lastGenerateNanos atomic.Int64
}

func NewPool(logger *slog.Logger, cfg Config) *Pool {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.TargetSize < 1 {
		cfg.TargetSize = 1
	}
	if cfg.MaxConcurrency < 1 {
		cfg.MaxConcurrency = 1
	}
	if cfg.MaxConcurrency > cfg.TargetSize {
		cfg.MaxConcurrency = cfg.TargetSize
	}
	if cfg.GenerationParallelism < 1 {
		cfg.GenerationParallelism = 2
	}
	if cfg.GenerateTimeout <= 0 {
		cfg.GenerateTimeout = 7 * time.Minute
	}
	if cfg.AcquireTimeout <= 0 {
		cfg.AcquireTimeout = 45 * time.Second
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 2 * time.Second
	}
	if cfg.FileCacheDir == "" {
		cfg.FileCacheDir = filepath.Join(".tmp", "tss-preparams")
	}

	p := &Pool{
		cfg:      cfg,
		logger:   logger,
		ch:       make(chan item, cfg.TargetSize),
		refillCh: make(chan struct{}, 1),
		fs:       newOSCacheFS(),
		generatePreParams: func(ctx context.Context, parallelism int) (*ecdsakeygen.LocalPreParams, error) {
			return ecdsakeygen.GeneratePreParamsWithContext(ctx, parallelism)
		},
	}
	p.gen = p.defaultGenerator
	p.validate = func(params *ecdsakeygen.LocalPreParams) bool {
		return params != nil && params.ValidateWithProof()
	}
	return p
}

func newPoolForTest(logger *slog.Logger, cfg Config, gen Generator, validate Validator) *Pool {
	p := NewPool(logger, cfg)
	if gen != nil {
		p.gen = gen
	}
	if validate != nil {
		p.validate = validate
	}
	return p
}

func (p *Pool) Start(ctx context.Context) error {
	if p.closed.Load() {
		return ErrPoolClosed
	}
	p.startOnce.Do(func() {
		if !p.cfg.Enabled {
			p.logger.Info("preparams pool disabled")
			return
		}
		if p.cfg.FileCacheEnabled {
			if err := ensurePrivateCacheDir(p.fs, p.cfg.FileCacheDir); err != nil {
				p.startErr = err
				return
			}
			if err := validateCacheCapabilities(p.fs, p.cfg.FileCacheDir); err != nil {
				p.startErr = err
				return
			}
			if err := p.loadFromCache(p.cfg.TargetSize); err != nil {
				p.startErr = fmt.Errorf("load preparams cache: %w", err)
				return
			}
		}
		// #nosec G118 -- cancel is stored on Pool and called from Close().
		p.runCtx, p.cancel = context.WithCancel(ctx)
		p.logger.Info("preparams pool started",
			"target_size", p.cfg.TargetSize,
			"max_concurrency", p.cfg.MaxConcurrency,
			"generation_parallelism", p.cfg.GenerationParallelism,
			"generate_timeout", p.cfg.GenerateTimeout,
			"acquire_timeout", p.cfg.AcquireTimeout,
			"sync_fallback_on_empty", p.cfg.SyncFallbackOnEmpty,
			"auto_refill_on_acquire", p.cfg.AutoRefillOnAcquire,
		)
		p.wg.Add(1)
		go p.refillLoop()
		p.signalRefill()
	})
	return p.startErr
}

func (p *Pool) Acquire(ctx context.Context) (*ecdsakeygen.LocalPreParams, error) {
	if p.closed.Load() {
		return p.failAcquire(ErrPoolClosed)
	}

	if !p.cfg.Enabled {
		return p.finishSynchronousAcquire(p.syncGenerate(ctx))
	}
	if p.runCtx == nil {
		p.poolEmpty.Add(1)
		if !p.cfg.SyncFallbackOnEmpty {
			return p.failAcquire(fmt.Errorf("acquire preparams from pool: %w", context.DeadlineExceeded))
		}
		p.syncFallback.Add(1)
		p.logger.Warn("preparams pool not started, using sync fallback")
		return p.finishSynchronousAcquire(p.syncGenerate(ctx))
	}

	acquireCtx := ctx
	cancel := func() {}
	if p.cfg.AcquireTimeout > 0 {
		acquireCtx, cancel = context.WithTimeout(ctx, p.cfg.AcquireTimeout)
	}
	defer cancel()

	started := time.Now()
	select {
	case <-acquireCtx.Done():
		p.poolEmpty.Add(1)
		p.acquireWaitNanos.Add(durationToNanos(time.Since(started)))
		if !p.cfg.SyncFallbackOnEmpty {
			return p.failAcquire(fmt.Errorf("acquire preparams from pool: %w", acquireCtx.Err()))
		}
		p.syncFallback.Add(1)
		p.logger.Warn("preparams pool empty, using sync fallback", "err", acquireCtx.Err())
		return p.finishSynchronousAcquire(p.syncGenerate(ctx))
	case it := <-p.ch:
		p.acquireWaitNanos.Add(durationToNanos(time.Since(started)))
		if p.cfg.AutoRefillOnAcquire {
			defer p.signalRefill()
		}
		return p.finishItem(it)
	}
}

func (p *Pool) TryAcquire(ctx context.Context) (*ecdsakeygen.LocalPreParams, error) {
	if err := ctx.Err(); err != nil {
		return p.failAcquire(err)
	}
	if p.closed.Load() {
		return p.failAcquire(ErrPoolClosed)
	}
	if !p.cfg.Enabled {
		return p.finishSynchronousAcquire(p.syncGenerate(ctx))
	}
	select {
	case it := <-p.ch:
		if p.cfg.AutoRefillOnAcquire {
			defer p.signalRefill()
		}
		return p.finishItem(it)
	default:
		p.poolEmpty.Add(1)
		p.signalRefill()
		return p.failAcquire(ErrPoolEmpty)
	}
}

func (p *Pool) finishItem(it item) (*ecdsakeygen.LocalPreParams, error) {
	if !p.validate(it.params) {
		return p.failAcquire(ErrInvalidCachedPreParams)
	}
	if p.cfg.FileCacheEnabled && it.cachePath == "" {
		return p.failAcquire(ErrCachePathRequired)
	}
	if it.cachePath != "" {
		if err := durablyRemoveCacheFile(p.fs, p.cfg.FileCacheDir, it.cachePath); err != nil {
			return p.failAcquire(err)
		}
	}
	p.acquires.Add(1)
	return it.params, nil
}

func (p *Pool) finishSynchronousAcquire(params *ecdsakeygen.LocalPreParams, err error) (*ecdsakeygen.LocalPreParams, error) {
	if err != nil {
		return p.failAcquire(err)
	}
	p.acquires.Add(1)
	return params, nil
}

func (p *Pool) failAcquire(err error) (*ecdsakeygen.LocalPreParams, error) {
	p.acquireFailed.Add(1)
	return nil, err
}

func (p *Pool) Size() int {
	return len(p.ch)
}

func (p *Pool) Snapshot() Snapshot {
	return Snapshot{
		Size:               len(p.ch),
		InFlight:           p.inFlight.Load(),
		GenerationsSuccess: p.generationsOK.Load(),
		GenerationsFailed:  p.generationsFailed.Load(),
		AcquireCount:       p.acquires.Load(),
		AcquireFailedCount: p.acquireFailed.Load(),
		AcquireWaitNanos:   p.acquireWaitNanos.Load(),
		PoolEmptyCount:     p.poolEmpty.Load(),
		SyncFallbackCount:  p.syncFallback.Load(),
		LastGenerateNanos:  p.lastGenerateNanos.Load(),
		RefillPaused:       p.refillPaused.Load(),
	}
}

// PauseRefill prevents new background generation jobs from starting. Generation
// jobs that were already in flight continue to completion.
func (p *Pool) PauseRefill() {
	p.refillMu.Lock()
	defer p.refillMu.Unlock()
	p.refillPaused.CompareAndSwap(false, true)
}

// ResumeRefill re-enables background generation and asynchronously fills any
// inventory deficit. Repeated calls have no effect.
func (p *Pool) ResumeRefill() {
	p.refillMu.Lock()
	resumed := p.refillPaused.CompareAndSwap(true, false)
	p.refillMu.Unlock()
	if resumed {
		p.signalRefill()
	}
}

func (p *Pool) Close() error {
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		if p.cancel != nil {
			p.cancel()
		}
		p.wg.Wait()
	})
	return nil
}

func (p *Pool) refillLoop() {
	defer p.wg.Done()

	for {
		p.ensureRefillWorkers()
		select {
		case <-p.runCtx.Done():
			return
		case <-p.refillCh:
		}
	}
}

func (p *Pool) ensureRefillWorkers() {
	p.refillMu.Lock()
	defer p.refillMu.Unlock()

	for {
		if p.closed.Load() || p.refillPaused.Load() {
			return
		}
		inFlight := int(p.inFlight.Load())
		if inFlight >= p.cfg.MaxConcurrency {
			return
		}
		deficit := p.cfg.TargetSize - (len(p.ch) + inFlight)
		if deficit <= 0 {
			return
		}
		p.inFlight.Add(1)
		p.wg.Add(1)
		go p.generateOne()
	}
}

func (p *Pool) generateOne() {
	defer p.wg.Done()
	defer func() {
		p.inFlight.Add(-1)
		p.signalRefill()
	}()

	if p.runCtx == nil {
		return
	}
	started := time.Now()
	params, err := p.gen(p.runCtx)
	if err != nil {
		if p.runCtx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return
		}
		p.generationsFailed.Add(1)
		p.logger.Warn("preparams generation failed", "err", err)
		p.waitBackoff()
		return
	}
	if !p.validate(params) {
		p.generationsFailed.Add(1)
		p.logger.Warn("preparams validation failed")
		p.waitBackoff()
		return
	}
	p.lastGenerateNanos.Store(time.Since(started).Nanoseconds())

	it := item{params: params}
	if p.cfg.FileCacheEnabled {
		cachePath, err := p.saveToCache(params)
		if err != nil {
			p.generationsFailed.Add(1)
			p.logger.Warn("preparams save cache failed", "err", err)
			p.waitBackoff()
			return
		}
		it.cachePath = cachePath
	}

	select {
	case <-p.runCtx.Done():
		if it.cachePath != "" {
			if err := durablyRemoveCacheFile(p.fs, p.cfg.FileCacheDir, it.cachePath); err != nil {
				p.logger.Warn("preparams cache cleanup failed", "err", err)
			}
		}
		return
	case p.ch <- it:
		p.generationsOK.Add(1)
		p.logger.Debug("preparams generated", "pool_size", len(p.ch), "duration", time.Since(started))
	default:
		if it.cachePath != "" {
			if err := durablyRemoveCacheFile(p.fs, p.cfg.FileCacheDir, it.cachePath); err != nil {
				p.logger.Warn("preparams cache cleanup failed", "err", err)
			}
		}
	}
}

func (p *Pool) syncGenerate(ctx context.Context) (*ecdsakeygen.LocalPreParams, error) {
	started := time.Now()
	params, err := p.gen(ctx)
	if err != nil {
		return nil, err
	}
	if !p.validate(params) {
		return nil, errors.New("generated preparams failed validation")
	}
	p.lastGenerateNanos.Store(time.Since(started).Nanoseconds())
	return params, nil
}

func (p *Pool) defaultGenerator(parent context.Context) (*ecdsakeygen.LocalPreParams, error) {
	ctx := parent
	cancel := func() {}
	if p.cfg.GenerateTimeout > 0 {
		ctx, cancel = context.WithTimeout(parent, p.cfg.GenerateTimeout)
	}
	defer cancel()

	return p.generatePreParams(ctx, p.cfg.GenerationParallelism)
}

func (p *Pool) waitBackoff() {
	if p.cfg.RetryBackoff <= 0 || p.runCtx == nil {
		return
	}
	t := time.NewTimer(p.cfg.RetryBackoff)
	defer t.Stop()
	select {
	case <-p.runCtx.Done():
	case <-t.C:
	}
}

func (p *Pool) signalRefill() {
	select {
	case p.refillCh <- struct{}{}:
	default:
	}
}

func (p *Pool) loadFromCache(max int) error {
	if !p.cfg.FileCacheEnabled {
		return nil
	}
	entries, err := p.fs.ReadDir(p.cfg.FileCacheDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if len(p.ch) >= max {
			break
		}
		if !entry.Type().IsRegular() || filepath.Ext(entry.Name()) != ".gob" {
			continue
		}
		path := filepath.Join(p.cfg.FileCacheDir, entry.Name())
		params, err := loadOne(p.fs, p.cfg.FileCacheDir, path)
		if err != nil || !p.validate(params) {
			if removeErr := durablyRemoveCacheFile(p.fs, p.cfg.FileCacheDir, path); removeErr != nil {
				return fmt.Errorf("remove malformed preparams cache entry: %w", removeErr)
			}
			continue
		}
		select {
		case p.ch <- item{params: params, cachePath: path}:
		default:
			return nil
		}
	}
	return nil
}

func (p *Pool) saveToCache(params *ecdsakeygen.LocalPreParams) (string, error) {
	if !p.cfg.FileCacheEnabled {
		return "", nil
	}
	if err := ensurePrivateCacheDir(p.fs, p.cfg.FileCacheDir); err != nil {
		return "", err
	}
	path := filepath.Join(p.cfg.FileCacheDir, uuid.NewString()+".gob")
	path, err := tssutils.SafePathUnderDir(p.cfg.FileCacheDir, path)
	if err != nil {
		return "", err
	}
	if err := publishCacheFile(p.fs, p.cfg.FileCacheDir, path, func(writer io.Writer) error {
		return gob.NewEncoder(writer).Encode(params)
	}); err != nil {
		return "", err
	}
	return path, nil
}

func loadOne(fs cacheFS, baseDir, path string) (*ecdsakeygen.LocalPreParams, error) {
	safePath, err := tssutils.SafePathUnderDir(baseDir, path)
	if err != nil {
		return nil, err
	}
	f, err := fs.Open(safePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var p ecdsakeygen.LocalPreParams
	if err := gob.NewDecoder(f).Decode(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

func durationToNanos(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return d.Nanoseconds()
}
