package execution

import (
	"context"
	"sync/atomic"

	"golang.org/x/sync/errgroup"
)

type sessionRuntime struct {
	Ctx      context.Context
	cancel   context.CancelFunc
	Group    *errgroup.Group
	Events   chan protocolEvent
	stopping atomic.Bool

	workersDone chan struct{}
	workerErr   error
}

func newSessionRuntime(parent context.Context, eventBuf int) *sessionRuntime {
	// #nosec G118 -- cancel is called via Stop() by protocol loop teardown.
	runCtx, cancel := context.WithCancel(parent)
	g, gctx := errgroup.WithContext(runCtx)
	if eventBuf < 1 {
		eventBuf = 1
	}
	return &sessionRuntime{
		Ctx:         gctx,
		cancel:      cancel,
		Group:       g,
		Events:      make(chan protocolEvent, eventBuf),
		workersDone: make(chan struct{}),
	}
}

func (rt *sessionRuntime) Emit(ev protocolEvent) bool {
	select {
	case <-rt.Ctx.Done():
		return false
	case rt.Events <- ev:
		return true
	}
}

func (rt *sessionRuntime) Stop() {
	rt.stopping.Store(true)
	rt.cancel()
}

func (rt *sessionRuntime) StopError() error {
	if rt.stopping.Load() {
		return nil
	}
	return rt.Ctx.Err()
}

func (rt *sessionRuntime) Stopping() bool {
	return rt.stopping.Load()
}

// startWorkerWait is called once, after all session workers have been registered.
func (rt *sessionRuntime) startWorkerWait() {
	go func() {
		rt.workerErr = rt.Group.Wait()
		close(rt.workersDone)
	}()
}

// Wait may be called repeatedly. Closing workersDone publishes the worker error.
func (rt *sessionRuntime) Wait() error {
	<-rt.workersDone
	return rt.workerErr
}

// StopAndWait is the completion barrier, including during deferred cleanup.
func (rt *sessionRuntime) StopAndWait() error {
	rt.Stop()
	return rt.Wait()
}
