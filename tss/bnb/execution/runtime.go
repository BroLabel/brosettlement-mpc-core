package execution

import (
	"context"

	"golang.org/x/sync/errgroup"
)

type sessionRuntime[T any] struct {
	Ctx    context.Context
	cancel context.CancelFunc
	Group  *errgroup.Group
	Events chan T
}

func newSessionRuntime[T any](parent context.Context, eventBuf int) *sessionRuntime[T] {
	// #nosec G118 -- cancel is called via Stop() by protocol loop teardown.
	runCtx, cancel := context.WithCancel(parent)
	g, gctx := errgroup.WithContext(runCtx)
	if eventBuf < 1 {
		eventBuf = 1
	}
	return &sessionRuntime[T]{
		Ctx:    gctx,
		cancel: cancel,
		Group:  g,
		Events: make(chan T, eventBuf),
	}
}

func (rt *sessionRuntime[T]) Emit(ev T) bool {
	select {
	case <-rt.Ctx.Done():
		return false
	case rt.Events <- ev:
		return true
	}
}

func (rt *sessionRuntime[T]) Stop() {
	rt.cancel()
}
