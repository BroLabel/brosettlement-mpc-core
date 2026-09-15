package execution

import (
	"context"
	"errors"
	"testing"
)

func TestStopAndWaitJoinsWorkerAndPreservesError(t *testing.T) {
	rt := newSessionRuntime(context.Background(), 1)
	workerCanceled := make(chan struct{})
	releaseWorker := make(chan struct{})
	workerErr := errors.New("worker failed during shutdown")
	rt.Group.Go(func() error {
		<-rt.Ctx.Done()
		close(workerCanceled)
		<-releaseWorker
		return workerErr
	})
	rt.startWorkerWait()

	result := make(chan error, 1)
	go func() { result <- rt.StopAndWait() }()
	waitForSignal(t, workerCanceled, "worker cancellation")
	select {
	case err := <-result:
		close(releaseWorker)
		t.Fatalf("StopAndWait returned before worker exit: %v", err)
	default:
	}
	close(releaseWorker)
	if err := <-result; !errors.Is(err, workerErr) {
		t.Fatalf("StopAndWait error = %v, want worker error", err)
	}
	if err := rt.StopAndWait(); !errors.Is(err, workerErr) {
		t.Fatalf("repeated StopAndWait error = %v, want worker error", err)
	}
}

func TestRuntimeWaitPreservesNaturalCompletion(t *testing.T) {
	rt := newSessionRuntime(context.Background(), 1)
	defer rt.Stop()
	rt.Group.Go(func() error { return nil })
	rt.startWorkerWait()

	waitForSignal(t, rt.workersDone, "natural worker completion")
	if err := rt.Wait(); err != nil {
		t.Fatalf("Wait error = %v", err)
	}
	if rt.Stopping() {
		t.Fatal("natural completion must not be classified as an owner stop")
	}
	if err := rt.StopAndWait(); err != nil {
		t.Fatalf("StopAndWait after completion error = %v", err)
	}
}
