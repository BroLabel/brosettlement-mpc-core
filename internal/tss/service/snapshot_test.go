package service

import (
	"context"
	"errors"
	"testing"

	"github.com/BroLabel/brosettlement-mpc-core/internal/preparams"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type snapshotLifecyclePool struct {
	stubLifecyclePool
	snapshot preparams.Snapshot
}

func (p *snapshotLifecyclePool) Snapshot() preparams.Snapshot {
	return p.snapshot
}

func TestServiceSnapshotMergesPoolAndHandleTransitionMetrics(t *testing.T) {
	pool := &snapshotLifecyclePool{
		stubLifecyclePool: stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}},
		snapshot: preparams.Snapshot{
			Size:               3,
			AcquireCount:       2,
			AcquireFailedCount: 1,
		},
	}
	svc := New(newECDSASecp256k1StubRunner(t, "session-1"), newTestLogger(), pool, nil, nil)

	discarded, err := svc.AcquireDKGPreParams(context.Background())
	if err != nil {
		t.Fatalf("acquire discarded handle: %v", err)
	}
	if err := discarded.Discard(); err != nil {
		t.Fatalf("discard handle: %v", err)
	}
	if err := discarded.Discard(); err != nil {
		t.Fatalf("repeat discard handle: %v", err)
	}
	if _, err := preparams.Consume(svc.preParamsBinding, discarded); !errors.Is(err, preparams.ErrPreParamsDiscarded) {
		t.Fatalf("consume discarded handle error = %v", err)
	}

	consumed, err := svc.AcquireDKGPreParams(context.Background())
	if err != nil {
		t.Fatalf("acquire consumed handle: %v", err)
	}
	if _, err := preparams.Consume(svc.preParamsBinding, consumed); err != nil {
		t.Fatalf("consume handle: %v", err)
	}
	if _, err := preparams.Consume(svc.preParamsBinding, consumed); !errors.Is(err, preparams.ErrPreParamsConsumed) {
		t.Fatalf("reuse consumed handle error = %v", err)
	}
	if err := consumed.Discard(); !errors.Is(err, preparams.ErrPreParamsConsumed) {
		t.Fatalf("discard consumed handle error = %v", err)
	}

	got := svc.Snapshot()
	want := Snapshot{
		PreParamsPoolSize:                  3,
		PreParamsAcquiredCount:             2,
		PreParamsConsumedCount:             1,
		PreParamsDiscardedBeforeStartCount: 1,
		PreParamsAcquireFailedCount:        1,
		PreParamsConsumeConflictCount:      2,
	}
	if got != want {
		t.Fatalf("Snapshot() = %+v, want %+v", got, want)
	}
}

func TestServiceSnapshotSurfacesHandleMetricsWithoutInternalPool(t *testing.T) {
	source := &stubPreParamsSource{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(newECDSASecp256k1StubRunner(t, "session-1"), newTestLogger(), nil, nil, nil, source)
	handle, err := svc.AcquireDKGPreParams(context.Background())
	if err != nil {
		t.Fatalf("acquire handle: %v", err)
	}
	if err := handle.Discard(); err != nil {
		t.Fatalf("discard handle: %v", err)
	}

	want := Snapshot{PreParamsDiscardedBeforeStartCount: 1}
	if got := svc.Snapshot(); got != want {
		t.Fatalf("Snapshot() = %+v, want %+v", got, want)
	}
}

func TestTryAcquireDKGPreParamsPreservesExternalSource(t *testing.T) {
	source := &stubPreParamsSource{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(newECDSASecp256k1StubRunner(t, "session-1"), newTestLogger(), nil, nil, nil, source)

	handle, err := svc.TryAcquireDKGPreParams(context.Background())
	if err != nil || handle == nil {
		t.Fatalf("TryAcquireDKGPreParams() = (%v, %v), want external handle", handle, err)
	}
	if source.acquires != 1 {
		t.Fatalf("external source acquires = %d, want 1", source.acquires)
	}
}
