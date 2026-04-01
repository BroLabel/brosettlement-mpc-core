package service

import (
	"context"

	"brosettlement-mpc-signer/brosettlement-mpc-core/internal/preparams"
	tssbnbrunner "brosettlement-mpc-signer/brosettlement-mpc-core/internal/tssbnb/runner"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type Pool interface {
	Size() int
}

type SnapshotProvider interface {
	Snapshot() preparams.Snapshot
}

type PreParamsPool interface {
	Acquire(ctx context.Context) (*ecdsakeygen.LocalPreParams, error)
}

type Snapshot struct {
	PreParamsPoolSize          int
	PreParamsSyncFallbackCount uint64
	PreParamsAcquireWaitNanos  int64
}

func BuildSnapshot(pool Pool, provider SnapshotProvider) Snapshot {
	if pool == nil {
		return Snapshot{}
	}

	snapshot := Snapshot{
		PreParamsPoolSize: pool.Size(),
	}
	if provider != nil {
		poolSnapshot := provider.Snapshot()
		snapshot.PreParamsSyncFallbackCount = poolSnapshot.SyncFallbackCount
		snapshot.PreParamsAcquireWaitNanos = poolSnapshot.AcquireWaitNanos
		if snapshot.PreParamsPoolSize == 0 {
			snapshot.PreParamsPoolSize = poolSnapshot.Size
		}
	}
	return snapshot
}

func AttachPreParams(ctx context.Context, pool PreParamsPool, job *tssbnbrunner.DKGJob, shouldAttach bool) error {
	if job == nil || pool == nil || job.ECDSAPreParams != nil || !shouldAttach {
		return nil
	}
	pre, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	job.ECDSAPreParams = pre
	return nil
}
