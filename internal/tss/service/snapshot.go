package service

import "github.com/BroLabel/brosettlement-mpc-core/internal/preparams"

type Snapshot struct {
	PreParamsPoolSize          int
	PreParamsSyncFallbackCount uint64
	PreParamsAcquireWaitNanos  int64
}

type SnapshotProvider interface {
	Snapshot() preparams.Snapshot
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
