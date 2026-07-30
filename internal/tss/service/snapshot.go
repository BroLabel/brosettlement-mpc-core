package service

import "github.com/BroLabel/brosettlement-mpc-core/internal/preparams"

type Snapshot struct {
	PreParamsPoolSize                  int
	PreParamsSyncFallbackCount         uint64
	PreParamsAcquireWaitNanos          int64
	PreParamsAcquiredCount             uint64
	PreParamsConsumedCount             uint64
	PreParamsDiscardedBeforeStartCount uint64
	PreParamsAcquireFailedCount        uint64
	PreParamsConsumeConflictCount      uint64
}

type SnapshotProvider interface {
	Snapshot() preparams.Snapshot
}

func BuildSnapshot(pool Pool, provider SnapshotProvider, handles preparams.HandleMetrics) Snapshot {
	snapshot := Snapshot{
		PreParamsConsumedCount:             handles.ConsumedCount,
		PreParamsDiscardedBeforeStartCount: handles.DiscardedBeforeStartCount,
		PreParamsConsumeConflictCount:      handles.ConsumeConflictCount,
	}

	if pool != nil {
		snapshot.PreParamsPoolSize = pool.Size()
	}
	if provider != nil {
		poolSnapshot := provider.Snapshot()
		snapshot.PreParamsSyncFallbackCount = poolSnapshot.SyncFallbackCount
		snapshot.PreParamsAcquireWaitNanos = poolSnapshot.AcquireWaitNanos
		snapshot.PreParamsAcquiredCount = poolSnapshot.AcquireCount
		snapshot.PreParamsAcquireFailedCount = poolSnapshot.AcquireFailedCount
		if snapshot.PreParamsPoolSize == 0 {
			snapshot.PreParamsPoolSize = poolSnapshot.Size
		}
	}
	return snapshot
}
