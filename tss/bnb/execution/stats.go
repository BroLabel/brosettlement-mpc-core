package execution

import "sync/atomic"

type protocolStats struct {
	sentFrames atomic.Uint64
	recvFrames atomic.Uint64
	dedupDrops atomic.Uint64
}

func (s *protocolStats) IncSent() {
	s.sentFrames.Add(1)
}

func (s *protocolStats) IncRecv() {
	s.recvFrames.Add(1)
}

func (s *protocolStats) IncDedupDrop() {
	s.dedupDrops.Add(1)
}

func (s *protocolStats) Sent() uint64 {
	return s.sentFrames.Load()
}

func (s *protocolStats) Recv() uint64 {
	return s.recvFrames.Load()
}

func (s *protocolStats) DedupDrops() uint64 {
	return s.dedupDrops.Load()
}
