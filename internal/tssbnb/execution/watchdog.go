package execution

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"sync/atomic"
	"time"
)

func (e *ProtocolExecution) markProgress(msgType string, roundHint uint32) {
	now := time.Now().UnixNano()
	atomic.StoreInt64(&e.lastProgressNanos, now)
	if msgType != "" {
		e.lastMsgType.Store(msgType)
	}
	if roundHint > 0 {
		e.lastRoundHint.Store(roundHint)
	}
}

func (e *ProtocolExecution) runWatchdog(ctx context.Context) error {
	ticker := time.NewTicker(e.cfg.WatchdogTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			last := time.Unix(0, atomic.LoadInt64(&e.lastProgressNanos))
			if last.IsZero() {
				continue
			}
			idle := time.Since(last)
			if idle >= e.cfg.StallWarn {
				lastWarn := time.Unix(0, atomic.LoadInt64(&e.lastWarnNanos))
				if lastWarn.IsZero() || time.Since(lastWarn) >= e.cfg.StallWarnEvery {
					atomic.StoreInt64(&e.lastWarnNanos, time.Now().UnixNano())
					msgType, _ := e.lastMsgType.Load().(string)
					e.logger.Warn("tss protocol stall warning",
						"correlation_id", e.correlationID,
						"session_id", e.sessionID,
						"party_id", e.localPartyID,
						"stage", e.stage,
						"idle", idle,
						"last_msg_type", msgType,
						"last_round_hint", e.lastRoundHint.Load(),
						"last_recv_seq", e.lastRecvSeq.Load(),
						"last_sent_seq", e.lastSentSeq.Load(),
					)
				}
			}
			if idle >= e.cfg.StallFail {
				e.metrics.IncStalls(e.stage)
				if e.debug {
					e.logger.Debug("tss protocol stalled; goroutine dump",
						"correlation_id", e.correlationID,
						"session_id", e.sessionID,
						"party_id", e.localPartyID,
						"stage", e.stage,
						"idle", idle,
						"stacktrace", goroutineDump(),
					)
				}
				return fmt.Errorf("%w: idle=%s", ErrStalledProtocol, idle)
			}
		}
	}
}

func goroutineDump() string {
	var buf bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&buf, 2); err == nil && buf.Len() > 0 {
		return buf.String()
	}
	size := 1 << 20
	bufBytes := make([]byte, size)
	n := runtime.Stack(bufBytes, true)
	if n > 0 {
		return string(bufBytes[:n])
	}
	return string(debug.Stack())
}
