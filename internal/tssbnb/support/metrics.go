package utils

import "time"

type Metrics interface {
	IncSessionsStarted(stage string)
	IncSessionsSucceeded(stage string)
	IncSessionsFailed(stage string, reason string)
	IncStalls(stage string)
	IncTimeouts(stage string)
	IncDedupHits(stage string)
	IncFramesSent(stage string)
	IncFramesRecv(stage string)
	IncQueueFull(stage string)
	IncOversizedFrames(stage string)
	ObserveSessionDuration(stage string, d time.Duration)
}

type NoopMetrics struct{}

func (NoopMetrics) IncSessionsStarted(string)                    {}
func (NoopMetrics) IncSessionsSucceeded(string)                  {}
func (NoopMetrics) IncSessionsFailed(string, string)             {}
func (NoopMetrics) IncStalls(string)                             {}
func (NoopMetrics) IncTimeouts(string)                           {}
func (NoopMetrics) IncDedupHits(string)                          {}
func (NoopMetrics) IncFramesSent(string)                         {}
func (NoopMetrics) IncFramesRecv(string)                         {}
func (NoopMetrics) IncQueueFull(string)                          {}
func (NoopMetrics) IncOversizedFrames(string)                    {}
func (NoopMetrics) ObserveSessionDuration(string, time.Duration) {}
