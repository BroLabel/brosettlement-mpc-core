package utils

import (
	"os"
	"strconv"
	"time"
)

type RunnerConfig struct {
	StallWarn       time.Duration
	StallFail       time.Duration
	StallWarnEvery  time.Duration
	WatchdogTick    time.Duration
	MaxFrameBytes   int
	InboundQueueCap int
	DedupTTL        time.Duration
	DedupMaxEntries int
}

func DefaultRunnerConfig() RunnerConfig {
	return RunnerConfig{
		StallWarn:       15 * time.Second,
		StallFail:       45 * time.Second,
		StallWarnEvery:  30 * time.Second,
		WatchdogTick:    5 * time.Second,
		MaxFrameBytes:   2 << 20,
		InboundQueueCap: 256,
		DedupTTL:        10 * time.Minute,
		DedupMaxEntries: 10000,
	}
}

func LoadRunnerConfigFromEnv() RunnerConfig {
	cfg := DefaultRunnerConfig()
	cfg.StallWarn = envDuration("TSS_STALL_WARN", cfg.StallWarn)
	cfg.StallFail = envDuration("TSS_STALL_FAIL", cfg.StallFail)
	cfg.StallWarnEvery = envDuration("TSS_STALL_WARN_EVERY", cfg.StallWarnEvery)
	cfg.WatchdogTick = envDuration("TSS_WATCHDOG_TICK", cfg.WatchdogTick)
	cfg.DedupTTL = envDuration("TSS_DEDUP_TTL", cfg.DedupTTL)
	cfg.MaxFrameBytes = envInt("TSS_MAX_FRAME_BYTES", cfg.MaxFrameBytes)
	cfg.InboundQueueCap = envInt("TSS_INBOUND_QUEUE_CAP", cfg.InboundQueueCap)
	cfg.DedupMaxEntries = envInt("TSS_DEDUP_MAX_ENTRIES", cfg.DedupMaxEntries)
	if cfg.InboundQueueCap < 1 {
		cfg.InboundQueueCap = 1
	}
	if cfg.DedupMaxEntries < 100 {
		cfg.DedupMaxEntries = 100
	}
	if cfg.StallFail <= cfg.StallWarn {
		cfg.StallFail = cfg.StallWarn + 30*time.Second
	}
	if cfg.StallWarnEvery <= 0 {
		cfg.StallWarnEvery = 30 * time.Second
	}
	return cfg
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}
