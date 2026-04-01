package tss

import (
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type PreParamsConfig struct {
	Enabled             bool
	TargetSize          int
	MaxConcurrency      int
	GenerateTimeout     time.Duration
	AcquireTimeout      time.Duration
	RetryBackoff        time.Duration
	SyncFallbackOnEmpty bool
	FileCacheEnabled    bool
	FileCacheDir        string
}

func DefaultPreParamsConfig() PreParamsConfig {
	return PreParamsConfig{
		Enabled:             true,
		TargetSize:          5,
		MaxConcurrency:      1,
		GenerateTimeout:     7 * time.Minute,
		AcquireTimeout:      45 * time.Second,
		RetryBackoff:        2 * time.Second,
		SyncFallbackOnEmpty: true,
		FileCacheEnabled:    false,
		FileCacheDir:        filepath.Join(".tmp", "tss-preparams"),
	}
}

func LoadPreParamsConfigFromEnv() PreParamsConfig {
	cfg := DefaultPreParamsConfig()
	cfg.Enabled = envBool("TSS_PREPARAMS_ENABLED", cfg.Enabled)
	cfg.TargetSize = envInt("TSS_PREPARAMS_TARGET_SIZE", cfg.TargetSize)
	cfg.MaxConcurrency = envInt("TSS_PREPARAMS_MAX_CONCURRENCY", cfg.MaxConcurrency)
	cfg.GenerateTimeout = envDuration("TSS_PREPARAMS_GENERATE_TIMEOUT", cfg.GenerateTimeout)
	cfg.AcquireTimeout = envDuration("TSS_PREPARAMS_ACQUIRE_TIMEOUT", cfg.AcquireTimeout)
	cfg.RetryBackoff = envDuration("TSS_PREPARAMS_RETRY_BACKOFF", cfg.RetryBackoff)
	cfg.SyncFallbackOnEmpty = envBool("TSS_PREPARAMS_SYNC_FALLBACK_ON_EMPTY", cfg.SyncFallbackOnEmpty)
	cfg.FileCacheEnabled = envBool("TSS_PREPARAMS_FILE_CACHE_ENABLED", cfg.FileCacheEnabled)
	cfg.FileCacheDir = envString("TSS_PREPARAMS_FILE_CACHE_DIR", cfg.FileCacheDir)
	return normalizePreParamsConfig(cfg)
}

func normalizePreParamsConfig(cfg PreParamsConfig) PreParamsConfig {
	if cfg.TargetSize < 1 {
		cfg.TargetSize = 1
	}
	if cfg.MaxConcurrency < 1 {
		cfg.MaxConcurrency = 1
	}
	if cfg.MaxConcurrency > cfg.TargetSize {
		cfg.MaxConcurrency = cfg.TargetSize
	}
	if cfg.GenerateTimeout <= 0 {
		cfg.GenerateTimeout = 7 * time.Minute
	}
	if cfg.AcquireTimeout <= 0 {
		cfg.AcquireTimeout = 45 * time.Second
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 2 * time.Second
	}
	if cfg.FileCacheDir == "" {
		cfg.FileCacheDir = filepath.Join(".tmp", "tss-preparams")
	}
	return cfg
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
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
	if err != nil {
		return fallback
	}
	return n
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func envString(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}
