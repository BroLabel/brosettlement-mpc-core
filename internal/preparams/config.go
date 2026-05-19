package preparams

import (
	"path/filepath"
	"time"
)

type Config struct {
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

func DefaultConfig() Config {
	return Config{
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
