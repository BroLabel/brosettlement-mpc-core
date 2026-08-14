package preparams

import (
	"path/filepath"
	"time"
)

type Config struct {
	Enabled               bool
	TargetSize            int
	MaxConcurrency        int
	GenerationParallelism int
	GenerateTimeout       time.Duration
	AcquireTimeout        time.Duration
	RetryBackoff          time.Duration
	SyncFallbackOnEmpty   bool
	AutoRefillOnAcquire   bool
	FileCacheEnabled      bool
	FileCacheDir          string
}

func DefaultConfig() Config {
	return Config{
		Enabled:               true,
		TargetSize:            5,
		MaxConcurrency:        1,
		GenerationParallelism: 2,
		GenerateTimeout:       7 * time.Minute,
		AcquireTimeout:        45 * time.Second,
		RetryBackoff:          2 * time.Second,
		SyncFallbackOnEmpty:   true,
		AutoRefillOnAcquire:   true,
		FileCacheEnabled:      false,
		FileCacheDir:          filepath.Join(".tmp", "tss-preparams"),
	}
}
