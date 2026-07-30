package tss

import (
	"testing"
	"time"
)

func TestDefaultPreParamsConfigProvidesSafeDefaults(t *testing.T) {
	cfg := DefaultPreParamsConfig()

	if !cfg.Enabled {
		t.Fatal("expected preparams to be enabled by default")
	}
	if cfg.TargetSize != 5 {
		t.Fatalf("expected target size 5, got %d", cfg.TargetSize)
	}
	if cfg.GenerateTimeout != 7*time.Minute {
		t.Fatalf("unexpected generate timeout: %s", cfg.GenerateTimeout)
	}
	if cfg.GenerationParallelism != 2 {
		t.Fatalf("generation parallelism = %d, want compatible explicit default 2", cfg.GenerationParallelism)
	}
	if !cfg.AutoRefillOnAcquire {
		t.Fatal("expected acquire-triggered refill to remain enabled by default")
	}
}

func TestLoadPreParamsConfigProfileSupportsDeferredBoundedRefill(t *testing.T) {
	t.Setenv("TSS_PREPARAMS_TARGET_SIZE", "2")
	t.Setenv("TSS_PREPARAMS_MAX_CONCURRENCY", "1")
	t.Setenv("TSS_PREPARAMS_GENERATION_PARALLELISM", "1")
	t.Setenv("TSS_PREPARAMS_SYNC_FALLBACK_ON_EMPTY", "false")
	t.Setenv("TSS_PREPARAMS_AUTO_REFILL_ON_ACQUIRE", "false")

	cfg := LoadPreParamsConfigFromEnv()

	if cfg.TargetSize != 2 || cfg.MaxConcurrency != 1 || cfg.GenerationParallelism != 1 {
		t.Fatalf("generation profile = target:%d workers:%d parallelism:%d, want 2:1:1",
			cfg.TargetSize, cfg.MaxConcurrency, cfg.GenerationParallelism)
	}
	if cfg.SyncFallbackOnEmpty {
		t.Fatal("expected synchronous fallback to be disabled")
	}
	if cfg.AutoRefillOnAcquire {
		t.Fatal("expected acquire-triggered refill to be disabled")
	}
}

func TestLoadPreParamsConfigFromEnvNormalizesInvalidProfileValues(t *testing.T) {
	t.Setenv("TSS_PREPARAMS_TARGET_SIZE", "0")
	t.Setenv("TSS_PREPARAMS_MAX_CONCURRENCY", "0")
	t.Setenv("TSS_PREPARAMS_GENERATION_PARALLELISM", "0")
	t.Setenv("TSS_PREPARAMS_FILE_CACHE_DIR", "")

	cfg := LoadPreParamsConfigFromEnv()

	if cfg.TargetSize != 1 {
		t.Fatalf("expected normalized target size 1, got %d", cfg.TargetSize)
	}
	if cfg.MaxConcurrency != 1 {
		t.Fatalf("expected normalized concurrency 1, got %d", cfg.MaxConcurrency)
	}
	if cfg.GenerationParallelism != 2 {
		t.Fatalf("expected normalized generation parallelism 2, got %d", cfg.GenerationParallelism)
	}
	if cfg.FileCacheDir == "" {
		t.Fatal("expected fallback cache dir")
	}
}
