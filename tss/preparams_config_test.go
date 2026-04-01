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
}

func TestLoadPreParamsConfigFromEnvNormalizesInvalidValues(t *testing.T) {
	t.Setenv("TSS_PREPARAMS_TARGET_SIZE", "0")
	t.Setenv("TSS_PREPARAMS_MAX_CONCURRENCY", "0")
	t.Setenv("TSS_PREPARAMS_FILE_CACHE_DIR", "")

	cfg := LoadPreParamsConfigFromEnv()

	if cfg.TargetSize != 1 {
		t.Fatalf("expected normalized target size 1, got %d", cfg.TargetSize)
	}
	if cfg.MaxConcurrency != 1 {
		t.Fatalf("expected normalized concurrency 1, got %d", cfg.MaxConcurrency)
	}
	if cfg.FileCacheDir == "" {
		t.Fatal("expected fallback cache dir")
	}
}
