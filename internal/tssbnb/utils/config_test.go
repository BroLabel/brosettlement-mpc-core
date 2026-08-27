package utils

import (
	"testing"
	"time"
)

func TestDefaultRunnerConfigWatchdogThresholds(t *testing.T) {
	cfg := DefaultRunnerConfig()

	if cfg.StallWarn != 30*time.Second {
		t.Errorf("StallWarn = %s, want %s", cfg.StallWarn, 30*time.Second)
	}
	if cfg.StallFail != 45*time.Second {
		t.Errorf("StallFail = %s, want %s", cfg.StallFail, 45*time.Second)
	}
	if cfg.StallWarnEvery != 30*time.Second {
		t.Errorf("StallWarnEvery = %s, want %s", cfg.StallWarnEvery, 30*time.Second)
	}
}

func TestRunnerConfigFromEnvWatchdogOverrides(t *testing.T) {
	t.Setenv("TSS_STALL_WARN", "37s")
	t.Setenv("TSS_STALL_FAIL", "71s")
	t.Setenv("TSS_STALL_WARN_EVERY", "19s")

	cfg := LoadRunnerConfigFromEnv()

	if cfg.StallWarn != 37*time.Second {
		t.Errorf("StallWarn = %s, want %s", cfg.StallWarn, 37*time.Second)
	}
	if cfg.StallFail != 71*time.Second {
		t.Errorf("StallFail = %s, want %s", cfg.StallFail, 71*time.Second)
	}
	if cfg.StallWarnEvery != 19*time.Second {
		t.Errorf("StallWarnEvery = %s, want %s", cfg.StallWarnEvery, 19*time.Second)
	}
}
