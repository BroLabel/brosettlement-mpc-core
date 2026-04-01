package utils

import (
	"context"
	"log/slog"
	"os"
)

func IsTSSDebugEnabled(logger *slog.Logger) bool {
	if os.Getenv("TSS_DEBUG") == "1" {
		return true
	}
	if logger == nil {
		return false
	}
	return logger.Enabled(context.Background(), slog.LevelDebug)
}
