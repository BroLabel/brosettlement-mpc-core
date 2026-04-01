package utils

import (
	"context"
	"errors"
	"log/slog"
)

func ClassifyErr(err error) (kind string, level slog.Level, isTerminal bool) {
	switch {
	case err == nil:
		return "success", slog.LevelInfo, false
	case errors.Is(err, context.Canceled):
		return "canceled", slog.LevelDebug, false
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout", slog.LevelWarn, true
	default:
		return "error", slog.LevelError, true
	}
}
