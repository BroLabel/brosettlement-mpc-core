package logging

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"
)

func LogSessionStart(logger *slog.Logger, operation, sessionID, orgID, keyID, partyID string) {
	args := []any{
		"operation", operation,
		"session_id", sessionID,
		"org_id", orgID,
		"party_id", partyID,
	}
	if strings.TrimSpace(keyID) != "" {
		args = append(args, "key_id", keyID)
	}
	logger.Info("tss session start", args...)
}

func LogSessionEnd(logger *slog.Logger, operation, sessionID, orgID, keyID, partyID string, started time.Time, err error) {
	result := "success"
	level := slog.LevelInfo
	if errors.Is(err, context.Canceled) {
		result = "canceled"
		level = slog.LevelDebug
	} else if errors.Is(err, context.DeadlineExceeded) {
		result = "timeout"
		level = slog.LevelWarn
	} else if err != nil {
		result = "error"
		level = slog.LevelError
	}

	args := []any{
		"operation", operation,
		"session_id", sessionID,
		"org_id", orgID,
		"party_id", partyID,
		"duration", time.Since(started),
		"result", result,
	}
	if strings.TrimSpace(keyID) != "" {
		args = append(args, "key_id", keyID)
	}
	if err != nil {
		args = append(args, "err", err)
	}
	logger.Log(context.Background(), level, "tss session end", args...)
}
