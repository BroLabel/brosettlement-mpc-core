package utils

import (
	"context"
	"errors"
	"log/slog"
	"testing"
)

func TestClassifyErr(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		kind       string
		level      slog.Level
		isTerminal bool
	}{
		{name: "nil", err: nil, kind: "success", level: slog.LevelInfo, isTerminal: false},
		{name: "canceled", err: context.Canceled, kind: "canceled", level: slog.LevelDebug, isTerminal: false},
		{name: "deadline", err: context.DeadlineExceeded, kind: "timeout", level: slog.LevelWarn, isTerminal: true},
		{name: "other", err: errors.New("boom"), kind: "error", level: slog.LevelError, isTerminal: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, level, terminal := ClassifyErr(tc.err)
			if kind != tc.kind || level != tc.level || terminal != tc.isTerminal {
				t.Fatalf("ClassifyErr(%v) = (%s,%v,%v), want (%s,%v,%v)", tc.err, kind, level, terminal, tc.kind, tc.level, tc.isTerminal)
			}
		})
	}
}
