package utils

import (
	"context"
	"time"
)

func DeadlineRemaining(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	return time.Until(deadline)
}
