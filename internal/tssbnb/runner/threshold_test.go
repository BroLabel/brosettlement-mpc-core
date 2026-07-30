package bnb

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	tssbnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/utils"
)

type thresholdRecordHandler struct {
	mu               sync.Mutex
	publicThreshold  uint64
	libraryThreshold int64
	recorded         bool
}

func (*thresholdRecordHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *thresholdRecordHandler) Handle(_ context.Context, record slog.Record) error {
	if record.Message != "tss runner run dkg start" {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	record.Attrs(func(attr slog.Attr) bool {
		switch attr.Key {
		case "threshold_m":
			h.publicThreshold = attr.Value.Uint64()
		case "threshold_t":
			h.libraryThreshold = attr.Value.Int64()
		}
		return true
	})
	h.recorded = true
	return nil
}

func (h *thresholdRecordHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}

func (h *thresholdRecordHandler) WithGroup(string) slog.Handler {
	return h
}

func TestThresholdAdapterPreservesPublicRequiredSignersAndRecordsLibraryThreshold(t *testing.T) {
	handler := &thresholdRecordHandler{}
	runner := NewBnbRunner(
		slog.New(handler),
		WithConfig(tssbnbutils.DefaultRunnerConfig()),
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := runner.RunDKG(ctx, DKGJob{
		SessionID:    "threshold-adapter",
		LocalPartyID: "B",
		Parties:      []string{"A", "B", "C"},
		Threshold:    2,
		Curve:        "ed25519",
		Algorithm:    "eddsa",
	}, newBlockingPartyTransport())
	if err == nil {
		t.Fatal("RunDKG() with canceled context unexpectedly succeeded")
	}

	handler.mu.Lock()
	defer handler.mu.Unlock()
	if !handler.recorded {
		t.Fatal("runner did not record threshold adapter evidence")
	}
	if handler.publicThreshold != 2 {
		t.Fatalf("public required signer count = %d, want 2", handler.publicThreshold)
	}
	if handler.libraryThreshold != 1 {
		t.Fatalf("tss-lib threshold = %d, want 1", handler.libraryThreshold)
	}
}
