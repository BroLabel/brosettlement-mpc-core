package bnb

import (
	"context"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	bnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/support"
	tssbnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/utils"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type testMetrics struct{}

func (*testMetrics) IncSessionsStarted(string)                    {}
func (*testMetrics) IncSessionsSucceeded(string)                  {}
func (*testMetrics) IncSessionsFailed(string, string)             {}
func (*testMetrics) IncStalls(string)                             {}
func (*testMetrics) IncTimeouts(string)                           {}
func (*testMetrics) IncDedupHits(string)                          {}
func (*testMetrics) IncFramesSent(string)                         {}
func (*testMetrics) IncFramesRecv(string)                         {}
func (*testMetrics) IncQueueFull(string)                          {}
func (*testMetrics) IncOversizedFrames(string)                    {}
func (*testMetrics) ObserveSessionDuration(string, time.Duration) {}

func TestNewBnbRunner_DefaultOptions(t *testing.T) {
	t.Setenv("TSS_MAX_FRAME_BYTES", "123456")

	runner := NewBnbRunner(nil)

	if _, ok := runner.metrics.(bnbutils.NoopMetrics); !ok {
		t.Fatalf("expected NoopMetrics by default, got %T", runner.metrics)
	}
	if runner.cfg != tssbnbutils.LoadRunnerConfigFromEnv() {
		t.Fatalf("expected config loaded from env, got %+v", runner.cfg)
	}
	if runner.logger == nil {
		t.Fatal("expected default logger when nil logger is provided")
	}
}

func TestNewBnbRunner_WithMetrics(t *testing.T) {
	m := &testMetrics{}

	runner := NewBnbRunner(slog.Default(), WithMetrics(m))

	if runner.metrics != m {
		t.Fatalf("expected custom metrics to be set, got %T", runner.metrics)
	}
}

func TestNewBnbRunner_WithConfig(t *testing.T) {
	cfg := tssbnbutils.RunnerConfig{
		StallWarn:       time.Second,
		StallFail:       2 * time.Second,
		StallWarnEvery:  3 * time.Second,
		WatchdogTick:    4 * time.Second,
		MaxFrameBytes:   777,
		InboundQueueCap: 42,
		DedupTTL:        5 * time.Second,
		DedupMaxEntries: 100,
	}

	runner := NewBnbRunner(slog.Default(), WithConfig(cfg))

	if runner.cfg != cfg {
		t.Fatalf("expected custom config to be set, got %+v", runner.cfg)
	}
}

func TestRunSignDoesNotFallbackFromKeyIDToSessionID(t *testing.T) {
	runner := NewBnbRunner(slog.Default())
	runner.setTemporaryECDSADKGShare("session-1", ecdsakeygen.LocalPartySaveData{})

	err := runner.RunSign(context.Background(), SignJob{
		SessionID:             "session-1",
		KeyID:                 "key-1",
		Parties:               []string{"p1", "p2"},
		Digest:                []byte{1, 2, 3},
		Algorithm:             "ecdsa",
		KeyDerivationDelta:    big.NewInt(1),
		DerivationContextHash: strings.Repeat("a", 64),
	}, nil)
	if !errors.Is(err, ErrKeyShareNotFound) {
		t.Fatalf("expected ErrKeyShareNotFound, got %v", err)
	}
}

func TestRunSignRejectsMissingAdjustedKeyShare(t *testing.T) {
	runner := NewBnbRunner(slog.Default())
	runner.setTemporaryECDSADKGShare("key-1", ecdsakeygen.LocalPartySaveData{})

	err := runner.RunSign(context.Background(), SignJob{
		SessionID:             "sign-1",
		KeyID:                 "key-1",
		Parties:               []string{"p1", "p2"},
		Digest:                []byte{1, 2, 3},
		Algorithm:             "ecdsa",
		KeyDerivationDelta:    big.NewInt(1),
		DerivationContextHash: strings.Repeat("a", 64),
	}, nil)
	if !errors.Is(err, ErrKeyShareNotFound) {
		t.Fatalf("expected ErrKeyShareNotFound, got %v", err)
	}
}

func TestDeleteTemporaryECDSADKGSharePreservesKeyMaterial(t *testing.T) {
	runner := NewBnbRunner(slog.Default())
	runner.setTemporaryECDSADKGShare("key-1", ecdsakeygen.LocalPartySaveData{})
	runner.ImportECDSAKeyMaterial("key-1", coreshares.ECDSAKeyMaterial{
		Share:            ecdsakeygen.LocalPartySaveData{},
		ChainCode:        []byte{0x11},
		PublicKeyFormat:  "uncompressed_hex",
		DerivationScheme: "bip32_secp256k1",
	})

	runner.DeleteTemporaryECDSADKGShare("key-1")

	if _, ok := runner.getTemporaryECDSADKGShare("key-1"); ok {
		t.Fatal("expected temporary DKG share to be deleted")
	}
	if _, err := runner.ExportECDSAKeyMaterial("key-1"); err != nil {
		t.Fatalf("expected key material to remain, got %v", err)
	}
}
