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
	tsscrypto "github.com/bnb-chain/tss-lib/crypto"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
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
	runner.setTemporaryECDSADKGShare(DKGRunKey{SessionID: "session-1", LocalPartyID: "p1"}, ecdsakeygen.LocalPartySaveData{})

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
	runner.setTemporaryECDSADKGShare(DKGRunKey{SessionID: "key-1", LocalPartyID: "p1"}, ecdsakeygen.LocalPartySaveData{})

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
	runKey := DKGRunKey{SessionID: "key-1", LocalPartyID: "p1"}
	runner.setTemporaryECDSADKGShare(runKey, ecdsakeygen.LocalPartySaveData{})
	materialKey := ECDSAKeyMaterialKey{KeyID: "key-1", LocalPartyID: "p1"}
	runner.ImportECDSAKeyMaterial(materialKey, coreshares.ECDSAKeyMaterial{
		Share:            ecdsakeygen.LocalPartySaveData{},
		ChainCode:        []byte{0x11},
		PublicKeyFormat:  "uncompressed_hex",
		DerivationScheme: "bip32_secp256k1",
	})

	runner.DeleteTemporaryECDSADKGShare(runKey)

	if _, ok := runner.getTemporaryECDSADKGShare(runKey); ok {
		t.Fatal("expected temporary DKG share to be deleted")
	}
	if _, err := runner.ExportECDSAKeyMaterial(materialKey); err != nil {
		t.Fatalf("expected key material to remain, got %v", err)
	}
}

func TestECDSAAddressAcceptsDualLocalSharesWithCommonPublicPoint(t *testing.T) {
	runner := NewBnbRunner(slog.Default())
	publicPoint := tsscrypto.ScalarBaseMult(tsslib.S256(), big.NewInt(1))
	if publicPoint == nil {
		t.Fatal("create test public point")
	}
	material := coreshares.ECDSAKeyMaterial{
		Share: ecdsakeygen.LocalPartySaveData{ECDSAPub: publicPoint},
	}
	runner.ImportECDSAKeyMaterial(ECDSAKeyMaterialKey{KeyID: "key-1", LocalPartyID: "party-b"}, material)
	runner.ImportECDSAKeyMaterial(ECDSAKeyMaterialKey{KeyID: "key-1", LocalPartyID: "party-c"}, material)

	address, err := runner.ECDSAAddress("key-1")
	if err != nil {
		t.Fatalf("ECDSAAddress() error = %v", err)
	}
	if address == "" {
		t.Fatal("ECDSAAddress() returned an empty address")
	}
}

func TestECDSAAddressRejectsDualLocalSharesWithDifferentPublicPoints(t *testing.T) {
	runner := NewBnbRunner(slog.Default())
	for _, localParty := range []struct {
		id     string
		scalar int64
	}{
		{id: "party-b", scalar: 1},
		{id: "party-c", scalar: 2},
	} {
		publicPoint := tsscrypto.ScalarBaseMult(tsslib.S256(), big.NewInt(localParty.scalar))
		if publicPoint == nil {
			t.Fatalf("create test public point for %s", localParty.id)
		}
		runner.ImportECDSAKeyMaterial(
			ECDSAKeyMaterialKey{KeyID: "key-1", LocalPartyID: localParty.id},
			coreshares.ECDSAKeyMaterial{Share: ecdsakeygen.LocalPartySaveData{ECDSAPub: publicPoint}},
		)
	}

	_, err := runner.ECDSAAddress("key-1")
	if !errors.Is(err, ErrKeyShareNotFound) {
		t.Fatalf("ECDSAAddress() error = %v, want ErrKeyShareNotFound", err)
	}
}
