package bnb

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type blockingPartyTransport struct {
	sent chan protocol.Frame
}

func newBlockingPartyTransport() *blockingPartyTransport {
	return &blockingPartyTransport{sent: make(chan protocol.Frame, 8)}
}

func (t *blockingPartyTransport) SendFrame(ctx context.Context, frame protocol.Frame) error {
	frame.Payload = append([]byte(nil), frame.Payload...)
	select {
	case t.sent <- frame:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (*blockingPartyTransport) RecvFrame(ctx context.Context) (protocol.Frame, error) {
	<-ctx.Done()
	return protocol.Frame{}, ctx.Err()
}

func waitForPartyFrame(t *testing.T, transport *blockingPartyTransport, partyID string) protocol.Frame {
	t.Helper()
	select {
	case frame := <-transport.sent:
		if frame.FromParty != partyID {
			t.Fatalf("frame FromParty = %q, want %q", frame.FromParty, partyID)
		}
		return frame
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s transport", partyID)
		return protocol.Frame{}
	}
}

func waitForDKGResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for DKG result")
		return nil
	}
}

func TestConcurrentDKGAllowsSameSessionForDifferentPartiesAndIsolatesRuntimes(t *testing.T) {
	runner := NewBnbRunner(nil)
	job := DKGJob{
		SessionID: "shared-session",
		Parties:   []string{"B", "C"},
		Threshold: 2,
		Curve:     "ed25519",
		Algorithm: "eddsa",
	}
	bTransport := newBlockingPartyTransport()
	cTransport := newBlockingPartyTransport()
	bCtx, cancelB := context.WithCancel(context.Background())
	cCtx, cancelC := context.WithCancel(context.Background())
	defer cancelB()
	defer cancelC()

	bResult := make(chan error, 1)
	go func() {
		bJob := job
		bJob.LocalPartyID = "B"
		bResult <- runner.RunDKG(bCtx, bJob, bTransport)
	}()
	bFrame := waitForPartyFrame(t, bTransport, "B")

	cResult := make(chan error, 1)
	go func() {
		cJob := job
		cJob.LocalPartyID = "C"
		cResult <- runner.RunDKG(cCtx, cJob, cTransport)
	}()
	cFrame := waitForPartyFrame(t, cTransport, "C")

	if bFrame.SessionID != job.SessionID || cFrame.SessionID != job.SessionID {
		t.Fatalf("wire session ids differ: B=%q C=%q", bFrame.SessionID, cFrame.SessionID)
	}

	cancelB()
	if err := waitForDKGResult(t, bResult); !errors.Is(err, context.Canceled) {
		t.Fatalf("B result = %v, want context.Canceled", err)
	}

	cancelC()
	if err := waitForDKGResult(t, cResult); !errors.Is(err, context.Canceled) {
		t.Fatalf("C result = %v, want context.Canceled", err)
	}
}

func TestDKGRunKeyIsolatedCleanupPreservesSiblingParty(t *testing.T) {
	runner := NewBnbRunner(nil)
	bKey := DKGRunKey{SessionID: "shared-session", LocalPartyID: "B"}
	cKey := DKGRunKey{SessionID: "shared-session", LocalPartyID: "C"}
	runner.setTemporaryECDSADKGShare(bKey, ecdsakeygen.LocalPartySaveData{
		LocalSecrets: ecdsakeygen.LocalSecrets{Xi: big.NewInt(11)},
	})
	runner.setTemporaryECDSADKGShare(cKey, ecdsakeygen.LocalPartySaveData{
		LocalSecrets: ecdsakeygen.LocalSecrets{Xi: big.NewInt(22)},
	})

	runner.DeleteTemporaryECDSADKGShare(bKey)

	if _, err := runner.ExportTemporaryECDSADKGShare(bKey); !errors.Is(err, ErrKeyShareNotFound) {
		t.Fatalf("B export error = %v, want ErrKeyShareNotFound", err)
	}
	cShare, err := runner.ExportTemporaryECDSADKGShare(cKey)
	if err != nil {
		t.Fatalf("C export failed after B cleanup: %v", err)
	}
	if cShare.Xi == nil || cShare.Xi.Cmp(big.NewInt(22)) != 0 {
		t.Fatal("C share was corrupted by B cleanup")
	}
}

func TestDKGRunKeyFailedPartyPreservesSiblingResult(t *testing.T) {
	runner := NewBnbRunner(nil)
	cKey := DKGRunKey{SessionID: "shared-session", LocalPartyID: "C"}
	runner.setTemporaryECDSADKGShare(cKey, ecdsakeygen.LocalPartySaveData{
		LocalSecrets: ecdsakeygen.LocalSecrets{Xi: big.NewInt(22)},
	})

	err := runner.RunDKG(context.Background(), DKGJob{
		SessionID:    "shared-session",
		LocalPartyID: "B",
		Parties:      []string{"B", "C"},
		Threshold:    2,
		Curve:        "ed25519",
		Algorithm:    "unsupported",
	}, newBlockingPartyTransport())
	if err == nil {
		t.Fatal("B run unexpectedly succeeded")
	}

	cShare, exportErr := runner.ExportTemporaryECDSADKGShare(cKey)
	if exportErr != nil {
		t.Fatalf("C export failed after B failure: %v", exportErr)
	}
	if cShare.Xi == nil || cShare.Xi.Cmp(big.NewInt(22)) != 0 {
		t.Fatal("C share was corrupted by B failure")
	}
}
