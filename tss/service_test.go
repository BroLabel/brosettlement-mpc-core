package tss_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
	coreshare "github.com/BroLabel/brosettlement-mpc-core/shares"
	coretss "github.com/BroLabel/brosettlement-mpc-core/tss"
	"github.com/bnb-chain/tss-lib/common"
	tsscrypto "github.com/bnb-chain/tss-lib/crypto"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

type fakeRunner struct{}

func (fakeRunner) RunDKG(_ context.Context, _ coretss.DKGJob, _ coretss.Transport) error {
	return nil
}

func (fakeRunner) RunSign(_ context.Context, _ coretss.SignJob, _ coretss.Transport) error {
	return nil
}

func (fakeRunner) ExportECDSASignature(_ string) (common.SignatureData, error) {
	return common.SignatureData{}, nil
}

func (fakeRunner) ExportECDSAKeyShare(_ string) (ecdsakeygen.LocalPartySaveData, error) {
	return ecdsakeygen.LocalPartySaveData{}, nil
}

func (fakeRunner) ImportECDSAKeyShare(_ string, _ ecdsakeygen.LocalPartySaveData) {}

func (fakeRunner) DeleteECDSAKeyShare(_ string) {}

func (fakeRunner) ECDSAAddress(_ string) (string, error) {
	return "", nil
}

func TestNewServiceWithComponentsPanicsOnNilRunner(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for nil runner")
		}
		err, ok := r.(error)
		if !ok || !errors.Is(err, coretss.ErrNilRunner) {
			t.Fatalf("panic = %v, want %v", r, coretss.ErrNilRunner)
		}
	}()
	_ = coretss.NewServiceWithComponents(nil, slog.Default(), nil, nil)
}

func TestNewServiceWithComponentsReturnsService(t *testing.T) {
	svc := coretss.NewServiceWithComponents(fakeRunner{}, slog.Default(), nil, nil)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

type harnessRunner struct {
	dkgCalls             int
	signCalls            int
	deleteKeyShareCalls  int
	exportKeyShareCalls  int
	importKeyShareCalls  int
	exportSignatureCalls int

	dkgErr         error
	signErr        error
	exportSigErr   error
	exportShareErr error
	addressErr     error
	share          ecdsakeygen.LocalPartySaveData
	address        string
}

func (r *harnessRunner) RunDKG(_ context.Context, _ coretss.DKGJob, _ coretss.Transport) error {
	r.dkgCalls++
	return r.dkgErr
}

func (r *harnessRunner) RunSign(_ context.Context, _ coretss.SignJob, _ coretss.Transport) error {
	r.signCalls++
	return r.signErr
}

func (r *harnessRunner) ExportECDSASignature(_ string) (common.SignatureData, error) {
	r.exportSignatureCalls++
	return common.SignatureData{}, r.exportSigErr
}

func (r *harnessRunner) ExportECDSAKeyShare(_ string) (ecdsakeygen.LocalPartySaveData, error) {
	r.exportKeyShareCalls++
	if r.exportShareErr != nil {
		return ecdsakeygen.LocalPartySaveData{}, r.exportShareErr
	}
	return r.share, nil
}

func (r *harnessRunner) ImportECDSAKeyShare(_ string, _ ecdsakeygen.LocalPartySaveData) {
	r.importKeyShareCalls++
}

func (r *harnessRunner) DeleteECDSAKeyShare(_ string) {
	r.deleteKeyShareCalls++
}

func (r *harnessRunner) ECDSAAddress(_ string) (string, error) {
	return r.address, r.addressErr
}

type harnessShareStore struct {
	saveCalls int
	loadCalls int
	loadErr   error
	loaded    *coreshare.StoredShare
}

func (s *harnessShareStore) SaveShare(_ context.Context, _ string, _ []byte, _ coreshare.ShareMeta) error {
	s.saveCalls++
	return nil
}

func (s *harnessShareStore) LoadShare(_ context.Context, _ string) (*coreshare.StoredShare, error) {
	s.loadCalls++
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	if s.loaded == nil {
		return nil, coreshare.ErrShareNotFound
	}
	return &coreshare.StoredShare{
		Blob: append([]byte(nil), s.loaded.Blob...),
		Meta: s.loaded.Meta,
	}, nil
}

func (s *harnessShareStore) DisableShare(_ context.Context, _ string) error {
	return nil
}

type harnessPreParamsPool struct {
	pre *ecdsakeygen.LocalPreParams
	err error
}

func (p *harnessPreParamsPool) Start(context.Context) error { return nil }
func (p *harnessPreParamsPool) Acquire(context.Context) (*ecdsakeygen.LocalPreParams, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.pre, nil
}
func (p *harnessPreParamsPool) Size() int    { return 1 }
func (p *harnessPreParamsPool) Close() error { return nil }

type noopTransport struct{}

func (noopTransport) SendFrame(context.Context, protocol.Frame) error { return nil }
func (noopTransport) RecvFrame(context.Context) (protocol.Frame, error) {
	return protocol.Frame{}, context.Canceled
}

func newServiceHarness(t *testing.T) (*coretss.Service, *harnessRunner, *harnessShareStore) {
	t.Helper()

	runner := &harnessRunner{
		share:   validECDSAShare(t),
		address: "TLkQfN3vWXxN71M5Qh2kJ9v8h8X4W3Yt9A",
	}
	store := &harnessShareStore{}
	service := coretss.NewServiceWithComponents(runner, slog.Default(), nil, store)
	return service, runner, store
}

func validECDSAShare(t *testing.T) ecdsakeygen.LocalPartySaveData {
	t.Helper()
	curve := tsslib.S256()
	point, err := tsscrypto.NewECPoint(curve, curve.Params().Gx, curve.Params().Gy)
	if err != nil {
		t.Fatalf("NewECPoint() error = %v", err)
	}
	return ecdsakeygen.LocalPartySaveData{ECDSAPub: point}
}

func TestRunDKGSessionStoresShareAndCleansRunnerState(t *testing.T) {
	service, runner, store := newServiceHarness(t)

	err := service.RunDKGSession(context.Background(), coretss.DKGSessionRequest{
		Session: protocol.SessionDescriptor{
			SessionID: "session-1",
			OrgID:     "org-1",
			Parties:   []string{"p1", "p2"},
			Threshold: 1,
			Algorithm: "ecdsa",
			Curve:     "secp256k1",
			Chain:     "bnb",
		},
		LocalPartyID: "p1",
		Transport:    noopTransport{},
	})
	if err != nil {
		t.Fatalf("RunDKGSession() error = %v", err)
	}
	if store.saveCalls != 1 {
		t.Fatalf("saveCalls = %d, want 1", store.saveCalls)
	}
	if runner.deleteKeyShareCalls != 1 {
		t.Fatalf("deleteKeyShareCalls = %d, want 1", runner.deleteKeyShareCalls)
	}
}

func TestRunDKGSessionReturnsMissingPublicKey(t *testing.T) {
	service, runner, _ := newServiceHarness(t)
	runner.share = ecdsakeygen.LocalPartySaveData{}

	err := service.RunDKGSession(context.Background(), coretss.DKGSessionRequest{
		Session: protocol.SessionDescriptor{
			SessionID: "session-2",
			OrgID:     "org-1",
			Parties:   []string{"p1", "p2"},
			Threshold: 1,
			Algorithm: "ecdsa",
			Curve:     "secp256k1",
			Chain:     "bnb",
		},
		LocalPartyID: "p1",
		Transport:    noopTransport{},
	})
	if !errors.Is(err, coretss.ErrMissingDKGPublicKey) {
		t.Fatalf("RunDKGSession() error = %v, want %v", err, coretss.ErrMissingDKGPublicKey)
	}
}

func TestRunDKGSessionReturnsMissingAddress(t *testing.T) {
	service, runner, _ := newServiceHarness(t)
	runner.address = "   "

	err := service.RunDKGSession(context.Background(), coretss.DKGSessionRequest{
		Session: protocol.SessionDescriptor{
			SessionID: "session-3",
			OrgID:     "org-1",
			Parties:   []string{"p1", "p2"},
			Threshold: 1,
			Algorithm: "ecdsa",
			Curve:     "secp256k1",
			Chain:     "bnb",
		},
		LocalPartyID: "p1",
		Transport:    noopTransport{},
	})
	if !errors.Is(err, coretss.ErrMissingDKGAddress) {
		t.Fatalf("RunDKGSession() error = %v, want %v", err, coretss.ErrMissingDKGAddress)
	}
}

func TestRunSignSessionReturnsMetadataMismatch(t *testing.T) {
	service, runner, store := newServiceHarness(t)
	runner.address = "TLkQfN3vWXxN71M5Qh2kJ9v8h8X4W3Yt9A"

	blob, err := coreshare.MarshalShare(ecdsakeygen.LocalPartySaveData{})
	if err != nil {
		t.Fatalf("MarshalShare() error = %v", err)
	}
	store.loaded = &coreshare.StoredShare{
		Blob: blob,
		Meta: coreshare.ShareMeta{
			KeyID:     "different-key",
			OrgID:     "org-1",
			Algorithm: "ecdsa",
		},
	}

	err = service.RunSignSession(context.Background(), validSignSessionRequest())
	if !errors.Is(err, coreshare.ErrMetadataMismatch) {
		t.Fatalf("RunSignSession() error = %v, want %v", err, coreshare.ErrMetadataMismatch)
	}
	if runner.signCalls != 0 {
		t.Fatalf("RunSign() calls = %d, want 0", runner.signCalls)
	}
}

func TestRunSignSessionReturnsShareNotFound(t *testing.T) {
	service, runner, store := newServiceHarness(t)
	store.loadErr = coreshare.ErrShareNotFound

	err := service.RunSignSession(context.Background(), validSignSessionRequest())
	if !errors.Is(err, coreshare.ErrShareNotFound) {
		t.Fatalf("RunSignSession() error = %v, want %v", err, coreshare.ErrShareNotFound)
	}
	if runner.signCalls != 0 {
		t.Fatalf("RunSign() calls = %d, want 0", runner.signCalls)
	}
}

type observedRecords struct {
	mu       sync.Mutex
	messages []string
}

func (r *observedRecords) add(msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.messages = append(r.messages, msg)
}

func (r *observedRecords) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.messages))
	copy(out, r.messages)
	return out
}

type observedHandler struct {
	records *observedRecords
}

func (h observedHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h observedHandler) Handle(_ context.Context, record slog.Record) error {
	h.records.add(record.Message)
	return nil
}

func (h observedHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h observedHandler) WithGroup(string) slog.Handler      { return h }

func newObservedLogger() (*slog.Logger, *observedRecords) {
	records := &observedRecords{}
	return slog.New(observedHandler{records: records}), records
}

func newServiceWithLogger(t *testing.T, logger *slog.Logger) *coretss.Service {
	t.Helper()
	runner := &harnessRunner{}
	return coretss.NewServiceWithComponents(runner, logger, nil, nil)
}

func validSignSessionRequest() coretss.SignSessionRequest {
	return coretss.SignSessionRequest{
		Session: protocol.SessionDescriptor{
			SessionID: "session-sign-1",
			OrgID:     "org-1",
			KeyID:     "key-1",
			Parties:   []string{"p1", "p2"},
			Threshold: 1,
			Algorithm: "ecdsa",
			Curve:     "secp256k1",
			Chain:     "bnb",
		},
		LocalPartyID: "p1",
		Digest:       []byte{0x01},
		Transport:    noopTransport{},
	}
}

func assertLogMessages(t *testing.T, records *observedRecords, want []string) {
	t.Helper()

	deadline := time.Now().Add(250 * time.Millisecond)
	for {
		got := records.snapshot()
		all := true
		for _, w := range want {
			found := false
			for _, msg := range got {
				if msg == w {
					found = true
					break
				}
			}
			if !found {
				all = false
				break
			}
		}
		if all {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("log messages = %v, want to contain %v", got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func assertNoLogMessage(t *testing.T, records *observedRecords, notWanted string) {
	t.Helper()

	for _, msg := range records.snapshot() {
		if msg == notWanted {
			t.Fatalf("unexpected log message %q", notWanted)
		}
	}
}

func TestRunSignSessionLogsOnlySessionBoundaryEvents(t *testing.T) {
	logger, records := newObservedLogger()
	runner := &harnessRunner{}
	store := &harnessShareStore{loadErr: coreshare.ErrShareNotFound}
	service := coretss.NewServiceWithComponents(runner, logger, nil, store)

	_ = service.RunSignSession(context.Background(), validSignSessionRequest())

	assertLogMessages(t, records, []string{"tss session start", "tss session end"})
	assertNoLogMessage(t, records, "vault share operation success")
	assertNoLogMessage(t, records, "vault share operation failed")
	assertNoLogMessage(t, records, "tss dkg preparams acquired")
}

func TestRunDKGSessionLogsOnlySessionBoundaryEvents(t *testing.T) {
	logger, records := newObservedLogger()
	runner := &harnessRunner{
		share:   validECDSAShare(t),
		address: "TLkQfN3vWXxN71M5Qh2kJ9v8h8X4W3Yt9A",
	}
	store := &harnessShareStore{}
	pool := &harnessPreParamsPool{pre: &ecdsakeygen.LocalPreParams{}}
	service := coretss.NewServiceWithComponents(runner, logger, pool, store)

	_ = service.RunDKGSession(context.Background(), coretss.DKGSessionRequest{
		Session: protocol.SessionDescriptor{
			SessionID: "session-dkg-log-1",
			OrgID:     "org-1",
			Parties:   []string{"p1", "p2"},
			Threshold: 1,
			Algorithm: "ecdsa",
			Curve:     "secp256k1",
			Chain:     "bnb",
		},
		LocalPartyID: "p1",
		Transport:    noopTransport{},
	})

	assertLogMessages(t, records, []string{"tss session start", "tss session end"})
	assertNoLogMessage(t, records, "vault share operation success")
	assertNoLogMessage(t, records, "vault share operation failed")
	assertNoLogMessage(t, records, "tss dkg preparams acquired")
	assertNoLogMessage(t, records, "tss dkg preparams acquire failed")
}
