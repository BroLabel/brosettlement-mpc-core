package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	tssruntime "github.com/BroLabel/brosettlement-mpc-core/internal/tss/runtime"
	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
	coretransport "github.com/BroLabel/brosettlement-mpc-core/transport"
	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

func makeTestECDSAShare(t *testing.T) ecdsakeygen.LocalPartySaveData {
	t.Helper()

	priv, err := ecdsa.GenerateKey(tsslib.S256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() err = %v", err)
	}
	point, err := crypto.NewECPoint(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y)
	if err != nil {
		t.Fatalf("NewECPoint() err = %v", err)
	}
	return ecdsakeygen.LocalPartySaveData{ECDSAPub: point}
}

var (
	errEmptyKey         = errors.New("empty key")
	errMissingPub       = errors.New("missing public key")
	errMissingAddr      = errors.New("missing address")
	errMetadataMismatch = errors.New("metadata mismatch")
	errUnsupportedAlg   = errors.New("unsupported dkg output algorithm")
	errUnsupportedChain = errors.New("unsupported dkg output chain")
)

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type memoryShareStore struct {
	shares      map[string]*coreshares.StoredShare
	loadCalls   int
	loadErr     error
	loadErrOnce error
}

func newMemoryShareStore() *memoryShareStore {
	return &memoryShareStore{shares: map[string]*coreshares.StoredShare{}}
}

func newMemoryShareStoreWithBlob(keyID string, blob []byte, meta coreshares.ShareMeta) *memoryShareStore {
	store := newMemoryShareStore()
	store.shares[keyID] = &coreshares.StoredShare{
		Blob: append([]byte(nil), blob...),
		Meta: meta,
	}
	return store
}

func newMemoryShareStoreWithShare(t *testing.T, keyID, orgID, algorithm string, share ecdsakeygen.LocalPartySaveData) *memoryShareStore {
	t.Helper()

	blob, err := coreshares.MarshalShare(share)
	if err != nil {
		t.Fatalf("MarshalShare() err = %v", err)
	}

	return newMemoryShareStoreWithBlob(keyID, blob, coreshares.ShareMeta{
		KeyID:     keyID,
		OrgID:     orgID,
		Algorithm: algorithm,
		Status:    coreshares.StatusActive,
		Version:   1,
	})
}

func (s *memoryShareStore) SaveShare(_ context.Context, keyID string, blob []byte, meta coreshares.ShareMeta) error {
	s.shares[keyID] = &coreshares.StoredShare{
		Blob: append([]byte(nil), blob...),
		Meta: meta,
	}
	return nil
}

func (s *memoryShareStore) LoadShare(_ context.Context, keyID string) (*coreshares.StoredShare, error) {
	s.loadCalls++
	if s.loadErrOnce != nil {
		err := s.loadErrOnce
		s.loadErrOnce = nil
		return nil, err
	}
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	stored, ok := s.shares[keyID]
	if !ok {
		return nil, coreshares.ErrShareNotFound
	}
	return &coreshares.StoredShare{
		Blob: append([]byte(nil), stored.Blob...),
		Meta: stored.Meta,
	}, nil
}

type dkgOutputRunner struct {
	dkgShare         ecdsakeygen.LocalPartySaveData
	keyShares        map[string]ecdsakeygen.LocalPartySaveData
	signatures       map[string]common.SignatureData
	lastSignKeyID    string
	exportShareCalls int
}

func newDKGOutputRunner(share ecdsakeygen.LocalPartySaveData) *dkgOutputRunner {
	return &dkgOutputRunner{
		dkgShare:   share,
		keyShares:  map[string]ecdsakeygen.LocalPartySaveData{},
		signatures: map[string]common.SignatureData{},
	}
}

func (r *dkgOutputRunner) RunDKG(_ context.Context, job tssbnbrunner.DKGJob, _ coretransport.FrameTransport) error {
	r.keyShares[job.SessionID] = r.dkgShare
	return nil
}

func (r *dkgOutputRunner) RunSign(_ context.Context, job tssbnbrunner.SignJob, _ coretransport.FrameTransport) error {
	if _, ok := r.keyShares[job.KeyID]; !ok {
		return fmt.Errorf("missing key share for %s", job.KeyID)
	}
	r.lastSignKeyID = job.KeyID
	if _, ok := r.signatures[job.SessionID]; !ok {
		r.signatures[job.SessionID] = common.SignatureData{Signature: []byte{1, 2, 3}}
	}
	return nil
}

func (r *dkgOutputRunner) ExportECDSASignature(key string) (common.SignatureData, error) {
	sig, ok := r.signatures[key]
	if !ok {
		return common.SignatureData{}, fmt.Errorf("missing signature: %s", key)
	}
	return sig, nil
}

func (r *dkgOutputRunner) ExportECDSAKeyShare(key string) (ecdsakeygen.LocalPartySaveData, error) {
	r.exportShareCalls++
	share, ok := r.keyShares[key]
	if !ok {
		return ecdsakeygen.LocalPartySaveData{}, fmt.Errorf("missing key share: %s", key)
	}
	return share, nil
}

func (r *dkgOutputRunner) ImportECDSAKeyShare(key string, data ecdsakeygen.LocalPartySaveData) {
	r.keyShares[key] = data
}

func (r *dkgOutputRunner) DeleteECDSAKeyShare(key string) {
	delete(r.keyShares, key)
}

func (r *dkgOutputRunner) ECDSAAddress(key string) (string, error) {
	share, ok := r.keyShares[key]
	if !ok {
		return "", fmt.Errorf("missing key share: %s", key)
	}
	return tssruntime.ECDSAAddressFromShare("tron", share)
}

func TestReadDKGOutput_UsesPersistedShareWhenStorePresent(t *testing.T) {
	share := makeTestECDSAShare(t)
	store := newMemoryShareStoreWithShare(t, "session-1", "org-1", "ecdsa", share)
	runner := newDKGOutputRunner(share)
	svc := New(runner, testLogger(t), &stubLifecyclePool{}, store)

	out, err := svc.ReadDKGOutput(context.Background(), ReadDKGOutputInput{
		SessionID:           "session-1",
		OrgID:               "org-1",
		Algorithm:           "ecdsa",
		Chain:               "tron",
		EmptyKeyErr:         errEmptyKey,
		MissingPublicKey:    errMissingPub,
		MissingAddressErr:   errMissingAddr,
		MetadataMismatch:    errMetadataMismatch,
		UnsupportedAlgErr:   errUnsupportedAlg,
		UnsupportedChainErr: errUnsupportedChain,
	})
	if err != nil {
		t.Fatalf("ReadDKGOutput() err = %v", err)
	}
	if out.KeyID != "session-1" || out.PublicKey == "" || out.Address == "" {
		t.Fatalf("unexpected output: %+v", out)
	}
	if store.loadCalls != 1 {
		t.Fatalf("expected store.LoadShare once, got %d", store.loadCalls)
	}
}

func TestReadDKGOutput_UsesRunnerStateWithoutStore(t *testing.T) {
	share := makeTestECDSAShare(t)
	runner := newDKGOutputRunner(share)
	runner.ImportECDSAKeyShare("session-2", share)
	svc := New(runner, testLogger(t), &stubLifecyclePool{}, nil)

	out, err := svc.ReadDKGOutput(context.Background(), ReadDKGOutputInput{
		SessionID:           "session-2",
		OrgID:               "org-1",
		Algorithm:           "ecdsa",
		Chain:               "tron-mainnet",
		EmptyKeyErr:         errEmptyKey,
		MissingPublicKey:    errMissingPub,
		MissingAddressErr:   errMissingAddr,
		MetadataMismatch:    errMetadataMismatch,
		UnsupportedAlgErr:   errUnsupportedAlg,
		UnsupportedChainErr: errUnsupportedChain,
	})
	if err != nil {
		t.Fatalf("ReadDKGOutput() err = %v", err)
	}
	if out.KeyID != "session-2" || out.PublicKey == "" || out.Address == "" {
		t.Fatalf("unexpected output: %+v", out)
	}
	if runner.exportShareCalls != 1 {
		t.Fatalf("expected runner.ExportECDSAKeyShare once, got %d", runner.exportShareCalls)
	}
}

func TestReadDKGOutput_ReturnsUnsupportedAlgorithmWithoutTouchingSources(t *testing.T) {
	store := newMemoryShareStore()
	runner := newDKGOutputRunner(ecdsakeygen.LocalPartySaveData{})
	svc := New(runner, testLogger(t), &stubLifecyclePool{}, store)

	_, err := svc.ReadDKGOutput(context.Background(), ReadDKGOutputInput{
		SessionID:           "session-3",
		OrgID:               "org-1",
		Algorithm:           "eddsa",
		Chain:               "tron",
		EmptyKeyErr:         errEmptyKey,
		MissingPublicKey:    errMissingPub,
		MissingAddressErr:   errMissingAddr,
		MetadataMismatch:    errMetadataMismatch,
		UnsupportedAlgErr:   errUnsupportedAlg,
		UnsupportedChainErr: errUnsupportedChain,
	})
	if !errors.Is(err, errUnsupportedAlg) {
		t.Fatalf("expected errUnsupportedAlg, got %v", err)
	}
	if store.loadCalls != 0 || runner.exportShareCalls != 0 {
		t.Fatalf("expected no source access, store=%d runner=%d", store.loadCalls, runner.exportShareCalls)
	}
}

func TestReadDKGOutput_ReturnsMetadataMismatchForPersistedShare(t *testing.T) {
	share := makeTestECDSAShare(t)
	store := newMemoryShareStoreWithShare(t, "session-4", "other-org", "ecdsa", share)
	runner := newDKGOutputRunner(share)
	svc := New(runner, testLogger(t), &stubLifecyclePool{}, store)

	_, err := svc.ReadDKGOutput(context.Background(), ReadDKGOutputInput{
		SessionID:           "session-4",
		OrgID:               "org-1",
		Algorithm:           "ecdsa",
		Chain:               "tron",
		EmptyKeyErr:         errEmptyKey,
		MissingPublicKey:    errMissingPub,
		MissingAddressErr:   errMissingAddr,
		MetadataMismatch:    errMetadataMismatch,
		UnsupportedAlgErr:   errUnsupportedAlg,
		UnsupportedChainErr: errUnsupportedChain,
	})
	if !errors.Is(err, errMetadataMismatch) {
		t.Fatalf("expected errMetadataMismatch, got %v", err)
	}
}

func TestReadDKGOutput_ReturnsInvalidSharePayload(t *testing.T) {
	store := newMemoryShareStoreWithBlob("session-5", []byte("broken"), coreshares.ShareMeta{
		KeyID:     "session-5",
		OrgID:     "org-1",
		Algorithm: "ecdsa",
	})
	svc := New(newDKGOutputRunner(ecdsakeygen.LocalPartySaveData{}), testLogger(t), &stubLifecyclePool{}, store)

	_, err := svc.ReadDKGOutput(context.Background(), ReadDKGOutputInput{
		SessionID:           "session-5",
		OrgID:               "org-1",
		Algorithm:           "ecdsa",
		Chain:               "tron",
		EmptyKeyErr:         errEmptyKey,
		MissingPublicKey:    errMissingPub,
		MissingAddressErr:   errMissingAddr,
		MetadataMismatch:    errMetadataMismatch,
		UnsupportedAlgErr:   errUnsupportedAlg,
		UnsupportedChainErr: errUnsupportedChain,
	})
	if !errors.Is(err, coreshares.ErrInvalidSharePayload) {
		t.Fatalf("expected ErrInvalidSharePayload, got %v", err)
	}
}
