# DKG Output Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make successful ECDSA DKG return a reliable `DKGOutput { KeyID, PublicKey, Address }`, add `ReadDKGOutput` recovery/replay support, and keep persisted-share parsing and derivation inside core.

**Architecture:** Add share-level ECDSA derivation primitives first, then introduce a single internal DKG-output builder in `internal/tss/service` that reads from persisted share when `shareStore != nil` and from runner state otherwise. Finally, expose the new contract through the public `tss` facade with ECDSA-only `ReadDKGOutput`, canonical `SessionID -> KeyID` validation, chain normalization, and regression coverage for sign flow and partial-success recovery.

**Tech Stack:** Go, `testing`, `slog`, `tss-lib`, existing `internal/shares` codec, existing share store interfaces

---

## File Map

- Create: `internal/tss/runtime/share_output.go`
  Share-level ECDSA derivation helpers: public-key extraction, chain normalization, chain-aware address derivation.
- Create: `internal/tss/runtime/share_output_test.go`
  Unit tests for share-level derivation helpers and chain normalization aliases.
- Create: `internal/tss/service/dkg_output.go`
  Internal `DKGOutput`/`ReadDKGOutputInput` types plus the single builder that reads persisted share or runner state.
- Create: `internal/tss/service/dkg_output_test.go`
  Core orchestration tests for persisted-share mode, runner-state mode, readback errors, best-effort recovery, non-ECDSA read rejection, and sign regression.
- Modify: `internal/tss/service/orchestration.go`
  Return `DKGOutput` from `RunDKGSession`, call the internal builder, and remove the separate `EnsureDKGMetadata(...)` post-run contract.
- Modify: `internal/tss/service/orchestration_external_preparams_test.go`
  Update existing DKG tests to accept the new `(DKGOutput, error)` signature.
- Create: `tss/dkg_output.go`
  Public `DKGOutput`, `ReadDKGOutputInput`, public errors, public helper wrappers, and the facade `ReadDKGOutput`.
- Create: `tss/dkg_output_test.go`
  Public helper tests plus facade-level tests for non-ECDSA `ReadDKGOutput`.
- Modify: `tss/service.go`
  Change the public `RunDKGSession` signature, add ECDSA `SessionID`/`KeyID` validation, and map public errors into internal service calls.
- Modify: `tss/service_test.go`
  Add validation tests for mismatched ECDSA `SessionID`/`KeyID`.

### Task 1: Add Share-Level DKG Output Helpers

**Files:**
- Create: `internal/tss/runtime/share_output.go`
- Create: `internal/tss/runtime/share_output_test.go`
- Test: `internal/tss/runtime/share_output_test.go`

- [ ] **Step 1: Write the failing tests**

```go
func makeTestECDSAShare(t *testing.T) ecdsakeygen.LocalPartySaveData {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() err = %v", err)
	}

	point, err := crypto.NewECPoint(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y)
	if err != nil {
		t.Fatalf("NewECPoint() err = %v", err)
	}

	return ecdsakeygen.LocalPartySaveData{
		ECDSAPub: point,
	}
}

func TestExtractECDSAPublicKey_ReturnsHexEncodedUncompressedPoint(t *testing.T) {
	share := makeTestECDSAShare(t)

	got, err := ExtractECDSAPublicKey(share)
	if err != nil {
		t.Fatalf("ExtractECDSAPublicKey() err = %v", err)
	}
	if got == "" {
		t.Fatal("expected non-empty public key")
	}
	if !strings.HasPrefix(got, "04") {
		t.Fatalf("expected uncompressed public key prefix 04, got %q", got)
	}
}

func TestNormalizeDKGOutputChain_AcceptsTronAliases(t *testing.T) {
	cases := []string{"", "tron", "TRON", "tron-mainnet", "TRON-MAINNET"}
	for _, input := range cases {
		got, err := NormalizeDKGOutputChain(input)
		if err != nil {
			t.Fatalf("NormalizeDKGOutputChain(%q) err = %v", input, err)
		}
		if got != "tron" {
			t.Fatalf("NormalizeDKGOutputChain(%q) = %q, want tron", input, got)
		}
	}
}

func TestECDSAAddressFromShare_RejectsUnsupportedChain(t *testing.T) {
	share := makeTestECDSAShare(t)

	_, err := ECDSAAddressFromShare("ethereum", share)
	if !errors.Is(err, ErrUnsupportedDKGOutputChain) {
		t.Fatalf("expected ErrUnsupportedDKGOutputChain, got %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `GOCACHE=/tmp/go-build go test ./internal/tss/runtime -run 'TestExtractECDSAPublicKey_ReturnsHexEncodedUncompressedPoint|TestNormalizeDKGOutputChain_AcceptsTronAliases|TestECDSAAddressFromShare_RejectsUnsupportedChain' -count=1`
Expected: FAIL with unknown `ExtractECDSAPublicKey` / `NormalizeDKGOutputChain` / `ECDSAAddressFromShare` symbols.

- [ ] **Step 3: Write minimal implementation**

```go
package runtime

import (
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"strings"

	tssbnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/utils"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

var ErrUnsupportedDKGOutputChain = errors.New("dkg output chain is unsupported")

func NormalizeDKGOutputChain(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "tron", "tron-mainnet":
		return "tron", nil
	default:
		return "", ErrUnsupportedDKGOutputChain
	}
}

func ExtractECDSAPublicKey(share ecdsakeygen.LocalPartySaveData) (string, error) {
	if share.ECDSAPub == nil {
		return "", tssbnbutils.ErrECDSAPubKeyUnavailable
	}
	pub := share.ECDSAPub.ToECDSAPubKey()
	if pub == nil || pub.X == nil || pub.Y == nil || pub.Curve == nil {
		return "", tssbnbutils.ErrECDSAPubKeyUnavailable
	}

	marshaled := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	if len(marshaled) == 0 {
		return "", tssbnbutils.ErrECDSAPubKeyUnavailable
	}
	return hex.EncodeToString(marshaled), nil
}

func ECDSAAddressFromShare(chain string, share ecdsakeygen.LocalPartySaveData) (string, error) {
	normalized, err := NormalizeDKGOutputChain(chain)
	if err != nil {
		return "", err
	}
	switch normalized {
	case "tron":
		return tssbnbutils.ECDSAAddressFromShare(share)
	default:
		return "", ErrUnsupportedDKGOutputChain
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `GOCACHE=/tmp/go-build go test ./internal/tss/runtime -run 'TestExtractECDSAPublicKey_ReturnsHexEncodedUncompressedPoint|TestNormalizeDKGOutputChain_AcceptsTronAliases|TestECDSAAddressFromShare_RejectsUnsupportedChain' -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/tss/runtime/share_output.go internal/tss/runtime/share_output_test.go
git commit -m "feat: add share-level dkg output helpers"
```

### Task 2: Add the Internal DKG Output Builder

**Files:**
- Create: `internal/tss/service/dkg_output.go`
- Create: `internal/tss/service/dkg_output_test.go`
- Modify: `internal/tss/service/orchestration.go`
- Test: `internal/tss/service/dkg_output_test.go`

- [ ] **Step 1: Write the failing tests**

```go
func makeTestECDSAShare(t *testing.T) ecdsakeygen.LocalPartySaveData {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
		SessionID:          "session-1",
		OrgID:              "org-1",
		Algorithm:          "ecdsa",
		Chain:              "tron",
		EmptyKeyErr:        errEmptyKey,
		MissingPublicKey:   errMissingPub,
		MissingAddressErr:  errMissingAddr,
		MetadataMismatch:   errMetadataMismatch,
		UnsupportedAlgErr:  errUnsupportedAlg,
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
	svc := New(runner, testLogger(t), &stubLifecyclePool{}, nil)

	out, err := svc.ReadDKGOutput(context.Background(), ReadDKGOutputInput{
		SessionID:          "session-2",
		OrgID:              "org-1",
		Algorithm:          "ecdsa",
		Chain:              "tron-mainnet",
		EmptyKeyErr:        errEmptyKey,
		MissingPublicKey:   errMissingPub,
		MissingAddressErr:  errMissingAddr,
		MetadataMismatch:   errMetadataMismatch,
		UnsupportedAlgErr:  errUnsupportedAlg,
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
		SessionID:          "session-3",
		OrgID:              "org-1",
		Algorithm:          "eddsa",
		Chain:              "tron",
		EmptyKeyErr:        errEmptyKey,
		MissingPublicKey:   errMissingPub,
		MissingAddressErr:  errMissingAddr,
		MetadataMismatch:   errMetadataMismatch,
		UnsupportedAlgErr:  errUnsupportedAlg,
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
		SessionID:          "session-4",
		OrgID:              "org-1",
		Algorithm:          "ecdsa",
		Chain:              "tron",
		EmptyKeyErr:        errEmptyKey,
		MissingPublicKey:   errMissingPub,
		MissingAddressErr:  errMissingAddr,
		MetadataMismatch:   errMetadataMismatch,
		UnsupportedAlgErr:  errUnsupportedAlg,
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
		SessionID:          "session-5",
		OrgID:              "org-1",
		Algorithm:          "ecdsa",
		Chain:              "tron",
		EmptyKeyErr:        errEmptyKey,
		MissingPublicKey:   errMissingPub,
		MissingAddressErr:  errMissingAddr,
		MetadataMismatch:   errMetadataMismatch,
		UnsupportedAlgErr:  errUnsupportedAlg,
		UnsupportedChainErr: errUnsupportedChain,
	})
	if !errors.Is(err, coreshares.ErrInvalidSharePayload) {
		t.Fatalf("expected ErrInvalidSharePayload, got %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `GOCACHE=/tmp/go-build go test ./internal/tss/service -run 'TestReadDKGOutput_UsesPersistedShareWhenStorePresent|TestReadDKGOutput_UsesRunnerStateWithoutStore|TestReadDKGOutput_ReturnsUnsupportedAlgorithmWithoutTouchingSources|TestReadDKGOutput_ReturnsMetadataMismatchForPersistedShare|TestReadDKGOutput_ReturnsInvalidSharePayload' -count=1`
Expected: FAIL with unknown `ReadDKGOutput` / `ReadDKGOutputInput` / `DKGOutput` symbols.

- [ ] **Step 3: Write minimal implementation**

```go
package service

import (
	"context"
	"errors"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	tssruntime "github.com/BroLabel/brosettlement-mpc-core/internal/tss/runtime"
	tssutils "github.com/BroLabel/brosettlement-mpc-core/tss/utils"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type DKGOutput struct {
	KeyID     string
	PublicKey string
	Address   string
}

type ReadDKGOutputInput struct {
	SessionID           string
	OrgID               string
	Algorithm           string
	Chain               string
	EmptyKeyErr         error
	MissingPublicKey    error
	MissingAddressErr   error
	MetadataMismatch    error
	UnsupportedAlgErr   error
	UnsupportedChainErr error
}

func (s *Service) ReadDKGOutput(ctx context.Context, in ReadDKGOutputInput) (DKGOutput, error) {
	if !tssutils.IsECDSA(in.Algorithm) {
		return DKGOutput{}, in.UnsupportedAlgErr
	}

	keyID, err := tssutils.NormalizeKeyID(in.SessionID, in.EmptyKeyErr)
	if err != nil {
		return DKGOutput{}, err
	}

	var share ecdsakeygen.LocalPartySaveData
	if s.shareStore != nil {
		stored, err := s.shareStore.LoadShare(ctx, keyID)
		if err != nil {
			return DKGOutput{}, err
		}
		if err := tssruntime.ValidateLoadedMeta(keyID, in.OrgID, in.Algorithm, stored.Meta, in.MetadataMismatch); err != nil {
			return DKGOutput{}, err
		}
		share, err = coreshares.UnmarshalShare(stored.Blob)
		tssutils.ZeroBytes(stored.Blob)
		if err != nil {
			return DKGOutput{}, err
		}
	} else {
		share, err = s.runner.ExportECDSAKeyShare(keyID)
		if err != nil {
			return DKGOutput{}, err
		}
	}

	publicKey, err := tssruntime.ExtractECDSAPublicKey(share)
	if err != nil {
		return DKGOutput{}, in.MissingPublicKey
	}
	address, err := tssruntime.ECDSAAddressFromShare(in.Chain, share)
	if errors.Is(err, tssruntime.ErrUnsupportedDKGOutputChain) {
		return DKGOutput{}, in.UnsupportedChainErr
	}
	if err != nil {
		return DKGOutput{}, in.MissingAddressErr
	}

	return DKGOutput{
		KeyID:     keyID,
		PublicKey: publicKey,
		Address:   address,
	}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `GOCACHE=/tmp/go-build go test ./internal/tss/service -run 'TestReadDKGOutput_UsesPersistedShareWhenStorePresent|TestReadDKGOutput_UsesRunnerStateWithoutStore|TestReadDKGOutput_ReturnsUnsupportedAlgorithmWithoutTouchingSources|TestReadDKGOutput_ReturnsMetadataMismatchForPersistedShare|TestReadDKGOutput_ReturnsInvalidSharePayload' -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/tss/service/dkg_output.go internal/tss/service/dkg_output_test.go internal/tss/service/orchestration.go
git commit -m "feat: add internal dkg output builder"
```

### Task 3: Return DKG Output from Internal RunDKGSession

**Files:**
- Modify: `internal/tss/service/orchestration.go`
- Modify: `internal/tss/service/orchestration_external_preparams_test.go`
- Modify: `internal/tss/service/dkg_output_test.go`
- Test: `internal/tss/service/dkg_output_test.go`

- [ ] **Step 1: Write the failing tests**

```go
func TestRunDKGSession_ReturnsOutputFromPersistedShare(t *testing.T) {
	share := makeTestECDSAShare(t)
	runner := newDKGOutputRunner(share)
	store := newMemoryShareStore()
	svc := New(runner, testLogger(t), &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}, store)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-persisted",
		LocalPartyID: "p1",
		OrgID:        "org-1",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		Chain:        "tron",
		EmptyKeyErr:  errEmptyKey,
		MissingPub:   errMissingPub,
		MissingAddr:  errMissingAddr,
	})
	if err != nil {
		t.Fatalf("RunDKGSession() err = %v", err)
	}
	if out.KeyID != "session-persisted" || out.PublicKey == "" || out.Address == "" {
		t.Fatalf("unexpected output: %+v", out)
	}
	if _, err := runner.ExportECDSAKeyShare("session-persisted"); err == nil {
		t.Fatal("expected persisted DKG to clear runner-held share")
	}
	if store.loadCalls == 0 {
		t.Fatal("expected persisted share to be used for output readback")
	}
}

func TestRunDKGSession_ReturnsOutputFromRunnerWithoutStore(t *testing.T) {
	share := makeTestECDSAShare(t)
	runner := newDKGOutputRunner(share)
	svc := New(runner, testLogger(t), &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}, nil)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-runner",
		LocalPartyID: "p1",
		OrgID:        "org-1",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		Chain:        "tron-mainnet",
		EmptyKeyErr:  errEmptyKey,
		MissingPub:   errMissingPub,
		MissingAddr:  errMissingAddr,
	})
	if err != nil {
		t.Fatalf("RunDKGSession() err = %v", err)
	}
	if out.KeyID != "session-runner" || out.PublicKey == "" || out.Address == "" {
		t.Fatalf("unexpected output: %+v", out)
	}
}

func TestRunDKGSession_PartialSuccessReturnsReadbackErrorAndAllowsRecovery(t *testing.T) {
	share := makeTestECDSAShare(t)
	store := newMemoryShareStore()
	store.loadErrOnce = coreshares.ErrVaultReadFailed
	runner := newDKGOutputRunner(share)
	svc := New(runner, testLogger(t), &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}, store)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-recover",
		LocalPartyID: "p1",
		OrgID:        "org-1",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		Chain:        "tron",
		EmptyKeyErr:  errEmptyKey,
		MissingPub:   errMissingPub,
		MissingAddr:  errMissingAddr,
	})
	if !errors.Is(err, coreshares.ErrVaultReadFailed) {
		t.Fatalf("expected ErrVaultReadFailed, got %v", err)
	}
	if out != (DKGOutput{}) {
		t.Fatalf("expected zero output on readback error, got %+v", out)
	}

	recovered, err := svc.ReadDKGOutput(context.Background(), ReadDKGOutputInput{
		SessionID:          "session-recover",
		OrgID:              "org-1",
		Algorithm:          "ecdsa",
		Chain:              "tron",
		EmptyKeyErr:        errEmptyKey,
		MissingPublicKey:   errMissingPub,
		MissingAddressErr:  errMissingAddr,
		MetadataMismatch:   errMetadataMismatch,
		UnsupportedAlgErr:  errUnsupportedAlg,
		UnsupportedChainErr: errUnsupportedChain,
	})
	if err != nil {
		t.Fatalf("ReadDKGOutput() err = %v", err)
	}
	if recovered.KeyID != "session-recover" || recovered.PublicKey == "" || recovered.Address == "" {
		t.Fatalf("unexpected recovered output: %+v", recovered)
	}
}

func TestRunDKGSession_NonECDSAReturnsZeroOutput(t *testing.T) {
	runner := newDKGOutputRunner(ecdsakeygen.LocalPartySaveData{})
	svc := New(runner, testLogger(t), &stubLifecyclePool{}, nil)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-eddsa",
		LocalPartyID: "p1",
		OrgID:        "org-1",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "eddsa",
		Chain:        "tron",
		EmptyKeyErr:  errEmptyKey,
	})
	if err != nil {
		t.Fatalf("RunDKGSession() err = %v", err)
	}
	if out != (DKGOutput{}) {
		t.Fatalf("expected zero output, got %+v", out)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `GOCACHE=/tmp/go-build go test ./internal/tss/service -run 'TestRunDKGSession_ReturnsOutputFromPersistedShare|TestRunDKGSession_ReturnsOutputFromRunnerWithoutStore|TestRunDKGSession_PartialSuccessReturnsReadbackErrorAndAllowsRecovery|TestRunDKGSession_NonECDSAReturnsZeroOutput' -count=1`
Expected: FAIL because `RunDKGSession` still returns only `error` and does not call `ReadDKGOutput`.

- [ ] **Step 3: Write minimal implementation**

```go
func (s *Service) RunDKGSession(ctx context.Context, in DKGInput) (DKGOutput, error) {
	job := tssbnbrunner.DKGJob{
		SessionID:    in.SessionID,
		LocalPartyID: in.LocalPartyID,
		OrgID:        in.OrgID,
		Parties:      in.Parties,
		Threshold:    in.Threshold,
		Curve:        in.Curve,
		Algorithm:    in.Algorithm,
		Chain:        in.Chain,
	}

	keyID := strings.TrimSpace(in.KeyID)
	if keyID == "" {
		keyID = in.SessionID
	}

	tsslogging.LogSessionStart(s.logger, "dkg", in.SessionID, in.OrgID, keyID, in.LocalPartyID)
	started := time.Now()

	var out DKGOutput
	err := AttachPreParams(ctx, ResolvePreParamsSource(s.preParamsSource, s.preParamsPool), &job, tssutils.IsECDSA(job.Algorithm))
	if err == nil {
		err = s.runner.RunDKG(ctx, job, in.Transport)
	}
	if err == nil && s.shareStore != nil && tssutils.IsECDSA(job.Algorithm) {
		err = tssruntime.PersistShareAfterDKG(ctx, s.shareStore, s.runner, tssruntime.DKGPersistInput{
			SessionID:         job.SessionID,
			OrgID:             job.OrgID,
			Algorithm:         job.Algorithm,
			Curve:             job.Curve,
			EmptyKeyErr:       in.EmptyKeyErr,
			MissingPublicKey:  in.MissingPub,
			MissingAddressErr: in.MissingAddr,
		})
	}
	if err == nil && tssutils.IsECDSA(job.Algorithm) {
		out, err = s.ReadDKGOutput(ctx, ReadDKGOutputInput{
			SessionID:          job.SessionID,
			OrgID:              job.OrgID,
			Algorithm:          job.Algorithm,
			Chain:              job.Chain,
			EmptyKeyErr:        in.EmptyKeyErr,
			MissingPublicKey:   in.MissingPub,
			MissingAddressErr:  in.MissingAddr,
			MetadataMismatch:   coreshares.ErrMetadataMismatch,
			UnsupportedAlgErr:  errors.New("unsupported dkg output algorithm"),
			UnsupportedChainErr: tssruntime.ErrUnsupportedDKGOutputChain,
		})
	}

	tsslogging.LogSessionEnd(s.logger, "dkg", in.SessionID, in.OrgID, keyID, in.LocalPartyID, started, err)
	return out, err
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `GOCACHE=/tmp/go-build go test ./internal/tss/service -run 'TestRunDKGSession_ReturnsOutputFromPersistedShare|TestRunDKGSession_ReturnsOutputFromRunnerWithoutStore|TestRunDKGSession_PartialSuccessReturnsReadbackErrorAndAllowsRecovery|TestRunDKGSession_NonECDSAReturnsZeroOutput|TestRunDKGSession_UsesExternalPreParamsSourceWhenProvided|TestRunDKGSession_UsesInternalPoolWhenExternalPreParamsSourceMissing' -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/tss/service/orchestration.go internal/tss/service/dkg_output_test.go internal/tss/service/orchestration_external_preparams_test.go
git commit -m "feat: return dkg output from internal dkg sessions"
```

### Task 4: Expose the Public DKG Output API

**Files:**
- Create: `tss/dkg_output.go`
- Create: `tss/dkg_output_test.go`
- Modify: `tss/service.go`
- Modify: `tss/service_test.go`
- Test: `tss/dkg_output_test.go`

- [ ] **Step 1: Write the failing tests**

```go
func makePublicTestECDSAShare(t *testing.T) ecdsakeygen.LocalPartySaveData {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() err = %v", err)
	}
	point, err := crypto.NewECPoint(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y)
	if err != nil {
		t.Fatalf("NewECPoint() err = %v", err)
	}
	return ecdsakeygen.LocalPartySaveData{ECDSAPub: point}
}

type stubFacadePool struct{}

func (p *stubFacadePool) Acquire(context.Context) (*ecdsakeygen.LocalPreParams, error) {
	return &ecdsakeygen.LocalPreParams{}, nil
}

func (p *stubFacadePool) Size() int { return 0 }
func (p *stubFacadePool) Start(context.Context) error { return nil }
func (p *stubFacadePool) Close() error { return nil }

type stubPublicRunner struct {
	share ecdsakeygen.LocalPartySaveData
}

func (r *stubPublicRunner) RunDKG(context.Context, dkgJob, Transport) error { return nil }
func (r *stubPublicRunner) RunSign(context.Context, signJob, Transport) error { return nil }
func (r *stubPublicRunner) ExportECDSASignature(string) (common.SignatureData, error) {
	return common.SignatureData{}, nil
}
func (r *stubPublicRunner) ExportECDSAKeyShare(string) (ecdsakeygen.LocalPartySaveData, error) {
	return r.share, nil
}
func (r *stubPublicRunner) ImportECDSAKeyShare(string, ecdsakeygen.LocalPartySaveData) {}
func (r *stubPublicRunner) DeleteECDSAKeyShare(string) {}
func (r *stubPublicRunner) ECDSAAddress(string) (string, error) { return "", nil }

func TestDKGSessionRequestValidateRejectsMismatchedECDSAKeyID(t *testing.T) {
	req := DKGSessionRequest{
		Session: SessionDescriptor{
			SessionID: "session-1",
			OrgID:     "org-1",
			KeyID:     "other-key",
			Parties:   []string{"p1", "p2"},
			Threshold: 1,
			Algorithm: "ecdsa",
		},
		LocalPartyID: "p1",
		Transport:    noopTransport{},
	}

	err := req.Validate()
	if !errors.Is(err, ErrDKGKeyIDMismatch) {
		t.Fatalf("expected ErrDKGKeyIDMismatch, got %v", err)
	}
}

func TestExtractECDSAPublicKey_PublicWrapper(t *testing.T) {
	share := makePublicTestECDSAShare(t)

	got, err := ExtractECDSAPublicKey(share)
	if err != nil {
		t.Fatalf("ExtractECDSAPublicKey() err = %v", err)
	}
	if got == "" {
		t.Fatal("expected non-empty public key")
	}
}

func TestECDSAAddressFromShare_NormalizesChainAliases(t *testing.T) {
	share := makePublicTestECDSAShare(t)

	base, err := ECDSAAddressFromShare("", share)
	if err != nil {
		t.Fatalf("ECDSAAddressFromShare(\"\") err = %v", err)
	}
	got, err := ECDSAAddressFromShare("TRON-MAINNET", share)
	if err != nil {
		t.Fatalf("ECDSAAddressFromShare(\"TRON-MAINNET\") err = %v", err)
	}
	if got != base {
		t.Fatalf("expected alias-normalized addresses to match: %q != %q", got, base)
	}
}

func TestReadDKGOutput_PublicFacadeRejectsNonECDSA(t *testing.T) {
	svc := newService(&stubPublicRunner{share: makePublicTestECDSAShare(t)}, slog.Default(), &stubFacadePool{}, nil, nil)

	_, err := svc.ReadDKGOutput(context.Background(), ReadDKGOutputInput{
		SessionID: "session-1",
		OrgID:     "org-1",
		Algorithm: "eddsa",
		Chain:     "tron",
	})
	if !errors.Is(err, ErrUnsupportedDKGOutputAlgorithm) {
		t.Fatalf("expected ErrUnsupportedDKGOutputAlgorithm, got %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `GOCACHE=/tmp/go-build go test ./tss -run 'TestDKGSessionRequestValidateRejectsMismatchedECDSAKeyID|TestExtractECDSAPublicKey_PublicWrapper|TestECDSAAddressFromShare_NormalizesChainAliases|TestReadDKGOutput_PublicFacadeRejectsNonECDSA' -count=1`
Expected: FAIL with unknown `ErrDKGKeyIDMismatch` / `ReadDKGOutput` / `ReadDKGOutputInput` / `ExtractECDSAPublicKey` / `ECDSAAddressFromShare` symbols or wrong `RunDKGSession` signature.

- [ ] **Step 3: Write minimal implementation**

```go
package tss

import (
	"context"
	"errors"
	"strings"

	tssservice "github.com/BroLabel/brosettlement-mpc-core/internal/tss/service"
	tssruntime "github.com/BroLabel/brosettlement-mpc-core/internal/tss/runtime"
	tssutils "github.com/BroLabel/brosettlement-mpc-core/tss/utils"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type DKGOutput struct {
	KeyID     string
	PublicKey string
	Address   string
}

type ReadDKGOutputInput struct {
	SessionID string
	OrgID     string
	Algorithm string
	Chain     string
}

var (
	ErrDKGKeyIDMismatch             = errors.New("dkg key id must match session id")
	ErrUnsupportedDKGOutputAlgorithm = errors.New("dkg output algorithm is unsupported")
	ErrUnsupportedDKGOutputChain     = errors.New("dkg output chain is unsupported")
)

func ExtractECDSAPublicKey(share ecdsakeygen.LocalPartySaveData) (string, error) {
	got, err := tssruntime.ExtractECDSAPublicKey(share)
	if err != nil {
		return "", ErrMissingDKGPublicKey
	}
	return got, nil
}

func ECDSAAddressFromShare(chain string, share ecdsakeygen.LocalPartySaveData) (string, error) {
	got, err := tssruntime.ECDSAAddressFromShare(chain, share)
	if errors.Is(err, tssruntime.ErrUnsupportedDKGOutputChain) {
		return "", ErrUnsupportedDKGOutputChain
	}
	if err != nil {
		return "", ErrMissingDKGAddress
	}
	return got, nil
}

func validateECDSADKGKeyID(session SessionDescriptor) error {
	if !strings.EqualFold(strings.TrimSpace(session.Algorithm), "ecdsa") || strings.TrimSpace(session.KeyID) == "" {
		return nil
	}
	sessionID, err := tssutils.NormalizeKeyID(session.SessionID, ErrInvalidSessionDescriptor)
	if err != nil {
		return err
	}
	keyID, err := tssutils.NormalizeKeyID(session.KeyID, ErrDKGKeyIDMismatch)
	if err != nil {
		return err
	}
	if keyID != sessionID {
		return ErrDKGKeyIDMismatch
	}
	return nil
}

func (s *Service) ReadDKGOutput(ctx context.Context, in ReadDKGOutputInput) (DKGOutput, error) {
	out, err := s.impl.ReadDKGOutput(ctx, tssservice.ReadDKGOutputInput{
		SessionID:          in.SessionID,
		OrgID:              in.OrgID,
		Algorithm:          in.Algorithm,
		Chain:              in.Chain,
		EmptyKeyErr:        ErrVaultWriteFailed,
		MissingPublicKey:   ErrMissingDKGPublicKey,
		MissingAddressErr:  ErrMissingDKGAddress,
		MetadataMismatch:   ErrMetadataMismatch,
		UnsupportedAlgErr:  ErrUnsupportedDKGOutputAlgorithm,
		UnsupportedChainErr: ErrUnsupportedDKGOutputChain,
	})
	return DKGOutput(out), err
}
```

Also update `tss/service.go`:

```go
func (s *Service) RunDKGSession(ctx context.Context, req DKGSessionRequest) (DKGOutput, error) {
	if err := validateECDSADKGKeyID(req.Session); err != nil {
		return DKGOutput{}, err
	}

	out, err := s.impl.RunDKGSession(ctx, tssservice.DKGInput{
		SessionID:    req.Session.SessionID,
		LocalPartyID: req.LocalPartyID,
		OrgID:        req.Session.OrgID,
		KeyID:        req.Session.KeyID,
		Parties:      req.Session.Parties,
		Threshold:    req.Session.Threshold,
		Curve:        req.Session.Curve,
		Algorithm:    req.Session.Algorithm,
		Chain:        req.Session.Chain,
		Transport:    req.Transport,
		EmptyKeyErr:  ErrVaultWriteFailed,
		MissingPub:   ErrMissingDKGPublicKey,
		MissingAddr:  ErrMissingDKGAddress,
	})
	return DKGOutput(out), err
}

func (r DKGSessionRequest) Validate() error {
	if err := tssrequests.ValidateDKG(/* existing input */, ErrInvalidSessionDescriptor, ErrLocalPartyRequired, ErrTransportRequired); err != nil {
		return err
	}
	return validateECDSADKGKeyID(r.Session)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `GOCACHE=/tmp/go-build go test ./tss -run 'TestDKGSessionRequestValidateRejectsMismatchedECDSAKeyID|TestExtractECDSAPublicKey_PublicWrapper|TestECDSAAddressFromShare_NormalizesChainAliases|TestReadDKGOutput_PublicFacadeRejectsNonECDSA' -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tss/dkg_output.go tss/dkg_output_test.go tss/service.go tss/service_test.go
git commit -m "feat: expose public dkg output api"
```

### Task 5: Lock Regression Coverage and Final Verification

**Files:**
- Modify: `internal/tss/service/dkg_output_test.go`
- Test: `internal/tss/service/dkg_output_test.go`

- [ ] **Step 1: Write the failing tests**

```go
func TestRunSignSession_LoadsPersistedShareBeforeSign(t *testing.T) {
	share := makeTestECDSAShare(t)
	store := newMemoryShareStoreWithShare(t, "key-1", "org-1", "ecdsa", share)
	runner := newDKGOutputRunner(share)
	runner.signatures["sign-1"] = common.SignatureData{
		Signature: []byte{1, 2, 3},
	}
	svc := New(runner, testLogger(t), &stubLifecyclePool{}, store)

	err := svc.RunSignSession(context.Background(), SignInput{
		SessionID:        "sign-1",
		LocalPartyID:     "p1",
		OrgID:            "org-1",
		KeyID:            "key-1",
		Parties:          []string{"p1", "p2"},
		Digest:           []byte{9, 9, 9},
		Algorithm:        "ecdsa",
		Chain:            "tron",
		EmptyKeyErr:      errEmptyKey,
		MetadataMismatch: errMetadataMismatch,
	})
	if err != nil {
		t.Fatalf("RunSignSession() err = %v", err)
	}
	if runner.lastSignKeyID != "key-1" {
		t.Fatalf("expected sign to use imported key share, got %q", runner.lastSignKeyID)
	}
	if _, ok := runner.keyShares["key-1"]; ok {
		t.Fatal("expected imported key share to be cleaned after sign")
	}
}

func TestReadDKGOutput_RunnerModeFailsAfterShareIsCleared(t *testing.T) {
	share := makeTestECDSAShare(t)
	runner := newDKGOutputRunner(share)
	svc := New(runner, testLogger(t), &stubLifecyclePool{}, nil)

	if _, err := svc.ReadDKGOutput(context.Background(), ReadDKGOutputInput{
		SessionID:          "runner-best-effort",
		OrgID:              "org-1",
		Algorithm:          "ecdsa",
		Chain:              "tron",
		EmptyKeyErr:        errEmptyKey,
		MissingPublicKey:   errMissingPub,
		MissingAddressErr:  errMissingAddr,
		MetadataMismatch:   errMetadataMismatch,
		UnsupportedAlgErr:  errUnsupportedAlg,
		UnsupportedChainErr: errUnsupportedChain,
	}); err != nil {
		t.Fatalf("unexpected initial ReadDKGOutput() err = %v", err)
	}

	runner.DeleteECDSAKeyShare("runner-best-effort")

	if _, err := svc.ReadDKGOutput(context.Background(), ReadDKGOutputInput{
		SessionID:          "runner-best-effort",
		OrgID:              "org-1",
		Algorithm:          "ecdsa",
		Chain:              "tron",
		EmptyKeyErr:        errEmptyKey,
		MissingPublicKey:   errMissingPub,
		MissingAddressErr:  errMissingAddr,
		MetadataMismatch:   errMetadataMismatch,
		UnsupportedAlgErr:  errUnsupportedAlg,
		UnsupportedChainErr: errUnsupportedChain,
	}); err == nil {
		t.Fatal("expected missing runner share after cleanup")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `GOCACHE=/tmp/go-build go test ./internal/tss/service -run 'TestRunSignSession_LoadsPersistedShareBeforeSign|TestReadDKGOutput_RunnerModeFailsAfterShareIsCleared' -count=1`
Expected: FAIL until the new test stubs support sign execution and runner cleanup assertions.

- [ ] **Step 3: Write minimal implementation**

```go
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
```

- [ ] **Step 4: Run focused and full verification**

Run: `GOCACHE=/tmp/go-build go test ./internal/tss/service -run 'TestRunSignSession_LoadsPersistedShareBeforeSign|TestReadDKGOutput_RunnerModeFailsAfterShareIsCleared' -count=1`
Expected: PASS

Run: `GOCACHE=/tmp/go-build go test ./... -count=1`
Expected: PASS across the repository.

- [ ] **Step 5: Commit**

```bash
git add internal/tss/service/dkg_output_test.go
git commit -m "test: cover dkg recovery and sign regression"
```
