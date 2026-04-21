# DKG Output Return Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make successful `ecdsa` `RunDKGSession` calls return stable `DKGOutput{KeyID, PublicKey, Address}` derived before share-store persistence and cleanup, while preserving the current no-store in-memory DKG->Sign behavior. For non-`ecdsa` DKG, keep the existing protocol behavior and return `DKGOutput{KeyID}` with empty ECDSA-specific fields.

**Architecture:** Keep ECDSA DKG output derivation inside the core orchestration path instead of relying on post-run reads from runner state. Introduce a small internal/public `DKGOutput` type, export the ECDSA share from the runner immediately after `runner.RunDKG`, derive both `PublicKey` and `Address` directly from that share, persist the same share only when `shareStore` is enabled, and clean up the runner-held share only on the store-backed path. Non-ECDSA DKG bypasses ECDSA share derivation and runner cleanup in this change.

**Tech Stack:** Go, `tss-lib` ECDSA keygen share structures, existing `internal/tss/runtime` helpers, `testing`, `go test`

---

### Task 1: Introduce explicit DKG output types and new method signatures

**Files:**
- Modify: `internal/tss/service/orchestration.go`
- Modify: `tss/service.go`
- Test: `internal/tss/service/orchestration_external_preparams_test.go`
- Test: `tss/service_test.go`

- [ ] **Step 1: Write the failing compile-time/test changes for the new return contract**

Update the tests first so they call the future API shape and fail to compile until the implementation exists.

```go
// internal/tss/service/orchestration_external_preparams_test.go
output, err := svc.RunDKGSession(context.Background(), DKGInput{
	SessionID:    "session-1",
	LocalPartyID: "p1",
	OrgID:        "org",
	Parties:      []string{"p1", "p2"},
	Threshold:    1,
	Algorithm:    "ecdsa",
})
if err != nil {
	t.Fatalf("RunDKGSession returned error: %v", err)
}
if output.KeyID != "session-1" {
	t.Fatalf("expected key id to default to session id, got %q", output.KeyID)
}
```

```go
// tss/service_test.go
func TestNewBnbServiceReturnsFacade(t *testing.T) {
	svc := NewBnbService(slog.Default())
	if svc == nil {
		t.Fatal("expected non-nil facade")
	}

	if got := svc.Snapshot(); got != (Snapshot{}) {
		t.Fatalf("expected zero-value snapshot, got %+v", got)
	}

	var zero DKGOutput
	if zero != (DKGOutput{}) {
		t.Fatalf("expected zero-value output type, got %+v", zero)
	}
}
```

- [ ] **Step 2: Run the targeted tests to verify the signature change is still missing**

Run: `go test ./internal/tss/service ./tss -run 'TestRunDKGSession|TestNewBnbServiceReturnsFacade' -count=1`

Expected: FAIL to compile because `RunDKGSession` still returns only `error` and `DKGOutput` does not exist yet.

- [ ] **Step 3: Add `DKGOutput` to the internal and public service layers and change method signatures**

Add matching structs and update both `RunDKGSession` methods to return `(DKGOutput, error)`.

```go
// internal/tss/service/orchestration.go
type DKGOutput struct {
	KeyID     string
	PublicKey string
	Address   string
}

func (s *Service) RunDKGSession(ctx context.Context, in DKGInput) (DKGOutput, error) {
	// implementation filled in by later tasks
}
```

```go
// tss/service.go
type DKGOutput = tssservice.DKGOutput

func (s *Service) RunDKGSession(ctx context.Context, req DKGSessionRequest) (DKGOutput, error) {
	return s.impl.RunDKGSession(ctx, tssservice.DKGInput{
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
}
```

- [ ] **Step 4: Return zero-value output on existing early-error paths**

Make all early returns explicit and stable.

```go
// internal/tss/service/orchestration.go
if err != nil {
	tsslogging.LogSessionEnd(s.logger, "dkg", in.SessionID, in.OrgID, keyID, in.LocalPartyID, started, err)
	return DKGOutput{}, err
}
```

- [ ] **Step 5: Run the targeted tests again**

Run: `go test ./internal/tss/service ./tss -run 'TestRunDKGSession|TestNewBnbServiceReturnsFacade' -count=1`

Expected: FAIL in runtime assertions or because output derivation is not implemented yet, but compile errors from the new signature should be gone.

- [ ] **Step 6: Commit the API-contract skeleton**

```bash
git add internal/tss/service/orchestration.go tss/service.go internal/tss/service/orchestration_external_preparams_test.go tss/service_test.go
git commit -m "refactor: add explicit dkg output contract"
```

### Task 2: Add ECDSA output derivation and self-contained test fixtures

**Files:**
- Modify: `internal/tss/runtime/share_runtime.go`
- Modify: `internal/tss/service/orchestration.go`
- Test: `internal/tss/service/orchestration_external_preparams_test.go`

- [ ] **Step 1: Rewrite the service test harness so DKG output tests are self-contained**

Replace the minimal `stubRunner` with one that can serve seeded ECDSA shares, observe cleanup, and optionally require a runner-held share for sign. Add explicit helpers so the existing preparams tests do not start failing due to missing fixture state.

```go
var (
	errMissingPublicKey = errors.New("missing public key")
	errMissingAddress   = errors.New("missing address")
	errPersistFailed    = errors.New("persist failed")
	errShareMissing     = errors.New("share missing")
)

type stubRunner struct {
	lastDKGJob          tssbnbrunner.DKGJob
	lastSignJob         tssbnbrunner.SignJob
	shareByKey          map[string]ecdsakeygen.LocalPartySaveData
	exportedKeys        []string
	deletedKeys         []string
	events              []string
	requireShareForSign bool
	signatureExported   bool
}

func (r *stubRunner) ExportECDSAKeyShare(key string) (ecdsakeygen.LocalPartySaveData, error) {
	r.events = append(r.events, "export:"+key)
	r.exportedKeys = append(r.exportedKeys, key)
	share, ok := r.shareByKey[key]
	if !ok {
		return ecdsakeygen.LocalPartySaveData{}, errShareMissing
	}
	return share, nil
}

func (r *stubRunner) DeleteECDSAKeyShare(key string) {
	r.events = append(r.events, "cleanup:"+key)
	r.deletedKeys = append(r.deletedKeys, key)
	delete(r.shareByKey, key)
}

func (r *stubRunner) RunDKG(_ context.Context, job tssbnbrunner.DKGJob, _ coretransport.FrameTransport) error {
	r.lastDKGJob = job
	return nil
}

func (r *stubRunner) RunSign(_ context.Context, job tssbnbrunner.SignJob, _ coretransport.FrameTransport) error {
	r.lastSignJob = job
	if r.requireShareForSign {
		if _, ok := r.shareByKey[job.KeyID]; !ok {
			if _, ok := r.shareByKey[job.SessionID]; !ok {
				return errShareMissing
			}
		}
	}
	return nil
}

func (r *stubRunner) ExportECDSASignature(string) (common.SignatureData, error) {
	r.signatureExported = true
	return common.SignatureData{}, nil
}

func (r *stubRunner) ImportECDSAKeyShare(key string, data ecdsakeygen.LocalPartySaveData) {
	if r.shareByKey == nil {
		r.shareByKey = map[string]ecdsakeygen.LocalPartySaveData{}
	}
	r.shareByKey[key] = data
}

func (r *stubRunner) ECDSAAddress(string) (string, error) {
	return "", nil
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newECDSATestShare(t *testing.T) ecdsakeygen.LocalPartySaveData {
	t.Helper()
	pub := crypto.ScalarBaseMult(elliptic.P256(), big.NewInt(1))
	if pub == nil {
		t.Fatal("expected test public key point")
	}
	return ecdsakeygen.LocalPartySaveData{ECDSAPub: pub}
}

func newECDSAStubRunner(t *testing.T, sessionID string) *stubRunner {
	t.Helper()
	share := newECDSATestShare(t)
	return &stubRunner{
		shareByKey: map[string]ecdsakeygen.LocalPartySaveData{
			sessionID: share,
		},
	}
}

func newECDSAStubRunnerWithoutPub(t *testing.T, sessionID string) *stubRunner {
	t.Helper()
	return &stubRunner{
		shareByKey: map[string]ecdsakeygen.LocalPartySaveData{
			sessionID: {},
		},
	}
}
```

Update the existing preparams tests to use the seeded fixture:

```go
runner := newECDSAStubRunner(t, "session-1")
logger := newTestLogger()
internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
svc := New(runner, logger, internalPool, nil, externalSource)

out, err := svc.RunDKGSession(context.Background(), DKGInput{
	SessionID:    "session-1",
	LocalPartyID: "p1",
	OrgID:        "org",
	Parties:      []string{"p1", "p2"},
	Threshold:    1,
	Algorithm:    "ecdsa",
	MissingPub:   errMissingPublicKey,
	MissingAddr:  errMissingAddress,
})
if err != nil {
	t.Fatalf("RunDKGSession returned error: %v", err)
}
if out.KeyID != "session-1" || out.PublicKey == "" || out.Address == "" {
	t.Fatalf("expected populated ecdsa output, got %+v", out)
}
```

Add the new normalization-focused test:

```go
func TestRunDKGSession_ReturnsOutputBeforeCleanup(t *testing.T) {
	runner := newECDSAStubRunner(t, "session-1")
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(runner, logger, internalPool, nil)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-1",
		KeyID:        "key-1",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		MissingPub:   errMissingPublicKey,
		MissingAddr:  errMissingAddress,
	})
	if err != nil {
		t.Fatalf("RunDKGSession returned error: %v", err)
	}
	if out.KeyID != "key-1" {
		t.Fatalf("expected key id key-1, got %q", out.KeyID)
	}
	if out.PublicKey == "" || out.Address == "" {
		t.Fatalf("expected populated output, got %+v", out)
	}
	if len(runner.deletedKeys) != 0 {
		t.Fatalf("expected no cleanup without store, got %+v", runner.deletedKeys)
	}
}
```

- [ ] **Step 2: Run the focused test to verify missing helper functionality**

Run: `go test ./internal/tss/service -run 'TestRunDKGSession_ReturnsOutputBeforeCleanup' -count=1`

Expected: FAIL because output extraction helpers do not exist yet.

- [ ] **Step 3: Introduce a runtime helper that derives ECDSA metadata directly from a loaded share**

Keep public key extraction and address derivation in one place, and do not duplicate the service-layer `DKGOutput` type in `runtime`.

```go
// internal/tss/runtime/share_runtime.go
type DerivedECDSAOutput struct {
	PublicKey string
	Address   string
}

func DeriveECDSAOutputFromShare(share ecdsakeygen.LocalPartySaveData, missingPublicKeyErr, missingAddressErr error) (DerivedECDSAOutput, error) {
	pub := extractECDSAPublicKey(share)
	if pub == "" {
		return DerivedECDSAOutput{}, missingPublicKeyErr
	}
	address, err := tssbnbutils.ECDSAAddressFromShare(share)
	if err != nil {
		return DerivedECDSAOutput{}, err
	}
	if strings.TrimSpace(address) == "" {
		return DerivedECDSAOutput{}, missingAddressErr
	}
	return DerivedECDSAOutput{
		PublicKey: pub,
		Address:   address,
	}, nil
}
```

- [ ] **Step 4: Make orchestration build output immediately after `runner.RunDKG`**

Read the ECDSA share by `SessionID`, derive metadata from that share, and stamp the returned service output with normalized `keyID`. For non-ECDSA, return `DKGOutput{KeyID: keyID}` and skip ECDSA share access entirely.

```go
var out DKGOutput
if err == nil && tssutils.IsECDSA(job.Algorithm) {
	share, exportErr := s.runner.ExportECDSAKeyShare(in.SessionID)
	if exportErr != nil {
		tsslogging.LogSessionEnd(s.logger, "dkg", in.SessionID, in.OrgID, keyID, in.LocalPartyID, started, exportErr)
		return DKGOutput{}, exportErr
	}
	derived, deriveErr := tssruntime.DeriveECDSAOutputFromShare(share, in.MissingPub, in.MissingAddr)
	if deriveErr != nil {
		tsslogging.LogSessionEnd(s.logger, "dkg", in.SessionID, in.OrgID, keyID, in.LocalPartyID, started, deriveErr)
		return DKGOutput{}, deriveErr
	}
	out = DKGOutput{
		KeyID:     keyID,
		PublicKey: derived.PublicKey,
		Address:   derived.Address,
	}
}
if err == nil && !tssutils.IsECDSA(job.Algorithm) {
	out = DKGOutput{KeyID: keyID}
}
```

- [ ] **Step 5: Run the focused service tests**

Run: `go test ./internal/tss/service -run 'TestRunDKGSession_' -count=1`

Expected: PASS for the preparams tests and the new output-return tests, with no cleanup on the no-store ECDSA path.

- [ ] **Step 6: Commit the extraction logic**

```bash
git add internal/tss/runtime/share_runtime.go internal/tss/service/orchestration.go internal/tss/service/orchestration_external_preparams_test.go
git commit -m "feat: derive dkg output before cleanup"
```

### Task 3: Persist the same share after output extraction and clean up only on the store-backed path

**Files:**
- Modify: `internal/tss/runtime/share_runtime.go`
- Modify: `internal/tss/service/orchestration.go`
- Test: `internal/tss/service/orchestration_external_preparams_test.go`

- [ ] **Step 1: Add failing tests for store-backed cleanup order and no-store DKG->Sign regression coverage**

Use a store stub that records an event sequence and verifies the runner-held share is still present during `SaveShare`. Keep a separate no-store regression test that proves we did not break in-memory follow-up signing, and add a failing-store test that proves persist errors do not trigger cleanup.

```go
type recordingShareStore struct {
	savedKeyID string
	savedBlob  []byte
	savedMeta  coreshares.ShareMeta
	runner     *stubRunner
	sessionID  string
}

func (s *recordingShareStore) SaveShare(_ context.Context, keyID string, blob []byte, meta coreshares.ShareMeta) error {
	s.runner.events = append(s.runner.events, "persist:"+keyID)
	if _, ok := s.runner.shareByKey[s.sessionID]; !ok {
		return errors.New("share cleaned before persist")
	}
	s.savedKeyID = keyID
	s.savedBlob = append([]byte(nil), blob...)
	s.savedMeta = meta
	return nil
}

func (s *recordingShareStore) LoadShare(context.Context, string) (*coreshares.StoredShare, error) {
	return nil, coreshares.ErrShareNotFound
}
```

```go
func TestRunDKGSession_PersistsShareAfterOutputExtraction(t *testing.T) {
	runner := newECDSAStubRunner(t, "session-1")
	store := &recordingShareStore{runner: runner, sessionID: "session-1"}
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(runner, logger, internalPool, store)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-1",
		KeyID:        "key-1",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		MissingPub:   errMissingPublicKey,
		MissingAddr:  errMissingAddress,
	})
	if err != nil {
		t.Fatalf("RunDKGSession returned error: %v", err)
	}
	if out.KeyID != "key-1" {
		t.Fatalf("expected key id key-1, got %q", out.KeyID)
	}
	if len(store.savedBlob) == 0 {
		t.Fatal("expected share to be persisted")
	}
	wantEvents := []string{"export:session-1", "persist:key-1", "cleanup:session-1"}
	if !reflect.DeepEqual(runner.events, wantEvents) {
		t.Fatalf("expected events %v, got %v", wantEvents, runner.events)
	}
	if len(runner.deletedKeys) != 1 || runner.deletedKeys[0] != "session-1" {
		t.Fatalf("expected session share cleanup, got %+v", runner.deletedKeys)
	}
}
```

```go
type failingShareStore struct {
	err error
}

func (s *failingShareStore) SaveShare(context.Context, string, []byte, coreshares.ShareMeta) error {
	return s.err
}

func (s *failingShareStore) LoadShare(context.Context, string) (*coreshares.StoredShare, error) {
	return nil, coreshares.ErrShareNotFound
}
```

```go
func TestRunDKGSession_PersistFailureKeepsRunnerShare(t *testing.T) {
	runner := newECDSAStubRunner(t, "session-1")
	store := &failingShareStore{err: errPersistFailed}
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(runner, logger, internalPool, store)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-1",
		KeyID:        "key-1",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		MissingPub:   errMissingPublicKey,
		MissingAddr:  errMissingAddress,
	})
	if !errors.Is(err, errPersistFailed) {
		t.Fatalf("expected persist failure, got %v", err)
	}
	if out != (DKGOutput{}) {
		t.Fatalf("expected zero output on persist failure, got %+v", out)
	}
	if _, ok := runner.shareByKey["session-1"]; !ok {
		t.Fatal("expected runner share to remain after persist failure")
	}
	if len(runner.deletedKeys) != 0 {
		t.Fatalf("expected no cleanup on persist failure, got %+v", runner.deletedKeys)
	}
}
```

```go
func TestRunDKGThenSign_NoStoreKeepsRunnerShare(t *testing.T) {
	runner := newECDSAStubRunner(t, "key-1")
	runner.requireShareForSign = true
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(runner, logger, internalPool, nil)

	if _, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "key-1",
		KeyID:        "key-1",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		MissingPub:   errMissingPublicKey,
		MissingAddr:  errMissingAddress,
	}); err != nil {
		t.Fatalf("RunDKGSession returned error: %v", err)
	}
	if err := svc.RunSignSession(context.Background(), SignInput{
		SessionID:    "sign-1",
		KeyID:        "key-1",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Digest:       []byte{1, 2, 3},
		Algorithm:    "ecdsa",
	}); err != nil {
		t.Fatalf("expected in-memory sign to keep working, got %v", err)
	}
	if len(runner.deletedKeys) != 0 {
		t.Fatalf("expected no cleanup without store, got %+v", runner.deletedKeys)
	}
}
```

- [ ] **Step 2: Run the store-path test and verify the old helper shape blocks it**

Run: `go test ./internal/tss/service -run 'TestRunDKGSession_PersistsShareAfterOutputExtraction' -count=1`

Expected: FAIL because persistence still exports/deletes from runner internally and orchestration does not own cleanup order yet.

- [ ] **Step 3: Refactor persistence to accept the share directly**

Replace the current runner-dependent persist helper with a share-based helper.

```go
// internal/tss/runtime/share_runtime.go
type DKGPersistInput struct {
	KeyID     string
	OrgID     string
	Algorithm string
	Curve     string
}

func PersistShareAfterDKG(ctx context.Context, store ShareStore, share ecdsakeygen.LocalPartySaveData, in DKGPersistInput) error {
	blob, err := coreshares.MarshalShare(share)
	if err != nil {
		return err
	}
	defer tssutils.ZeroBytes(blob)
	return store.SaveShare(ctx, in.KeyID, blob, tssutils.DKGShareMeta(in.KeyID, in.OrgID, in.Algorithm, in.Curve))
}
```

- [ ] **Step 4: Make orchestration own cleanup only after successful persist on the store-backed ECDSA path**

Delete by `SessionID`, because that is where the runner stored the DKG share, but only when `shareStore != nil` and the persist call succeeded. The no-store path must retain the runner-held share for follow-up signing, and a persist failure must also leave the share in memory for retry/recovery.

```go
if err == nil && tssutils.IsECDSA(job.Algorithm) && s.shareStore != nil {
	err = tssruntime.PersistShareAfterDKG(ctx, s.shareStore, share, tssruntime.DKGPersistInput{
		KeyID:     keyID,
		OrgID:     job.OrgID,
		Algorithm: job.Algorithm,
		Curve:     job.Curve,
	})
	if err == nil {
		s.runner.DeleteECDSAKeyShare(in.SessionID)
	}
}
```

- [ ] **Step 5: Remove the obsolete post-persist metadata read**

Delete `EnsureDKGMetadata(...)` call from orchestration and remove the helper if it is no longer used anywhere.

```go
// remove this block entirely
if err == nil && tssutils.IsECDSA(job.Algorithm) {
	err = tssruntime.EnsureDKGMetadata(s.runner, in.SessionID, in.MissingPub, in.MissingAddr)
}
```

- [ ] **Step 6: Run the internal service package tests**

Run: `go test ./internal/tss/service ./internal/tss/runtime -count=1`

Expected: PASS, including the cleanup-order assertion for store-backed DKG, the no-store DKG->Sign regression test, and the persist-failure test that keeps the runner share intact.

- [ ] **Step 7: Commit the persist/cleanup refactor**

```bash
git add internal/tss/runtime/share_runtime.go internal/tss/service/orchestration.go internal/tss/service/orchestration_external_preparams_test.go
git commit -m "refactor: persist dkg shares after output extraction"
```

### Task 4: Cover public facade behavior and non-happy-path errors

**Files:**
- Modify: `tss/service_test.go`
- Modify: `internal/tss/service/orchestration_external_preparams_test.go`
- Modify: `internal/tss/runtime/share_runtime.go`

- [ ] **Step 1: Add failing tests for error propagation**

Add tests for:
- missing public key
- missing address
- persist failure
- zero-value output on error
- `eddsa` success returning `DKGOutput{KeyID}` without ECDSA-only fields
- store-backed persist failure still returning an error without breaking no-store semantics

```go
func TestRunDKGSession_ReturnsMissingPublicKeyError(t *testing.T) {
	runner := newECDSAStubRunnerWithoutPub(t, "session-1")
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{preParams: &ecdsakeygen.LocalPreParams{}}
	svc := New(runner, logger, internalPool, nil)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-1",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "ecdsa",
		MissingPub:   errMissingPublicKey,
	})
	if !errors.Is(err, errMissingPublicKey) {
		t.Fatalf("expected missing public key error, got %v", err)
	}
	if out != (DKGOutput{}) {
		t.Fatalf("expected zero output on error, got %+v", out)
	}
}
```

```go
func TestRunDKGSession_EdDSAReturnsKeyIDOnly(t *testing.T) {
	runner := &stubRunner{}
	logger := newTestLogger()
	internalPool := &stubLifecyclePool{}
	svc := New(runner, logger, internalPool, nil)

	out, err := svc.RunDKGSession(context.Background(), DKGInput{
		SessionID:    "session-eddsa",
		KeyID:        "key-eddsa",
		LocalPartyID: "p1",
		OrgID:        "org",
		Parties:      []string{"p1", "p2"},
		Threshold:    1,
		Algorithm:    "eddsa",
	})
	if err != nil {
		t.Fatalf("RunDKGSession returned error: %v", err)
	}
	if out != (DKGOutput{KeyID: "key-eddsa"}) {
		t.Fatalf("expected key-only eddsa output, got %+v", out)
	}
	if len(runner.exportedKeys) != 0 || len(runner.deletedKeys) != 0 {
		t.Fatalf("expected eddsa path to skip ecdsa share handling, got exports=%v deletes=%v", runner.exportedKeys, runner.deletedKeys)
	}
}
```

- [ ] **Step 2: Run the focused error-path tests**

Run: `go test ./internal/tss/service -run 'TestRunDKGSession_Returns' -count=1`

Expected: FAIL until all error paths return `DKGOutput{}` consistently.

- [ ] **Step 3: Make helper and orchestration return zero-value output on all DKG failures**

Audit every `return` in `RunDKGSession` and the new helpers. Preserve these invariants:
- ECDSA success: populated `KeyID`, `PublicKey`, `Address`
- non-ECDSA success: `KeyID` only
- any error: zero-value `DKGOutput{}`

```go
if err != nil {
	return DKGOutput{}, err
}
return out, nil
```

- [ ] **Step 4: Add a facade-level test that exercises the public alias**

```go
func TestDKGOutputAliasMatchesInternalContract(t *testing.T) {
	got := DKGOutput{
		KeyID:     "key-1",
		PublicKey: "04abcd",
		Address:   "T...",
	}
	if got.KeyID == "" || got.PublicKey == "" || got.Address == "" {
		t.Fatalf("expected populated facade output, got %+v", got)
	}
}
```

- [ ] **Step 5: Run the broader unit-test set**

Run: `go test ./internal/tss/service ./tss -count=1`

Expected: PASS.

- [ ] **Step 6: Commit the error-path coverage**

```bash
git add tss/service_test.go internal/tss/service/orchestration_external_preparams_test.go internal/tss/runtime/share_runtime.go
git commit -m "test: cover dkg output error paths"
```

### Task 5: Remove stale post-run output assumptions and verify the full package set

**Files:**
- Modify: `tss/service.go`
- Modify: `internal/tss/service/orchestration.go`
- Modify: `internal/tss/runtime/share_runtime.go`
- Modify: any in-repo call sites found by search

- [ ] **Step 1: Search for stale assumptions and failing call sites**

Run: `rg -n "RunDKGSession\\(|EnsureDKGMetadata|ReadDKGOutput|ExportECDSAKeyShare\\(|ECDSAAddress\\(" .`

Expected: identify all in-repo callers still assuming `RunDKGSession` returns only `error` or still leaning on post-run metadata reads.

- [ ] **Step 2: Update all in-repo callers to consume `(DKGOutput, error)`**

Follow the smallest possible change at each site.

```go
out, err := svc.RunDKGSession(ctx, req)
if err != nil {
	return err
}
_ = out // replace with real usage or explicit ignore where appropriate
```

- [ ] **Step 3: Remove dead helper code**

If `EnsureDKGMetadata` or any runner-post-read helper is unused after the refactor, delete it entirely.

```go
// remove obsolete helper and any now-unused Runner methods from helper-only interfaces
```

- [ ] **Step 4: Run the full verification suite**

Run: `go test ./...`

Expected: PASS across the repository.

- [ ] **Step 5: Inspect the final diff for contract clarity**

Run: `git diff --stat && git diff -- internal/tss/service/orchestration.go internal/tss/runtime/share_runtime.go tss/service.go`

Expected: diff shows the new output contract, pre-persist derivation, and no remaining post-run runner dependency for DKG output.

- [ ] **Step 6: Commit the cleanup pass**

```bash
git add internal/tss/service/orchestration.go internal/tss/runtime/share_runtime.go tss/service.go
git commit -m "chore: remove stale dkg output assumptions"
```
