package tss

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BroLabel/brosettlement-mpc-core/internal/preparams"
	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	corederivation "github.com/BroLabel/brosettlement-mpc-core/internal/tss/derivation"
	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
	bnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/support"
	"github.com/BroLabel/brosettlement-mpc-core/protocol"
	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

type noopTransport struct{}

func (noopTransport) SendFrame(_ context.Context, _ protocol.Frame) error { return nil }

func (noopTransport) RecvFrame(_ context.Context) (protocol.Frame, error) {
	return protocol.Frame{}, errors.New("not implemented")
}

func TestDKGSessionRequestValidateRequiresTransport(t *testing.T) {
	req := DKGSessionRequest{
		Session: DKGSessionDescriptor{
			SessionID: "session-1",
			OrgID:     "org-1",
			Parties:   []string{"p1", "p2", "p3"},
			Threshold: 2,
		},
		LocalPartyID: "p1",
	}

	err := req.Validate()
	if !errors.Is(err, ErrTransportRequired) {
		t.Fatalf("expected ErrTransportRequired, got %v", err)
	}
}

func TestDKGSessionRequestDoesNotExposeChainContext(t *testing.T) {
	if _, ok := reflect.TypeOf(DKGSessionRequest{}.Session).FieldByName("Chain"); ok {
		t.Fatal("DKG session request must not expose chain context")
	}
}

func TestDKGSessionRequestValidateRequiresECDSADerivationMaterial(t *testing.T) {
	req := DKGSessionRequest{
		Session: DKGSessionDescriptor{
			SessionID: "dkg-1",
			OrgID:     "org-1",
			KeyID:     "key-1",
			Parties:   []string{"p1", "p2", "p3"},
			Threshold: 2,
			Algorithm: AlgorithmECDSA,
			Curve:     CurveSecp256k1,
		},
		LocalPartyID: "p1",
		Transport:    noopTransport{},
	}

	err := req.Validate()
	if !errors.Is(err, ErrChainCodeMissing) {
		t.Fatalf("expected ErrChainCodeMissing, got %v", err)
	}
}

func TestDKGSessionRequestValidateRejectsMalformedChainCode(t *testing.T) {
	req := validDKGRequestWithMaterial()
	req.DerivationMaterial.ChainCode = "0x11"

	err := req.Validate()
	if !errors.Is(err, ErrChainCodeInvalid) {
		t.Fatalf("expected ErrChainCodeInvalid, got %v", err)
	}
}

func TestDKGSessionRequestValidateRequiresECDSAKeyID(t *testing.T) {
	req := validDKGRequestWithMaterial()
	req.Session.KeyID = ""

	err := req.Validate()
	if !errors.Is(err, ErrKeyIDRequired) {
		t.Fatalf("expected ErrKeyIDRequired, got %v", err)
	}
}

func TestSignSessionRequestValidateRequiresDigest(t *testing.T) {
	req := SignSessionRequest{
		Session: SignSessionDescriptor{
			SessionID: "session-1",
			OrgID:     "org-1",
			KeyID:     "key-1",
			Parties:   []string{"p1", "p2", "p3"},
			Threshold: 2,
		},
		LocalPartyID: "p1",
		Transport:    noopTransport{},
	}

	err := req.Validate()
	if !errors.Is(err, ErrDigestMissing) {
		t.Fatalf("expected ErrDigestMissing, got %v", err)
	}
}

func TestRunSignSession_NormalizesAndHashesDerivationContextBeforeInternalService(t *testing.T) {
	runner := newFacadeDerivedRunner(t, "key-1")
	svc := newService(runner, slog.Default(), nil, nil, nil, nil)
	ctx := validFacadeDerivationContext()
	ctx.Algorithm = " ECDSA "
	ctx.Curve = " SECP256K1 "
	ctx.Scheme = " BIP32_SECP256K1 "
	normalized, err := NormalizeDerivationContext(ctx)
	if err != nil {
		t.Fatalf("NormalizeDerivationContext returned error: %v", err)
	}
	expectedHash, err := DerivationContextHashV1(normalized)
	if err != nil {
		t.Fatalf("DerivationContextHashV1 returned error: %v", err)
	}

	err = svc.RunSignSession(context.Background(), SignSessionRequest{
		Session: SignSessionDescriptor{
			SessionID: "sign-1",
			OrgID:     "org",
			KeyID:     "key-1",
			Parties:   []string{"p1", "p2"},
			Threshold: 1,
			Algorithm: AlgorithmECDSA,
			Curve:     CurveSecp256k1,
		},
		LocalPartyID:      "p1",
		Digest:            []byte{1, 2, 3},
		DerivationContext: &ctx,
		Transport:         noopTransport{},
	})
	if err != nil {
		t.Fatalf("RunSignSession returned error: %v", err)
	}
	if runner.lastSignJob.DerivationContextHash != expectedHash {
		t.Fatalf("DerivationContextHash = %q, want %q", runner.lastSignJob.DerivationContextHash, expectedHash)
	}
	if ctx.Algorithm != " ECDSA " {
		t.Fatalf("RunSignSession mutated caller context: %+v", ctx)
	}
}

func TestRunSignSessionRejectsNilDerivationContextBeforeInternalService(t *testing.T) {
	svc := NewBnbService(slog.Default())
	err := svc.RunSignSession(context.Background(), SignSessionRequest{
		Session: SignSessionDescriptor{
			SessionID: "sign-1",
			OrgID:     "org-1",
			KeyID:     "key-1",
			Parties:   []string{"p1", "p2", "p3"},
			Threshold: 2,
			Algorithm: AlgorithmECDSA,
			Curve:     CurveSecp256k1,
		},
		LocalPartyID: "p1",
		Digest:       []byte{1, 2, 3},
		Transport:    noopTransport{},
	})
	if !errors.Is(err, ErrDerivationContextRequired) {
		t.Fatalf("expected ErrDerivationContextRequired, got %v", err)
	}
}

func TestRunSignSessionRejectsInvalidDerivationContextBeforeInternalService(t *testing.T) {
	svc := NewBnbService(slog.Default())
	ctx := DerivationContext{
		ProfileID:   "profile-1",
		Algorithm:   AlgorithmECDSA,
		Curve:       CurveSecp256k1,
		Scheme:      DerivationSchemeBIP32Secp256k1,
		AccountPath: "m/44'/60'/0'",
		ChildPath:   "/0/015",
		FullPath:    "m/44'/60'/0'/0/015",
	}
	err := svc.RunSignSession(context.Background(), SignSessionRequest{
		Session: SignSessionDescriptor{
			SessionID: "sign-1",
			OrgID:     "org-1",
			KeyID:     "key-1",
			Parties:   []string{"p1", "p2", "p3"},
			Threshold: 2,
			Algorithm: AlgorithmECDSA,
			Curve:     CurveSecp256k1,
		},
		LocalPartyID:      "p1",
		Digest:            []byte{1, 2, 3},
		DerivationContext: &ctx,
		Transport:         noopTransport{},
	})
	if !errors.Is(err, ErrDerivationPathInvalid) {
		t.Fatalf("expected ErrDerivationPathInvalid, got %v", err)
	}
}

func validDKGRequestWithMaterial() DKGSessionRequest {
	return DKGSessionRequest{
		Session: DKGSessionDescriptor{
			SessionID: "dkg-1",
			OrgID:     "org-1",
			KeyID:     "key-1",
			Parties:   []string{"p1", "p2", "p3"},
			Threshold: 2,
			Algorithm: AlgorithmECDSA,
			Curve:     CurveSecp256k1,
		},
		LocalPartyID: "p1",
		DerivationMaterial: &DKGDerivationMaterial{
			ChainCode:        strings.Repeat("11", 32),
			DerivationScheme: DerivationSchemeBIP32Secp256k1,
		},
		Transport: noopTransport{},
	}
}

func validFacadeDerivationContext() DerivationContext {
	return DerivationContext{
		ProfileID:   "profile-1",
		Algorithm:   AlgorithmECDSA,
		Curve:       CurveSecp256k1,
		Scheme:      DerivationSchemeBIP32Secp256k1,
		AccountPath: "m/44'/60'/0'",
		ChildPath:   "/0/15",
		FullPath:    "m/44'/60'/0'/0/15",
	}
}

type facadeDerivedRunner struct {
	materialByKey map[string]coreshares.ECDSAKeyMaterial
	lastDKGJob    tssbnbrunner.DKGJob
	lastSignJob   tssbnbrunner.SignJob
}

func newFacadeDerivedRunner(t *testing.T, keyID string) *facadeDerivedRunner {
	t.Helper()
	pub := crypto.ScalarBaseMult(tsslib.S256(), big.NewInt(5))
	xj := crypto.ScalarBaseMult(tsslib.S256(), big.NewInt(7))
	if pub == nil || xj == nil {
		t.Fatal("expected secp256k1 test points")
	}
	share := ecdsakeygen.LocalPartySaveData{
		ECDSAPub: pub,
		BigXj:    []*crypto.ECPoint{xj},
	}
	return &facadeDerivedRunner{
		materialByKey: map[string]coreshares.ECDSAKeyMaterial{
			keyID: {
				Share:            share,
				ChainCode:        bytes.Repeat([]byte{0x11}, 32),
				PublicKeyFormat:  corederivation.PublicKeyFormatUncompressedHex,
				DerivationScheme: corederivation.DerivationSchemeBIP32Secp256k1,
			},
		},
	}
}

func (r *facadeDerivedRunner) RunDKG(_ context.Context, job tssbnbrunner.DKGJob, _ tssbnbrunner.Transport) error {
	r.lastDKGJob = job
	return nil
}

func (r *facadeDerivedRunner) RunSign(_ context.Context, job tssbnbrunner.SignJob, _ tssbnbrunner.Transport) error {
	r.lastSignJob = job
	return nil
}

func (r *facadeDerivedRunner) ExportECDSASignature(string) (common.SignatureData, error) {
	return common.SignatureData{}, nil
}

func (r *facadeDerivedRunner) ExportTemporaryECDSADKGShare(tssbnbrunner.DKGRunKey) (ecdsakeygen.LocalPartySaveData, error) {
	return ecdsakeygen.LocalPartySaveData{}, ErrShareNotFound
}

func (r *facadeDerivedRunner) ExportECDSAKeyMaterial(key string) (coreshares.ECDSAKeyMaterial, error) {
	material, ok := r.materialByKey[key]
	if !ok {
		return coreshares.ECDSAKeyMaterial{}, ErrShareNotFound
	}
	return material, nil
}

func (r *facadeDerivedRunner) ImportECDSAKeyMaterial(key string, material coreshares.ECDSAKeyMaterial) {
	r.materialByKey[key] = material
}

func (r *facadeDerivedRunner) DeleteTemporaryECDSADKGShare(key tssbnbrunner.DKGRunKey) {
	delete(r.materialByKey, key.SessionID)
}

func (r *facadeDerivedRunner) ECDSAAddress(string) (string, error) {
	return "", nil
}

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

func TestServiceDoesNotExposeShareOnlyAPI(t *testing.T) {
	serviceType := reflect.TypeOf((*Service)(nil))
	for _, name := range []string{
		"ExportECDSAKeyShare",
		"ImportECDSAKeyShare",
		"DeleteECDSAKeyShare",
		"ExportTemporaryECDSADKGShare",
		"DeleteTemporaryECDSADKGShare",
	} {
		if _, ok := serviceType.MethodByName(name); ok {
			t.Fatalf("Service still exposes share-only method %s", name)
		}
	}
}

type forgedDKGPreParamsHandle struct{}

func (forgedDKGPreParamsHandle) Discard() error      { return nil }
func (forgedDKGPreParamsHandle) dkgPreParamsHandle() {}

func TestDKGPreParamsHandleExposesOnlyDiscardToCallers(t *testing.T) {
	handleType := reflect.TypeOf((*DKGPreParamsHandle)(nil)).Elem()
	var exported []string
	for i := 0; i < handleType.NumMethod(); i++ {
		method := handleType.Method(i)
		if method.PkgPath == "" {
			exported = append(exported, method.Name)
		}
	}
	if !reflect.DeepEqual(exported, []string{"Discard"}) {
		t.Fatalf("exported handle methods = %v, want only Discard", exported)
	}
}

func TestRunDKGSessionWithPreParamsRejectsInvalidAndForeignPublicHandles(t *testing.T) {
	request := validDKGRequestWithMaterial()
	sourceA := &sourceStub{value: &ecdsakeygen.LocalPreParams{}}
	sourceB := &sourceStub{value: &ecdsakeygen.LocalPreParams{}}
	runnerA := newFacadeDerivedRunner(t, request.Session.KeyID)
	runnerB := newFacadeDerivedRunner(t, request.Session.KeyID)
	serviceA := newService(runnerA, slog.Default(), nil, nil, nil, sourceA)
	serviceB := newService(runnerB, slog.Default(), nil, nil, nil, sourceB)

	owned, err := serviceA.AcquireDKGPreParams(context.Background())
	if err != nil {
		t.Fatalf("AcquireDKGPreParams failed: %v", err)
	}
	var typedNil *dkgPreParamsHandle
	for name, handle := range map[string]DKGPreParamsHandle{
		"nil":       nil,
		"typed nil": typedNil,
		"forged":    forgedDKGPreParamsHandle{},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := serviceA.RunDKGSessionWithPreParams(context.Background(), request, handle); !errors.Is(err, ErrInvalidPreParamsHandle) {
				t.Fatalf("error = %v, want ErrInvalidPreParamsHandle", err)
			}
			if runnerA.lastDKGJob.SessionID != "" {
				t.Fatal("runner started for invalid public handle")
			}
		})
	}

	if _, err := serviceB.RunDKGSessionWithPreParams(context.Background(), request, owned); !errors.Is(err, ErrForeignPreParamsHandle) {
		t.Fatalf("foreign service error = %v, want ErrForeignPreParamsHandle", err)
	}
	if runnerB.lastDKGJob.SessionID != "" {
		t.Fatal("foreign service started runner")
	}
	if err := owned.Discard(); err != nil {
		t.Fatalf("foreign attempt changed owned handle: %v", err)
	}
}

func TestRunDKGSessionWithPreParamsConsumesPublicHandle(t *testing.T) {
	request := validDKGRequestWithMaterial()
	material := &ecdsakeygen.LocalPreParams{}
	source := &sourceStub{value: material}
	runner := newFacadeDerivedRunner(t, request.Session.KeyID)
	service := newService(runner, slog.Default(), nil, nil, nil, source)

	handle, err := service.AcquireDKGPreParams(context.Background())
	if err != nil {
		t.Fatalf("AcquireDKGPreParams failed: %v", err)
	}
	if _, err := service.RunDKGSessionWithPreParams(context.Background(), request, handle); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("RunDKGSessionWithPreParams error = %v, want downstream share error", err)
	}
	if runner.lastDKGJob.ECDSAPreParams != material {
		t.Fatal("runner did not receive consumed preparams")
	}
	if err := handle.Discard(); !errors.Is(err, ErrPreParamsConsumed) {
		t.Fatalf("discard after run error = %v, want ErrPreParamsConsumed", err)
	}
	if _, err := service.RunDKGSessionWithPreParams(context.Background(), request, handle); !errors.Is(err, ErrPreParamsConsumed) {
		t.Fatalf("repeated run error = %v, want ErrPreParamsConsumed", err)
	}
	wantSnapshot := Snapshot{
		PreParamsConsumedCount:        1,
		PreParamsConsumeConflictCount: 1,
	}
	if got := service.Snapshot(); got != wantSnapshot {
		t.Fatalf("Snapshot() = %+v, want %+v", got, wantSnapshot)
	}
}

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

type stubShareReader struct{}

func (stubShareReader) LoadShare(_ context.Context, _ string) (*coreshares.StoredShare, error) {
	return nil, ErrShareNotFound
}

type stubShareWriter struct{}

func (stubShareWriter) SaveShare(_ context.Context, _ SaveShareInput) error {
	return nil
}

type sourceStub struct {
	value *ecdsakeygen.LocalPreParams
	err   error
	calls int
}

func (s *sourceStub) Acquire(_ context.Context) (*ecdsakeygen.LocalPreParams, error) {
	s.calls++
	return s.value, s.err
}

type refillControlPoolStub struct {
	sourceStub
	pauses   int
	resumes  int
	snapshot preparams.Snapshot
}

func (p *refillControlPoolStub) Size() int {
	return p.snapshot.Size
}

func (p *refillControlPoolStub) Start(context.Context) error {
	return nil
}

func (p *refillControlPoolStub) Close() error {
	return nil
}

func (p *refillControlPoolStub) PauseRefill() {
	p.pauses++
}

func (p *refillControlPoolStub) ResumeRefill() {
	p.resumes++
}

func (p *refillControlPoolStub) Snapshot() preparams.Snapshot {
	return p.snapshot
}

func TestServiceExposesGenericPreParamsRefillControlsAndMetrics(t *testing.T) {
	pool := &refillControlPoolStub{
		snapshot: preparams.Snapshot{
			Size:              2,
			InFlight:          1,
			RefillPaused:      true,
			RefillPauseCount:  2,
			RefillResumeCount: 1,
		},
	}
	runner := newFacadeDerivedRunner(t, "key-1")
	service := newService(runner, slog.Default(), pool, nil, nil, nil)

	service.PausePreParamsRefill()
	service.ResumePreParamsRefill()

	if pool.pauses != 1 || pool.resumes != 1 {
		t.Fatalf("refill control calls = pause:%d resume:%d, want 1:1", pool.pauses, pool.resumes)
	}
	want := Snapshot{
		PreParamsPoolSize:           2,
		PreParamsGenerationInFlight: 1,
		PreParamsRefillPaused:       true,
		PreParamsRefillPauseCount:   2,
		PreParamsRefillResumeCount:  1,
	}
	if got := service.Snapshot(); got != want {
		t.Fatalf("Snapshot() = %+v, want %+v", got, want)
	}
}

func TestNewBnbServiceWithOptionsConfigShareCapabilitiesMetrics(t *testing.T) {
	cfg := PreParamsConfig{
		Enabled:             false,
		TargetSize:          2,
		MaxConcurrency:      1,
		GenerateTimeout:     time.Second,
		AcquireTimeout:      time.Second,
		RetryBackoff:        time.Millisecond,
		SyncFallbackOnEmpty: false,
		FileCacheEnabled:    false,
		FileCacheDir:        ".tmp/test",
	}
	reader := stubShareReader{}
	writer := stubShareWriter{}

	svc := NewBnbService(
		slog.Default(),
		WithPreParamsConfig(cfg),
		WithShareReader(reader),
		WithShareWriter(writer),
		WithMetrics(bnbutils.NoopMetrics{}),
	)
	if svc == nil {
		t.Fatal("expected non-nil facade")
	}
}

func TestNewBnbServiceWithPreParamsSource(t *testing.T) {
	source := &sourceStub{value: &ecdsakeygen.LocalPreParams{}}

	svc := NewBnbService(slog.Default(), WithPreParamsSource(source))
	if svc == nil {
		t.Fatal("expected non-nil facade")
	}

	opts := buildServiceOptions(WithPreParamsSource(source))
	if opts.preParamsSource != source {
		t.Fatal("expected preparams source to be stored in service options")
	}
}

func TestNewBnbServiceCanCreateTwoServicesWithDifferentSources(t *testing.T) {
	sourceA := &sourceStub{value: &ecdsakeygen.LocalPreParams{}}
	sourceB := &sourceStub{value: &ecdsakeygen.LocalPreParams{}}

	svcA := NewBnbService(slog.Default(), WithPreParamsSource(sourceA))
	svcB := NewBnbService(slog.Default(), WithPreParamsSource(sourceB))
	if svcA == nil || svcB == nil {
		t.Fatal("expected both facades to be non-nil")
	}

	optsA := buildServiceOptions(WithPreParamsSource(sourceA))
	optsB := buildServiceOptions(WithPreParamsSource(sourceB))
	if optsA.preParamsSource != sourceA || optsB.preParamsSource != sourceB {
		t.Fatal("expected each service options set to keep its own source")
	}
}
