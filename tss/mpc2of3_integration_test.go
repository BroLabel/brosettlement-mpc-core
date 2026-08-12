package tss

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/btcsuite/btcd/btcec"
	"golang.org/x/sync/errgroup"
)

const (
	mpc2Of3PartyA = "A"
	mpc2Of3PartyB = "B"
	mpc2Of3PartyC = "C"
	mpc2Of3KeyID  = "mpc2of3-key"
)

type mpc2Of3PreParamsPool struct {
	acquires atomic.Uint32
	items    chan *ecdsakeygen.LocalPreParams
}

func (p *mpc2Of3PreParamsPool) Acquire(ctx context.Context) (*ecdsakeygen.LocalPreParams, error) {
	select {
	case item := <-p.items:
		p.acquires.Add(1)
		return item, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func newMPC2Of3PreParamsPool(items ...*ecdsakeygen.LocalPreParams) *mpc2Of3PreParamsPool {
	pool := &mpc2Of3PreParamsPool{items: make(chan *ecdsakeygen.LocalPreParams, len(items))}
	for _, item := range items {
		pool.items <- item
	}
	return pool
}

type mpc2Of3ShareStore struct {
	mu       sync.RWMutex
	shares   map[mpc2Of3ShareKey]StoredShare
	bindings []mpc2Of3SaveBinding
}

type mpc2Of3ShareKey struct {
	partyID string
	keyID   string
}

type mpc2Of3SaveBinding struct {
	sessionID                   string
	keyID                       string
	localPartyID                string
	opaqueDescriptorFingerprint []byte
}

type mpc2Of3PartyShareReader struct {
	store   *mpc2Of3ShareStore
	partyID string
}

func newMPC2Of3ShareStore() *mpc2Of3ShareStore {
	return &mpc2Of3ShareStore{shares: make(map[mpc2Of3ShareKey]StoredShare)}
}

func (s *mpc2Of3ShareStore) SaveShare(_ context.Context, in SaveShareInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := mpc2Of3ShareKey{partyID: in.LocalPartyID, keyID: in.KeyID}
	if _, exists := s.shares[key]; exists {
		return errors.New("test share already exists")
	}
	s.shares[key] = StoredShare{
		Blob: append([]byte(nil), in.CodecBlob...),
	}
	s.bindings = append(s.bindings, mpc2Of3SaveBinding{
		sessionID:                   in.SessionID,
		keyID:                       in.KeyID,
		localPartyID:                in.LocalPartyID,
		opaqueDescriptorFingerprint: append([]byte(nil), in.OpaqueDescriptorFingerprint...),
	})
	return nil
}

func (r *mpc2Of3PartyShareReader) LoadShare(_ context.Context, keyID string) (*StoredShare, error) {
	if r == nil || r.store == nil {
		return nil, ErrShareNotFound
	}
	return r.store.load(r.partyID, keyID)
}

func (s *mpc2Of3ShareStore) load(partyID, keyID string) (*StoredShare, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stored, ok := s.shares[mpc2Of3ShareKey{partyID: partyID, keyID: keyID}]
	if !ok {
		return nil, ErrShareNotFound
	}
	copy := stored
	copy.Blob = append([]byte(nil), stored.Blob...)
	return &copy, nil
}

func (s *mpc2Of3ShareStore) blob(partyID, keyID string) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]byte(nil), s.shares[mpc2Of3ShareKey{partyID: partyID, keyID: keyID}].Blob...)
}

func (s *mpc2Of3ShareStore) savedBindings() []mpc2Of3SaveBinding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bindings := make([]mpc2Of3SaveBinding, len(s.bindings))
	for index, binding := range s.bindings {
		bindings[index] = binding
		bindings[index].opaqueDescriptorFingerprint = append(
			[]byte(nil),
			binding.opaqueDescriptorFingerprint...,
		)
	}
	return bindings
}

type mpc2Of3FrameBus struct {
	mu        sync.RWMutex
	endpoints map[string]chan protocol.Frame
}

type mpc2Of3Transport struct {
	bus     *mpc2Of3FrameBus
	inbound <-chan protocol.Frame
}

func newMPC2Of3FrameBus(parties []string) (*mpc2Of3FrameBus, map[string]Transport) {
	bus := &mpc2Of3FrameBus{endpoints: make(map[string]chan protocol.Frame, len(parties))}
	transports := make(map[string]Transport, len(parties))
	for _, partyID := range parties {
		inbound := make(chan protocol.Frame, 256)
		bus.endpoints[partyID] = inbound
		transports[partyID] = &mpc2Of3Transport{bus: bus, inbound: inbound}
	}
	return bus, transports
}

func (t *mpc2Of3Transport) SendFrame(ctx context.Context, frame protocol.Frame) error {
	t.bus.mu.RLock()
	defer t.bus.mu.RUnlock()

	if frame.IsBroadcast() {
		for partyID, inbound := range t.bus.endpoints {
			if partyID == frame.FromParty {
				continue
			}
			if err := sendMPC2Of3Frame(ctx, inbound, frame); err != nil {
				return err
			}
		}
		return nil
	}
	inbound, ok := t.bus.endpoints[frame.ToParty]
	if !ok {
		return fmt.Errorf("test transport target is unavailable: %s", frame.ToParty)
	}
	return sendMPC2Of3Frame(ctx, inbound, frame)
}

func sendMPC2Of3Frame(ctx context.Context, inbound chan<- protocol.Frame, frame protocol.Frame) error {
	copy := frame
	copy.Payload = append([]byte(nil), frame.Payload...)
	select {
	case inbound <- copy:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *mpc2Of3Transport) RecvFrame(ctx context.Context) (protocol.Frame, error) {
	select {
	case frame := <-t.inbound:
		return frame, nil
	case <-ctx.Done():
		return protocol.Frame{}, ctx.Err()
	}
}

type mpc2Of3Fixture struct {
	services  map[string]*Service
	outputs   map[string]DKGOutput
	chainCode []byte
	keyID     string
}

func TestMPC2Of3DKGAndEverySigningSubset(t *testing.T) {
	fixture := runMPC2Of3DKG(t)

	subsets := [][]string{
		{mpc2Of3PartyA, mpc2Of3PartyB},
		{mpc2Of3PartyA, mpc2Of3PartyC},
		{mpc2Of3PartyB, mpc2Of3PartyC},
	}
	paths := []struct {
		name      string
		childPath string
	}{
		{name: "root", childPath: "/0/0"},
		{name: "non-root", childPath: "/1/7"},
	}

	for _, subset := range subsets {
		subset := subset
		for _, path := range paths {
			path := path
			t.Run(subset[0]+"+"+subset[1]+"/"+path.name, func(t *testing.T) {
				verifyMPC2Of3SigningSession(t, fixture, subset, path.childPath)
			})
		}
	}
}

func runMPC2Of3DKG(t *testing.T) mpc2Of3Fixture {
	t.Helper()

	parties := []string{mpc2Of3PartyA, mpc2Of3PartyB, mpc2Of3PartyC}
	chainCode := randomMPC2Of3Bytes(t, 32)
	chainCodeHex := hex.EncodeToString(chainCode)
	descriptorFingerprint := []byte("mpc2of3-test")
	store := newMPC2Of3ShareStore()
	preParams := generateMPC2Of3PreParams(t, len(parties))
	aPool := newMPC2Of3PreParamsPool(preParams[0])
	bcPool := newMPC2Of3PreParamsPool(preParams[1], preParams[2])
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	aService := NewBnbService(logger,
		WithPreParamsSource(aPool),
		WithShareWriter(store),
	)
	bcService := NewBnbService(logger,
		WithPreParamsSource(bcPool),
		WithShareWriter(store),
	)
	dkgServices := map[string]*Service{
		mpc2Of3PartyA: aService,
		mpc2Of3PartyB: bcService,
		mpc2Of3PartyC: bcService,
	}

	_, transports := newMPC2Of3FrameBus(parties)
	sessionID := "mpc2of3-dkg-" + hex.EncodeToString(randomMPC2Of3Bytes(t, 8))
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	outputs := make(map[string]DKGOutput, len(parties))
	var outputsMu sync.Mutex
	group, groupCtx := errgroup.WithContext(ctx)
	for _, partyID := range parties {
		partyID := partyID
		group.Go(func() error {
			output, err := dkgServices[partyID].RunDKGSession(groupCtx, DKGSessionRequest{
				Session: DKGSessionDescriptor{
					SessionID: sessionID,
					OrgID:     "mpc2of3-test",
					KeyID:     mpc2Of3KeyID,
					Parties:   parties,
					Threshold: 2,
					Algorithm: AlgorithmECDSA,
					Curve:     CurveSecp256k1,
				},
				LocalPartyID:                partyID,
				OpaqueDescriptorFingerprint: descriptorFingerprint,
				DerivationMaterial: &DKGDerivationMaterial{
					ChainCode:        chainCodeHex,
					DerivationScheme: DerivationSchemeBIP32Secp256k1,
				},
				Transport: transports[partyID],
			})
			if err != nil {
				return fmt.Errorf("party %s DKG failed: %w", partyID, err)
			}
			outputsMu.Lock()
			outputs[partyID] = output
			outputsMu.Unlock()
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		t.Fatal(err)
	}

	if aPool.acquires.Load() != 1 {
		t.Fatalf("A preparams acquires = %d, want 1", aPool.acquires.Load())
	}
	if bcPool.acquires.Load() != 2 {
		t.Fatalf("shared B/C preparams acquires = %d, want 2", bcPool.acquires.Load())
	}
	assertMPC2Of3DKGEvidence(
		t,
		parties,
		outputs,
		store,
		sessionID,
		mpc2Of3KeyID,
		descriptorFingerprint,
		chainCodeHex,
	)
	signingServices := make(map[string]*Service, len(parties))
	for _, partyID := range parties {
		signingServices[partyID] = NewBnbService(
			logger,
			WithShareReader(&mpc2Of3PartyShareReader{store: store, partyID: partyID}),
		)
	}

	return mpc2Of3Fixture{
		services:  signingServices,
		outputs:   outputs,
		chainCode: chainCode,
		keyID:     mpc2Of3KeyID,
	}
}

func generateMPC2Of3PreParams(t *testing.T, count int) []*ecdsakeygen.LocalPreParams {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	items := make([]*ecdsakeygen.LocalPreParams, count)
	group, groupCtx := errgroup.WithContext(ctx)
	for index := range items {
		index := index
		group.Go(func() error {
			item, err := ecdsakeygen.GeneratePreParamsWithContext(groupCtx, 2)
			if err != nil {
				return fmt.Errorf("generate test-only preparams %d: %w", index, err)
			}
			items[index] = item
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		t.Fatal(err)
	}
	return items
}

func assertMPC2Of3DKGEvidence(
	t *testing.T,
	parties []string,
	outputs map[string]DKGOutput,
	store *mpc2Of3ShareStore,
	sessionID string,
	keyID string,
	descriptorFingerprint []byte,
	chainCodeHex string,
) {
	t.Helper()

	accountPublicKey := outputs[mpc2Of3PartyA].PublicKey
	if accountPublicKey == "" {
		t.Fatal("DKG returned no account public key")
	}
	accountAddress := outputs[mpc2Of3PartyA].Address
	if accountAddress == "" {
		t.Fatal("DKG returned no account address")
	}
	var accountPublicKeyEvidence []byte
	chainCodeHash := sha256.Sum256(mustDecodeMPC2Of3Hex(t, chainCodeHex))
	for _, partyID := range parties {
		output := outputs[partyID]
		if output.KeyID != keyID {
			t.Fatal("DKG party returned a different key ID")
		}
		if output.PublicKey != accountPublicKey {
			t.Fatal("DKG parties returned different account public keys")
		}
		if output.Address != accountAddress {
			t.Fatal("DKG parties returned different account addresses")
		}
		if output.ChainCode != chainCodeHex {
			t.Fatal("DKG party returned a different chain code")
		}
		blob := store.blob(partyID, keyID)
		if len(blob) == 0 {
			t.Fatalf("party %s codec blob is missing", partyID)
		}
		evidence, err := InspectEncodedECDSAKeyMaterial(blob)
		if err != nil {
			t.Fatalf("inspect party %s codec blob: %v", partyID, err)
		}
		if len(evidence.AccountPublicKey) != 33 {
			t.Fatalf("party %s account public key evidence is missing", partyID)
		}
		if accountPublicKeyEvidence == nil {
			accountPublicKeyEvidence = append([]byte(nil), evidence.AccountPublicKey...)
		} else if !bytes.Equal(evidence.AccountPublicKey, accountPublicKeyEvidence) {
			t.Fatal("persisted DKG shares contain different account public keys")
		}
		if evidence.ChainCodeHash != chainCodeHash {
			t.Fatal("persisted DKG share contains a different chain code")
		}
	}
	assertMPC2Of3SaveBindings(t, store, parties, sessionID, keyID, descriptorFingerprint)
	if bytes.Equal(store.blob(mpc2Of3PartyB, keyID), store.blob(mpc2Of3PartyC, keyID)) {
		t.Fatal("B and C codec blobs are identical")
	}
}

func assertMPC2Of3SaveBindings(
	t *testing.T,
	store *mpc2Of3ShareStore,
	parties []string,
	sessionID string,
	keyID string,
	descriptorFingerprint []byte,
) {
	t.Helper()

	bindings := store.savedBindings()
	if len(bindings) != len(parties) {
		t.Fatalf("saved share binding count = %d, want %d", len(bindings), len(parties))
	}
	expectedParties := make(map[string]struct{}, len(parties))
	for _, partyID := range parties {
		expectedParties[partyID] = struct{}{}
	}
	seenParties := make(map[string]struct{}, len(parties))
	for _, binding := range bindings {
		if binding.sessionID != sessionID {
			t.Fatal("saved share has a different DKG session binding")
		}
		if binding.keyID != keyID {
			t.Fatal("saved share has a different key ID binding")
		}
		if !bytes.Equal(binding.opaqueDescriptorFingerprint, descriptorFingerprint) {
			t.Fatal("saved share has a different descriptor fingerprint binding")
		}
		if _, ok := expectedParties[binding.localPartyID]; !ok {
			t.Fatal("saved share has an unexpected local party binding")
		}
		if _, duplicate := seenParties[binding.localPartyID]; duplicate {
			t.Fatal("saved shares contain a duplicate local party binding")
		}
		seenParties[binding.localPartyID] = struct{}{}
	}
	if len(seenParties) != len(expectedParties) {
		t.Fatal("saved shares do not cover every DKG local party")
	}
}

func verifyMPC2Of3SigningSession(t *testing.T, fixture mpc2Of3Fixture, parties []string, childPath string) {
	t.Helper()

	derivationContext := DerivationContext{
		ProfileID:       "mpc2of3-profile",
		Chain:           "ethereum",
		Algorithm:       AlgorithmECDSA,
		Curve:           CurveSecp256k1,
		Scheme:          DerivationSchemeBIP32Secp256k1,
		PublicKeyFormat: PublicKeyFormatUncompressedHex,
		AccountPath:     "m/44'/60'/0'",
		ChildPath:       childPath,
	}
	derivedPublicKey, err := DeriveECDSAChildPublicKey(
		fixture.outputs[mpc2Of3PartyA].PublicKey,
		fixture.chainCode,
		derivationContext,
	)
	if err != nil {
		t.Fatalf("public child derivation failed: %v", err)
	}
	derivationContext.DerivedPublicKey = derivedPublicKey
	digest := randomMPC2Of3Bytes(t, 32)
	sessionID := "mpc2of3-sign-" + hex.EncodeToString(randomMPC2Of3Bytes(t, 8))
	_, transports := newMPC2Of3FrameBus(parties)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	group, groupCtx := errgroup.WithContext(ctx)
	for _, partyID := range parties {
		partyID := partyID
		group.Go(func() error {
			err := fixture.services[partyID].RunSignSession(groupCtx, SignSessionRequest{
				Session: SignSessionDescriptor{
					SessionID: sessionID,
					OrgID:     "mpc2of3-test",
					KeyID:     fixture.keyID,
					Parties:   parties,
					Threshold: 2,
					Algorithm: AlgorithmECDSA,
					Curve:     CurveSecp256k1,
					Chain:     "ethereum",
				},
				LocalPartyID:      partyID,
				Digest:            digest,
				DerivationContext: &derivationContext,
				Transport:         transports[partyID],
			})
			if err != nil {
				return fmt.Errorf("party %s signing failed: %w", partyID, err)
			}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		t.Fatal(err)
	}

	signature, err := fixture.services[parties[0]].ExportECDSASignature(sessionID)
	if err != nil {
		t.Fatalf("export signature: %v", err)
	}
	assertMPC2Of3Signature(t, &signature, derivedPublicKey, digest)
}

func assertMPC2Of3Signature(t *testing.T, signature *common.SignatureData, publicKeyHex string, digest []byte) {
	t.Helper()

	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("decode derived public key: %v", err)
	}
	publicKey, err := btcec.ParsePubKey(publicKeyBytes, btcec.S256())
	if err != nil {
		t.Fatalf("parse derived public key with independent verifier: %v", err)
	}
	r := new(big.Int).SetBytes(signature.GetR())
	s := new(big.Int).SetBytes(signature.GetS())
	if r.Sign() <= 0 || s.Sign() <= 0 {
		t.Fatal("signature is missing ECDSA components")
	}
	if !bytes.Equal(signature.GetM(), digest) {
		t.Fatal("signature result carries a different digest")
	}
	if !ecdsa.Verify(publicKey.ToECDSA(), digest, r, s) {
		t.Fatal("independent secp256k1 verification rejected signature")
	}

	modified := append([]byte(nil), digest...)
	modified[0] ^= 0x80
	if ecdsa.Verify(publicKey.ToECDSA(), modified, r, s) {
		t.Fatal("signature accepted a modified digest")
	}
	unrelated := randomMPC2Of3Bytes(t, len(digest))
	if bytes.Equal(unrelated, digest) {
		unrelated[len(unrelated)-1] ^= 1
	}
	if ecdsa.Verify(publicKey.ToECDSA(), unrelated, r, s) {
		t.Fatal("signature accepted an unrelated digest")
	}
}

func mustDecodeMPC2Of3Hex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode test value: %v", err)
	}
	return decoded
}

func randomMPC2Of3Bytes(t *testing.T, size int) []byte {
	t.Helper()
	out := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, out); err != nil {
		t.Fatalf("read test randomness: %v", err)
	}
	return out
}
