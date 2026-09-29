package tss

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corederivation "github.com/BroLabel/brosettlement-mpc-core/internal/tss/derivation"
	"github.com/btcsuite/btcd/btcec/v2"
)

// Frozen old-producer bytes catch accidental fixture edits and decoder/derivation
// incompatibility. Expected public identities are never rebuilt by the candidate.
type legacyManifest struct {
	Warning                  string
	CodecVersion             int
	RootPublicKey, ChainCode string
	Participants             []struct {
		Role, PartyID, ShareID, Blob, SHA256 string
		SortedIndex                          int
	}
	Children   []struct{ Path, PublicKey string }
	Signatures []struct {
		Parties            []string
		Path, Digest, R, S string
	}
}

func loadLegacyFixture(dir string) (legacyManifest, error) {
	var manifest legacyManifest
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return manifest, err
	}
	if err = json.Unmarshal(data, &manifest); err != nil {
		return manifest, err
	}
	for _, participant := range manifest.Participants {
		blob, err := os.ReadFile(filepath.Join(dir, participant.Blob))
		if err != nil {
			return manifest, err
		}
		hash := sha256.Sum256(blob)
		if hex.EncodeToString(hash[:]) != participant.SHA256 {
			return manifest, fmt.Errorf("manifest mismatch: %s", participant.PartyID)
		}
	}
	return manifest, nil
}

func TestLegacyV1FixtureManifest(t *testing.T) {
	dir := filepath.Join("..", "testdata", "legacy-v1")
	manifest, err := loadLegacyFixture(dir)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Warning != "TEST ONLY — NEVER FUND" || manifest.CodecVersion != 2 || len(manifest.Participants) != 3 || len(manifest.Children) != 2 || len(manifest.Signatures) != 6 {
		t.Fatal("incomplete synthetic legacy manifest")
	}
	expectedParties := map[string]string{"A": "mpc-signer", "B": "co-signer-primary", "C": "co-signer-recovery"}
	chainCode, err := hex.DecodeString(manifest.ChainCode)
	if err != nil || len(chainCode) != 32 {
		t.Fatal("invalid chain code")
	}
	seen := map[string]bool{}
	for _, participant := range manifest.Participants {
		if expectedParties[participant.Role] != participant.PartyID || seen[participant.Role] {
			t.Fatal("incorrect product party mapping")
		}
		seen[participant.Role] = true
		blob, err := os.ReadFile(filepath.Join(dir, participant.Blob))
		if err != nil {
			t.Fatal(err)
		}
		material, err := UnmarshalKeyMaterial(blob)
		if err != nil {
			t.Fatal(err)
		}
		stableID := sha256.Sum256([]byte(participant.PartyID))
		if material.Share.ShareID.String() != participant.ShareID || material.Share.ShareID.Cmp(new(big.Int).SetBytes(stableID[:])) != 0 {
			t.Fatal("legacy party identity changed")
		}
		if len(material.Share.Ks) != 3 || participant.SortedIndex < 0 || participant.SortedIndex >= 3 || material.Share.Ks[participant.SortedIndex].Cmp(material.Share.ShareID) != 0 {
			t.Fatal("legacy participant index changed")
		}
		root := material.Share.ECDSAPub.ToECDSAPubKey()
		public := elliptic.Marshal(btcec.S256(), root.X, root.Y)
		if hex.EncodeToString(public) != manifest.RootPublicKey || !bytes.Equal(material.ChainCode, chainCode) {
			t.Fatal("legacy account identity changed")
		}
		for _, child := range manifest.Children {
			derived, err := DeriveECDSAChildPublicKey(manifest.RootPublicKey, material.ChainCode, legacyDerivation(child.Path))
			if err != nil || derived != child.PublicKey {
				t.Fatalf("child identity changed for %s: %v", child.Path, err)
			}
		}
	}
	children := map[string]string{}
	for _, child := range manifest.Children {
		children[child.Path] = child.PublicKey
	}
	if len(children) != 2 || children["/0/0"] == "" || children["/1/7"] == "" {
		t.Fatal("missing child identities")
	}
	seenSignatures := map[string]bool{}
	for _, signature := range manifest.Signatures {
		if len(signature.Parties) != 2 || signature.Parties[0] == signature.Parties[1] {
			t.Fatal("invalid signing pair")
		}
		validPairs := map[string]bool{"mpc-signer+co-signer-primary": true, "mpc-signer+co-signer-recovery": true, "co-signer-primary+co-signer-recovery": true}
		pair := strings.Join(signature.Parties, "+")
		label := pair + signature.Path
		if !validPairs[pair] || seenSignatures[label] {
			t.Fatal("invalid or duplicate baseline signing pair")
		}
		seenSignatures[label] = true
		publicBytes, err := hex.DecodeString(children[signature.Path])
		if err != nil {
			t.Fatal(err)
		}
		public, err := btcec.ParsePubKey(publicBytes)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := hex.DecodeString(signature.Digest)
		if err != nil || len(digest) != 32 {
			t.Fatal("invalid baseline digest")
		}
		r, ok := new(big.Int).SetString(signature.R, 16)
		if !ok {
			t.Fatal("invalid R")
		}
		s, ok := new(big.Int).SetString(signature.S, 16)
		if !ok {
			t.Fatal("invalid S")
		}
		if !ecdsa.Verify(public.ToECDSA(), digest, r, s) {
			t.Fatal("invalid independently verified baseline signature")
		}
		digest[0] ^= 0x80
		if ecdsa.Verify(public.ToECDSA(), digest, r, s) {
			t.Fatal("signature accepted changed digest")
		}
	}
	t.Run("corrupted copy is rejected", func(t *testing.T) {
		copyDir := t.TempDir()
		data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(copyDir, "manifest.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		for i, p := range manifest.Participants {
			blob, err := os.ReadFile(filepath.Join(dir, p.Blob))
			if err != nil {
				t.Fatal(err)
			}
			if i == 0 {
				blob[len(blob)/2] ^= 1
			}
			target := filepath.Join(copyDir, p.Blob)
			if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(target, blob, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := loadLegacyFixture(copyDir); err == nil || !strings.Contains(err.Error(), "manifest mismatch") {
			t.Fatalf("corrupt fixture must fail manifest check: %v", err)
		}
	})
}

func legacyDerivation(path string) DerivationContext {
	return DerivationContext{ProfileID: "legacy-synthetic", Chain: "application:opaque-network", Algorithm: AlgorithmECDSA, Curve: CurveSecp256k1, Scheme: DerivationSchemeBIP32Secp256k1, PublicKeyFormat: PublicKeyFormatUncompressedHex, AccountPath: "m/44'/60'/0'", ChildPath: path}
}

// The old corpus is loaded directly; SIGN must never persist or replace it.
type legacyNoSaveWriter struct{ calls atomic.Uint32 }

func (w *legacyNoSaveWriter) SaveShare(context.Context, SaveShareInput) error {
	w.calls.Add(1)
	return errors.New("legacy SIGN attempted SaveShare")
}

func newLegacySigningFixture(t *testing.T) (mpc2Of3Fixture, legacyManifest) {
	t.Helper()
	dir := filepath.Join("..", "testdata", "legacy-v1")
	manifest, err := loadLegacyFixture(dir)
	if err != nil {
		t.Fatal(err)
	}
	store := newMPC2Of3ShareStore()
	writer := &legacyNoSaveWriter{}
	fixture := mpc2Of3Fixture{services: map[string]*Service{}, outputs: map[string]DKGOutput{}, keyID: "synthetic-legacy-v1-never-fund", chainCode: mustDecodeMPC2Of3Hex(t, manifest.ChainCode)}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, p := range manifest.Participants {
		blob, err := os.ReadFile(filepath.Join(dir, p.Blob))
		if err != nil {
			t.Fatal(err)
		}
		store.shares[mpc2Of3ShareKey{p.PartyID, fixture.keyID}] = StoredShare{Blob: blob}
		fixture.outputs[p.PartyID] = DKGOutput{PublicKey: manifest.RootPublicKey}
		fixture.services[p.PartyID] = NewBnbService(logger, WithShareReader(&mpc2Of3PartyShareReader{store: store, partyID: p.PartyID}), WithShareWriter(writer))
	}
	t.Cleanup(func() {
		if writer.calls.Load() != 0 {
			t.Fatal("legacy SIGN wrote a share")
		}
		for _, p := range manifest.Participants {
			hash := sha256.Sum256(store.blob(p.PartyID, fixture.keyID))
			if hex.EncodeToString(hash[:]) != p.SHA256 {
				t.Fatalf("stored legacy blob changed: %s", p.PartyID)
			}
		}
		if _, err := loadLegacyFixture(dir); err != nil {
			t.Fatal(err)
		}
	})
	return fixture, manifest
}

func TestLegacyV1EverySigningSubset(t *testing.T) {
	fixture, manifest := newLegacySigningFixture(t)
	for _, baseline := range manifest.Signatures {
		t.Run(strings.Join(baseline.Parties, "+")+baseline.Path, func(t *testing.T) {
			verifyMPC2Of3SigningSession(t, fixture, baseline.Parties, baseline.Path)
		})
	}
}

// Concurrent sessions share facade instances and persisted blobs but not signing state.
func TestLegacyV1ConcurrentSigning(t *testing.T) {
	fixture, manifest := newLegacySigningFixture(t)
	for _, baseline := range manifest.Signatures {
		t.Run(strings.Join(baseline.Parties, "+")+baseline.Path, func(t *testing.T) {
			t.Parallel()
			verifyMPC2Of3SigningSession(t, fixture, baseline.Parties, baseline.Path)
		})
	}
}

// Snapshot the actual decoded inputs, including point coordinates and Xi, rather
// than comparing pointers whose referents might have been mutated in place.
func TestLegacyV1DerivationDoesNotAliasInputs(t *testing.T) {
	_, manifest := newLegacySigningFixture(t)
	for _, p := range manifest.Participants {
		blob, err := os.ReadFile(filepath.Join("..", "testdata", "legacy-v1", p.Blob))
		if err != nil {
			t.Fatal(err)
		}
		material, err := UnmarshalKeyMaterial(blob)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := func(v any) []byte {
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		before := snapshot(material)
		first, err := corederivation.PrepareECDSASigningShare(material.Share, material.ChainCode, toCoreDerivationContext(legacyDerivation("/0/0")))
		if err != nil {
			t.Fatal(err)
		}
		firstBefore := snapshot(first)
		second, err := corederivation.PrepareECDSASigningShare(material.Share, material.ChainCode, toCoreDerivationContext(legacyDerivation("/1/7")))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, snapshot(material)) || !bytes.Equal(firstBefore, snapshot(first)) {
			t.Fatal("derivation mutated an input or a previous session")
		}
		if first.DerivedPublicKey != manifest.Children[0].PublicKey || second.DerivedPublicKey != manifest.Children[1].PublicKey {
			t.Fatal("child identity changed")
		}
		// Replacing a prepared BigXj entry must not overwrite another session's slice.
		second.Share.BigXj[0] = second.Share.ECDSAPub
		if !bytes.Equal(before, snapshot(material)) || !bytes.Equal(firstBefore, snapshot(first)) {
			t.Fatal("BigXj slice aliases another session")
		}
	}
}

func TestLegacyV1RejectsInvalidSigningRequest(t *testing.T) {
	fixture, manifest := newLegacySigningFixture(t)
	parties := manifest.Signatures[0].Parties
	for _, name := range []string{"unknown local participant", "undersized subset", "duplicate subset", "wrong derived key", "wrong chain", "empty digest"} {
		t.Run(name, func(t *testing.T) {
			dc := legacyDerivation("/0/0")
			_, transports := newMPC2Of3FrameBus(parties)
			req := SignSessionRequest{Session: SignSessionDescriptor{SessionID: "invalid-" + name, OrgID: "legacy-test", KeyID: fixture.keyID, Parties: append([]string(nil), parties...), Threshold: 2, Algorithm: AlgorithmECDSA, Curve: CurveSecp256k1, Chain: dc.Chain}, LocalPartyID: parties[0], Digest: bytes.Repeat([]byte{1}, 32), DerivationContext: &dc, Transport: transports[parties[0]]}
			switch name {
			case "unknown local participant":
				req.LocalPartyID = "unknown"
			case "undersized subset":
				req.Session.Parties = parties[:1]
			case "duplicate subset":
				req.Session.Parties = []string{parties[0], parties[0]}
			case "wrong derived key":
				dc.DerivedPublicKey = manifest.Children[1].PublicKey
			case "wrong chain":
				dc.Chain = "application:wrong-network"
			case "empty digest":
				req.Digest = nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := fixture.services[parties[0]].RunSignSession(ctx, req)
			if err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("request did not fail validation: %v", err)
			}
			if _, err := fixture.services[parties[0]].ExportECDSASignature(req.Session.SessionID); err == nil {
				t.Fatal("invalid request exported a signature")
			}
		})
	}
}

func TestLegacyV1DuplicateSubsetFailsValidation(t *testing.T) {
	dc := legacyDerivation("/0/0")
	_, transports := newMPC2Of3FrameBus([]string{"mpc-signer"})
	req := SignSessionRequest{Session: SignSessionDescriptor{SessionID: "duplicate", OrgID: "test-only", KeyID: "test-only", Parties: []string{"mpc-signer", "mpc-signer"}, Threshold: 2, Algorithm: AlgorithmECDSA, Curve: CurveSecp256k1, Chain: dc.Chain}, LocalPartyID: "mpc-signer", Digest: []byte{1}, DerivationContext: &dc, Transport: transports["mpc-signer"]}
	if err := req.Validate(); !errors.Is(err, ErrInvalidSessionDescriptor) {
		t.Fatalf("duplicate subset error = %v, want ErrInvalidSessionDescriptor", err)
	}
}
