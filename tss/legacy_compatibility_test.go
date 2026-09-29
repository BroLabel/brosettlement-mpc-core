package tss

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec"
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
		public := &btcec.PublicKey{Curve: btcec.S256(), X: root.X, Y: root.Y}
		if hex.EncodeToString(public.SerializeUncompressed()) != manifest.RootPublicKey || !bytes.Equal(material.ChainCode, chainCode) {
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
		public, err := btcec.ParsePubKey(publicBytes, btcec.S256())
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
