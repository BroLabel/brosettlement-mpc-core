// TEST ONLY — NEVER FUND: embedded Paillier preparameters are public.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
	core "github.com/BroLabel/brosettlement-mpc-core/tss"
	kg "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/btcsuite/btcd/btcec"
	"golang.org/x/sync/errgroup"
)

//go:embed preparams/public-test-only-*.json
var publicPreparams embed.FS

const warning = "TEST ONLY — NEVER FUND"
const keyID = "synthetic-legacy-v1-never-fund"

var parties = []string{"mpc-signer", "co-signer-primary", "co-signer-recovery"}
var paths = []string{"/0/0", "/1/7"}

type producer struct{ Module, Version, Revision, Sum string }
type participant struct {
	Role, PartyID, ShareID, Blob, SHA256 string
	SortedIndex                          int
}
type child struct{ Path, PublicKey string }
type signature struct {
	Parties            []string
	Path, Digest, R, S string
}
type preparamsInput struct{ File, SHA256, UpstreamFile string }
type manifest struct {
	Warning                  string
	CodecVersion             int
	GoVersion                string
	Producers                []producer
	Preparams                []preparamsInput
	RootPublicKey, ChainCode string
	Participants             []participant
	Children                 []child
	Signatures               []signature
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func hash(blob []byte) string { sum := sha256.Sum256(blob); return hex.EncodeToString(sum[:]) }
func logger() *slog.Logger    { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// Consumed once per party DKG; reuse across PUBLIC synthetic runs is test-only.
type onePreparam struct{ item *kg.LocalPreParams }

func (p *onePreparam) Acquire(context.Context) (*kg.LocalPreParams, error) {
	if p.item == nil {
		return nil, fmt.Errorf("test preparameter already consumed")
	}
	result := p.item
	p.item = nil
	return result, nil
}

type store struct {
	mu    sync.Mutex
	blobs map[string][]byte
}

func (s *store) SaveShare(_ context.Context, in core.SaveShareInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.KeyID != keyID || in.SessionID != "synthetic-legacy-dkg" || !bytes.Equal(in.OpaqueDescriptorFingerprint, []byte(warning)) {
		return fmt.Errorf("unexpected storage binding")
	}
	if _, ok := s.blobs[in.LocalPartyID]; ok {
		return fmt.Errorf("duplicate saved share")
	}
	s.blobs[in.LocalPartyID] = append([]byte(nil), in.CodecBlob...)
	return nil
}

type reader struct{ blob []byte }

func (r reader) LoadShare(_ context.Context, id string) (*core.StoredShare, error) {
	if id != keyID {
		return nil, core.ErrShareNotFound
	}
	return &core.StoredShare{Blob: append([]byte(nil), r.blob...)}, nil
}

type transport struct {
	own      string
	channels map[string]chan protocol.Frame
}

func (t transport) SendFrame(ctx context.Context, frame protocol.Frame) error {
	for id, channel := range t.channels {
		if id == frame.FromParty || (!frame.IsBroadcast() && id != frame.ToParty) {
			continue
		}
		copied := frame
		copied.Payload = append([]byte(nil), frame.Payload...)
		select {
		case channel <- copied:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
func (t transport) RecvFrame(ctx context.Context) (protocol.Frame, error) {
	select {
	case frame := <-t.channels[t.own]:
		return frame, nil
	case <-ctx.Done():
		return protocol.Frame{}, ctx.Err()
	}
}
func transports(ids []string) map[string]transport {
	channels := map[string]chan protocol.Frame{}
	for _, id := range ids {
		channels[id] = make(chan protocol.Frame, 256)
	}
	result := map[string]transport{}
	for _, id := range ids {
		result[id] = transport{id, channels}
	}
	return result
}
func producers() []producer {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		panic("missing module build metadata")
	}
	expected := []producer{
		{Module: "github.com/BroLabel/brosettlement-mpc-core", Version: "v0.5.0", Revision: "22d2e09211a702daad8b9f5a44a810d7eafda39c", Sum: "h1:tfg+FCuhunr/zerGbvDEfStND1tPqGFIlqyjabLGBS4="},
		{Module: "github.com/bnb-chain/tss-lib", Version: "v1.5.0", Revision: "3d95e54c2c9e26211ec0599f90772e8eb260c62b", Sum: "h1:fuP69k0c4K9kaWCrG+FPH4GDdGZpMRhLyAaA+TyGn0w="},
	}
	for _, want := range expected {
		found := false
		for _, dep := range info.Deps {
			if dep.Path == want.Module {
				if dep.Replace != nil || dep.Version != want.Version || dep.Sum != want.Sum {
					panic("generator dependency drift")
				}
				found = true
			}
		}
		if !found {
			panic("missing pinned generator dependency")
		}
	}
	return expected
}
func derivation(path string) core.DerivationContext {
	return core.DerivationContext{ProfileID: "legacy-synthetic", Chain: "application:opaque-network", Algorithm: core.AlgorithmECDSA, Curve: core.CurveSecp256k1, Scheme: core.DerivationSchemeBIP32Secp256k1, PublicKeyFormat: core.PublicKeyFormatUncompressedHex, AccountPath: "m/44'/60'/0'", ChildPath: path}
}

func generate(dir string) {
	// Refuse overwriting a frozen corpus; reruns require a new output directory.
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		panic("output must be a new directory")
	}
	m := manifest{Warning: warning, CodecVersion: 2, GoVersion: runtime.Version(), Producers: producers()}
	chainCode := sha256.Sum256([]byte("synthetic legacy corpus chain code — never fund"))
	m.ChainCode = hex.EncodeToString(chainCode[:])
	saved := &store{blobs: map[string][]byte{}}
	wire := transports(parties)
	outputs := make([]core.DKGOutput, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	group, ctx := errgroup.WithContext(ctx)
	for i, id := range parties {
		file := fmt.Sprintf("preparams/public-test-only-%d.json", i)
		blob, err := publicPreparams.ReadFile(file)
		must(err)
		m.Preparams = append(m.Preparams, preparamsInput{File: file, SHA256: hash(blob), UpstreamFile: fmt.Sprintf("test/_ecdsa_fixtures/keygen_data_%d.json", i)})
		var pre kg.LocalPreParams
		must(json.Unmarshal(blob, &pre))
		if !pre.ValidateWithProof() {
			panic("incomplete public test preparameters")
		}
		source := &onePreparam{item: &pre}
		service := core.NewBnbService(logger(), core.WithShareWriter(saved), core.WithPreParamsSource(source), core.WithPreParamsConfig(core.PreParamsConfig{}))
		group.Go(func() error {
			output, err := service.RunDKGSession(ctx, core.DKGSessionRequest{
				Session:      core.DKGSessionDescriptor{SessionID: "synthetic-legacy-dkg", OrgID: "synthetic-never-fund", KeyID: keyID, Parties: parties, Threshold: 2, Algorithm: core.AlgorithmECDSA, Curve: core.CurveSecp256k1},
				LocalPartyID: id, OpaqueDescriptorFingerprint: []byte(warning), DerivationMaterial: &core.DKGDerivationMaterial{ChainCode: m.ChainCode, DerivationScheme: core.DerivationSchemeBIP32Secp256k1}, Transport: wire[id],
			})
			if err == nil && source.item != nil {
				return fmt.Errorf("preparameter was not consumed")
			}
			outputs[i] = output
			return err
		})
	}
	must(group.Wait())
	m.RootPublicKey = outputs[0].PublicKey
	for i, id := range parties {
		if outputs[i].PublicKey != m.RootPublicKey || outputs[i].ChainCode != m.ChainCode {
			panic("DKG identity disagreement")
		}
		blob := saved.blobs[id]
		// Inspect identity only: never re-encode the saved old-facade blob.
		material, err := core.UnmarshalKeyMaterial(blob)
		must(err)
		stable := sha256.Sum256([]byte(id))
		if material.Share.ShareID.Cmp(new(big.Int).SetBytes(stable[:])) != 0 {
			panic("product party mapping mismatch")
		}
		index := -1
		for j, k := range material.Share.Ks {
			if k.Cmp(material.Share.ShareID) == 0 {
				index = j
			}
		}
		if index < 0 {
			panic("participant absent from stored mapping")
		}
		m.Participants = append(m.Participants, participant{Role: string(rune('A' + i)), PartyID: id, ShareID: material.Share.ShareID.String(), Blob: "codec-v2/" + id + ".gob", SHA256: hash(blob), SortedIndex: index})
	}
	for _, path := range paths {
		public, err := core.DeriveECDSAChildPublicKey(m.RootPublicKey, chainCode[:], derivation(path))
		must(err)
		m.Children = append(m.Children, child{Path: path, PublicKey: public})
	}
	m.Signatures = signAll(m, saved.blobs)
	must(os.MkdirAll(filepath.Join(dir, "codec-v2"), 0700))
	for _, p := range m.Participants {
		must(os.WriteFile(filepath.Join(dir, p.Blob), saved.blobs[p.PartyID], 0600))
	}
	data, err := json.MarshalIndent(m, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(dir, "manifest.json"), append(data, '\n'), 0600))
	fmt.Println("old Core DKG/storage facade and six signatures: PASS")
}

func signAll(m manifest, blobs map[string][]byte) []signature {
	var results []signature
	for _, pair := range [][]string{{parties[0], parties[1]}, {parties[0], parties[2]}, {parties[1], parties[2]}} {
		for _, child := range m.Children {
			results = append(results, sign(blobs, pair, child))
		}
	}
	return results
}
func sign(blobs map[string][]byte, pair []string, child child) signature {
	digest := sha256.Sum256([]byte("synthetic legacy signature " + pair[0] + "+" + pair[1] + child.Path))
	digest[0] = 0 // Exercise leading-zero digest preservation too.
	dc := derivation(child.Path)
	dc.DerivedPublicKey = child.PublicKey
	sessionID := "synthetic-sign-" + pair[0] + "-" + pair[1] + child.Path
	wire := transports(pair)
	services := make([]*core.Service, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	group, ctx := errgroup.WithContext(ctx)
	for i, id := range pair {
		service := core.NewBnbService(logger(), core.WithShareReader(reader{blobs[id]}), core.WithPreParamsConfig(core.PreParamsConfig{}))
		services[i] = service
		group.Go(func() error {
			return service.RunSignSession(ctx, core.SignSessionRequest{
				Session: core.SignSessionDescriptor{SessionID: sessionID, OrgID: "synthetic-never-fund", KeyID: keyID, Parties: pair, Threshold: 2, Algorithm: core.AlgorithmECDSA, Curve: core.CurveSecp256k1, Chain: dc.Chain}, LocalPartyID: id, Digest: digest[:], DerivationContext: &dc, Transport: wire[id],
			})
		})
	}
	must(group.Wait())
	publicBytes, err := hex.DecodeString(child.PublicKey)
	must(err)
	public, err := btcec.ParsePubKey(publicBytes, btcec.S256())
	must(err)
	result := signature{Parties: pair, Path: child.Path, Digest: hex.EncodeToString(digest[:])}
	for i, service := range services {
		signed, err := service.ExportECDSASignature(sessionID)
		must(err)
		r, s := new(big.Int).SetBytes(signed.R), new(big.Int).SetBytes(signed.S)
		if !ecdsa.Verify(public.ToECDSA(), digest[:], r, s) || !bytes.Equal(signed.M, digest[:]) {
			panic("independent ECDSA verification failed")
		}
		if i == 0 {
			result.R = hex.EncodeToString(signed.R)
			result.S = hex.EncodeToString(signed.S)
		} else if result.R != hex.EncodeToString(signed.R) || result.S != hex.EncodeToString(signed.S) {
			panic("signers disagree")
		}
	}
	fmt.Printf("signature %s+%s %s: PASS\n", pair[0], pair[1], child.Path)
	return result
}
func check(dir string) {
	_ = producers()
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	must(err)
	var m manifest
	must(json.Unmarshal(data, &m))
	if m.Warning != warning || m.CodecVersion != 2 || len(m.Participants) != 3 || len(m.Children) != 2 {
		panic("invalid manifest")
	}
	blobs := map[string][]byte{}
	for _, p := range m.Participants {
		blob, err := os.ReadFile(filepath.Join(dir, p.Blob))
		must(err)
		if hash(blob) != p.SHA256 {
			panic("manifest mismatch")
		}
		blobs[p.PartyID] = blob
	}
	_ = signAll(m, blobs)
	fmt.Println("frozen old-codec signing check: PASS (no files written)")
}
func main() {
	if len(os.Args) != 3 {
		panic("usage: go run . generate|check NEW_OUTPUT_OR_FROZEN_DIRECTORY")
	}
	switch os.Args[1] {
	case "generate":
		generate(os.Args[2])
	case "check":
		check(os.Args[2])
	default:
		panic("unknown mode")
	}
}
