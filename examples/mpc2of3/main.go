// Command mpc2of3 runs a complete in-memory 2-of-3 DKG and signing flow.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
	"github.com/BroLabel/brosettlement-mpc-core/transport"
	"github.com/BroLabel/brosettlement-mpc-core/tss"
	"github.com/btcsuite/btcd/btcec"
	"golang.org/x/sync/errgroup"
)

const (
	keyID         = "quickstart-key"
	dkgSessionID  = "quickstart-dkg"
	signSessionID = "quickstart-sign"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	if err := run(ctx); err != nil {
		panic(err)
	}
}

func run(ctx context.Context) error {
	parties := []string{"A", "B", "C"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	services := make(map[string]*tss.Service, len(parties))
	for _, partyID := range parties {
		shares := newMemoryShareStore(partyID)
		services[partyID] = tss.NewBnbService(
			logger,
			tss.WithShareReader(shares),
			tss.WithShareWriter(shares),
		)
	}

	chainCode, err := randomBytes(32)
	if err != nil {
		return fmt.Errorf("generate chain code: %w", err)
	}
	dkgTransport := newFrameNetwork(parties)
	dkgOutputs, err := runDKG(ctx, services, dkgTransport, parties, chainCode)
	if err != nil {
		return err
	}

	derivation := tss.DerivationContext{
		ProfileID:       "quickstart-profile",
		Chain:           "ethereum",
		Algorithm:       tss.AlgorithmECDSA,
		Curve:           tss.CurveSecp256k1,
		Scheme:          tss.DerivationSchemeBIP32Secp256k1,
		PublicKeyFormat: tss.PublicKeyFormatUncompressedHex,
		AccountPath:     "m/44'/60'/0'",
		ChildPath:       "/0/0",
	}
	derivedPublicKey, err := tss.DeriveECDSAChildPublicKey(
		dkgOutputs["A"].PublicKey,
		chainCode,
		derivation,
	)
	if err != nil {
		return fmt.Errorf("derive child public key: %w", err)
	}
	derivation.DerivedPublicKey = derivedPublicKey

	digest := sha256.Sum256([]byte("BroSettlement quickstart"))
	signers := []string{"A", "B"}
	signTransport := newFrameNetwork(signers)
	if err := runSign(ctx, services, signTransport, signers, digest[:], derivation); err != nil {
		return err
	}

	signature, err := services["A"].ExportECDSASignature(signSessionID)
	if err != nil {
		return fmt.Errorf("export signature: %w", err)
	}
	if !bytes.Equal(signature.GetM(), digest[:]) {
		return fmt.Errorf("signature contains an unexpected digest")
	}
	if err := verifyECDSA(
		derivedPublicKey,
		digest[:],
		signature.GetR(),
		signature.GetS(),
	); err != nil {
		return err
	}

	fmt.Printf(
		"verified 2-of-3 signature\naccount public key: %s\nderived public key: %s\nr: %x\ns: %x\n",
		dkgOutputs["A"].PublicKey,
		derivedPublicKey,
		signature.GetR(),
		signature.GetS(),
	)
	return nil
}

func runDKG(
	ctx context.Context,
	services map[string]*tss.Service,
	transports map[string]transport.FrameTransport,
	parties []string,
	chainCode []byte,
) (map[string]tss.DKGOutput, error) {
	outputs := make(map[string]tss.DKGOutput, len(parties))
	var outputsMu sync.Mutex

	err := runParties(ctx, parties, func(groupCtx context.Context, partyID string) error {
		output, err := services[partyID].RunDKGSession(groupCtx, tss.DKGSessionRequest{
			Session: tss.DKGSessionDescriptor{
				SessionID: dkgSessionID,
				OrgID:     "quickstart",
				KeyID:     keyID,
				Parties:   parties,
				Threshold: 2,
				Algorithm: tss.AlgorithmECDSA,
				Curve:     tss.CurveSecp256k1,
			},
			LocalPartyID:                partyID,
			OpaqueDescriptorFingerprint: []byte("quickstart-v1"),
			DerivationMaterial: &tss.DKGDerivationMaterial{
				ChainCode:        hex.EncodeToString(chainCode),
				DerivationScheme: tss.DerivationSchemeBIP32Secp256k1,
			},
			Transport: transports[partyID],
		})
		if err != nil {
			return fmt.Errorf("party %s DKG: %w", partyID, err)
		}
		outputsMu.Lock()
		outputs[partyID] = output
		outputsMu.Unlock()
		return nil
	})
	if err != nil {
		return nil, err
	}

	accountPublicKey := outputs[parties[0]].PublicKey
	chainCodeHex := hex.EncodeToString(chainCode)
	for _, partyID := range parties {
		output := outputs[partyID]
		if output.PublicKey != accountPublicKey {
			return nil, fmt.Errorf("party %s returned a different account public key", partyID)
		}
		if output.ChainCode != chainCodeHex {
			return nil, fmt.Errorf("party %s returned a different chain code", partyID)
		}
	}
	return outputs, nil
}

func runSign(
	ctx context.Context,
	services map[string]*tss.Service,
	transports map[string]transport.FrameTransport,
	signers []string,
	digest []byte,
	derivation tss.DerivationContext,
) error {
	return runParties(ctx, signers, func(groupCtx context.Context, partyID string) error {
		err := services[partyID].RunSignSession(groupCtx, tss.SignSessionRequest{
			Session: tss.SignSessionDescriptor{
				SessionID: signSessionID,
				OrgID:     "quickstart",
				KeyID:     keyID,
				Parties:   signers,
				Threshold: 2,
				Algorithm: tss.AlgorithmECDSA,
				Curve:     tss.CurveSecp256k1,
				Chain:     "ethereum",
			},
			LocalPartyID:      partyID,
			Digest:            digest,
			DerivationContext: &derivation,
			Transport:         transports[partyID],
		})
		if err != nil {
			return fmt.Errorf("party %s signing: %w", partyID, err)
		}
		return nil
	})
}

func runParties(
	ctx context.Context,
	parties []string,
	run func(context.Context, string) error,
) error {
	group, groupCtx := errgroup.WithContext(ctx)
	for _, partyID := range parties {
		group.Go(func() error {
			return run(groupCtx, partyID)
		})
	}
	return group.Wait()
}

type frameBus struct {
	endpoints map[string]chan protocol.Frame
}

type frameEndpoint struct {
	bus     *frameBus
	inbound <-chan protocol.Frame
}

func newFrameNetwork(parties []string) map[string]transport.FrameTransport {
	bus := &frameBus{endpoints: make(map[string]chan protocol.Frame, len(parties))}
	transports := make(map[string]transport.FrameTransport, len(parties))
	for _, partyID := range parties {
		inbound := make(chan protocol.Frame, 256)
		bus.endpoints[partyID] = inbound
		transports[partyID] = &frameEndpoint{bus: bus, inbound: inbound}
	}
	return transports
}

func (t *frameEndpoint) SendFrame(ctx context.Context, frame protocol.Frame) error {
	if frame.IsBroadcast() {
		for partyID, inbound := range t.bus.endpoints {
			if partyID == frame.FromParty {
				continue
			}
			if err := sendFrame(ctx, inbound, frame); err != nil {
				return err
			}
		}
		return nil
	}

	inbound, ok := t.bus.endpoints[frame.ToParty]
	if !ok {
		return fmt.Errorf("frame target %q is unavailable", frame.ToParty)
	}
	return sendFrame(ctx, inbound, frame)
}

func (t *frameEndpoint) RecvFrame(ctx context.Context) (protocol.Frame, error) {
	select {
	case frame := <-t.inbound:
		return frame, nil
	case <-ctx.Done():
		return protocol.Frame{}, ctx.Err()
	}
}

func sendFrame(ctx context.Context, inbound chan<- protocol.Frame, frame protocol.Frame) error {
	frame.Payload = append([]byte(nil), frame.Payload...)
	select {
	case inbound <- frame:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type memoryShareStore struct {
	partyID string
	mu      sync.RWMutex
	shares  map[string][]byte
}

func newMemoryShareStore(partyID string) *memoryShareStore {
	return &memoryShareStore{
		partyID: partyID,
		shares:  make(map[string][]byte),
	}
}

func (s *memoryShareStore) SaveShare(_ context.Context, in tss.SaveShareInput) error {
	if in.LocalPartyID != s.partyID {
		return fmt.Errorf("share for party %q sent to party %q store", in.LocalPartyID, s.partyID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.shares[in.KeyID]; exists {
		return fmt.Errorf("share %q already exists", in.KeyID)
	}
	s.shares[in.KeyID] = append([]byte(nil), in.CodecBlob...)
	return nil
}

func (s *memoryShareStore) LoadShare(_ context.Context, requestedKeyID string) (*tss.StoredShare, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	blob, ok := s.shares[requestedKeyID]
	if !ok {
		return nil, tss.ErrShareNotFound
	}
	return &tss.StoredShare{Blob: append([]byte(nil), blob...)}, nil
}

func verifyECDSA(publicKeyHex string, digest, rBytes, sBytes []byte) error {
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return fmt.Errorf("decode derived public key: %w", err)
	}
	publicKey, err := btcec.ParsePubKey(publicKeyBytes, btcec.S256())
	if err != nil {
		return fmt.Errorf("parse derived public key: %w", err)
	}
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)
	if !ecdsa.Verify(publicKey.ToECDSA(), digest, r, s) {
		return fmt.Errorf("independent secp256k1 verification rejected the signature")
	}
	return nil
}

func randomBytes(size int) ([]byte, error) {
	out := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, out); err != nil {
		return nil, err
	}
	return out, nil
}
