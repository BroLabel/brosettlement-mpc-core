package tss

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
	kg "github.com/bnb-chain/tss-lib/v3/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/v3/tss"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Mutate one mathematical proof component, preserving a parseable v3 message,
// session/routing metadata, and the payload checksum. No production hook is used.
type invalidModProofTransport struct {
	Transport
	mutated atomic.Uint32
}

func (tr *invalidModProofTransport) SendFrame(ctx context.Context, frame protocol.Frame) error {
	if strings.HasSuffix(frame.MessageType, ".KGRound2Message2") && tr.mutated.CompareAndSwap(0, 1) {
		var envelope anypb.Any
		if err := proto.Unmarshal(frame.Payload, &envelope); err != nil {
			return err
		}
		var message kg.KGRound2Message2
		if err := envelope.UnmarshalTo(&message); err != nil {
			return err
		}
		proof, err := message.UnmarshalModProof()
		if err != nil {
			return err
		}
		// Change one modular root response, retaining every proof field and its
		// normal size. Verification must reject it after successful parsing.
		proof.Z[0] = new(big.Int).Add(proof.Z[0], big.NewInt(1))
		parts := proof.Bytes()
		message.ModProof = parts[:]
		envelope.Value, err = proto.Marshal(&message)
		if err != nil {
			return err
		}
		frame.Payload, err = proto.Marshal(&envelope)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(frame.Payload)
		frame.PayloadHash = hex.EncodeToString(sum[:])
		parsed, err := tsslib.ParseWireMessage(frame.Payload, tsslib.NewPartyID(frame.FromParty, frame.FromParty, big.NewInt(1)), frame.IsBroadcast())
		if err != nil {
			return fmt.Errorf("mutated proof framing: %w", err)
		}
		if !parsed.Content().ValidateBasic() {
			return fmt.Errorf("mutated proof lost valid framing")
		}
	}
	return tr.Transport.SendFrame(ctx, frame)
}

// TEST ONLY — NEVER FUND. Public upstream preparameters are intentionally reused
// across test runs, never across production DKG. Each pool item is decoded into
// its own allocation and acquired once. The fresh-prime release test is separate.
func publicDKGPreParams(t *testing.T, index int) *kg.LocalPreParams {
	t.Helper()
	path := filepath.Join("..", "tools", "legacy-fixture", "preparams", fmt.Sprintf("public-test-only-%d.json", index))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var params kg.LocalPreParams
	if err := json.Unmarshal(data, &params); err != nil {
		t.Fatal(err)
	}
	return &params
}

func TestDKGRejectsInvalidProof(t *testing.T) {
	parties := []string{mpc2Of3PartyA, mpc2Of3PartyB, mpc2Of3PartyC}
	store := newMPC2Of3ShareStore()
	services := map[string]*Service{}
	pools := map[string]*mpc2Of3PreParamsPool{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for i, id := range parties {
		pools[id] = newMPC2Of3PreParamsPool(publicDKGPreParams(t, i), publicDKGPreParams(t, i))
		services[id] = NewBnbService(logger, WithShareWriter(store), WithPreParamsSource(pools[id]))
	}
	chainCode := randomMPC2Of3Bytes(t, 32)
	run := func(invalid bool) (map[string]DKGOutput, error, uint32) {
		_, transports := newMPC2Of3FrameBus(parties)
		mutation := &invalidModProofTransport{Transport: transports[parties[0]]}
		if invalid {
			transports[parties[0]] = mutation
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		group, groupCtx := errgroup.WithContext(ctx)
		outputs := map[string]DKGOutput{}
		var mu sync.Mutex
		for _, id := range parties {
			group.Go(func() error {
				out, err := services[id].RunDKGSession(groupCtx, DKGSessionRequest{
					Session:      DKGSessionDescriptor{SessionID: fmt.Sprintf("proof-test-%t", invalid), OrgID: "test-only", KeyID: mpc2Of3KeyID, Parties: parties, Threshold: 2, Algorithm: AlgorithmECDSA, Curve: CurveSecp256k1},
					LocalPartyID: id, OpaqueDescriptorFingerprint: []byte("TEST ONLY — NEVER FUND"), DerivationMaterial: &DKGDerivationMaterial{ChainCode: hex.EncodeToString(chainCode), DerivationScheme: DerivationSchemeBIP32Secp256k1}, Transport: transports[id],
				})
				if err != nil {
					return fmt.Errorf("party %s: %w", id, err)
				}
				mu.Lock()
				outputs[id] = out
				mu.Unlock()
				return nil
			})
		}
		err := group.Wait()
		return outputs, err, mutation.mutated.Load()
	}
	outputs, err, mutated := run(true)
	if mutated != 1 {
		t.Fatalf("mutated %d proof messages, want 1", mutated)
	}
	if err == nil || !strings.Contains(err.Error(), "modProof verify failed") {
		t.Fatalf("expected cryptographic proof rejection, got %v", err)
	}
	if len(outputs) != 0 || len(store.savedBindings()) != 0 {
		t.Fatal("invalid proof activated or persisted a share")
	}
	t.Logf("invalid proof rejected without persistence: %v", err)
	// Reuse the same service instances: failure must not poison the next session.
	outputs, err, _ = run(false)
	if err != nil {
		t.Fatalf("valid session after proof rejection failed: %v", err)
	}
	assertMPC2Of3DKGEvidence(t, parties, outputs, store, "proof-test-false", mpc2Of3KeyID, []byte("TEST ONLY — NEVER FUND"), hex.EncodeToString(chainCode))
	for _, id := range parties {
		if pools[id].acquires.Load() != 2 {
			t.Fatalf("%s did not consume one item per attempt", id)
		}
	}
	signing := mpc2Of3Fixture{services: map[string]*Service{}, outputs: outputs, keyID: mpc2Of3KeyID, chainCode: chainCode}
	for _, id := range parties {
		signing.services[id] = NewBnbService(logger, WithShareReader(&mpc2Of3PartyShareReader{store: store, partyID: id}))
	}
	verifyMPC2Of3SigningSession(t, signing, parties[:2], "/0/0")
}
