package flow

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	tssbnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/utils"
	"github.com/bnb-chain/tss-lib/v3/common"
	tsslib "github.com/bnb-chain/tss-lib/v3/tss"
	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// TEST ONLY — NEVER FUND. Frozen old shares exercise BuildSign directly so the
// facade's digest normalization cannot hide missing fullBytesLen propagation.
func TestBuildSignPreservesLeadingZeroDigest(t *testing.T) {
	ids := []string{"mpc-signer", "co-signer-primary"}
	digest := append([]byte{0}, bytes.Repeat([]byte{0x31}, 31)...)
	out := make(chan tsslib.Message, 64)
	parties := make(map[string]tsslib.Party, len(ids))
	ends := make([]<-chan *common.SignatureData, len(ids))
	var public *btcec.PublicKey
	for i, id := range ids {
		blob, err := os.ReadFile(filepath.Join("../../../testdata/legacy-v1/codec-v2", id+".gob"))
		if err != nil {
			t.Fatal(err)
		}
		material, err := shares.UnmarshalKeyMaterial(blob)
		if err != nil {
			t.Fatal(err)
		}
		root := material.Share.ECDSAPub.ToECDSAPubKey()
		public, err = btcec.ParsePubKey(elliptic.Marshal(root.Curve, root.X, root.Y))
		if err != nil {
			t.Fatal(err)
		}
		params, _, _, err := tssbnbutils.BuildParams(ids, id, 2, "", "ecdsa")
		if err != nil {
			t.Fatal(err)
		}
		built, err := BuildSign(SignBuildInput{
			Digest: digest, Params: params, KeyShare: material.Share,
			KeyDerivationDelta: big.NewInt(0), OutCh: out,
		})
		if err != nil {
			t.Fatal(err)
		}
		parties[id], ends[i] = built.Party, built.End
	}
	started := make(chan *tsslib.Error, len(parties))
	for _, party := range parties {
		go func(p tsslib.Party) { started <- p.Start() }(party)
	}
	// Start may enqueue protocol frames but cannot fill this bounded two-party buffer.
	for range parties {
		if err := <-started; err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	var results []*common.SignatureData
	for len(results) < len(ids) {
		select {
		case sig := <-ends[0]:
			results = append(results, sig)
			ends[0] = nil
		case sig := <-ends[1]:
			results = append(results, sig)
			ends[1] = nil
		case msg := <-out:
			wire, routing, err := msg.WireBytes()
			if err != nil {
				t.Fatal(err)
			}
			for id, party := range parties {
				if id == routing.From.Id {
					continue
				}
				if !routing.IsBroadcast {
					addressed := false
					for _, recipient := range routing.To {
						if recipient.Id == id {
							addressed = true
						}
					}
					if !addressed {
						continue
					}
				}
				if _, err := party.UpdateFromBytes(wire, routing.From, routing.IsBroadcast); err != nil {
					t.Fatal(err)
				}
			}
		case <-deadline.C:
			t.Fatal("timed out waiting for synthetic signing results")
		}
	}
	for _, sig := range results {
		if sig == nil {
			t.Fatal("nil signature result")
		}
		if !bytes.Equal(sig.M, digest) {
			t.Fatalf("BuildSign result M = %x, want exact digest %x", sig.M, digest)
		}
		if len(sig.Signature) != 64 || len(sig.SignatureRecovery) != 1 || sig.SignatureRecovery[0] > 3 {
			t.Fatal("invalid compact signature or recovery ID")
		}
		r, s := new(big.Int).SetBytes(sig.R), new(big.Int).SetBytes(sig.S)
		if !ecdsa.Verify(public.ToECDSA(), digest, r, s) {
			t.Fatal("independent ECDSA verification failed")
		}
		if s.Cmp(new(big.Int).Rsh(btcec.S256().Params().N, 1)) > 0 {
			t.Fatal("signature is not low-S")
		}
		recovered, _, err := btcecdsa.RecoverCompact(append([]byte{27 + sig.SignatureRecovery[0]}, sig.Signature...), digest)
		if err != nil || !bytes.Equal(recovered.SerializeCompressed(), public.SerializeCompressed()) || !bytes.Equal(recovered.SerializeUncompressed(), public.SerializeUncompressed()) {
			t.Fatalf("independent signature recovery failed: %v", err)
		}
	}
}
