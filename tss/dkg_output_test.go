package tss

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"log/slog"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

func makePublicTestECDSAShare(t *testing.T) ecdsakeygen.LocalPartySaveData {
	t.Helper()

	priv, err := ecdsa.GenerateKey(tsslib.S256(), rand.Reader)
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

func (p *stubFacadePool) Size() int                  { return 0 }
func (p *stubFacadePool) Start(context.Context) error { return nil }
func (p *stubFacadePool) Close() error               { return nil }

type stubPublicRunner struct {
	share ecdsakeygen.LocalPartySaveData
}

func (r *stubPublicRunner) RunDKG(context.Context, dkgJob, Transport) error { return nil }
func (r *stubPublicRunner) RunSign(context.Context, signJob, Transport) error {
	return nil
}
func (r *stubPublicRunner) ExportECDSASignature(string) (common.SignatureData, error) {
	return common.SignatureData{}, nil
}
func (r *stubPublicRunner) ExportECDSAKeyShare(string) (ecdsakeygen.LocalPartySaveData, error) {
	return r.share, nil
}
func (r *stubPublicRunner) ImportECDSAKeyShare(string, ecdsakeygen.LocalPartySaveData) {}
func (r *stubPublicRunner) DeleteECDSAKeyShare(string)                                  {}
func (r *stubPublicRunner) ECDSAAddress(string) (string, error)                         { return "", nil }

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
