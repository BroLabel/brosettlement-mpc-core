package runtime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/bnb-chain/tss-lib/crypto"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

func makeTestECDSAShare(t *testing.T) ecdsakeygen.LocalPartySaveData {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() err = %v", err)
	}

	point, err := crypto.NewECPoint(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y)
	if err != nil {
		t.Fatalf("NewECPoint() err = %v", err)
	}

	return ecdsakeygen.LocalPartySaveData{
		ECDSAPub: point,
	}
}

func TestExtractECDSAPublicKey_ReturnsHexEncodedUncompressedPoint(t *testing.T) {
	share := makeTestECDSAShare(t)

	got, err := ExtractECDSAPublicKey(share)
	if err != nil {
		t.Fatalf("ExtractECDSAPublicKey() err = %v", err)
	}
	if got == "" {
		t.Fatal("expected non-empty public key")
	}
	if !strings.HasPrefix(got, "04") {
		t.Fatalf("expected uncompressed public key prefix 04, got %q", got)
	}
}

func TestNormalizeDKGOutputChain_AcceptsTronAliases(t *testing.T) {
	cases := []string{"", "tron", "TRON", "tron-mainnet", "TRON-MAINNET"}
	for _, input := range cases {
		got, err := NormalizeDKGOutputChain(input)
		if err != nil {
			t.Fatalf("NormalizeDKGOutputChain(%q) err = %v", input, err)
		}
		if got != "tron" {
			t.Fatalf("NormalizeDKGOutputChain(%q) = %q, want tron", input, got)
		}
	}
}

func TestECDSAAddressFromShare_RejectsUnsupportedChain(t *testing.T) {
	share := makeTestECDSAShare(t)

	_, err := ECDSAAddressFromShare("ethereum", share)
	if !errors.Is(err, ErrUnsupportedDKGOutputChain) {
		t.Fatalf("expected ErrUnsupportedDKGOutputChain, got %v", err)
	}
}
