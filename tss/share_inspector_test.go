package tss

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"testing"

	tsscrypto "github.com/bnb-chain/tss-lib/crypto"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

func TestInspectEncodedECDSAKeyMaterialExposesCoreEvidence(t *testing.T) {
	point := tsscrypto.ScalarBaseMult(tsslib.S256(), big.NewInt(1))
	if point == nil {
		t.Fatal("create secp256k1 test point")
	}
	blob, err := MarshalKeyMaterial(ECDSAKeyMaterial{
		Share:            ecdsakeygen.LocalPartySaveData{ECDSAPub: point},
		ChainCode:        bytes.Repeat([]byte{0x42}, 32),
		PublicKeyFormat:  PublicKeyFormatUncompressedHex,
		DerivationScheme: DerivationSchemeBIP32Secp256k1,
	})
	if err != nil {
		t.Fatalf("MarshalKeyMaterial() error = %v", err)
	}

	evidence, err := InspectEncodedECDSAKeyMaterial(blob)
	if err != nil {
		t.Fatalf("InspectEncodedECDSAKeyMaterial() error = %v", err)
	}
	if evidence.CodecVersion != 2 || len(evidence.AccountPublicKey) != 33 {
		t.Fatal("InspectEncodedECDSAKeyMaterial() returned incomplete public evidence")
	}
	if evidence.ChainCodeHash != sha256.Sum256(bytes.Repeat([]byte{0x42}, 32)) {
		t.Fatal("InspectEncodedECDSAKeyMaterial() returned the wrong chain code hash")
	}
}
