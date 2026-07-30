package shares

import (
	"bytes"
	"math/big"
	"testing"

	tsscrypto "github.com/bnb-chain/tss-lib/crypto"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/bnb-chain/tss-lib/tss"
)

func FuzzInspectEncodedECDSAKeyMaterial(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("not-a-gob"))
	f.Add([]byte{0})
	point := tsscrypto.ScalarBaseMult(tsslib.S256(), big.NewInt(1))
	if point == nil {
		f.Fatal("create secp256k1 fuzz seed point")
	}
	validBlob, err := MarshalKeyMaterial(ECDSAKeyMaterial{
		Share:     ecdsakeygen.LocalPartySaveData{ECDSAPub: point},
		ChainCode: bytes.Repeat([]byte{0x42}, 32),
	})
	if err != nil {
		f.Fatalf("marshal valid fuzz seed: %v", err)
	}
	f.Add(validBlob)

	f.Fuzz(func(t *testing.T, blob []byte) {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("InspectEncodedECDSAKeyMaterial() panicked: %v", recovered)
			}
		}()
		_, _ = InspectEncodedECDSAKeyMaterial(blob)
	})
}
