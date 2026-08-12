package shares

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"

	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

const (
	codecVersion uint32 = 2

	codecPublicKeyFormat  = "uncompressed_hex"
	codecDerivationScheme = "bip32_secp256k1"

	// maxKeyMaterialBlobBytes is the maximum durable codec-v2 blob. The same
	// bound applies to MarshalKeyMaterial and UnmarshalKeyMaterial, so a blob
	// emitted by this package is always accepted by its v2 decoder. The bound
	// limits Gob allocation from untrusted stored input without changing the
	// representation of accepted v2 values.
	maxKeyMaterialBlobBytes = 1 << 20
)

type ECDSAKeyMaterial struct {
	Share            ecdsakeygen.LocalPartySaveData
	ChainCode        []byte
	PublicKeyFormat  string
	DerivationScheme string
}

type KeyMaterialMeta struct {
	ChainCode        []byte
	PublicKeyFormat  string
	DerivationScheme string
}

type shareEnvelope struct {
	Version uint32
	Share   ecdsakeygen.LocalPartySaveData
	Meta    KeyMaterialMeta
}

func MarshalKeyMaterial(material ECDSAKeyMaterial) ([]byte, error) {
	meta := KeyMaterialMeta{
		ChainCode:        append([]byte(nil), material.ChainCode...),
		PublicKeyFormat:  material.PublicKeyFormat,
		DerivationScheme: material.DerivationScheme,
	}
	defer clearBytes(meta.ChainCode)
	if err := validateKeyMaterialMeta(meta); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(shareEnvelope{
		Version: codecVersion,
		Share:   material.Share,
		Meta:    meta,
	}); err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidSharePayload, err)
	}
	if buf.Len() > maxKeyMaterialBlobBytes {
		return nil, fmt.Errorf("%w: blob exceeds %d bytes", ErrInvalidSharePayload, maxKeyMaterialBlobBytes)
	}
	return buf.Bytes(), nil
}

func UnmarshalKeyMaterial(blob []byte) (ECDSAKeyMaterial, error) {
	if len(blob) > maxKeyMaterialBlobBytes {
		return ECDSAKeyMaterial{}, fmt.Errorf("%w: blob exceeds %d bytes", ErrInvalidSharePayload, maxKeyMaterialBlobBytes)
	}

	decoder := gob.NewDecoder(bytes.NewReader(blob))
	var env shareEnvelope
	defer func() {
		clearBytes(env.Meta.ChainCode)
	}()
	if err := decoder.Decode(&env); err != nil {
		return ECDSAKeyMaterial{}, fmt.Errorf("%w: decode: %v", ErrInvalidSharePayload, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ECDSAKeyMaterial{}, fmt.Errorf("%w: trailing data", ErrInvalidSharePayload)
	}
	if env.Version != codecVersion {
		return ECDSAKeyMaterial{}, fmt.Errorf("%w: got=%d expected=%d", ErrUnsupportedVersion, env.Version, codecVersion)
	}
	if err := validateKeyMaterialMeta(env.Meta); err != nil {
		return ECDSAKeyMaterial{}, err
	}
	return ECDSAKeyMaterial{
		Share:            env.Share,
		ChainCode:        copyAndClearBytes(env.Meta.ChainCode),
		PublicKeyFormat:  env.Meta.PublicKeyFormat,
		DerivationScheme: env.Meta.DerivationScheme,
	}, nil
}

func validateKeyMaterialMeta(meta KeyMaterialMeta) error {
	if len(meta.ChainCode) != 32 || meta.PublicKeyFormat != codecPublicKeyFormat || meta.DerivationScheme != codecDerivationScheme {
		return fmt.Errorf("%w: unsupported key material metadata", ErrInvalidSharePayload)
	}
	return nil
}

func copyAndClearBytes(source []byte) []byte {
	copy := append([]byte(nil), source...)
	clearBytes(source)
	return copy
}

func clearBytes(buffer []byte) {
	for index := range buffer {
		buffer[index] = 0
	}
}
