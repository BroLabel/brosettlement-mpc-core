package shares

import (
	"bytes"
	"encoding/gob"
	"fmt"

	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

const codecVersion uint32 = 2

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
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(shareEnvelope{
		Version: codecVersion,
		Share:   material.Share,
		Meta: KeyMaterialMeta{
			ChainCode:        append([]byte(nil), material.ChainCode...),
			PublicKeyFormat:  material.PublicKeyFormat,
			DerivationScheme: material.DerivationScheme,
		},
	}); err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidSharePayload, err)
	}
	return buf.Bytes(), nil
}

func UnmarshalKeyMaterial(blob []byte) (ECDSAKeyMaterial, error) {
	var env shareEnvelope
	if err := gob.NewDecoder(bytes.NewReader(blob)).Decode(&env); err != nil {
		return ECDSAKeyMaterial{}, fmt.Errorf("%w: decode: %v", ErrInvalidSharePayload, err)
	}
	if env.Version != codecVersion {
		return ECDSAKeyMaterial{}, fmt.Errorf("%w: got=%d expected=%d", ErrUnsupportedVersion, env.Version, codecVersion)
	}
	return ECDSAKeyMaterial{
		Share:            env.Share,
		ChainCode:        append([]byte(nil), env.Meta.ChainCode...),
		PublicKeyFormat:  env.Meta.PublicKeyFormat,
		DerivationScheme: env.Meta.DerivationScheme,
	}, nil
}

func MarshalShare(share ecdsakeygen.LocalPartySaveData) ([]byte, error) {
	return MarshalKeyMaterial(ECDSAKeyMaterial{Share: share})
}

func UnmarshalShare(blob []byte) (ecdsakeygen.LocalPartySaveData, error) {
	material, err := UnmarshalKeyMaterial(blob)
	if err != nil {
		return ecdsakeygen.LocalPartySaveData{}, err
	}
	return material.Share, nil
}
