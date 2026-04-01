package shares

import (
	"bytes"
	"encoding/gob"
	"fmt"

	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

const codecVersion uint32 = 1

type shareEnvelope struct {
	Version uint32
	Share   ecdsakeygen.LocalPartySaveData
}

func MarshalShare(share ecdsakeygen.LocalPartySaveData) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(shareEnvelope{
		Version: codecVersion,
		Share:   share,
	}); err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidSharePayload, err)
	}
	return buf.Bytes(), nil
}

func UnmarshalShare(blob []byte) (ecdsakeygen.LocalPartySaveData, error) {
	var env shareEnvelope
	if err := gob.NewDecoder(bytes.NewReader(blob)).Decode(&env); err != nil {
		return ecdsakeygen.LocalPartySaveData{}, fmt.Errorf("%w: decode: %v", ErrInvalidSharePayload, err)
	}
	if env.Version != codecVersion {
		return ecdsakeygen.LocalPartySaveData{}, fmt.Errorf("%w: got=%d expected=%d", ErrUnsupportedVersion, env.Version, codecVersion)
	}
	return env.Share, nil
}
