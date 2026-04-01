package tss

import (
	"context"

	"github.com/BroLabel/brosettlement-mpc-core/tss/bnb"
	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type Transport = bnb.Transport

// Runner is the adapter boundary for tss-lib integration.
type Runner interface {
	RunDKG(ctx context.Context, job DKGJob, transport Transport) error
	RunSign(ctx context.Context, job SignJob, transport Transport) error
	ExportECDSASignature(key string) (common.SignatureData, error)
	ExportECDSAKeyShare(key string) (ecdsakeygen.LocalPartySaveData, error)
	ImportECDSAKeyShare(key string, data ecdsakeygen.LocalPartySaveData)
	DeleteECDSAKeyShare(key string)
	ECDSAAddress(key string) (string, error)
}
