package service

import (
	"context"
	"errors"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
	corederivation "github.com/BroLabel/brosettlement-mpc-core/internal/tss/derivation"
	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
	coretransport "github.com/BroLabel/brosettlement-mpc-core/transport"
	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

var ErrNilRunner = errors.New("runner is required")

type Runner interface {
	RunDKG(ctx context.Context, job tssbnbrunner.DKGJob, transport coretransport.FrameTransport) error
	RunSign(ctx context.Context, job tssbnbrunner.SignJob, transport coretransport.FrameTransport) error
	ExportECDSASignature(key string) (common.SignatureData, error)
	ExportECDSAKeyShare(key string) (ecdsakeygen.LocalPartySaveData, error)
	ExportECDSAKeyMaterial(key string) (coreshares.ECDSAKeyMaterial, error)
	ImportECDSAKeyShare(key string, data ecdsakeygen.LocalPartySaveData)
	ImportECDSAKeyMaterial(key string, material coreshares.ECDSAKeyMaterial)
	DeleteECDSAKeyShare(key string)
	ECDSAAddress(key string) (string, error)
}

type ShareStore interface {
	SaveShare(ctx context.Context, keyID string, blob []byte, meta coreshares.ShareMeta) error
	LoadShare(ctx context.Context, keyID string) (*coreshares.StoredShare, error)
}

type LifecyclePool interface {
	PreParamsPool
	Pool
	Start(ctx context.Context) error
	Close() error
}

type SnapshotPool interface {
	LifecyclePool
	SnapshotProvider
}

type DKGDerivationMaterial struct {
	ChainCode        string
	DerivationScheme string
}

type DKGInput struct {
	SessionID          string
	LocalPartyID       string
	OrgID              string
	KeyID              string
	Parties            []string
	Threshold          uint32
	Curve              string
	Algorithm          string
	Chain              string
	DerivationMaterial DKGDerivationMaterial
	Transport          coretransport.FrameTransport
	EmptyKeyErr        error
	MissingPub         error
	MissingAddr        error
}

type DKGOutput struct {
	KeyID            string
	PublicKey        string
	Address          string
	ChainCode        string
	PublicKeyFormat  string
	DerivationScheme string
}

type SignInput struct {
	SessionID             string
	LocalPartyID          string
	OrgID                 string
	KeyID                 string
	Parties               []string
	Digest                []byte
	Algorithm             string
	Curve                 string
	Chain                 string
	DerivationContext     corederivation.Context
	DerivationContextHash string
	Transport             coretransport.FrameTransport
	EmptyKeyErr           error
	MetadataMismatch      error
}
