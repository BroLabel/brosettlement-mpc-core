package bnb

import (
	coretransport "github.com/BroLabel/brosettlement-mpc-core/transport"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

// Transport bridges TSS runtime with relay frame transport.
type Transport = coretransport.FrameTransport

// DKGJob describes a single DKG execution request.
type DKGJob struct {
	SessionID    string
	LocalPartyID string
	OrgID        string
	Parties      []string
	Threshold    uint32
	Curve        string
	Algorithm    string
	Chain        string
	// ECDSAPreParams is optional and speeds up ECDSA DKG when precomputed out-of-band.
	ECDSAPreParams *ecdsakeygen.LocalPreParams
}

// SignJob describes a single signing execution request.
type SignJob struct {
	SessionID    string
	LocalPartyID string
	OrgID        string
	KeyID        string
	Parties      []string
	Digest       []byte
	Algorithm    string
	Chain        string
}
