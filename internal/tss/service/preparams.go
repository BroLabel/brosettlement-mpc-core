package service

import (
	"context"

	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

type Pool interface {
	Size() int
}

type PreParamsPool interface {
	Acquire(ctx context.Context) (*ecdsakeygen.LocalPreParams, error)
}

func ResolvePreParamsSource(external PreParamsPool, fallback PreParamsPool) PreParamsPool {
	if external != nil {
		return external
	}
	return fallback
}

func AttachPreParams(ctx context.Context, pool PreParamsPool, job *tssbnbrunner.DKGJob, shouldAttach bool) error {
	if job == nil || pool == nil || job.ECDSAPreParams != nil || !shouldAttach {
		return nil
	}
	pre, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	job.ECDSAPreParams = pre
	return nil
}
