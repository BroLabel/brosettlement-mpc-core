package service

import (
	"context"

	tssruntime "github.com/BroLabel/brosettlement-mpc-core/internal/tss/runtime"
	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
	tssutils "github.com/BroLabel/brosettlement-mpc-core/tss/utils"
)

func prepareShareForSign(ctx context.Context, shareStore ShareStore, runner Runner, job tssbnbrunner.SignJob, emptyKeyErr, metadataMismatch error) (func(), error) {
	if shareStore == nil || !tssutils.IsECDSA(job.Algorithm) {
		return func() {}, nil
	}
	return tssruntime.PrepareShareForSign(ctx, shareStore, runner, tssruntime.SignPrepareInput{
		KeyID:            job.KeyID,
		OrgID:            job.OrgID,
		Algorithm:        job.Algorithm,
		EmptyKeyErr:      emptyKeyErr,
		MetadataMismatch: metadataMismatch,
	})
}
