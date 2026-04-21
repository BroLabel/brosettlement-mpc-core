package service

import (
	"context"
	"testing"

	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
)

func TestPrepareShareForSign_SkipsWhenStoreMissing(t *testing.T) {
	t.Parallel()

	runner := newECDSAStubRunner(t, "key-1")
	cleanup, err := prepareShareForSign(context.Background(), nil, runner, tssbnbrunner.SignJob{
		KeyID:     "key-1",
		OrgID:     "org",
		Algorithm: "ecdsa",
	}, errShareMissing, errShareMissing)
	if err != nil {
		t.Fatalf("prepareShareForSign returned error: %v", err)
	}
	cleanup()
	if len(runner.deletedKeys) != 0 {
		t.Fatalf("expected noop cleanup without store, got %+v", runner.deletedKeys)
	}
}
