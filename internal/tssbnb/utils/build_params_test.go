package utils

import (
	"strconv"
	"testing"
)

func TestBuildParamsConvertsRequiredSignerThresholdForTSSLib(t *testing.T) {
	params, _, _, err := BuildParams(
		[]string{"A", "B", "C"},
		"B",
		2,
		"secp256k1",
		"ecdsa",
	)
	if err != nil {
		t.Fatalf("BuildParams() error = %v", err)
	}
	if params.PartyCount() != 3 {
		t.Fatalf("tss-lib party count = %d, want 3", params.PartyCount())
	}
	if params.Threshold() != 1 {
		t.Fatalf("tss-lib threshold = %d, want 1 for two required signers", params.Threshold())
	}
}

func TestBuildParamsRejectsInvalidRequiredSignerThreshold(t *testing.T) {
	for _, requiredSigners := range []int{1, 4} {
		t.Run(strconv.Itoa(requiredSigners), func(t *testing.T) {
			_, _, _, err := BuildParams(
				[]string{"A", "B", "C"},
				"A",
				requiredSigners,
				"secp256k1",
				"ecdsa",
			)
			if err == nil {
				t.Fatalf("BuildParams() accepted %d required signers for 3 parties", requiredSigners)
			}
		})
	}
}
