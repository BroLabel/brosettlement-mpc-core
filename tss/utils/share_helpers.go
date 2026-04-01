package utils

import (
	"fmt"
	"strings"
	"time"

	coreshares "github.com/BroLabel/brosettlement-mpc-core/internal/shares"
)

// NormalizeKeyID validates and normalizes key id.
func NormalizeKeyID(raw string, emptyErr error) (string, error) {
	keyID := strings.TrimSpace(raw)
	if keyID == "" {
		return "", fmt.Errorf("%w: empty key_id", emptyErr)
	}
	return keyID, nil
}

// DKGShareMeta builds metadata for platform share persisted after DKG.
func DKGShareMeta(keyID, orgID, algorithm, curve string) coreshares.ShareMeta {
	return coreshares.ShareMeta{
		KeyID:     keyID,
		OrgID:     orgID,
		Algorithm: NormalizeAlgorithm(algorithm),
		Curve:     curve,
		CreatedAt: time.Now().UTC(),
		Version:   1,
		Status:    coreshares.StatusActive,
	}
}
