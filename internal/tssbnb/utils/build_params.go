package utils

import (
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"

	tsslib "github.com/bnb-chain/tss-lib/tss"
)

func BuildParams(
	parties []string,
	localPartyID string,
	threshold int,
	curve string,
	algorithm string,
) (*tsslib.Parameters, map[string]*tsslib.PartyID, *tsslib.PartyID, error) {
	if len(parties) < 2 {
		return nil, nil, nil, errors.New("tss requires at least 2 parties")
	}

	tssThreshold, err := ToTSSLibThreshold(threshold, len(parties))
	if err != nil {
		return nil, nil, nil, err
	}

	sortedParties := slices.Clone(parties)
	slices.Sort(sortedParties)

	partyIDs := make(tsslib.UnSortedPartyIDs, 0, len(sortedParties))
	partyMap := make(map[string]*tsslib.PartyID, len(sortedParties))
	for _, partyID := range sortedParties {
		pid := tsslib.NewPartyID(partyID, partyID, stablePartyKey(partyID))
		partyIDs = append(partyIDs, pid)
		partyMap[partyID] = pid
	}

	local := pickLocalPartyID(sortedParties, partyMap, localPartyID)
	if local == nil {
		return nil, nil, nil, fmt.Errorf("unknown local party id: %s", localPartyID)
	}

	sortedIDs := tsslib.SortPartyIDs(partyIDs)
	peerCtx := tsslib.NewPeerContext(sortedIDs)
	selectedCurve, err := selectCurve(curve, algorithm)
	if err != nil {
		return nil, nil, nil, err
	}

	params := tsslib.NewParameters(selectedCurve, peerCtx, local, len(sortedIDs), tssThreshold)
	return params, partyMap, local, nil
}

func ToTSSLibThreshold(requiredThreshold, partiesCount int) (int, error) {
	if requiredThreshold < 2 || requiredThreshold > partiesCount {
		return 0, fmt.Errorf("invalid required threshold %d for %d parties", requiredThreshold, partiesCount)
	}
	return requiredThreshold - 1, nil
}

func pickLocalPartyID(sortedParties []string, partyMap map[string]*tsslib.PartyID, requested string) *tsslib.PartyID {
	if requested != "" {
		return partyMap[requested]
	}
	if len(sortedParties) == 0 {
		return nil
	}
	return partyMap[sortedParties[0]]
}

func selectCurve(curve, algorithm string) (elliptic.Curve, error) {
	alg := strings.ToLower(strings.TrimSpace(algorithm))
	switch alg {
	case "", "ecdsa":
		if curve == "" {
			return tsslib.S256(), nil
		}
		switch strings.ToLower(strings.TrimSpace(curve)) {
		case "secp256k1":
			return tsslib.S256(), nil
		default:
			return nil, fmt.Errorf("unsupported ecdsa curve: %s", curve)
		}
	case "eddsa":
		if curve == "" || strings.EqualFold(curve, "ed25519") {
			return tsslib.Edwards(), nil
		}
		return nil, fmt.Errorf("unsupported eddsa curve: %s", curve)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

func stablePartyKey(partyID string) *big.Int {
	sum := sha256.Sum256([]byte(partyID))
	key := new(big.Int).SetBytes(sum[:])
	if key.Sign() == 0 {
		return big.NewInt(1)
	}
	return key
}
