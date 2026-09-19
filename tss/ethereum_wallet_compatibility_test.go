package tss

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	corederivation "github.com/BroLabel/brosettlement-mpc-core/internal/tss/derivation"
	"github.com/bnb-chain/tss-lib/common"
	"github.com/btcsuite/btcd/btcec"
	"golang.org/x/sync/errgroup"
)

const (
	ethereumWalletV1SourceHash = "reBSo1hUdbEqcU3ZMMxt9xLB08ZIVHlyYR3Cp0ocmEI"
	ethereumWalletV1MainnetID  = "ethereum-wallet-v1-mainnet-eth"
)

type ethereumWalletV1Fixture struct {
	SchemaVersion              int      `json:"schemaVersion"`
	SourceHash                 string   `json:"sourceHash"`
	CanonicalVectorIDs         []string `json:"canonicalVectorIDs"`
	TestOnlyDerivationMaterial struct {
		AccountPublicKeyUncompressed string `json:"accountPublicKeyUncompressed"`
		ChainCode                    string `json:"chainCode"`
	} `json:"testOnlyDerivationMaterial"`
	Vectors []ethereumWalletV1FixtureVector `json:"vectors"`
}

func TestEthereumWalletV1X01DerivationAndThresholdSignature(t *testing.T) {
	fixture := loadEthereumWalletV1Fixture(t)
	for _, fixtureVector := range fixture.Vectors {
		assertEthereumWalletV1DerivationFixture(t, fixture, fixtureVector)
	}
	vector := findEthereumWalletV1Vector(t, fixture, ethereumWalletV1MainnetID)
	digest := mustDecodeEthereumWalletV1Hex(t, vector.UnsignedHash)
	if len(digest) != 32 {
		t.Fatalf("X01 digest length = %d, want 32", len(digest))
	}
	if vector.Derivation.ChildPath != "/0/7" || vector.Derivation.FullPath != "m/44'/60'/0'/0/7" {
		t.Fatalf("unexpected X01 child/full path: %q -> %q", vector.Derivation.ChildPath, vector.Derivation.FullPath)
	}

	ethereumContext := ethereumWalletV1Context(vector)
	mpcFixture := runMPC2Of3DKG(t)
	mpcDerivationContext := ethereumContext
	mpcDerivationContext.DerivedPublicKey = ""
	tronContext := mpcDerivationContext
	tronContext.Chain = "tron:mainnet"
	tronContext.ProfileID = "tron-bip44-account-0"
	tronContext.ProfileTemplateID = "tron-bip44-account"
	tronContext.AccountPath = "m/44'/195'/0'"
	tronContext.FullPath = "m/44'/195'/0'/0/7"

	tronPublicKey, err := DeriveECDSAChildPublicKey(mpcFixture.outputs[mpc2Of3PartyA].PublicKey, mpcFixture.chainCode, tronContext)
	if err != nil {
		t.Fatalf("derive TRON-context public key: %v", err)
	}
	ethereumPublicKey, err := DeriveECDSAChildPublicKey(mpcFixture.outputs[mpc2Of3PartyA].PublicKey, mpcFixture.chainCode, mpcDerivationContext)
	if err != nil {
		t.Fatalf("derive Ethereum-context public key: %v", err)
	}
	if tronPublicKey != ethereumPublicKey {
		t.Fatal("same account key, chain code, and child path derived different public keys")
	}
	tronHash, err := DerivationContextHashV1(tronContext)
	if err != nil {
		t.Fatalf("hash TRON context: %v", err)
	}
	ethereumHash, err := DerivationContextHashV1(ethereumContext)
	if err != nil {
		t.Fatalf("hash Ethereum context: %v", err)
	}
	if tronHash == ethereumHash {
		t.Fatal("TRON and Ethereum contexts share a binding hash")
	}

	wrongChainContext := tronContext
	if err := validateDerivationContextForSession(wrongChainContext, SignSessionDescriptor{
		Algorithm: AlgorithmECDSA,
		Curve:     CurveSecp256k1,
		Chain:     vector.Derivation.Chain,
	}); !errors.Is(err, ErrInvalidDerivationContext) {
		t.Fatalf("wrong chain context error = %v, want ErrInvalidDerivationContext", err)
	}

	signingContext := mpcDerivationContext
	signingContext.DerivedPublicKey = ethereumPublicKey
	signature := signEthereumWalletV1Digest(t, mpcFixture, vector.Derivation.Chain, digest, signingContext)
	assertEthereumWalletV1Signature(t, signature, ethereumPublicKey, digest)
}

func loadEthereumWalletV1Fixture(t *testing.T) ethereumWalletV1Fixture {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate compatibility test source")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "testdata", "ethereum-wallet-v1", "vectors.json"))
	if err != nil {
		t.Fatalf("read Ethereum wallet fixture: %v", err)
	}
	var fixture ethereumWalletV1Fixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decode Ethereum wallet fixture: %v", err)
	}
	if fixture.SchemaVersion != 1 || fixture.SourceHash != ethereumWalletV1SourceHash {
		t.Fatalf("unexpected fixture identity: schema=%d sourceHash=%q", fixture.SchemaVersion, fixture.SourceHash)
	}
	if !slices.Equal(fixture.CanonicalVectorIDs, []string{ethereumWalletV1MainnetID, "ethereum-wallet-v1-sepolia-erc20"}) {
		t.Fatalf("canonical vector IDs = %q", fixture.CanonicalVectorIDs)
	}
	return fixture
}

func assertEthereumWalletV1DerivationFixture(t *testing.T, fixture ethereumWalletV1Fixture, vector ethereumWalletV1FixtureVector) {
	t.Helper()
	derivationContext := ethereumWalletV1Context(vector)
	payload, err := corederivation.CanonicalHashPayloadV1(toCoreDerivationContext(derivationContext))
	if err != nil {
		t.Fatalf("%s canonical derivation payload: %v", vector.ID, err)
	}
	if string(payload) != vector.Derivation.ContextPayload {
		t.Fatalf("%s canonical derivation payload = %q, want fixture %q", vector.ID, payload, vector.Derivation.ContextPayload)
	}
	contextHash, err := DerivationContextHashV1(derivationContext)
	if err != nil {
		t.Fatalf("%s hash derivation context: %v", vector.ID, err)
	}
	if contextHash != vector.Derivation.ContextHash {
		t.Fatalf("%s derivation context hash = %q, want fixture %q", vector.ID, contextHash, vector.Derivation.ContextHash)
	}
	chainCode := mustDecodeEthereumWalletV1Hex(t, fixture.TestOnlyDerivationMaterial.ChainCode)
	derivedPublicKey, err := DeriveECDSAChildPublicKey(fixture.TestOnlyDerivationMaterial.AccountPublicKeyUncompressed, chainCode, derivationContext)
	if err != nil {
		t.Fatalf("%s derive fixture public key: %v", vector.ID, err)
	}
	if derivedPublicKey != vector.Derivation.DerivedPublicKey {
		t.Fatalf("%s derived fixture public key = %q, want %q", vector.ID, derivedPublicKey, vector.Derivation.DerivedPublicKey)
	}
}

func findEthereumWalletV1Vector(t *testing.T, fixture ethereumWalletV1Fixture, id string) ethereumWalletV1FixtureVector {
	t.Helper()
	for _, vector := range fixture.Vectors {
		if vector.ID == id {
			return vector
		}
	}
	t.Fatalf("missing canonical X01 vector %q", id)
	return ethereumWalletV1FixtureVector{}
}

type ethereumWalletV1FixtureVector struct {
	ID         string `json:"id"`
	Derivation struct {
		AccountPath       string `json:"accountPath"`
		ChildPath         string `json:"childPath"`
		FullPath          string `json:"fullPath"`
		ProfileID         string `json:"profileId"`
		ProfileTemplateID string `json:"profileTemplateId"`
		Chain             string `json:"chain"`
		Algorithm         string `json:"algorithm"`
		Curve             string `json:"curve"`
		Scheme            string `json:"scheme"`
		PublicKeyFormat   string `json:"publicKeyFormat"`
		DerivedPublicKey  string `json:"derivedPublicKey"`
		DescriptorVersion uint32 `json:"descriptorVersion"`
		ProfileVersion    uint32 `json:"profileVersion"`
		KeyVersion        uint32 `json:"keyVersion"`
		ContextPayload    string `json:"contextPayload"`
		ContextHash       string `json:"contextHash"`
	} `json:"derivation"`
	UnsignedHash string `json:"unsignedHash"`
}

func ethereumWalletV1Context(vector ethereumWalletV1FixtureVector) DerivationContext {
	return DerivationContext{
		ProfileID:         vector.Derivation.ProfileID,
		ProfileTemplateID: vector.Derivation.ProfileTemplateID,
		Chain:             vector.Derivation.Chain,
		Algorithm:         vector.Derivation.Algorithm,
		Curve:             vector.Derivation.Curve,
		Scheme:            vector.Derivation.Scheme,
		PublicKeyFormat:   vector.Derivation.PublicKeyFormat,
		AccountPath:       vector.Derivation.AccountPath,
		ChildPath:         vector.Derivation.ChildPath,
		FullPath:          vector.Derivation.FullPath,
		DerivedPublicKey:  vector.Derivation.DerivedPublicKey,
		DescriptorVersion: vector.Derivation.DescriptorVersion,
		ProfileVersion:    vector.Derivation.ProfileVersion,
		KeyVersion:        vector.Derivation.KeyVersion,
	}
}

func signEthereumWalletV1Digest(t *testing.T, fixture mpc2Of3Fixture, chain string, digest []byte, derivationContext DerivationContext) *common.SignatureData {
	t.Helper()
	parties := []string{mpc2Of3PartyA, mpc2Of3PartyB}
	sessionID := "ethereum-wallet-v1-sign"
	_, transports := newMPC2Of3FrameBus(parties)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	group, groupCtx := errgroup.WithContext(ctx)
	for _, partyID := range parties {
		partyID := partyID
		group.Go(func() error {
			return fixture.services[partyID].RunSignSession(groupCtx, SignSessionRequest{
				Session:      SignSessionDescriptor{SessionID: sessionID, OrgID: "ethereum-wallet-v1", KeyID: fixture.keyID, Parties: parties, Threshold: 2, Algorithm: AlgorithmECDSA, Curve: CurveSecp256k1, Chain: chain},
				LocalPartyID: partyID, Digest: digest, DerivationContext: &derivationContext, Transport: transports[partyID],
			})
		})
	}
	if err := group.Wait(); err != nil {
		t.Fatalf("threshold signing: %v", err)
	}
	signature, err := fixture.services[mpc2Of3PartyA].ExportECDSASignature(sessionID)
	if err != nil {
		t.Fatalf("export signature: %v", err)
	}
	return &signature
}

func assertEthereumWalletV1Signature(t *testing.T, signature *common.SignatureData, publicKeyHex string, digest []byte) {
	t.Helper()
	if len(signature.GetSignature()) != 64 || !bytes.Equal(signature.GetSignature(), append(append([]byte(nil), signature.GetR()...), signature.GetS()...)) {
		t.Fatal("signature is not compact 64-byte R||S")
	}
	if len(signature.GetSignatureRecovery()) != 1 || signature.GetSignatureRecovery()[0] > 3 {
		t.Fatal("signature has invalid recovery parity")
	}
	r, s := new(big.Int).SetBytes(signature.GetR()), new(big.Int).SetBytes(signature.GetS())
	if s.Cmp(new(big.Int).Rsh(btcec.S256().Params().N, 1)) > 0 {
		t.Fatal("signature is not low-S")
	}
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("decode derived public key: %v", err)
	}
	publicKey, err := btcec.ParsePubKey(publicKeyBytes, btcec.S256())
	if err != nil {
		t.Fatalf("parse derived public key: %v", err)
	}
	if !ecdsa.Verify(publicKey.ToECDSA(), digest, r, s) {
		t.Fatal("independent verifier rejected signature")
	}
	compact := append([]byte{27 + signature.GetSignatureRecovery()[0]}, signature.GetSignature()...)
	recovered, _, err := btcec.RecoverCompact(btcec.S256(), compact, digest)
	if err != nil {
		t.Fatalf("recover compact signature: %v", err)
	}
	if !bytes.Equal(recovered.SerializeUncompressed(), publicKey.SerializeUncompressed()) {
		t.Fatal("recovery parity did not recover derived public key")
	}
}

func mustDecodeEthereumWalletV1Hex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil {
		t.Fatalf("decode fixture hex: %v", err)
	}
	return decoded
}
