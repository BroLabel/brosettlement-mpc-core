# TSS v3 compatibility candidate

The implementation migrates the existing Core facade to `github.com/bnb-chain/tss-lib/v3 v3.0.0`. Go 1.24.0 remains the module floor. The outward facade, codec-v2 serialization, root/child derivation, product party mapping and signature format remain stable. Default modulus/factor proof verification remains enabled.

## Tested source and compatibility

Cryptographic implementation/test commit: `a404d4514d6e0b8de74946655eb3494ecdd0d5f7`. The fixture producer is isolated in `tools/legacy-fixture`, pinned to Core v0.5.0 and TSS v1.5.0. Frozen old codec-v2 data and producer/checksum evidence live in `testdata/legacy-v1`; old Gob preparameter cache evidence lives in `testdata/legacy-preparams`. Every synthetic fixture is **TEST ONLY — NEVER FUND**.

The actual v3 facade signed frozen old shares for A+B, A+C and B+C at `/0/0` and `/1/7`, including concurrent sessions. Independent ECDSA and public-key recovery validated every result, exact leading-zero digest bytes and frozen public identities. Hash/write/alias checks preserve the original shares. The default proof parameters were inspected; a normally framed v3 DKG message with a modified modulus proof failed cryptographic verification, saved no share and did not prevent a following valid DKG/SIGN. Real safe-prime generation and fresh DKG passed on Linux. The legacy Gob cache preserves its one-use/cancellation/discard behavior.

Malformed duplicate participant IDs now return the existing invalid-descriptor error before protocol startup. This closes a pre-existing upstream panic boundary; it does not introduce a protocol or valid-session behavior change.

## Executed checks

With `GOWORK=off` throughout, on the tested commit:

| Command | Result |
| --- | --- |
| `go test ./tss -run 'TestLegacyV1|TestDKGRejectsInvalidProof' -count=1 -timeout=20m` | PASS (Linux focused cryptographic gate) |
| `go test ./internal/preparams -count=1 -timeout=10m` | PASS |
| `go test ./tss -run '^TestMPC2Of3DKGAndEverySigningSubset$' -count=1 -timeout=20m` | PASS, actual fresh safe-prime generation; 34.730s controller run |
| `go test -race ./... -count=1 -timeout=30m` | PASS, all packages; tss 100.882s |
| `go vet ./...` | PASS |
| Focused pointer/nil/closed-channel/final-send/cancellation tests and example build | PASS |

The complete log records and fixture hashes are retained in the implementation release ledger. This repository has no existing release CI workflow; these are local executed results, not inferred CI evidence.

## Upstream identity

TSS v3.0.0 resolves to upstream commit `3f677ff761fcf692edb0243a5d812930844d879a`:

- Module sum: `h1:Vqc4qExogT4X61+Jvh7rxJM5RF5ksQxsQjWY3VwbTd0=`.
- go.mod sum: `h1:2YiekCEVQ+XNOq2ECsJDvYeGs1vgK+cfOHJ357XIWIk=`.

Confirmed with `go mod download -json github.com/bnb-chain/tss-lib/v3@v3.0.0`.

## Immutable consumer identity

The ready PRs consume one exact pushed Core commit as a resolved Go pseudo-version. This avoids publishing a stable tag before Core review/merge. The Backend test/release manifest and release evidence document record the literal resolved version, commit, module/go.mod sums, and all consumer source/binary identities after download verification. No committed local Core/TSS replacement or moving branch is permitted. A later semantic release requires repeating consumer pin/build/gate checks; it is a separate release action.

TSS upstream requires the following exact replacement in each main consuming Go module (dependency replacements are not inherited):

```go
replace github.com/agl/ed25519 => github.com/binance-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43
```

## Rollout restrictions

Healthy existing-key provenance/parameters and absence of compromise are accepted premises. This is not a production key audit. No existing key replacement, resharing, re-encryption, schema/codec bump or custody transfer is part of the migration.

Stop the complete v1 participant set and terminate old sessions before admitting v3 sessions. Never disable proofs, fall back silently, mix TSS majors or replay old transcripts. Ordinary Signer remains A+B; A+C is Core compatibility coverage only, while recovery remains B+C. Service/recovery packaging, staging, production and operator installation each require their own evidence. Passing this Core gate is not deployment completion.
