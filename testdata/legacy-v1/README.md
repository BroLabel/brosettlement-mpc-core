# Frozen legacy v1 compatibility corpus

**TEST ONLY — NEVER FUND**

These three plaintext codec-v2 shares are synthetic compatibility inputs. They
were produced by fresh DKG through the public Core v0.5.0 `RunDKGSession` facade
and captured verbatim by its `ShareWriter.SaveShare` callback. The generator does
not construct save data, reassign numeric party IDs, or re-encode saved blobs.
No account, production share, ciphertext, or infrastructure was used.

The embedded **public upstream test preparameters** make generation bounded, but
are deliberately unsafe for funded keys. Each party consumes its own preparameter
once per DKG; reuse between synthetic generator runs is strictly test-only. Normal
proof checks remain enabled. All public preparameters and generated shares in this
corpus must remain isolated from production workflows.

## Contents and identity

`manifest.json` records the old producer module versions, commit revisions and Go
module checksums, Go runtime, public preparameter source paths and SHA-256 values,
codec version, SHA-256 of each stored blob, account public key and chain code,
child public keys for `/0/0` and `/1/7`, and six baseline signatures.

| Role | Product party ID |
| --- | --- |
| A | `mpc-signer` |
| B | `co-signer-primary` |
| C | `co-signer-recovery` |

Core constructs stable numeric IDs as unsigned big-endian SHA-256 of each party
ID and sorts by numeric ID. The recorded `ShareID` and `SortedIndex` come from the
stored shares; no IDs are substituted after DKG. Signatures cover A+B, A+C and B+C
on both child paths. A+C is only a Core compatibility case; it does not enable that
combination in the Signer product. Normal service signing remains A+B and isolated
recovery remains B+C.

Each signature was independently verified using Go `crypto/ecdsa` with a
`btcec` secp256k1 public key, and both participants' outputs agreed. The manifest
test rechecks those frozen signatures, decoder identity and public derivation,
and rejects a changed digest and an intentionally corrupted temporary blob.

## Verification

From the Core repository root:

```sh
GOWORK=off go test ./tss -run '^TestLegacyV1FixtureManifest$' -count=1
```

To replay all six signatures with the pinned **old** producer in a separate
process, without changing any corpus file:

```sh
cd tools/legacy-fixture
GOWORK=off go run . check ../../testdata/legacy-v1
```

The nested module pins Core v0.5.0 and tss-lib v1.5.0, rejects dependency
replacements/drift at runtime, and is never imported by the parent tests or
production module. Never load old and candidate TSS versions into one process;
protobuf registrations may collide.

## Reproduction without replacing the frozen corpus

From `tools/legacy-fixture`, choose a directory that does not exist:

```sh
GOWORK=off go run . generate /tmp/new-synthetic-legacy-corpus
```

The command refuses to overwrite an existing directory. It reproduces the old
DKG/storage/signing procedure, not identical keys or bytes: DKG and ECDSA use fresh
cryptographic randomness. Keep the checked-in frozen corpus unchanged as the
candidate library evolves. Do not regenerate it to make a compatibility test pass.

The three `tools/legacy-fixture/preparams/public-test-only-*.json` files contain
only the `LocalPreParams` fields extracted from tss-lib v1.5.0
`test/_ecdsa_fixtures/keygen_data_{0,1,2}.json`. No upstream signing-share fields
were copied. The upstream MIT license accompanies those inputs in `preparams/`.
The generator module needs normal read access to the private Core module; it has
no credentials embedded and uses no product services.
