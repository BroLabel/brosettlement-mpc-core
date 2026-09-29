# Frozen legacy preparameter cache

**TEST ONLY — NEVER FUND.** These public Paillier secrets cannot secure real keys.

`public-test-only-v1.gob` is a Gob of `*keygen.LocalPreParams`, matching the
old Core v0.5.0 pool's encoder. It was emitted in a separate old-only process:

```sh
cd tools/legacy-fixture
GOWORK=off go run ./cmd/preparams-cache preparams/public-test-only-0.json ../../testdata/legacy-preparams/public-test-only-v1.gob
```

The command refuses to overwrite an existing file and checks its runtime TSS
version/checksum. The module remains pinned to `github.com/bnb-chain/tss-lib
v1.5.0`, sum `h1:fuP69k0c4K9kaWCrG+FPH4GDdGZpMRhLyAaA+TyGn0w=`;
source revision `3d95e54c2c9e26211ec0599f90772e8eb260c62b`.
The existing old share generator and its frozen codec-v2 corpus are unchanged.

Input is the already-vendored public upstream preparameter-only JSON documented
in `../legacy-v1/README.md`; its SHA-256 is
`26b0cbfab4b155397557f0ee91575f13367368a451b2bc572a21805985f75334`.
Output SHA-256 is
`5b539d6a5d10ec727a4943e2484ebdd0e9718208f8752201e06a6c109f16b987`.
No signing-share fields or real account data are used. Do not regenerate this
fixture to accommodate a candidate decoder change. Test copies are acquired
once and consumed or discarded; public-input reuse across tests is not a
production policy. `ValidateWithProof` checks field presence, not proof validity.
