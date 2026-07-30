# MPC 2-of-3 integration data

The `TestMPC2Of3DKGAndEverySigningSubset` integration test generates all
cryptographic inputs at runtime. This directory intentionally contains no key
shares, chain codes, pre-parameters, signatures, or decrypted codec blobs.

Each test run generates three fresh ECDSA pre-parameter sets. Party A consumes
one set from its test-only pool, while parties B and C consume two distinct sets
from a single shared test-only pool through one public `Service`. Generated
material is never reused or published as a test fixture.

The test asserts only public DKG output, safe codec inspector evidence, and
independently verified secp256k1 signatures for A+B, A+C, and B+C.

All three DKG participants use one shared test key ID. The in-memory test writer
indexes persisted shares by local party plus key ID, and signing uses
party-bound readers so every subset loads the correct local share without
changing the production persistence API.
