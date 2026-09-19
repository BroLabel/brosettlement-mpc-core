# Ethereum wallet v1 Core subset

This directory contains the Core test subset of the canonical
`contracts/ethereum-wallet-v1/vectors.json` fixture in BroSettlement back-end.
It retains the canonical source hash and both Ethereum vector IDs.

The subset includes only the documented test account public key and chain code,
the exact Core v0.4.6 canonical derivation payloads and lowercase hex context
hashes, derived public keys, and unsigned transaction digests needed by the
2-of-3 compatibility test. It contains no production material.
