# brosettlement-mpc-core

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Reusable Go packages for MPC/TSS flows and transport framing.

## Module

```bash
go get github.com/BroLabel/brosettlement-mpc-core
```

Module path:

```go
import "github.com/BroLabel/brosettlement-mpc-core/..."
```

## Packages

- `protocol`: session and frame contracts used between peers.
- `transport`: small transport interfaces plus in-memory adapters.
- `tss`: high-level service layer for DKG and signing sessions.

## Public API Boundary

Public API is limited to imports from `protocol`, `transport`, and `tss`.

Packages under `internal/*` are implementation details and are not part of the public API surface.

## Basic Usage

```go
package main

import (
	"log/slog"

	"github.com/BroLabel/brosettlement-mpc-core/tss"
)

func main() {
	logger := slog.Default()
	_ = tss.NewBnbService(logger)
}
```

## Derived Signing

Public SIGN requests require `tss.DerivationContext`.
ECDSA secp256k1 signing signs the requested non-hardened BIP32 child key.
Root or account-key signing is intentionally unsupported through the public SIGN API.

ECDSA DKG creates account-level key material and requires upstream-supplied `tss.DKGDerivationMaterial`.
The upstream orchestration layer must generate one 32-byte chain code per ECDSA DKG intent and pass the byte-identical value to every participant.
Core validates and persists that chain code after successful DKG; SIGN requests never carry chain code.

Core returns local DKG output.
Key activation is an upstream orchestration responsibility and must compare matching outputs from the complete required participant set before activating a key.

Core normalizes and hashes the signing derivation context with `tss.DerivationContextHashV1`.
SIGN frames carry that hash so peers fail closed when they are using different profile/path commitments.

Core does not store derivation profiles, prove profile or account-path ownership, compute chain-specific child addresses, or validate `ExpectedAddress`.
EdDSA derivation values are reserved in the public contract, but derived EdDSA signing returns `tss.ErrDerivedSigningUnsupported` in this scope.

## Development

Typical verification:

```bash
go test ./...
```

If you are publishing releases for downstream consumers, create semantic version tags such as `v0.1.0`.
