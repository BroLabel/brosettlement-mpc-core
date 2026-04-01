# brosettlement-mpc-core

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

## Development

Typical verification:

```bash
go test ./...
```

If you are publishing releases for downstream consumers, create semantic version tags such as `v0.1.0`.
