# brosettlement-mpc-core

Reusable Go packages for MPC/TSS flows, transport framing, and share persistence.

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
- `shares`: share serialization and persistence abstractions.
- `shares/file`: encrypted on-disk share store.
- `tss`: high-level service layer for DKG and signing sessions.
- `tss/preparams`: pre-parameter pool configuration and runtime.

## Basic Usage

```go
package main

import "github.com/BroLabel/brosettlement-mpc-core/protocol"

func main() {
	_ = protocol.Frame{
		SessionID: "session-1",
		FromParty: "party-a",
		Payload:   []byte("hello"),
	}
}
```

## Compatibility Note

The `tss/...` packages still import `brosettlement-mpc-signer/pkg/idgen`. Until that helper is moved into this repository or published as its own module, consumers that build `tss/...` packages need that dependency available in their build graph.

Packages outside `tss/...` do not depend on `pkg/idgen`.

## Development

Typical verification:

```bash
go test ./...
```

If you are publishing releases for downstream consumers, create semantic version tags such as `v0.1.0`.
