# Module Independence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `github.com/BroLabel/brosettlement-mpc-core` independently consumable through the public packages `protocol`, `transport`, and `tss`.

**Architecture:** Keep `protocol`, `transport`, and `tss` as the only supported public API, and move all implementation details behind `internal/*` without leaking broken import paths or stale documentation. The work proceeds in four stages: restore self-contained compilation, align docs with the public surface, add facade-level tests, then run a full release-readiness verification pass.

**Tech Stack:** Go 1.25, standard library testing, `github.com/bnb-chain/tss-lib`, Go modules, Markdown docs

---

## File Map

**Public files to modify**
- Modify: `go.mod`
- Modify: `README.md`
- Modify: `protocol/frame_test.go`
- Modify: `transport/transport.go`
- Modify: `tss/service.go`
- Modify: `tss/sharestore.go`
- Modify: `tss/transport.go`
- Modify: `tss/utils/share_helpers.go`

**Internal files likely to modify**
- Modify: `internal/preparams/pool.go`
- Modify: `internal/shares/file/config.go`
- Modify: `internal/shares/file/store.go`
- Modify: `internal/shares/file/store_test.go`
- Modify: `internal/tss/runtime/share_runtime.go`
- Modify: `internal/tss/service/orchestration.go`
- Modify: `internal/tss/service/state.go`
- Modify: `internal/tssbnb/execution/deduper.go`
- Modify: `internal/tssbnb/execution/execution.go`
- Modify: `internal/tssbnb/execution/execution_test.go`
- Modify: `internal/tssbnb/flow/dkg.go`
- Modify: `internal/tssbnb/flow/sign.go`
- Modify: `internal/tssbnb/runner/bnb_runner.go`
- Modify: `internal/tssbnb/runner/types.go`
- Modify: `internal/tssbnb/utils/recv_loop.go`

**New tests to add**
- Create: `tss/preparams_config_test.go`
- Create: `tss/sharestore_test.go`
- Create: `tss/service_test.go`
- Create: `tss/transport_test.go`

**Design and plan references**
- Read: `docs/superpowers/specs/2026-04-01-module-independence-design.md`

### Task 1: Restore Independent Module Compilation

**Files:**
- Modify: `transport/transport.go`
- Modify: `tss/service.go`
- Modify: `tss/sharestore.go`
- Modify: `tss/transport.go`
- Modify: `tss/utils/share_helpers.go`
- Modify: `internal/preparams/pool.go`
- Modify: `internal/shares/file/config.go`
- Modify: `internal/shares/file/store.go`
- Modify: `internal/shares/file/store_test.go`
- Modify: `internal/tss/runtime/share_runtime.go`
- Modify: `internal/tss/service/orchestration.go`
- Modify: `internal/tss/service/state.go`
- Modify: `internal/tssbnb/execution/deduper.go`
- Modify: `internal/tssbnb/execution/execution.go`
- Modify: `internal/tssbnb/execution/execution_test.go`
- Modify: `internal/tssbnb/flow/dkg.go`
- Modify: `internal/tssbnb/flow/sign.go`
- Modify: `internal/tssbnb/runner/bnb_runner.go`
- Modify: `internal/tssbnb/runner/types.go`
- Modify: `internal/tssbnb/utils/recv_loop.go`
- Test: `go test ./...`

- [ ] **Step 1: Write the failing module-compile check**

Run:

```bash
GOCACHE=/tmp/go-build go test ./...
```

Expected: FAIL with import errors mentioning `brosettlement-mpc-signer/brosettlement-mpc-core/...`, for example from `tss/service.go` and `transport/transport.go`.

- [ ] **Step 2: Add a search guard for legacy module imports**

Run:

```bash
rg -n 'brosettlement-mpc-signer/brosettlement-mpc-core' .
```

Expected: one or more matches in public and internal Go files.

- [ ] **Step 3: Replace legacy module imports with the canonical module path**

Apply the same import rewrite pattern everywhere the old path appears:

```go
import (
	"context"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
)
```

and:

```go
import (
	"context"
	"errors"
	"log/slog"

	"github.com/BroLabel/brosettlement-mpc-core/internal/preparams"
	tssrequests "github.com/BroLabel/brosettlement-mpc-core/internal/tss/requests"
	tssservice "github.com/BroLabel/brosettlement-mpc-core/internal/tss/service"
	tssbnbrunner "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/runner"
	bnbutils "github.com/BroLabel/brosettlement-mpc-core/internal/tssbnb/support"
	"github.com/bnb-chain/tss-lib/common"
	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)
```

Do not change package structure in this task; only normalize imports to the canonical module path.

- [ ] **Step 4: Format touched Go files**

Run:

```bash
gofmt -w transport/transport.go tss/service.go tss/sharestore.go tss/transport.go tss/utils/share_helpers.go internal/preparams/pool.go internal/shares/file/config.go internal/shares/file/store.go internal/shares/file/store_test.go internal/tss/runtime/share_runtime.go internal/tss/service/orchestration.go internal/tss/service/state.go internal/tssbnb/execution/deduper.go internal/tssbnb/execution/execution.go internal/tssbnb/execution/execution_test.go internal/tssbnb/flow/dkg.go internal/tssbnb/flow/sign.go internal/tssbnb/runner/bnb_runner.go internal/tssbnb/runner/types.go internal/tssbnb/utils/recv_loop.go
```

Expected: command exits 0 with no output.

- [ ] **Step 5: Re-run the legacy-import search**

Run:

```bash
rg -n 'brosettlement-mpc-signer/brosettlement-mpc-core' .
```

Expected: exit code 1 and no matches.

- [ ] **Step 6: Re-run the module-wide build gate**

Run:

```bash
GOCACHE=/tmp/go-build go test ./...
```

Expected: either PASS or fail only on public-contract issues unrelated to legacy import paths.

- [ ] **Step 7: Commit the import-path cleanup**

```bash
git add transport/transport.go tss/service.go tss/sharestore.go tss/transport.go tss/utils/share_helpers.go internal/preparams/pool.go internal/shares/file/config.go internal/shares/file/store.go internal/shares/file/store_test.go internal/tss/runtime/share_runtime.go internal/tss/service/orchestration.go internal/tss/service/state.go internal/tssbnb/execution/deduper.go internal/tssbnb/execution/execution.go internal/tssbnb/execution/execution_test.go internal/tssbnb/flow/dkg.go internal/tssbnb/flow/sign.go internal/tssbnb/runner/bnb_runner.go internal/tssbnb/runner/types.go internal/tssbnb/utils/recv_loop.go
git commit -m "fix: restore canonical module imports"
```

### Task 2: Align README With the Actual Public API

**Files:**
- Modify: `README.md`
- Test: `README.md`

- [ ] **Step 1: Write the failing documentation check**

Run:

```bash
sed -n '1,220p' README.md
```

Expected: README still mentions `shares`, `shares/file`, and the outdated `pkg/idgen` compatibility note even though the intended public surface is only `protocol`, `transport`, and `tss`.

- [ ] **Step 2: Rewrite the package list and compatibility note**

Replace the package section with a public-surface-only version like:

```md
## Packages

- `protocol`: wire-level frame types exchanged between peers.
- `transport`: minimal transport interface used by the public API.
- `tss`: public service facade, share helpers, and pre-params configuration.
```

Replace the compatibility note with:

```md
## Public API Boundary

Only `protocol`, `transport`, and `tss` are supported public packages.

Directories under `internal/` are implementation details and are not part of the compatibility contract.
```

- [ ] **Step 3: Update the basic usage example to a real public entrypoint**

Use a `tss`-based example instead of a removed package surface:

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

- [ ] **Step 4: Re-read the README for drift**

Run:

```bash
sed -n '1,220p' README.md
```

Expected: only `protocol`, `transport`, and `tss` are presented as public API, and no text references `brosettlement-mpc-signer/pkg/idgen`.

- [ ] **Step 5: Commit the README correction**

```bash
git add README.md
git commit -m "docs: align readme with public api"
```

### Task 3: Add Public Facade Tests For `tss`

**Files:**
- Create: `tss/preparams_config_test.go`
- Create: `tss/sharestore_test.go`
- Create: `tss/service_test.go`
- Create: `tss/transport_test.go`
- Modify: `protocol/frame_test.go`
- Test: `go test ./tss ./protocol ./transport`

- [ ] **Step 1: Write the failing test for pre-params defaults and normalization**

Create `tss/preparams_config_test.go`:

```go
package tss

import (
	"testing"
	"time"
)

func TestDefaultPreParamsConfigProvidesSafeDefaults(t *testing.T) {
	cfg := DefaultPreParamsConfig()

	if !cfg.Enabled {
		t.Fatal("expected preparams to be enabled by default")
	}
	if cfg.TargetSize != 5 {
		t.Fatalf("expected target size 5, got %d", cfg.TargetSize)
	}
	if cfg.GenerateTimeout != 7*time.Minute {
		t.Fatalf("unexpected generate timeout: %s", cfg.GenerateTimeout)
	}
}

func TestLoadPreParamsConfigFromEnvNormalizesInvalidValues(t *testing.T) {
	t.Setenv("TSS_PREPARAMS_TARGET_SIZE", "0")
	t.Setenv("TSS_PREPARAMS_MAX_CONCURRENCY", "0")
	t.Setenv("TSS_PREPARAMS_FILE_CACHE_DIR", "")

	cfg := LoadPreParamsConfigFromEnv()

	if cfg.TargetSize != 1 {
		t.Fatalf("expected normalized target size 1, got %d", cfg.TargetSize)
	}
	if cfg.MaxConcurrency != 1 {
		t.Fatalf("expected normalized concurrency 1, got %d", cfg.MaxConcurrency)
	}
	if cfg.FileCacheDir == "" {
		t.Fatal("expected fallback cache dir")
	}
}
```

- [ ] **Step 2: Run the new config tests to verify they fail for the right reason**

Run:

```bash
GOCACHE=/tmp/go-build go test ./tss -run 'TestDefaultPreParamsConfigProvidesSafeDefaults|TestLoadPreParamsConfigFromEnvNormalizesInvalidValues' -count=1
```

Expected: FAIL only if imports or facade behavior are still broken; fix the code, not the assertions.

- [ ] **Step 3: Write the failing test for share codec facade helpers**

Create `tss/sharestore_test.go`:

```go
package tss

import (
	"testing"

	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

func TestMarshalAndUnmarshalShareRoundTrip(t *testing.T) {
	original := ecdsakeygen.NewLocalPartySaveData(3)

	blob, err := MarshalShare(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	decoded, err := UnmarshalShare(blob)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(decoded.Ks) != len(original.Ks) {
		t.Fatalf("expected %d ks entries, got %d", len(original.Ks), len(decoded.Ks))
	}
}

func TestShareStatusConstantsStayStable(t *testing.T) {
	if ShareStatusActive == "" {
		t.Fatal("expected active share status to be exported")
	}
	if ShareStatusDisabled == "" {
		t.Fatal("expected disabled share status to be exported")
	}
}
```

- [ ] **Step 4: Run the sharestore facade tests to verify they fail first**

Run:

```bash
GOCACHE=/tmp/go-build go test ./tss -run 'TestMarshalAndUnmarshalShareRoundTrip|TestShareStatusConstantsStayStable' -count=1
```

Expected: FAIL if the public facade still has broken imports or broken aliases.

- [ ] **Step 5: Write the failing validation and constructor tests for `tss.Service`**

Create `tss/service_test.go`:

```go
package tss

import (
	"errors"
	"log/slog"
	"testing"
)

type noopTransport struct{}

func (noopTransport) SendFrame(_ context.Context, _ protocol.Frame) error { return nil }
func (noopTransport) RecvFrame(_ context.Context) (protocol.Frame, error) {
	return protocol.Frame{}, errors.New("not implemented")
}

func TestDKGSessionRequestValidateRequiresTransport(t *testing.T) {
	req := DKGSessionRequest{
		Session: SessionDescriptor{
			SessionID: "session-1",
			OrgID:     "org-1",
			Parties:   []string{"p1", "p2", "p3"},
			Threshold: 2,
		},
		LocalPartyID: "p1",
	}

	err := req.Validate()
	if !errors.Is(err, ErrTransportRequired) {
		t.Fatalf("expected ErrTransportRequired, got %v", err)
	}
}

func TestSignSessionRequestValidateRequiresDigest(t *testing.T) {
	req := SignSessionRequest{
		Session: SessionDescriptor{
			SessionID: "session-1",
			OrgID:     "org-1",
			KeyID:     "key-1",
			Parties:   []string{"p1", "p2", "p3"},
			Threshold: 2,
		},
		LocalPartyID: "p1",
		Transport:    noopTransport{},
	}

	err := req.Validate()
	if !errors.Is(err, ErrDigestMissing) {
		t.Fatalf("expected ErrDigestMissing, got %v", err)
	}
}

func TestNewBnbServiceReturnsFacade(t *testing.T) {
	svc := NewBnbService(slog.Default())
	if svc == nil || svc.impl == nil {
		t.Fatal("expected non-nil facade and internal implementation")
	}
}
```

- [ ] **Step 6: Run the service facade tests to verify they fail first**

Run:

```bash
GOCACHE=/tmp/go-build go test ./tss -run 'TestDKGSessionRequestValidateRequiresTransport|TestSignSessionRequestValidateRequiresDigest|TestNewBnbServiceReturnsFacade' -count=1
```

Expected: FAIL until the public package compiles and the facade behavior is wired correctly.

- [ ] **Step 7: Add a narrow transport alias test**

Create `tss/transport_test.go`:

```go
package tss

import (
	"context"
	"testing"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
)

type aliasTransport struct{}

func (aliasTransport) SendFrame(_ context.Context, _ protocol.Frame) error { return nil }
func (aliasTransport) RecvFrame(_ context.Context) (protocol.Frame, error) { return protocol.Frame{}, nil }

func TestTransportAliasAcceptsFrameTransportImplementations(t *testing.T) {
	var _ Transport = aliasTransport{}
}
```

- [ ] **Step 8: Run the public facade package tests**

Run:

```bash
GOCACHE=/tmp/go-build go test ./tss ./protocol ./transport -count=1
```

Expected: PASS.

- [ ] **Step 9: Commit the public facade tests**

```bash
git add tss/preparams_config_test.go tss/sharestore_test.go tss/service_test.go tss/transport_test.go protocol/frame_test.go
git commit -m "test: cover public tss facade"
```

### Task 4: Final Verification And Release Readiness

**Files:**
- Modify: `README.md` if verification reveals drift
- Modify: `go.mod` only if verification changes it
- Test: `go test ./...`

- [ ] **Step 1: Run the full readiness search checks**

Run:

```bash
rg -n 'brosettlement-mpc-signer/brosettlement-mpc-core|brosettlement-mpc-signer/pkg/idgen' .
```

Expected: exit code 1 and no matches.

- [ ] **Step 2: Run the full repository test gate**

Run:

```bash
GOCACHE=/tmp/go-build go test ./... -count=1
```

Expected: PASS for all packages.

- [ ] **Step 3: Re-read the public API docs**

Run:

```bash
sed -n '1,220p' README.md
```

Expected: README documents only `protocol`, `transport`, and `tss`, with a working example and explicit `internal/*` boundary.

- [ ] **Step 4: Inspect the worktree before the final commit**

Run:

```bash
git status --short
```

Expected: only the intended readiness changes are present.

- [ ] **Step 5: Commit the final release-readiness pass**

```bash
git add README.md go.mod go.sum protocol transport tss internal
git commit -m "chore: finalize module independence"
```

- [ ] **Step 6: Create the first release tag after review**

Run:

```bash
git tag v0.1.0
```

Expected: tag is created locally only after all tests pass and the public API review is complete.
