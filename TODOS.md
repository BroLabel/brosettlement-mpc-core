# TODOS

## MPC Core

### Replace the fixed SIGN completion grace with deterministic finalization

**What:** Investigate and implement a protocol-aware SIGN completion boundary that does not depend on the fixed `100ms` `signProtocolDoneGrace` delay.

**Why:** A fixed sleep does not prove that all required outbound signing messages have completed and adds unconditional latency to every successful signature.

**Context:** BROSET-127 changes only ECDSA DKG because staging proved a Round 3 race and pinned `tss-lib` provides a testable message-before-result ordering. SIGN currently waits `100ms` after `signECDSAEndCh` before emitting `eventProtocolDone`, and no SIGN-specific lost-frame incident is known. Start by proving the signing message/result ordering in the pinned library and a real multi-party test; do not reuse the DKG pump design unless that proof establishes the same ownership boundary.

**Effort:** M
**Priority:** P3
**Depends on:** Evidence of the pinned SIGN message/result ordering and a focused regression that fails under the current grace-based behavior.

## Completed

_None._
