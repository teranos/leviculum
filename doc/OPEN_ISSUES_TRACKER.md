# leviculum — Issues Tracker

All known issues that cannot be fixed immediately go here.
When an issue is fixed, remove it from this file entirely.

## Phases

Phase numbering follows `doc/BATTLEPLAN.md`. Phases 0–6 are complete.

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Cleanup | done |
| 1 | Test infrastructure | done |
| 2 | Test coverage (TDD) | done |
| 3 | Bug fixes | done |
| 4 | The big rename (Connection → Link) | done |
| 5 | Structural refactoring (LinkManager dissolution) | done |
| 6 | Consolidation (SSOT, receipt tracking) | done |
| 7 | API polish (naming, visibility, perf) | **in progress** |

## Status Overview

| ID | P | Phase | Status | Category | Summary |
|----|---|-------|--------|----------|---------|
| F2 | L | 7 | open | Coupling | `connect()` silently broadcasts when no path exists |
| G1 | L | 7 | open | Perf | Lock-and-read pattern in event loop |
| E7 | M | 7 | open | Structural | Split transport.rs (8k+ LoC) |
| E8 | H | 7 | open | Feature gap | Single-packet encryption missing |

---

## Issues

### F2: `connect()` silently broadcasts when no path exists
- **Status:** open
- **Priority:** LOW
- **Phase:** 7
- **Category:** Coupling
- **Blocked-by:** —
- **Detail:** Falls back to broadcast instead of returning an error. Caller doesn't know whether the link request was routed or broadcast.
- **Fix:** Return an enum indicating `Routed` vs `Broadcast`, or return an error.
- **Test:** N/A (behavior change — add test with fix).

### G1: Lock-and-read pattern in event loop
- **Status:** open
- **Priority:** LOW
- **Phase:** 7
- **Category:** Perf
- **Blocked-by:** —
- **Detail:** After `handle_timeout()` releases the Mutex, it's immediately re-acquired solely to read `next_deadline()` and `now_ms()`. Two lock acquisitions where one suffices.
- **Fix:** Return next_deadline from `handle_timeout()` as part of `TickOutput`.
- **Test:** N/A (optimization — existing tests cover behavior).

### E8: Single-packet encryption missing
- **Status:** open
- **Priority:** HIGH
- **Phase:** 7
- **Category:** Feature gap
- **Blocked-by:** —
- **Detail:** `send_single_packet()` sends plaintext. Python `Destination.SINGLE` always decrypts incoming data via X25519 (`Destination.decrypt()` → `Identity.decrypt()`). Every single packet from Rust to Python is silently dropped because decryption fails and `Destination.receive()` returns `False`. This blocks all single-packet interop including the proof round-trip test (`test_single_packet_proof_round_trip_via_node`, currently `#[ignore]`). Needs: encrypt payload using destination's public key before sending, matching Python's `Packet.encrypt()` / `Identity.encrypt()`.
- **Fix:** In `send_single_packet()`, look up the destination's public key and encrypt the payload with X25519+AES before packing. Mirror Python's `Identity.encrypt()` which uses ephemeral X25519 key exchange + Fernet token.
- **Test:** Un-ignore `test_single_packet_proof_round_trip_via_node` in `proof_tests.rs`. Add dedicated encrypt/decrypt interop test.

### E7: Split transport.rs (8k+ LoC)
- **Status:** open
- **Priority:** MEDIUM
- **Phase:** 7
- **Category:** Structural
- **Blocked-by:** —
- **Detail:** transport.rs is the largest file in the codebase at 8k+ lines. After H1 eliminates DestinationEntry, evaluate natural split boundaries (routing, announce handling, proof handling, path management). Not urgent — Transport's internals are stable and well-tested. But new features (Resource Transfers, Transport Nodes) will make it worse if not addressed.
- **Fix:** Split into submodules under `transport/` (e.g., `transport/routing.rs`, `transport/announce.rs`, `transport/proof.rs`, `transport/path.rs`). The `Transport` struct stays as the coordinator; handler methods move to focused files.
- **Test:** Existing tests must continue to pass. No behavioral change.


