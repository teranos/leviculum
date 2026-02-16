# leviculum — Issues Tracker

All known issues that cannot be fixed immediately go here.
When an issue is fixed, remove it from this file entirely.

## Phases

Phase numbering follows `doc/BATTLEPLAN.md`. Phases 0–5 are complete.

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Cleanup | done |
| 1 | Test infrastructure | done |
| 2 | Test coverage (TDD) | done |
| 3 | Bug fixes | done |
| 4 | The big rename (Connection → Link) | done |
| 5 | Structural refactoring (LinkManager dissolution) | done |
| 6 | Consolidation (SSOT, receipt tracking) | **next** |
| 7 | API polish (naming, visibility, perf) | open |

## Status Overview

| ID | P | Phase | Status | Category | Summary |
|----|---|-------|--------|----------|---------|
| E2 | M | 7 | open | API | `pub(crate)` field audit |
| E3 | M | 7 | open | Robustness | Silent send failures (`let _ =` on transport calls) |
| E4 | L | 7 | open | SSOT | Identity table asymmetry |
| D2 | M | 7 | open | Naming | `PacketEndpoint` isn't an endpoint |
| D3 | M | 7 | open | Naming | `send()` vs `send_bytes()` hides real distinction |
| D5 | M | 7 | open | Naming | `DataReceived` vs `MessageReceived` subtle distinction |
| D6 | M | 7 | open | Naming | `DeliveryConfirmed` vs `LinkDeliveryConfirmed` |
| D7 | M | 7 | open | Naming | `ProofRequested` vs `LinkProofRequested` |
| D12 | L | 7 | open | Naming | No distinction between handshake and active-link timeout |
| D13 | L | 7 | open | Naming | Channel exhaustion indistinguishable from other closes |
| F2 | L | 7 | open | Coupling | `connect()` silently broadcasts when no path exists |
| G1 | L | 7 | open | Perf | Lock-and-read pattern in event loop |
| E7 | M | 7 | open | Structural | Split transport.rs (8k+ LoC) |
| E8 | H | post-H1 | open | Feature gap | Single-packet encryption missing |
| H1 | M | 6 | open | SSOT | Destination in 2 maps |

---

## Issues

### E2: `pub(crate)` field audit
- **Status:** open
- **Priority:** MEDIUM
- **Phase:** 7
- **Category:** API
- **Blocked-by:** —
- **Detail:** The strangler fig migration left `pub(crate)` fields on structs that should expose methods instead. `DataReceipt` was eliminated (absorbed into `ReceiptTracker`), but other structs may still have this pattern. Audit all `pub(crate)` fields in non-test code across `link/`, `node/`, `transport/`. Each one is either (a) correct because the module boundary requires it, or (b) a method that was never written. Fix the (b) cases.
- **Test:** N/A (visibility change — compilation verifies).

### E3: Silent send failures (`let _ =` on transport calls)
- **Status:** open
- **Priority:** MEDIUM
- **Phase:** 7
- **Category:** Robustness
- **Blocked-by:** —
- **Detail:** `route_link_packet()` uses `let _ = self.transport.send_on_interface(...)`. Count all `let _ =` on send/transport calls in non-test code. Each one silently swallows a send failure. At minimum add `tracing::debug!` on failure. Evaluate whether any callers should propagate the error.
- **Test:** N/A (observability improvement — existing tests cover behavior).

### E4: Identity table asymmetry
- **Status:** open
- **Priority:** LOW
- **Phase:** 7
- **Category:** SSOT
- **Blocked-by:** —
- **Detail:** Local destinations have their Identity in both `Transport.identity_table` and `NodeCore.destinations[hash].identity`. Remote peers only in `Transport.identity_table`. Asymmetric ownership. Identities are immutable so this isn't a consistency bug, but it's wasted memory and a confusing data model. Evaluate whether Transport should be the sole owner of the identity table, with NodeCore querying it.
- **Test:** N/A (data model simplification).

### D2: `PacketEndpoint` isn't an endpoint
- **Status:** open
- **Priority:** MEDIUM
- **Phase:** 7
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** Send handle scoped to a destination hash. Not a listener, not an addressable entity.
- **Fix:** Rename to `PacketSender` or `SinglePacketSender`.
- **Test:** N/A (rename).

### D3: `send()` vs `send_bytes()` hides real distinction
- **Status:** open
- **Priority:** MEDIUM
- **Phase:** 7
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** `send()` = non-blocking, returns `WouldBlock` on backpressure. `send_bytes()` = async retry loop. Impossible to tell from names.
- **Fix:** `send()` → `try_send()`, `send_bytes()` → `send()`.
- **Test:** N/A (rename — existing tests cover behavior).

### D5: `DataReceived` vs `MessageReceived` subtle distinction
- **Status:** open
- **Priority:** MEDIUM
- **Phase:** 7
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** `DataReceived` = raw link data without channel framing. `MessageReceived` = channel message with type/sequence. A new developer won't know the difference.
- **Fix:** Rename to `LinkDataReceived` / `ChannelMessageReceived`, or document prominently.
- **Test:** N/A (rename).

### D6: `DeliveryConfirmed` vs `LinkDeliveryConfirmed`
- **Status:** open
- **Priority:** MEDIUM
- **Phase:** 7
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** Both confirm delivery, for different transport methods. Only the `Link` prefix distinguishes. Easy to confuse.
- **Fix:** Rename to `PacketDeliveryConfirmed` / `LinkDeliveryConfirmed`. Or `SinglePacketDelivered` / `LinkMessageDelivered`.
- **Test:** N/A (rename).

### D7: `ProofRequested` vs `LinkProofRequested`
- **Status:** open
- **Priority:** MEDIUM
- **Phase:** 7
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** Same pattern as D6. Both request proofs, different paths.
- **Fix:** Rename to `PacketProofRequested` / `LinkProofRequested`.
- **Test:** N/A (rename).

### D12: No distinction between handshake timeout and active-link timeout
- **Status:** open
- **Priority:** LOW
- **Phase:** 7
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** Both "link request never answered" and "established link went silent" produce the same `LinkClosed { reason: Timeout }` event. The application cannot distinguish a failed link attempt from a dropped link.
- **Fix:** Add separate event variants or reason sub-types (e.g., `Timeout::Handshake` vs `Timeout::Keepalive`).
- **Test:** Currently untested. Verify the two timeout paths produce distinct events.

### D13: Channel exhaustion indistinguishable from other closes
- **Status:** open
- **Priority:** LOW
- **Phase:** 7
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** When a channel hits max retries, it tears down the link. The resulting `LinkClosed` event carries a generic close reason. The application cannot tell "channel gave up retransmitting" from "peer closed cleanly" or "keepalive timeout".
- **Fix:** Add a `ChannelExhausted` close reason, or emit a separate `ChannelFailed` event before the close.
- **Test:** Currently untested. Verify exhaustion produces a distinct close reason.

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
- **Phase:** post-H1
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
- **Blocked-by:** H1 (eliminating DestinationEntry clarifies boundaries)
- **Detail:** transport.rs is the largest file in the codebase at 8k+ lines. After H1 eliminates DestinationEntry, evaluate natural split boundaries (routing, announce handling, proof handling, path management). Not urgent — Transport's internals are stable and well-tested. But new features (Resource Transfers, Transport Nodes) will make it worse if not addressed.
- **Fix:** Split into submodules under `transport/` (e.g., `transport/routing.rs`, `transport/announce.rs`, `transport/proof.rs`, `transport/path.rs`). The `Transport` struct stays as the coordinator; handler methods move to focused files.
- **Test:** Existing tests must continue to pass. No behavioral change.

### H1: Destination in 2 maps
- **Status:** open
- **Priority:** MEDIUM
- **Phase:** 6
- **Category:** SSOT
- **Blocked-by:** —
- **Ref:** doc/ISSUES.md H1, doc/ARCHITECTURE_REVIEW2.md (ownership graph)
- **Detail:** `Transport.destinations` (DestinationEntry: routing, proof strategy, identity=None) and `NodeCore.destinations` (Destination: full object). Two representations, two locations, one concept. (Previously 3 maps — `LinkManager.accepted_destinations` was eliminated in Phase 5c.)
- **Fix:** Single canonical `Destination` registry on NodeCore. Transport queries it.
- **Test:** Currently untested. Verify both maps stay in sync after register/unregister.


