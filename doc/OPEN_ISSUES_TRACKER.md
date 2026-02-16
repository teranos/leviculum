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

## Effort

| Size | Meaning |
|------|---------|
| S | Hours — single file, mechanical change |
| M | Day — multiple files, some thinking needed |
| L | Days — many files, new infrastructure |
| XL | Week — touches entire codebase, cascading changes |

---

## Status Overview

| ID | P | Effort | Phase | Status | Category | Summary |
|----|---|--------|-------|--------|----------|---------|
| A4 | M | M | 6 | open | Structural | `data_receipts` + `channel_receipt_keys` tight coupling |
| E1 | M | S | 6 | open | Structural | `handle_link_data` god method (241 lines) |
| E2 | M | S | 7 | open | API | `pub(crate)` field audit |
| E3 | M | S | 7 | open | Robustness | Silent send failures (`let _ =` on transport calls) |
| E4 | L | S | 7 | open | SSOT | Identity table asymmetry |
| E5 | H | S | 6 | open | Bug | H1 unregister path missing |
| D2 | M | S | 7 | open | Naming | `PacketEndpoint` isn't an endpoint |
| D3 | M | S | 7 | open | Naming | `send()` vs `send_bytes()` hides real distinction |
| D5 | M | S | 7 | open | Naming | `DataReceived` vs `MessageReceived` subtle distinction |
| D6 | M | S | 7 | open | Naming | `DeliveryConfirmed` vs `LinkDeliveryConfirmed` |
| D7 | M | S | 7 | open | Naming | `ProofRequested` vs `LinkProofRequested` |
| D12 | L | S | 7 | open | Naming | No distinction between handshake and active-link timeout |
| D13 | L | S | 7 | open | Naming | Channel exhaustion indistinguishable from other closes |
| F2 | L | S | 7 | open | Coupling | `connect()` silently broadcasts when no path exists |
| G1 | L | S | 7 | open | Perf | Lock-and-read pattern in event loop |
| H1 | M | M | 6 | open | SSOT | Destination in 2 maps |
| H4 | M | M | 6 | open | SSOT | `channel_receipt_keys` and `channel_hash_to_seq` — same mapping, two directions |

---

## Issues

### A4: `data_receipts` + `channel_receipt_keys` tight coupling
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** M
- **Phase:** 6
- **Category:** Structural
- **Blocked-by:** —
- **Ref:** doc/ISSUES.md A4, doc/ARCHITECTURE_REVIEW2.md (hot path analysis)
- **Detail:** Two maps on NodeCore: `data_receipts` (keyed by truncated packet hash, global) and `channel_receipt_keys` (keyed per link+sequence). Tightly coupled to each other and to `links`. Global hash-based lookup in `handle_data_proof()` prevents per-link storage.
- **Fix:** Consider moving per-link receipt data onto Link struct. Global hash lookup may still require a NodeCore-level index.
- **Test:** Receipt lifecycle tested (`test_channel_receipt_lifecycle`, `test_data_receipts_expire_after_timeout`, etc.). Full coupling not verified.

### E1: `handle_link_data` god method (241 lines)
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 6
- **Category:** Structural
- **Blocked-by:** —
- **Blocks:** H4, A4 (split makes both migrations readable)
- **Detail:** `node/link_management.rs:498-738` dispatches 6+ link-layer message types (RTT, keepalive, close, channel data, channel proof, proof request) in a single match. Every new link-layer feature grows this method. At 241 lines it's the largest production method in the codebase.
- **Fix:** Extract `handle_rtt_packet()`, `handle_keepalive_packet()`, `handle_close_packet()`, `handle_channel_packet()`, `handle_data_packet()`. Pure mechanical extraction, no behavior change.
- **Test:** Existing tests cover all arms. No new tests needed (refactor, not behavior change).

### E2: `pub(crate)` field audit
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 7
- **Category:** API
- **Blocked-by:** —
- **Detail:** The strangler fig migration left `pub(crate)` fields on structs that should expose methods instead (confirmed: `DataReceipt.full_hash`, `DataReceipt.link_id`, `DataReceipt.sent_at_ms`). Audit all `pub(crate)` fields in non-test code across `link/`, `node/`, `transport/`. Each one is either (a) correct because the module boundary requires it, or (b) a method that was never written. Fix the (b) cases.
- **Test:** N/A (visibility change — compilation verifies).

### E3: Silent send failures (`let _ =` on transport calls)
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 7
- **Category:** Robustness
- **Blocked-by:** —
- **Detail:** `route_link_packet()` uses `let _ = self.transport.send_on_interface(...)`. Count all `let _ =` on send/transport calls in non-test code. Each one silently swallows a send failure. At minimum add `tracing::debug!` on failure. Evaluate whether any callers should propagate the error.
- **Test:** N/A (observability improvement — existing tests cover behavior).

### E4: Identity table asymmetry
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 7
- **Category:** SSOT
- **Blocked-by:** —
- **Detail:** Local destinations have their Identity in both `Transport.identity_table` and `NodeCore.destinations[hash].identity`. Remote peers only in `Transport.identity_table`. Asymmetric ownership. Identities are immutable so this isn't a consistency bug, but it's wasted memory and a confusing data model. Evaluate whether Transport should be the sole owner of the identity table, with NodeCore querying it.
- **Test:** N/A (data model simplification).

### E5: H1 unregister path missing
- **Status:** open
- **Priority:** HIGH
- **Effort:** S
- **Phase:** 6
- **Category:** Bug
- **Blocked-by:** —
- **Detail:** `unregister_destination()` removes from `NodeCore.destinations` and calls `transport.unregister_destination()`, but verify that Transport actually cleans up its `DestinationEntry`. If Transport keeps a ghost entry after unregister, that's a bug — stale `accepts_links` and `proof_strategy` values for a destination that no longer exists. This is part of H1 but the bug aspect should be verified and fixed independently.
- **Test:** Write test: register destination, unregister, verify Transport's `DestinationEntry` is gone.

### D2: `PacketEndpoint` isn't an endpoint
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 7
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** Send handle scoped to a destination hash. Not a listener, not an addressable entity.
- **Fix:** Rename to `PacketSender` or `SinglePacketSender`.
- **Test:** N/A (rename).

### D3: `send()` vs `send_bytes()` hides real distinction
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 7
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** `send()` = non-blocking, returns `WouldBlock` on backpressure. `send_bytes()` = async retry loop. Impossible to tell from names.
- **Fix:** `send()` → `try_send()`, `send_bytes()` → `send()`.
- **Test:** N/A (rename — existing tests cover behavior).

### D5: `DataReceived` vs `MessageReceived` subtle distinction
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 7
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** `DataReceived` = raw link data without channel framing. `MessageReceived` = channel message with type/sequence. A new developer won't know the difference.
- **Fix:** Rename to `LinkDataReceived` / `ChannelMessageReceived`, or document prominently.
- **Test:** N/A (rename).

### D6: `DeliveryConfirmed` vs `LinkDeliveryConfirmed`
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 7
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** Both confirm delivery, for different transport methods. Only the `Link` prefix distinguishes. Easy to confuse.
- **Fix:** Rename to `PacketDeliveryConfirmed` / `LinkDeliveryConfirmed`. Or `SinglePacketDelivered` / `LinkMessageDelivered`.
- **Test:** N/A (rename).

### D7: `ProofRequested` vs `LinkProofRequested`
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 7
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** Same pattern as D6. Both request proofs, different paths.
- **Fix:** Rename to `PacketProofRequested` / `LinkProofRequested`.
- **Test:** N/A (rename).

### D12: No distinction between handshake timeout and active-link timeout
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 7
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** Both "link request never answered" and "established link went silent" produce the same `LinkClosed { reason: Timeout }` event. The application cannot distinguish a failed link attempt from a dropped link.
- **Fix:** Add separate event variants or reason sub-types (e.g., `Timeout::Handshake` vs `Timeout::Keepalive`).
- **Test:** Currently untested. Verify the two timeout paths produce distinct events.

### D13: Channel exhaustion indistinguishable from other closes
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 7
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** When a channel hits max retries, it tears down the link. The resulting `LinkClosed` event carries a generic close reason. The application cannot tell "channel gave up retransmitting" from "peer closed cleanly" or "keepalive timeout".
- **Fix:** Add a `ChannelExhausted` close reason, or emit a separate `ChannelFailed` event before the close.
- **Test:** Currently untested. Verify exhaustion produces a distinct close reason.

### F2: `connect()` silently broadcasts when no path exists
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 7
- **Category:** Coupling
- **Blocked-by:** —
- **Detail:** Falls back to broadcast instead of returning an error. Caller doesn't know whether the link request was routed or broadcast.
- **Fix:** Return an enum indicating `Routed` vs `Broadcast`, or return an error.
- **Test:** N/A (behavior change — add test with fix).

### G1: Lock-and-read pattern in event loop
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 7
- **Category:** Perf
- **Blocked-by:** —
- **Detail:** After `handle_timeout()` releases the Mutex, it's immediately re-acquired solely to read `next_deadline()` and `now_ms()`. Two lock acquisitions where one suffices.
- **Fix:** Return next_deadline from `handle_timeout()` as part of `TickOutput`.
- **Test:** N/A (optimization — existing tests cover behavior).

### H1: Destination in 2 maps
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** M
- **Phase:** 6
- **Category:** SSOT
- **Blocked-by:** —
- **Ref:** doc/ISSUES.md H1, doc/ARCHITECTURE_REVIEW2.md (ownership graph)
- **Detail:** `Transport.destinations` (DestinationEntry: routing, proof strategy, identity=None) and `NodeCore.destinations` (Destination: full object). Two representations, two locations, one concept. (Previously 3 maps — `LinkManager.accepted_destinations` was eliminated in Phase 5c.)
- **Fix:** Single canonical `Destination` registry on NodeCore. Transport queries it.
- **Test:** Currently untested. Verify both maps stay in sync after register/unregister.

### H4: `channel_receipt_keys` and `channel_hash_to_seq` — same mapping, two directions
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** M
- **Phase:** 6
- **Category:** SSOT
- **Blocked-by:** —
- **Ref:** doc/ISSUES.md H4
- **Detail:** Both maps on NodeCore: `channel_receipt_keys` maps `(LinkId, seq) → truncated_hash`, `channel_hash_to_seq` maps `full_hash → (LinkId, seq)`. Same logical association, indexed from opposite directions. No guarantee they stay in sync.
- **Fix:** Consolidate into one structure with bidirectional lookup. Move to Channel or Link.
- **Test:** Tested: `test_channel_receipt_lifecycle`, `test_channel_receipt_keys_cleaned_on_close`. Sync between the two maps not explicitly verified.

