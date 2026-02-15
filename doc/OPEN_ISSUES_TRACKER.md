# leviculum — Issues Tracker

All known issues that cannot be fixed immediately go here.
When an issue is fixed, remove it from this file entirely.

## Phases

Work proceeds in TDD order: tests first, then fixes, then refactoring.

| Phase | Description | Rationale |
|-------|-------------|-----------|
| 1 | Write missing tests | Safety net before any code changes (TDD) |
| 2 | Quick wins | Small, low-risk fixes that don't require structural changes |
| 3 | Structural refactoring | Major changes (A1, A2) that affect many files |
| 4 | Post-refactoring cleanup | Issues that dissolve or simplify after Phase 3 |

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
| A2 | H | XL | 3 | in_progress | Structural | Four parallel LinkId maps — 3 of 4 eliminated (pending_outgoing, pending_incoming, channels) |
| A3 | M | M | 3 | open | Structural | `channel_hash_to_seq` cross-layer dependency |
| A4 | M | M | 3 | open | Structural | `data_receipts` + `channel_receipt_keys` tight coupling |
| A5 | L | S | 4 | open | Structural | Event cascade: 13/20 pass-through translations |
| A6 | L | S | 4 | open | Structural | Drain buffers exist only because of struct separation |
| C2 | L | S | 2 | open | Dead Code | ~20 pub re-exports never imported |
| C3 | L | S | 2 | open | Dead Code | Buffer types exported but unreachable |
| C4 | L | S | 4 | open | Dead Code | 5 pure delegation methods |
| D2 | M | S | 2 | open | Naming | `PacketEndpoint` isn't an endpoint |
| D3 | M | S | 2 | open | Naming | `send()` vs `send_bytes()` hides real distinction |
| D5 | M | S | 2 | open | Naming | `DataReceived` vs `MessageReceived` subtle distinction |
| D6 | M | S | 2 | open | Naming | `DeliveryConfirmed` vs `LinkDeliveryConfirmed` |
| D7 | M | S | 2 | open | Naming | `ProofRequested` vs `LinkProofRequested` |
| D12 | L | S | 2 | open | Naming | No distinction between handshake and active-link timeout |
| D13 | L | S | 2 | open | Naming | Channel exhaustion indistinguishable from other closes |
| E2 | L | S | 2 | open | Visibility | LinkManager drain methods are pub |
| F2 | L | S | 2 | open | Coupling | `connect()` silently broadcasts when no path exists |
| G1 | L | S | 2 | open | Perf | Lock-and-read pattern in event loop |
| G2 | L | S | 4 | open | Perf | Pass-through parameters cross 3-5 boundaries |
| H1 | M | M | 3 | open | SSOT | Destination in 3 maps |
| H4 | M | M | 3 | open | SSOT | `channel_receipt_keys` and `channel_hash_to_seq` — same mapping, two directions |

---

## Issues

### A2: Four parallel LinkId maps
- **Status:** in_progress
- **Priority:** HIGH
- **Effort:** XL
- **Phase:** 3
- **Category:** Structural
- **Blocked-by:** —
- **Ref:** doc/ISSUES.md A2, doc/ARCHITECTURE_REVIEW2.md (ownership graph), doc/ARCHITECTURE_REVIEW3.md (LinkManager dissolution plan)
- **Detail:** Originally 4 parallel maps keyed by `LinkId`: `links`, `channels`, `pending_outgoing`, `pending_incoming`. Root cause of the two-channel bug. Phase 4 eliminated the `connections` map. Phase 5a+5b eliminated 3 more: `pending_outgoing` → `LinkPhase::PendingOutgoing` on Link, `pending_incoming` → `LinkPhase::PendingIncoming` on Link, `channels` → `Option<Channel>` on Link. Remaining: `channel_receipt_keys` and `data_receipts` (deferred to Phase 5c).
- **Fix:** Remaining maps (`channel_receipt_keys`, `data_receipts`) require global hash-based lookup and cannot trivially move onto Link. Evaluate consolidation in Phase 5c.
- **Test:** Existing tests cover all cleanup paths (close, close_local, timeout, peer close, channel exhaustion). 632 core tests pass.

### A3: `channel_hash_to_seq` cross-layer dependency
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** M
- **Phase:** 3
- **Category:** Structural
- **Blocked-by:** —
- **Ref:** doc/ISSUES.md A3
- **Detail:** Lives in `NodeCore`, maps packet hashes to sequence numbers that only make sense in the context of a `Channel` tx_ring in `LinkManager`. When the channel dies, entries orphan. Logically belongs to Channel/Link.
- **Fix:** Move into Channel or Link. Clean up on link close.
- **Test:** Currently untested. Verify entries are created on send and removed on link close.

### A4: `data_receipts` + `channel_receipt_keys` tight coupling
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** M
- **Phase:** 3
- **Category:** Structural
- **Blocked-by:** —
- **Ref:** doc/ISSUES.md A4, doc/ARCHITECTURE_REVIEW2.md (hot path analysis)
- **Detail:** Two maps in LinkManager: `data_receipts` (keyed by packet hash, global) and `channel_receipt_keys` (keyed per link+sequence). Tightly coupled to each other and to both `links` and `channels`. Global hash-based lookup in `handle_data_proof()` prevents per-link storage.
- **Fix:** Keep together. Move with slimmed LinkManager → LinkTable on NodeCore.
- **Test:** Partially tested (receipt tests exist). Full coupling not verified.

### A5: Event cascade: 13/20 pass-through translations
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 4
- **Category:** Structural
- **Blocked-by:** A2
- **Ref:** doc/ISSUES.md A5, doc/ARCHITECTURE_REVIEW2.md (event cascade analysis)
- **Detail:** 6/9 `TransportEvent` and 7/11 `LinkEvent` variants are 1:1 mechanical translations with only trivial `DestinationHash::new()` wrapping. Cost of clean layering.
- **Fix:** Accept as layering cost. Optionally collapse after LinkManager dissolution.
- **Test:** N/A (design issue).

### A6: Drain buffers exist only because of struct separation
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 4
- **Category:** Structural
- **Blocked-by:** A2
- **Detail:** `Vec<LinkEvent>`, `Vec<PendingPacket>`, `Vec<TransportEvent>`, `Vec<Action>` — exist solely because LinkManager cannot access Transport directly. Eliminated by A2 dissolution.
- **Fix:** Remove as consequence of LinkManager dissolution.
- **Test:** N/A (removed with structural refactoring).


### C2: ~20 pub re-exports never imported
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Dead Code
- **Blocked-by:** —
- **Ref:** doc/ISSUES.md C2, doc/ARCHITECTURE_REVIEW3.md (API surface audit)
- **Detail:** Re-exported from `reticulum-core/src/lib.rs` but never imported by `reticulum-std`, `reticulum-cli`, or `reticulum-ffi`: `Link`, `LinkEvent`, `Packet`, `PacketReceipt`, `ReceiptStatus`, `ChannelAction`, `Envelope`, `MessageState`, `KnownRatchets`, `Ratchet`, `RatchetError`, `IfacConfig`, `IfacError`, `generate_random_hash`, `StreamDataMessage`, `SendHandle`, `SendResult`, `SendMethod`.
- **Fix:** Reduce to `pub(crate)` or remove from re-exports. Keep only types that FFI or external consumers need.
- **Test:** N/A (visibility change — compilation verifies).

### C3: Buffer types exported but unreachable
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Dead Code
- **Blocked-by:** —
- **Detail:** `RawChannelReader`, `RawChannelWriter`, `BufferedChannelWriter` — publicly exported from `lib.rs` but no path in the API to obtain or use them.
- **Fix:** Remove from public exports until the Buffer API is implemented.
- **Test:** N/A (visibility change).

### C4: Pure delegation methods
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 4
- **Category:** Dead Code
- **Blocked-by:** A2
- **Detail:** 5 methods that only forward to another method: `Channel::send()` → `send_internal()`, `LinkManager::process_packet()` → match dispatcher, `LinkManager::mark_channel_delivered()` → `Channel::mark_delivered()`, `handle_link_event(LinkRequestReceived)` → 1:1 → `NodeEvent::LinkRequest`, `handle_link_event(ChannelMessageReceived)` → 1:1 → `NodeEvent::MessageReceived`.
- **Fix:** Inline where possible after structural refactoring.
- **Test:** N/A (code simplification).

### D2: `PacketEndpoint` isn't an endpoint
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 2
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** Send handle scoped to a destination hash. Not a listener, not an addressable entity.
- **Fix:** Rename to `PacketSender` or `SinglePacketSender`.
- **Test:** N/A (rename).

### D3: `send()` vs `send_bytes()` hides real distinction
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 2
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** `send()` = non-blocking, returns `WouldBlock` on backpressure. `send_bytes()` = async retry loop. Impossible to tell from names.
- **Fix:** `send()` → `try_send()`, `send_bytes()` → `send()`.
- **Test:** N/A (rename — existing tests cover behavior).

### D5: `DataReceived` vs `MessageReceived` subtle distinction
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 2
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** `DataReceived` = raw link data without channel framing. `MessageReceived` = channel message with type/sequence. A new developer won't know the difference.
- **Fix:** Rename to `LinkDataReceived` / `ChannelMessageReceived`, or document prominently.
- **Test:** N/A (rename).

### D6: `DeliveryConfirmed` vs `LinkDeliveryConfirmed`
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 2
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** Both confirm delivery, for different transport methods. Only the `Link` prefix distinguishes. Easy to confuse.
- **Fix:** Rename to `PacketDeliveryConfirmed` / `LinkDeliveryConfirmed`. Or `SinglePacketDelivered` / `LinkMessageDelivered`.
- **Test:** N/A (rename).

### D7: `ProofRequested` vs `LinkProofRequested`
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 2
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** Same pattern as D6. Both request proofs, different paths.
- **Fix:** Rename to `PacketProofRequested` / `LinkProofRequested`.
- **Test:** N/A (rename).

### D12: No distinction between handshake timeout and active-link timeout
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** Both "link request never answered" and "established link went silent" produce the same `LinkClosed { reason: Timeout }` event. The application cannot distinguish a failed link attempt from a dropped link.
- **Fix:** Add separate event variants or reason sub-types (e.g., `Timeout::Handshake` vs `Timeout::Keepalive`).
- **Test:** Currently untested. Verify the two timeout paths produce distinct events.

### D13: Channel exhaustion indistinguishable from other closes
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** When a channel hits max retries, it tears down the link. The resulting `LinkClosed` event carries a generic close reason. The application cannot tell "channel gave up retransmitting" from "peer closed cleanly" or "keepalive timeout".
- **Fix:** Add a `ChannelExhausted` close reason, or emit a separate `ChannelFailed` event before the close.
- **Test:** Currently untested. Verify exhaustion produces a distinct close reason.

### E2: LinkManager drain methods are pub
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Visibility
- **Blocked-by:** —
- **Detail:** `take_pending_rtt_packet()`, `drain_close_packets()`, `drain_keepalive_packets()`, `drain_proof_packets()` — only used in `#[cfg(test)]`.
- **Fix:** `pub(crate)` or `#[cfg(test)]`.
- **Note:** Deferred — interop tests in reticulum-std call these methods cross-crate, preventing pub(crate) visibility.
- **Test:** N/A (visibility change).

### F2: `connect()` silently broadcasts when no path exists
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Coupling
- **Blocked-by:** —
- **Detail:** Falls back to broadcast instead of returning an error. Caller doesn't know whether the link request was routed or broadcast.
- **Fix:** Return an enum indicating `Routed` vs `Broadcast`, or return an error.
- **Test:** N/A (behavior change — add test with fix).


### G1: Lock-and-read pattern in event loop
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Perf
- **Blocked-by:** —
- **Detail:** After `handle_timeout()` releases the Mutex, it's immediately re-acquired solely to read `next_deadline()` and `now_ms()`. Two lock acquisitions where one suffices.
- **Fix:** Return next_deadline from `handle_timeout()` as part of `TickOutput`.
- **Test:** N/A (optimization — existing tests cover behavior).

### G2: Pass-through parameters cross 3-5 boundaries
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 4
- **Category:** Perf
- **Blocked-by:** A2
- **Detail:** `data: &[u8]`, `link_id`, `now_ms`, `rng: &mut R` pass through multiple struct boundaries unchanged. `interface_index: usize` crosses 5+ boundaries. Reduced naturally by A2.
- **Fix:** Reduced naturally by structural refactoring (fewer layers).
- **Test:** N/A (design issue).

### H1: Destination in 3 maps
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** M
- **Phase:** 3
- **Category:** SSOT
- **Blocked-by:** —
- **Ref:** doc/ISSUES.md H1, doc/ARCHITECTURE_REVIEW2.md (ownership graph)
- **Detail:** `Transport.destinations` (DestinationEntry: routing, proof strategy, identity=None), `NodeCore.destinations` (Destination: full object), `LinkManager.accepted_destinations` (BTreeSet: accept filter). Three representations, three locations, one concept.
- **Fix:** Single canonical `Destination` registry on NodeCore. Transport and LinkManager query it.
- **Test:** Currently untested. Verify all three maps stay in sync after register/unregister.

### H4: `channel_receipt_keys` and `channel_hash_to_seq` — same mapping, two directions
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** M
- **Phase:** 3
- **Category:** SSOT
- **Blocked-by:** —
- **Ref:** doc/ISSUES.md H4
- **Detail:** `channel_receipt_keys` in LinkManager maps `(LinkId, seq) → hash`. `channel_hash_to_seq` in NodeCore maps `hash → seq`. Same logical association, indexed from opposite directions, living in different structs. No guarantee they stay in sync.
- **Fix:** Consolidate into one structure with bidirectional lookup. Move to Channel or Link.
- **Test:** Verify both maps agree after send, retransmit, and close. (Currently: NO unit test, NO interop test.)

