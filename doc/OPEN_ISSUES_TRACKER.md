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
| A1 | H | XL | 3 | open | Structural | Link/Connection naming confusion — 4 names for 1 concept |
| A2 | H | XL | 3 | open | Structural | Four parallel LinkId maps — split-brain root cause |
| A3 | M | M | 3 | open | Structural | `channel_hash_to_seq` cross-layer dependency |
| A4 | M | M | 3 | open | Structural | `data_receipts` + `channel_receipt_keys` tight coupling |
| A5 | L | S | 4 | open | Structural | Event cascade: 13/20 pass-through translations |
| A6 | L | S | 4 | open | Structural | Drain buffers exist only because of struct separation |
| B1 | H | S | 2 | open | Bug | Closed links accumulate indefinitely (memory leak) |
| B2 | M | S | 2 | open | Bug | `channel_hash_to_seq` never cleaned on link close |
| B3 | L | S | 4 | open | Bug | Asymmetric cleanup between links and channels |
| C1 | M | S | 2 | open | Dead Code | 8 dead error variants across 5 enums |
| C2 | L | S | 2 | open | Dead Code | ~20 pub re-exports never imported |
| C3 | L | S | 2 | open | Dead Code | Buffer types exported but unreachable |
| C4 | L | S | 4 | open | Dead Code | 5 pure delegation methods |
| D1 | M | S | 4 | open | Naming | `ConnectionStream` doesn't implement Stream |
| D2 | M | S | 2 | open | Naming | `PacketEndpoint` isn't an endpoint |
| D3 | M | S | 2 | open | Naming | `send()` vs `send_bytes()` hides real distinction |
| D4 | M | S | 2 | open | Naming | `PacketReceived { from }` — `from` is not the sender |
| D5 | M | S | 2 | open | Naming | `DataReceived` vs `MessageReceived` subtle distinction |
| D6 | M | S | 2 | open | Naming | `DeliveryConfirmed` vs `LinkDeliveryConfirmed` |
| D7 | M | S | 2 | open | Naming | `ProofRequested` vs `LinkProofRequested` |
| D8 | L | S | 4 | open | Naming | `initiate()` vs `connect()` across layers |
| D9 | L | S | 4 | open | Naming | `accept_link()` vs `accept_connection()` |
| D10 | L | S | 2 | open | Naming | `ReticulumNodeImpl` aliased as `ReticulumNode` |
| D11 | L | S | 4 | open | Naming | `Connection` struct is nearly empty |
| D12 | L | S | 2 | open | Naming | No distinction between handshake and active-link timeout |
| D13 | L | S | 2 | open | Naming | Channel exhaustion indistinguishable from other closes |
| D14 | L | S | 2 | open | Naming | `PathRequestReceived` looks actionable but is informational |
| D15 | L | S | 2 | open | Naming | `ChannelRetransmit` is observability-only |
| E1 | M | S | 2 | open | Visibility | `NodeCore::transport()` exposes entire Transport internals |
| E2 | L | S | 2 | open | Visibility | LinkManager drain methods are pub |
| E3 | L | S | 4 | open | Visibility | `Channel::send()` pure delegation |
| F1 | M | S | 2 | open | Coupling | TickOutput must be dispatched — undocumented |
| F2 | L | S | 2 | open | Coupling | `connect()` silently broadcasts when no path exists |
| F3 | L | S | 2 | open | Coupling | `register_destination()` before `accept_connection()` not enforced |
| F4 | L | S | 2 | open | Coupling | `mark_channel_delivered()` return value ignored |
| G1 | L | S | 2 | open | Perf | Lock-and-read pattern in event loop |
| G2 | L | S | 4 | open | Perf | Pass-through parameters cross 3-5 boundaries |
| H1 | M | M | 3 | open | SSOT | Destination in 3 maps |
| H2 | L | S | 2 | open | SSOT | RTT in 2 places |
| H3 | L | S | 4 | open | SSOT | CloseReason / LinkCloseReason identical duplicate |
| H4 | M | M | 3 | open | SSOT | `channel_receipt_keys` and `channel_hash_to_seq` — same mapping, two directions |
| H5 | L | S | 2 | open | SSOT | WindowFull / PacingDelay in 3 error enums |
| T1 | M | S | 1 | open | Test | MockClock defined 4 times |
| T2 | M | M | 2 | open | Test | 80+ Transport tests with no shared setup |
| T3 | M | M | 2 | open | Test | Magic numbers instead of constants in tests |
| T4 | L | S | 2 | open | Test | 5 Link tests ignore existing helper |
| T5 | M | M | 2 | open | Test | 24 tests access private struct fields |
| T6 | H | L | 1 | open | Test | NodeCore messaging path completely untested |
| T7 | H | L | 1 | open | Test | LinkManager lifecycle management untested |
| T8 | M | S | 1 | open | Test | FAST tier guard untested |
| T9 | L | S | 1 | open | Test | Channel coverage gaps (5 missing) |
| T10 | L | S | 1 | open | Test | Link lifecycle gaps (4 missing) |
| T11 | L | S | 1 | open | Test | Transport minor gaps (4 missing) |
| T12 | L | S | 2 | open | Test | 3 smoke tests with no meaningful assertions |
| T13 | L | M | 4 | open | Test | 4 tests >80 LOC combining multiple concerns |
| T14 | L | S | 2 | open | Test | `test_connection_new` name collision across files |
| T15 | L | S | 2 | open | Test | 1 exact duplicate test |
| T16 | H | L | 1 | open | Test | ISSUES.md bugs have no test coverage (10 of 14) |

---

## Issues

### A1: Link/Connection naming confusion
- **Status:** open
- **Priority:** HIGH
- **Effort:** XL
- **Phase:** 3
- **Category:** Structural
- **Blocked-by:** —
- **Ref:** doc/ISSUES.md A1, doc/ARCHITECTURE_REVIEW.md
- **Detail:** Four names for one concept: `Link` (core internal), `Connection` (core API), `ConnectionStream` (std), `link_id` (field names everywhere). Python uses `Link` consistently. The `Connection` struct is a nearly-empty metadata wrapper (4 fields). All real state lives in `Link`. Events say "Connection" but carry `link_id` fields. `CloseReason` and `LinkCloseReason` are identical duplicated enums with a mechanical `From` impl.
- **Fix:** Eliminate `Connection`, use `Link` everywhere. Move 4 fields into `Link`. `ConnectionStream` → `LinkHandle`. `NodeEvent::ConnectionEstablished` → `NodeEvent::LinkEstablished`. Drop `CloseReason` duplicate. Dissolves D1, D8, D9, D11, H3.
- **Test:** N/A (naming refactor — existing tests verify behavior).

### A2: Four parallel LinkId maps
- **Status:** open
- **Priority:** HIGH
- **Effort:** XL
- **Phase:** 3
- **Category:** Structural
- **Blocked-by:** —
- **Ref:** doc/ISSUES.md A2, doc/ARCHITECTURE_REVIEW2.md (ownership graph), doc/ARCHITECTURE_REVIEW3.md (LinkManager dissolution plan)
- **Detail:** `links`, `channels`, `pending_outgoing/incoming`, `connections` — all keyed by `LinkId`, all with different lifecycles. Root cause of the two-channel bug. Removal is not always paired (see B1, B3).
- **Fix:** Channel → `Option<Channel>` on Link. Pending → phase enum on Link. Connection fields → Link. Reduces 4+ maps to 1. See doc/ARCHITECTURE_REVIEW3.md for the detailed dissolution plan with ownership graph and migration steps.
- **Test:** Create link, establish channel, send message, close via each path, verify all maps are empty. (Currently: NO unit test, partial interop.)

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

### B1: Closed links accumulate indefinitely
- **Status:** open
- **Priority:** HIGH
- **Effort:** S
- **Phase:** 2
- **Category:** Bug
- **Blocked-by:** —
- **Ref:** doc/ISSUES.md B1
- **Detail:** `close()`, `check_stale_links()`, and PeerClosed paths set `LinkState::Closed` but never remove the entry from `self.links`. No periodic garbage collection exists. Unbounded memory leak for long-running nodes.
- **Fix:** Add periodic GC that removes Closed-state links (and their associated `channels`, `data_receipts`, `channel_receipt_keys` entries). A few lines in `poll()`.
- **Test:** Create 100 links, close them all, verify `links.len() == 0` after GC runs. (Currently: NO unit test, NO interop test.) Write test first (T16).

### B2: `channel_hash_to_seq` never cleaned on link close
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 2
- **Category:** Bug
- **Blocked-by:** —
- **Ref:** doc/ISSUES.md B2
- **Detail:** 34 bytes per entry, orphaned permanently. No cleanup path exists. Functionally benign (stale lookups return harmlessly) but unbounded over time.
- **Fix:** In `handle_link_event(LinkClosed)`, iterate and remove all `channel_hash_to_seq` entries for the closed LinkId. Or move into Channel (see A3). A few lines.
- **Test:** Send a message (populates channel_hash_to_seq), close the link, verify map entry removed. (Currently: NO unit test, NO interop test.) Write test first (T16).

### B3: Asymmetric cleanup between links and channels
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 4
- **Category:** Bug
- **Blocked-by:** B1
- **Detail:** `close()` and `check_stale_links()` remove neither from `links` nor `channels`. `check_channel_timeouts()` TearDownLink removes from `channels` but not `links`. `close_local()` removes both (correct). No path removes a Closed link from `links`.
- **Fix:** Addressed by B1 (GC for Closed links).
- **Test:** Close via each path, verify both maps cleaned. (Currently: NO unit test, NO interop test.)

### C1: 8 dead error variants across 5 enums
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 2
- **Category:** Dead Code
- **Blocked-by:** —
- **Ref:** doc/ISSUES.md C1, doc/TEST_REVIEW2.md Part A6 (error variant audit)
- **Detail:** `BuildError::NoIdentity`/`InvalidConfig` (build() never fails), `LinkError::Timeout` (timeouts use events), `SendError::Timeout`/`InvalidDestination` (never constructed), `ConnectionError::InvalidState`/`TooLarge` (dead in production), `DeliveryError::NoPath` (never constructed). `ConnectionError::ChannelError(_)` is live (constructed via `From<ChannelError>` impl).
- **Fix:** Remove dead variants. Make `build()` infallible (return `NodeCore` directly, not `Result`).
- **Test:** N/A (removal — compilation verifies).

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
- **Detail:** 5 methods that only forward to another method: `Channel::send()` → `send_internal()`, `LinkManager::process_packet()` → match dispatcher, `LinkManager::mark_channel_delivered()` → `Channel::mark_delivered()`, `handle_link_event(LinkRequestReceived)` → 1:1 → `NodeEvent::ConnectionRequest`, `handle_link_event(ChannelMessageReceived)` → 1:1 → `NodeEvent::MessageReceived`.
- **Fix:** Inline where possible after structural refactoring.
- **Test:** N/A (code simplification).

### D1: `ConnectionStream` doesn't implement Stream
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 4
- **Category:** Naming
- **Blocked-by:** A1
- **Detail:** Send-only handle. Incoming data arrives via separate `NodeEvent` channel. Name strongly suggests `AsyncRead`/`AsyncWrite`/`futures::Stream`. Implements none.
- **Fix:** Rename to `LinkHandle` or `LinkSender` (after A1 rename).
- **Test:** N/A (rename).

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

### D4: `PacketReceived { from }` — `from` is not the sender
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 2
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** `from` field contains the destination hash (our registered destination), not the sender's identity.
- **Fix:** Rename field to `destination` or `dest_hash`.
- **Test:** N/A (rename).

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

### D8: `initiate()` vs `connect()` across layers
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 4
- **Category:** Naming
- **Blocked-by:** A1
- **Detail:** `LinkManager::initiate()` → `NodeCore::connect()` → `ReticulumNode::connect()`. Different verbs for the same action at different layers.
- **Fix:** Unify naming after A1 rename. All layers use same verb.
- **Test:** N/A (rename).

### D9: `accept_link()` vs `accept_connection()`
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 4
- **Category:** Naming
- **Blocked-by:** A1
- **Detail:** Same divergence as D8. `LinkManager::accept_link()` vs `NodeCore::accept_connection()`.
- **Fix:** Unify after A1 rename.
- **Test:** N/A (rename).

### D10: `ReticulumNodeImpl` aliased as `ReticulumNode`
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** Both names exported. Grep finds both. Confusing which is canonical.
- **Fix:** Remove the alias, use one name.
- **Test:** N/A (rename).

### D11: `Connection` struct is nearly empty
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 4
- **Category:** Naming
- **Blocked-by:** A1
- **Detail:** 4 fields, all real state in `Link`. Dissolved by A1 (fields move into Link, Connection eliminated).
- **Fix:** Dissolved by A1.
- **Test:** N/A (dissolved by A1).

### D12: No distinction between handshake timeout and active-link timeout
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** Both "link request never answered" and "established link went silent" produce the same `ConnectionClosed { reason: Timeout }` event. The application cannot distinguish a failed connection attempt from a dropped connection.
- **Fix:** Add separate event variants or reason sub-types (e.g., `Timeout::Handshake` vs `Timeout::Keepalive`).
- **Test:** Currently untested. Verify the two timeout paths produce distinct events.

### D13: Channel exhaustion indistinguishable from other closes
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** When a channel hits max retries, it tears down the link. The resulting `ConnectionClosed` event carries a generic close reason. The application cannot tell "channel gave up retransmitting" from "peer closed cleanly" or "keepalive timeout".
- **Fix:** Add a `ChannelExhausted` close reason, or emit a separate `ChannelFailed` event before the close.
- **Test:** Currently untested. Verify exhaustion produces a distinct close reason.

### D14: `PathRequestReceived` looks actionable but is informational
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** `NodeEvent::PathRequestReceived` is emitted for observability only — transport handles path requests internally. It sits in the same enum as actionable events like `ConnectionRequest`.
- **Fix:** Document as informational. Consider a separate `ObservabilityEvent` enum.
- **Test:** N/A (documentation / design).

### D15: `ChannelRetransmit` is observability-only
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Naming
- **Blocked-by:** —
- **Detail:** `NodeEvent::ChannelRetransmit` reports that a retransmission occurred. Like D14, purely informational but mixed with actionable events.
- **Fix:** Same approach as D14 — document or separate.
- **Test:** N/A (documentation / design).

### E1: `NodeCore::transport()` exposes entire Transport internals
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 2
- **Category:** Visibility
- **Blocked-by:** —
- **Detail:** Public method, but only used by `reticulum-std` for `clock().now_ms()`.
- **Fix:** Replace with `pub fn now_ms(&self) -> u64` accessor. Make `transport()` `pub(crate)`.
- **Test:** N/A (visibility change — compilation verifies).

### E2: LinkManager drain methods are pub
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Visibility
- **Blocked-by:** —
- **Detail:** `take_pending_rtt_packet()`, `drain_close_packets()`, `drain_keepalive_packets()`, `drain_proof_packets()` — only used in `#[cfg(test)]`.
- **Fix:** `pub(crate)` or `#[cfg(test)]`.
- **Test:** N/A (visibility change).

### E3: `Channel::send()` pure delegation
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 4
- **Category:** Visibility
- **Blocked-by:** A2
- **Detail:** Calls `send_internal()` adding only msgtype validation. Extra indirection.
- **Fix:** Inline or rename to make the distinction clear. Simplifies after A2.
- **Test:** N/A (code simplification).

### F1: TickOutput must be dispatched — undocumented
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 2
- **Category:** Coupling
- **Blocked-by:** —
- **Detail:** `connect()`, `send_on_connection()`, `close_connection()` return `TickOutput` that MUST be dispatched to interfaces. If the caller discards it, the operation silently fails (no packet sent, no error). Only `announce_destination()` documents this requirement.
- **Fix:** Add `#[must_use]` attribute on `TickOutput`. Document on all methods.
- **Test:** Call `connect()`, discard TickOutput, verify link stays pending forever. Or: verify `TickOutput` has `#[must_use]`. (Currently: NO unit test, NO interop test.)

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

### F3: `register_destination()` before `accept_connection()` not enforced
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Coupling
- **Blocked-by:** —
- **Detail:** `accept_connection()` returns `ConnectionError::IdentityNotFound` if destination isn't registered — misleading error name.
- **Fix:** Rename error to `DestinationNotRegistered`. Or enforce at type level.
- **Test:** N/A (error rename — existing test covers the error path).

### F4: `mark_channel_delivered()` return value ignored
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Coupling
- **Blocked-by:** —
- **Detail:** `NodeCore::handle_data_proof()` calls `link_manager.mark_channel_delivered()` which returns `Option<LinkEvent>`, but the return value is silently discarded. If a bogus sequence number ACK arrives, the failure is invisible.
- **Fix:** Propagate the return value and log or handle the `None` case.
- **Test:** Send bogus sequence ACK, verify failure is visible. (Currently: NO unit test, NO interop test.)

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

### H2: RTT in 2 places
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** SSOT
- **Blocked-by:** —
- **Detail:** `Link.rtt_us` (handshake RTT, microseconds) and `Channel.srtt_ms` (smoothed RTT from proofs, milliseconds). Different values, different units, different purposes.
- **Fix:** Architecturally justified (tier promotion vs timeout calculation). Document the distinction. Unify units to milliseconds.
- **Test:** N/A (documentation — existing tests cover both RTT paths).

### H3: CloseReason / LinkCloseReason identical duplicate
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 4
- **Category:** SSOT
- **Blocked-by:** A1
- **Detail:** Same variants, mechanical `From` impl. Exists solely for Link→Connection rename. Eliminated by A1.
- **Fix:** Eliminated by A1 (one enum, one name).
- **Test:** N/A (dissolved by A1).

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

### H5: WindowFull / PacingDelay in 3 error enums
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** SSOT
- **Blocked-by:** —
- **Detail:** `ChannelError::WindowFull`, `LinkError::WindowFull`, `SendError::WindowFull` — same concept, defined three times. Same for `PacingDelay`.
- **Fix:** Single error type at the lowest layer, re-exported or wrapped once.
- **Test:** N/A (dedup — compilation verifies).

### T1: MockClock defined 4 times
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 1
- **Category:** Test
- **Blocked-by:** —
- **Ref:** doc/TEST_REVIEW2.md Part C1 (consolidation plan)
- **Detail:** Identical `MockClock` struct defined independently in `transport.rs`, `node/mod.rs`, `node/builder.rs`, and `traits.rs`. Three use `Cell<u64>`, one is immutable. All do the same thing.
- **Fix:** Single `MockClock` in a shared `test_utils.rs` module (gated `#[cfg(test)]`). ~60 LOC savings. See TEST_REVIEW2.md Part C1 for the four locations and unified design.
- **Test:** N/A (test infrastructure).

### T2: 80+ Transport tests with no shared setup
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** M
- **Phase:** 2
- **Category:** Test
- **Blocked-by:** T1
- **Ref:** doc/TEST_REVIEW2.md Part C1 (consolidation plan), doc/TEST_REVIEW.md Section 3D
- **Detail:** Every transport test constructs `Transport::new()` + `register_interface()` + `register_destination()` from scratch. 5-15 lines of identical boilerplate per test. ~400 LOC of pure duplication.
- **Fix:** `test_transport()` helper function in `test_utils.rs`.
- **Test:** N/A (test infrastructure).

### T3: Magic numbers instead of constants in tests
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** M
- **Phase:** 2
- **Category:** Test
- **Blocked-by:** —
- **Ref:** doc/TEST_REVIEW2.md Part C5 (magic number table)
- **Detail:** `1_000_000` (initial clock, ~55 tests), `500` (MTU, ~15 tests), `464` (MDU, ~20 tests), `20_000` (rebroadcast delay, ~10 tests), `8` (MAX_TRIES, ~4 tests). Tests use raw literals instead of referencing `constants.rs`.
- **Fix:** Use named constants. Add `TEST_TIME_MS` for the initial clock value.
- **Test:** N/A (test infrastructure).

### T4: 5 Link tests ignore existing `setup_active_link_pair()` helper
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Test
- **Blocked-by:** —
- **Ref:** doc/TEST_REVIEW.md Section 3C, doc/TEST_REVIEW2.md Part C4
- **Detail:** `test_full_handshake_simulation`, `test_link_encrypt_decrypt`, `test_link_decrypt_tampered`, `test_bidirectional_data_after_handshake`, `test_encrypted_size` — all manually perform the full handshake despite the helper existing. ~100 LOC of unnecessary duplication.
- **Fix:** Rewrite to use `setup_active_link_pair()` where they only need active links.
- **Test:** N/A (test refactoring).

### T5: 24 tests access private struct fields
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** M
- **Phase:** 2
- **Category:** Test
- **Blocked-by:** —
- **Ref:** doc/TEST_REVIEW2.md Part B (fragility assessment — full table of 24 tests with suggested accessors)
- **Detail:** 16 in Channel, 5 in LinkManager, 3 in Link. These break on any refactoring without indicating real bugs. 18 tests MUST write private fields (no public API exists), 4 could use existing getters, 2 need new read-only accessors.
- **Fix:** Add 6 `#[cfg(test)]` setter methods. Replace 4 direct reads with existing getters. Add 2 new read-only accessors (`ephemeral_public_bytes()`, `rx_ring_is_empty()`). See TEST_REVIEW2.md Part B for the per-test breakdown.
- **Test:** N/A (test fragility reduction).

### T6: NodeCore messaging path completely untested
- **Status:** open
- **Priority:** HIGH
- **Effort:** L
- **Phase:** 1
- **Category:** Test
- **Blocked-by:** —
- **Ref:** doc/TEST_REVIEW2.md Part A5 (NodeCore coverage gap table — 13 missing features listed)
- **Detail:** 13 missing features. Zero unit tests for: `accept_connection()`, `reject_connection()`, `send_on_connection()`, `close_connection()`, `announce_destination()` (node-level), multiple simultaneous connections, `channel_hash_to_seq` lifecycle, `handle_packet()` for link requests/proofs/data, `handle_timeout()` keepalive generation, active links on `interface_down`, full wire→node→event packet flow. Only covered by interop tests (slow, don't test internal invariants).
- **Fix:** Write unit tests for each missing feature.
- **Test:** 13 new unit tests needed.

### T7: LinkManager lifecycle management untested
- **Status:** open
- **Priority:** HIGH
- **Effort:** L
- **Phase:** 1
- **Category:** Test
- **Blocked-by:** —
- **Ref:** doc/TEST_REVIEW2.md Part A3 (LinkManager coverage gap table — 9 missing features listed)
- **Detail:** 9 missing features. Zero unit tests for: `close()` sending close packet, `check_stale_links()`, `check_keepalives()`, `check_channel_timeouts()` in isolation, concurrent links, memory cleanup on close, stale recovery, peer close processing, keepalive timer reset on data. These are exactly the areas where memory leaks (B1) and split-brain bugs (A2) live.
- **Fix:** Write unit tests for each missing feature.
- **Test:** 9 new unit tests needed.

### T8: FAST tier guard untested
- **Status:** open
- **Priority:** MEDIUM
- **Effort:** S
- **Phase:** 1
- **Category:** Test
- **Blocked-by:** —
- **Ref:** doc/TEST_REVIEW2.md Part A1 (Channel coverage gap — "FAST tier guarded by handshake RTT, not SRTT")
- **Detail:** The v0.5.19 fix (window tiers use handshake RTT, not SRTT) has no test. Scenario: SRTT < 180ms (would trigger FAST promotion) but handshake RTT >= 180ms (should prevent it). Without this test, a future refactoring could silently break the guard and re-introduce the Window=48 crash under corruption.
- **Fix:** Write test: create channel with handshake RTT=1200ms, deliver messages so SRTT drops to ~200ms, verify window stays MEDIUM (max=12), not FAST (max=48).
- **Test:** 1 new unit test needed.

### T9: Channel coverage gaps
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 1
- **Category:** Test
- **Blocked-by:** —
- **Ref:** doc/TEST_REVIEW2.md Part A1 (Channel coverage gap table — 5 missing features)
- **Detail:** 5 missing: `poll()` with empty tx_ring, `poll()` with no SENT-state messages, window floor enforcement (`window_min`), `adjust_window(true)` direct test. Mostly edge cases, but `window_min` enforcement affects congestion control correctness.
- **Fix:** Write 5 unit tests.
- **Test:** 5 new unit tests needed.

### T10: Link lifecycle gaps
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 1
- **Category:** Test
- **Blocked-by:** T7
- **Ref:** doc/TEST_REVIEW2.md Part A2 (Link coverage gap table — 4 missing features)
- **Detail:** 4 missing: `attached_interface` routing verification, keepalive timer reset on inbound data, full Active→Stale→Closed cycle, stale recovery (Stale→Active). The lifecycle gaps require LinkManager coordination, which is itself untested (T7).
- **Fix:** Write 4 unit tests (after T7 provides the lifecycle test infrastructure).
- **Test:** 4 new unit tests needed.

### T11: Transport minor gaps
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 1
- **Category:** Test
- **Blocked-by:** —
- **Ref:** doc/TEST_REVIEW2.md Part A4 (Transport coverage gap table — 4 missing features)
- **Detail:** 4 missing: announce signature validation (tested in `announce.rs` but not at transport layer), hop limit enforcement (>128 hops), `register_destination_with_proof()`, `create_receipt()`/`get_receipt()`. Transport is otherwise comprehensively tested with 129 tests.
- **Fix:** Write 4 unit tests.
- **Test:** 4 new unit tests needed.

### T12: 3 smoke tests with no meaningful assertions
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Test
- **Blocked-by:** —
- **Ref:** doc/TEST_REVIEW.md Section 4B
- **Detail:** `test_connection_stream_close_idempotent` (driver/stream.rs), `test_reticulum_node_builder_creates_node` (driver/mod.rs), `test_create_instance` (reticulum.rs) — each only asserts that the code doesn't panic. No behavioral verification.
- **Fix:** Either add meaningful assertions or document as intentional panic-guard tests.
- **Test:** N/A (test quality improvement).

### T13: 4 tests >80 LOC combining multiple concerns
- **Status:** open
- **Priority:** LOW
- **Effort:** M
- **Phase:** 4
- **Category:** Test
- **Blocked-by:** T7
- **Ref:** doc/TEST_REVIEW.md Section 4D
- **Detail:** `test_retransmit_registers_new_receipt_and_removes_old` (137 LOC), `test_multiple_retransmits_clean_up_receipts` (109 LOC), `test_pending_link_recovery_rate_limited` (86 LOC), `test_channel_proof_suppressed_on_rx_ring_full` (84 LOC). Each exercises multiple concerns in a single function.
- **Fix:** Split into focused tests after LinkManager lifecycle tests (T7) provide setup helpers.
- **Test:** N/A (test refactoring).

### T14: `test_connection_new` name collision across files
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Test
- **Blocked-by:** —
- **Ref:** doc/TEST_REVIEW.md Section 4E
- **Detail:** `test_connection_new` exists in both `node/mod.rs` and `node/connection.rs`, testing the same `Connection` struct. Not a build error (Rust scopes by module) but confusing when reading test output.
- **Fix:** Rename one (e.g., `test_connection_struct_fields` in connection.rs).
- **Test:** N/A (rename).

### T15: 1 exact duplicate test
- **Status:** open
- **Priority:** LOW
- **Effort:** S
- **Phase:** 2
- **Category:** Test
- **Blocked-by:** —
- **Ref:** doc/TEST_REVIEW.md Section 4E
- **Detail:** `test_nodecore_handle_timeout_empty` (node/mod.rs:1274) and `test_handle_timeout_empty_node` (node/mod.rs:1388) are identical. Same test, different names.
- **Fix:** Delete one.
- **Test:** N/A (deletion).

### T16: ISSUES.md bugs have no test coverage
- **Status:** open
- **Priority:** HIGH
- **Effort:** L
- **Phase:** 1
- **Category:** Test
- **Blocked-by:** —
- **Ref:** doc/TEST_REVIEW2.md Part D (missing test categories — full table of 10 untested issues)
- **Detail:** 10 of 14 checked ISSUES.md items have zero test coverage: A2 (four parallel maps), B1 (closed links accumulate), B2 (channel_hash_to_seq leak), B3 (asymmetric cleanup), F1 (TickOutput dispatch), F4 (mark_delivered return), H1 (destination in 3 maps), H4 (bidirectional hash/seq maps), D12 (handshake vs active timeout), D13 (channel exhaustion reason). The highest-risk bugs (memory leaks, map sync) are exactly the ones with no tests.
- **Fix:** Write regression tests for each bug before fixing it (TDD). See TEST_REVIEW2.md Part D for per-issue test plans.
- **Test:** 10 new tests needed (one per untested issue).
