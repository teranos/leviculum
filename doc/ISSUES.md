# leviculum — Complete Issues List

Compiled from Architecture Reviews Round 1-3 (2026-02-15).

---

## A. Structural Problems (Design)

### A1. Link/Connection naming confusion [HIGH]

Four names for one concept: `Link` (core internal), `Connection` (core API), `ConnectionStream` (std), `link_id` (field names everywhere). Python uses `Link` consistently. The `Connection` struct is a nearly-empty metadata wrapper (4 fields: `link_id`, `destination_hash`, `is_initiator`, `compression_enabled`). All real state lives in `Link`. Events say "Connection" but carry `link_id` fields. `CloseReason` and `LinkCloseReason` are identical duplicated enums with a mechanical `From` impl.

**Fix:** Eliminate `Connection`, use `Link` everywhere. Move 4 fields into `Link`. `ConnectionStream` → `LinkHandle`. `NodeEvent::ConnectionEstablished` → `NodeEvent::LinkEstablished`. Drop `CloseReason` duplicate.

### A2. Four parallel LinkId maps [HIGH]

`links`, `channels`, `pending_outgoing/incoming`, `connections` — all keyed by `LinkId`, all with different lifecycles. Root cause of the two-channel bug. Removal is not always paired (see B1, B3).

**Fix:** Channel → `Option<Channel>` on Link. Pending → phase enum on Link. Connection fields → Link. Reduces 4+ maps to 1.

### A3. `channel_hash_to_seq` cross-layer dependency [MEDIUM]

Lives in `NodeCore`, maps packet hashes to sequence numbers that only make sense in the context of a `Channel` tx_ring in `LinkManager`. When the channel dies, entries orphan. Logically belongs to Channel/Link.

**Fix:** Move into Channel or Link. Clean up on link close.

### A4. `data_receipts` + `channel_receipt_keys` tight coupling [MEDIUM]

Two maps in LinkManager:
- `data_receipts`: `BTreeMap<[u8; TRUNCATED_HASHBYTES], DataReceipt>` — keyed by packet hash (global)
- `channel_receipt_keys`: `BTreeMap<(LinkId, u16), [u8; TRUNCATED_HASHBYTES]>` — keyed per link+sequence

Tightly coupled to each other and to both `links` and `channels`. Global hash-based lookup in `handle_data_proof()` prevents per-link storage.

**Fix:** Keep together. Move with slimmed LinkManager → LinkTable on NodeCore.

### A5. Event cascade: 13/20 pass-through translations [LOW]

6/9 `TransportEvent` and 7/11 `LinkEvent` variants are 1:1 mechanical translations with only trivial `DestinationHash::new()` wrapping. Cost of clean layering.

**Fix:** Accept as layering cost. Optionally collapse after LinkManager dissolution.

### A6. Drain buffers exist only because of struct separation [LOW]

`Vec<LinkEvent>`, `Vec<PendingPacket>`, `Vec<TransportEvent>`, `Vec<Action>` — exist solely because LinkManager cannot access Transport directly. If LinkManager dissolves, these become unnecessary.

**Fix:** Eliminate as consequence of LinkManager dissolution.

---

## B. Memory Leaks / Bugs

### B1. Closed links accumulate indefinitely [HIGH]

`close()`, `check_stale_links()`, and PeerClosed paths set `LinkState::Closed` but never remove the entry from `self.links`. No periodic garbage collection exists. Unbounded memory leak for long-running nodes.

**Fix:** Add periodic GC that removes Closed-state links (and their associated `channels`, `data_receipts`, `channel_receipt_keys` entries).

### B2. `channel_hash_to_seq` never cleaned on link close [MEDIUM]

34 bytes per entry, orphaned permanently. No cleanup path exists. Functionally benign (stale lookups return harmlessly) but unbounded over time.

**Fix:** In `handle_link_event(LinkClosed)`, iterate and remove all `channel_hash_to_seq` entries for the closed LinkId. Or move into Channel (see A4).

### B3. Asymmetric cleanup between links and channels [LOW]

- `close()` and `check_stale_links()` remove neither from `links` nor `channels`
- `check_channel_timeouts()` TearDownLink removes from `channels` but not `links`
- `close_local()` removes both (correct)
- No path removes a Closed link from `links`

Zombie entries in both maps. Not functionally dangerous but inconsistent.

**Fix:** Addressed by B1 (GC for Closed links).

---

## C. Dead Code

### C1. 8 dead error variants across 5 enums [MEDIUM]

| Enum | Dead Variants | Notes |
|------|--------------|-------|
| `BuildError` | `NoIdentity`, `InvalidConfig` | Both dead — `build()` never fails, `Result` return type is misleading |
| `LinkError` | `Timeout` | Timeouts go through event system, not errors |
| `SendError` | `Timeout`, `InvalidDestination` | Never constructed |
| `ConnectionError` | `InvalidState`, `TooLarge` | Dead in production (`ChannelError(_)` is live — constructed via `From<ChannelError>` impl) |
| `DeliveryError` | `NoPath` | Never constructed |

**Fix:** Remove dead variants. Make `build()` infallible (return `NodeCore` directly, not `Result`).

### C2. ~20 pub re-exports never imported [LOW]

Re-exported from `reticulum-core/src/lib.rs` but never imported by `reticulum-std`, `reticulum-cli`, or `reticulum-ffi`: `Link`, `LinkEvent`, `Packet`, `PacketReceipt`, `ReceiptStatus`, `ChannelAction`, `Envelope`, `MessageState`, `KnownRatchets`, `Ratchet`, `RatchetError`, `IfacConfig`, `IfacError`, `generate_random_hash`, `StreamDataMessage`, `SendHandle`, `SendResult`, `SendMethod`.

**Fix:** Reduce to `pub(crate)` or remove from re-exports. Keep only types that FFI or external consumers need.

### C3. Buffer types exported but unreachable [LOW]

`RawChannelReader`, `RawChannelWriter`, `BufferedChannelWriter` — publicly exported from `lib.rs` but no path in the API to obtain or use them. They exist for a Python `Buffer`-like pattern not yet wired into the node API.

**Fix:** Remove from public exports until the Buffer API is implemented.

### C4. Pure delegation methods [LOW]

5 methods that only forward to another method:
- `Channel::send()` → `send_internal()` (adds only msgtype validation)
- `LinkManager::process_packet()` → match dispatcher
- `LinkManager::mark_channel_delivered()` → `Channel::mark_delivered()` (BTreeMap lookup + delegate)
- `handle_link_event(LinkRequestReceived)` → 1:1 → `NodeEvent::ConnectionRequest`
- `handle_link_event(ChannelMessageReceived)` → 1:1 → `NodeEvent::MessageReceived`

**Fix:** Inline where possible after structural refactoring.

---

## D. Naming / API Clarity

### D1. `ConnectionStream` doesn't implement Stream [MEDIUM]

Send-only handle. Incoming data arrives via separate `NodeEvent` channel. Name strongly suggests `AsyncRead`/`AsyncWrite`/`futures::Stream`. Implements none.

**Fix:** Rename to `LinkHandle` or `LinkSender` (after A1 rename).

### D2. `PacketEndpoint` isn't an endpoint [MEDIUM]

Send handle scoped to a destination hash. Not a listener, not an addressable entity.

**Fix:** Rename to `PacketSender` or `SinglePacketSender`.

### D3. `send()` vs `send_bytes()` hides real distinction [MEDIUM]

`send()` = non-blocking, returns `WouldBlock` on backpressure. `send_bytes()` = async retry loop. Impossible to tell from names.

**Fix:** `send()` → `try_send()`, `send_bytes()` → `send()`.

### D4. `PacketReceived { from }` — `from` is not the sender [MEDIUM]

`from` field contains the destination hash (our registered destination), not the sender's identity.

**Fix:** Rename field to `destination` or `dest_hash`.

### D5. `DataReceived` vs `MessageReceived` subtle distinction [MEDIUM]

`DataReceived` = raw link data without channel framing. `MessageReceived` = channel message with type/sequence. A new developer won't know the difference.

**Fix:** Rename to `LinkDataReceived` / `ChannelMessageReceived`, or document prominently.

### D6. `DeliveryConfirmed` vs `LinkDeliveryConfirmed` [MEDIUM]

Both confirm delivery, for different transport methods. Only the `Link` prefix distinguishes. Easy to confuse.

**Fix:** Rename to `PacketDeliveryConfirmed` / `LinkDeliveryConfirmed`. Or `SinglePacketDelivered` / `LinkMessageDelivered`.

### D7. `ProofRequested` vs `LinkProofRequested` [MEDIUM]

Same pattern as D6. Both request proofs, different paths.

**Fix:** Rename to `PacketProofRequested` / `LinkProofRequested`.

### D8. `initiate()` vs `connect()` across layers [LOW]

`LinkManager::initiate()` → `NodeCore::connect()` → `ReticulumNode::connect()`. Different verbs for the same action at different layers.

**Fix:** Unify naming after A1 rename. All layers use same verb.

### D9. `accept_link()` vs `accept_connection()` [LOW]

Same divergence as D8. `LinkManager::accept_link()` vs `NodeCore::accept_connection()`.

**Fix:** Unify after A1 rename.

### D10. `ReticulumNodeImpl` aliased as `ReticulumNode` [LOW]

Both names exported. Grep finds both. Confusing which is canonical.

**Fix:** Remove the alias, use one name.

### D11. `Connection` struct is nearly empty [LOW]

4 fields, all real state in `Link`. Name creates expectation it's the primary connection object.

**Fix:** Dissolved by A1 (fields move into Link, Connection eliminated).

### D12. No distinction between handshake timeout and active-link timeout [LOW]

Both "link request never answered" and "established link went silent" produce the same `ConnectionClosed { reason: Timeout }` event. The application cannot distinguish a failed connection attempt from a dropped connection.

**Fix:** Add separate event variants or reason sub-types (e.g., `Timeout::Handshake` vs `Timeout::Keepalive`).

### D13. Channel exhaustion indistinguishable from other closes [LOW]

When a channel hits max retries, it tears down the link. The resulting `ConnectionClosed` event carries a generic close reason. The application cannot tell "channel gave up retransmitting" from "peer closed cleanly" or "keepalive timeout".

**Fix:** Add a `ChannelExhausted` close reason, or emit a separate `ChannelFailed` event before the close.

### D14. `PathRequestReceived` looks actionable but is informational [LOW]

`NodeEvent::PathRequestReceived` is emitted for observability only — transport handles path requests internally. It sits in the same enum as actionable events like `ConnectionRequest`, creating ambiguity about whether the application should respond.

**Fix:** Document as informational. Consider a separate `ObservabilityEvent` enum, or prefix with a naming convention.

### D15. `ChannelRetransmit` is observability-only [LOW]

`NodeEvent::ChannelRetransmit` reports that a retransmission occurred. Like D14, it's purely informational but mixed with actionable events in the same enum.

**Fix:** Same approach as D14 — document or separate.

---

## E. Visibility / Encapsulation

### E1. `NodeCore::transport()` exposes entire Transport internals [MEDIUM]

Public method, but only used by `reticulum-std` for `clock().now_ms()`.

**Fix:** Replace with `pub fn now_ms(&self) -> u64` accessor. Make `transport()` `pub(crate)`.

### E2. LinkManager drain methods are pub [LOW]

`take_pending_rtt_packet()`, `drain_close_packets()`, `drain_keepalive_packets()`, `drain_proof_packets()` — only used in `#[cfg(test)]`.

**Fix:** `pub(crate)` or `#[cfg(test)]`.

### E3. `Channel::send()` pure delegation [LOW]

Calls `send_internal()` adding only msgtype validation. Extra indirection.

**Fix:** Inline or rename to make the distinction clear.

---

## F. Temporal Coupling / Silent Failures

### F1. TickOutput must be dispatched — undocumented [MEDIUM]

`connect()`, `send_on_connection()`, `close_connection()` return `TickOutput` that MUST be dispatched to interfaces. If the caller discards it, the operation silently fails (no packet sent, no error). Only `announce_destination()` documents this requirement.

**Fix:** Document on all methods. Consider a builder pattern or `must_use` attribute on `TickOutput`.

### F2. `connect()` silently broadcasts when no path exists [LOW]

Falls back to broadcast instead of returning an error. Caller doesn't know whether the link request was routed or broadcast.

**Fix:** Return an enum indicating `Routed` vs `Broadcast`, or return an error.

### F3. `register_destination()` before `accept_connection()` not enforced [LOW]

`accept_connection()` returns `ConnectionError::IdentityNotFound` if destination isn't registered — misleading error name.

**Fix:** Rename error to `DestinationNotRegistered`. Or enforce at type level.

### F4. `mark_channel_delivered()` return value ignored [LOW]

`NodeCore::handle_data_proof()` calls `link_manager.mark_channel_delivered()` which returns `Option<LinkEvent>`, but the return value is silently discarded. If a bogus sequence number ACK arrives, the failure is invisible.

**Fix:** Propagate the return value and log or handle the `None` case.

---

## G. Hot Path / Performance

### G1. Lock-and-read pattern in event loop [LOW]

After `handle_timeout()` releases the Mutex, it's immediately re-acquired solely to read `next_deadline()` and `now_ms()`. Two lock acquisitions where one suffices.

**Fix:** Return next_deadline from `handle_timeout()` as part of `TickOutput`.

### G2. Pass-through parameters cross 3-5 boundaries [LOW]

`data: &[u8]`, `link_id`, `now_ms`, `rng: &mut R` pass through multiple struct boundaries unchanged. `interface_index: usize` crosses 5+ boundaries.

**Fix:** Reduced naturally by structural refactoring (fewer layers).

---

## H. Single Source of Truth Violations

### H1. Destination in 3 maps [MEDIUM]

- `Transport.destinations`: `DestinationEntry` (routing, proof strategy, identity=None)
- `NodeCore.destinations`: `Destination` (full object)
- `LinkManager.accepted_destinations`: `BTreeSet` (accept filter)

Three representations, three locations, one concept.

**Fix:** Single canonical `Destination` registry on NodeCore. Transport and LinkManager query it.

### H2. RTT in 2 places [LOW]

`Link.rtt_us` (handshake RTT, microseconds) and `Channel.srtt_ms` (smoothed RTT from proofs, milliseconds). Different values, different units, different purposes.

**Fix:** Architecturally justified (tier promotion vs timeout calculation). Document the distinction. Unify units to milliseconds.

### H3. CloseReason / LinkCloseReason identical duplicate [LOW]

Same variants, mechanical `From` impl. Exists solely for Link→Connection rename.

**Fix:** Eliminated by A1 (one enum, one name).

### H4. `channel_receipt_keys` and `channel_hash_to_seq` — same mapping, two directions [MEDIUM]

`channel_receipt_keys` in LinkManager maps `(LinkId, seq) → hash`.
`channel_hash_to_seq` in NodeCore maps `hash → seq`.

Same logical association, indexed from opposite directions, living in different structs. No guarantee they stay in sync.

**Fix:** Consolidate into one structure with bidirectional lookup. Move to Channel or Link.

### H5. WindowFull / PacingDelay in 3 error enums [LOW]

`ChannelError::WindowFull`, `LinkError::WindowFull`, `SendError::WindowFull` — same concept, defined three times. Same for `PacingDelay`.

**Fix:** Single error type at the lowest layer, re-exported or wrapped once.

---

## T. Test Infrastructure & Coverage

### T1. MockClock defined 4 times [MEDIUM]

Identical `MockClock` struct defined independently in `transport.rs`, `node/mod.rs`, `node/builder.rs`, and `traits.rs`. Three use `Cell<u64>`, one is immutable. All do the same thing.

**Fix:** Single `MockClock` in a shared `test_utils.rs` module (gated `#[cfg(test)]`).

### T2. 80+ Transport tests with no shared setup [MEDIUM]

Every transport test constructs `Transport::new()` + `register_interface()` + `register_destination()` from scratch. 5-15 lines of identical boilerplate per test. ~400 LOC of pure duplication.

**Fix:** `test_transport()` helper function in `test_utils.rs`.

### T3. Magic numbers instead of constants in tests [MEDIUM]

| Number | Meaning | Occurrences |
|--------|---------|-------------|
| `1_000_000` | Initial clock time (ms) | ~55 tests |
| `500` | Interface MTU | ~15 tests |
| `464` | MDU | ~20 tests |
| `20_000` | Rebroadcast delay window | ~10 tests |
| `8` | MAX_TRIES | ~4 tests |

Tests use raw literals instead of referencing `constants.rs`. Breaks when constants change.

**Fix:** Use named constants. Add `TEST_TIME_MS` for the initial clock value.

### T4. 5 Link tests ignore existing `setup_active_link_pair()` helper [LOW]

`test_full_handshake_simulation`, `test_link_encrypt_decrypt`, `test_link_decrypt_tampered`, `test_bidirectional_data_after_handshake`, `test_encrypted_size` — all manually perform the full handshake despite the helper existing. ~100 LOC of unnecessary duplication.

**Fix:** Rewrite to use `setup_active_link_pair()` where they only need active links.

### T5. 24 tests access private struct fields [MEDIUM]

16 in Channel, 5 in LinkManager, 3 in Link. These break on any refactoring without indicating real bugs. 18 tests MUST write private fields (no public API exists), 4 could use existing getters, 2 need new read-only accessors.

**Fix:** Add 6 `#[cfg(test)]` setter methods. Replace 4 direct reads with existing getters. Add 2 new read-only accessors (`ephemeral_public_bytes()`, `rx_ring_is_empty()`).

### T6. NodeCore messaging path completely untested [HIGH]

13 missing features. Zero unit tests for: `accept_connection()`, `reject_connection()`, `send_on_connection()`, `close_connection()`, `announce_destination()` (node-level), multiple simultaneous connections, `channel_hash_to_seq` lifecycle, `handle_packet()` for link requests/proofs/data, `handle_timeout()` keepalive generation, active links on `interface_down`, full wire→node→event packet flow.

Only covered by interop tests (slow, don't test internal invariants).

### T7. LinkManager lifecycle management untested [HIGH]

9 missing features. Zero unit tests for: `close()` sending close packet, `check_stale_links()`, `check_keepalives()`, `check_channel_timeouts()` in isolation, concurrent links, memory cleanup on close, stale recovery, peer close processing, keepalive timer reset on data.

These are exactly the areas where memory leaks (B1) and split-brain bugs (A2) live.

### T8. FAST tier guard untested [MEDIUM]

The v0.5.19 fix (window tiers use handshake RTT, not SRTT) has no test. Scenario: SRTT < 180ms (would trigger FAST promotion) but handshake RTT >= 180ms (should prevent it). Without this test, a future refactoring could silently break the guard and re-introduce the Window=48 crash under corruption.

### T9. Channel coverage gaps [LOW]

5 missing: `poll()` with empty tx_ring, `poll()` with no SENT-state messages, window floor enforcement (`window_min`), `adjust_window(true)` direct test. Mostly edge cases, but `window_min` enforcement affects congestion control correctness.

### T10. Link lifecycle gaps [LOW]

4 missing: `attached_interface` routing verification, keepalive timer reset on inbound data, full Active→Stale→Closed cycle, stale recovery (Stale→Active). The lifecycle gaps require LinkManager coordination, which is itself untested (T7).

### T11. Transport minor gaps [LOW]

4 missing: announce signature validation (tested in `announce.rs` but not at transport layer), hop limit enforcement (>128 hops), `register_destination_with_proof()`, `create_receipt()`/`get_receipt()`. Transport is otherwise comprehensively tested with 129 tests.

### T12. 3 smoke tests with no meaningful assertions [LOW]

`test_connection_stream_close_idempotent` (driver/stream.rs), `test_reticulum_node_builder_creates_node` (driver/mod.rs), `test_create_instance` (reticulum.rs) — each only asserts that the code doesn't panic. No behavioral verification.

**Fix:** Either add meaningful assertions or document as intentional panic-guard tests.

### T13. 4 tests >80 LOC combining multiple concerns [LOW]

| Test | File | LOC |
|------|------|-----|
| `test_retransmit_registers_new_receipt_and_removes_old` | link/manager.rs | 137 |
| `test_multiple_retransmits_clean_up_receipts` | link/manager.rs | 109 |
| `test_pending_link_recovery_rate_limited` | node/mod.rs | 86 |
| `test_channel_proof_suppressed_on_rx_ring_full` | link/manager.rs | 84 |

Each test exercises multiple concerns in a single function. Fragile and hard to diagnose on failure.

**Fix:** Split into focused tests after LinkManager lifecycle tests (T7) are written, which will provide the setup helpers needed.

### T14. `test_connection_new` name collision across files [LOW]

`test_connection_new` exists in both `node/mod.rs` and `node/connection.rs`, testing the same `Connection` struct. Not a build error (Rust scopes by module) but confusing when reading test output.

**Fix:** Rename one (e.g., `test_connection_struct_fields` in connection.rs).

### T15. 1 exact duplicate test [LOW]

`test_nodecore_handle_timeout_empty` (node/mod.rs:1274) and `test_handle_timeout_empty_node` (node/mod.rs:1388) are identical. Same test, different names.

**Fix:** Delete one.

### T16. ISSUES.md bugs have no test coverage [HIGH]

10 of 14 checked ISSUES.md items have zero test coverage:

| Issue | Unit Test | Interop Test | Risk |
|-------|-----------|-------------|------|
| A2 Four parallel maps | NO | Partial | HIGH |
| B1 Closed links accumulate | NO | NO | HIGH |
| B2 channel_hash_to_seq leak | NO | NO | MEDIUM |
| B3 Asymmetric cleanup | NO | NO | MEDIUM |
| F1 TickOutput dispatch | NO | NO | MEDIUM |
| F4 mark_delivered return | NO | NO | LOW |
| H1 Destination in 3 maps | NO | NO | LOW |
| H4 Bidirectional hash/seq maps | NO | NO | MEDIUM |
| D12 Handshake vs active timeout | NO | NO | LOW |
| D13 Channel exhaustion reason | NO | NO | LOW |

The highest-risk bugs (memory leaks, map sync) are exactly the ones with no tests.

---

## Summary

| Category | High | Medium | Low | Total |
|----------|------|--------|-----|-------|
| A. Structural | 2 | 2 | 2 | 6 |
| B. Memory Leaks | 1 | 1 | 1 | 3 |
| C. Dead Code | 0 | 1 | 3 | 4 |
| D. Naming / API | 0 | 7 | 8 | 15 |
| E. Visibility | 0 | 1 | 2 | 3 |
| F. Temporal Coupling | 0 | 1 | 3 | 4 |
| G. Performance | 0 | 0 | 2 | 2 |
| H. Single Source of Truth | 0 | 2 | 3 | 5 |
| T. Test Infrastructure | 3 | 5 | 8 | 16 |
| **Total** | **6** | **20** | **32** | **58** |
