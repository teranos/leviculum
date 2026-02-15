# Test Review, Round 2: Coverage Gaps, Fragility, and Consolidation Plan

Compiled 2026-02-15. Builds on the Round 1 inventory (doc/TEST_REVIEW.md).

---

## Part A: Coverage Gap Analysis

### A1. Channel (link/channel/mod.rs) — 46 tests

| Feature | Tested? | Test Name(s) |
|---------|---------|--------------|
| send() WindowFull | YES | `test_send_window_full`, `test_window_full_before_pacing` |
| send() PacingDelay | YES | `test_pacing_delay_returned` |
| send() TooLarge | YES | `test_send_too_large`, `test_send_system_respects_mdu` |
| send() msgtype validation | YES | `test_invalid_msgtype`, `test_send_rejects_system_msgtype` |
| send_system() bypasses validation | YES | `test_send_system_allows_reserved_msgtype` |
| receive() out-of-order | YES | `test_receive_out_of_order`, `test_channel_receive_message_out_of_order` |
| receive() backward sequence (reproving) | YES | `test_receive_backward_sequence_reproving`, `_many_ahead`, `_wraparound` |
| receive() type mismatch | YES | `test_channel_receive_message_wrong_type` |
| receive() RxRingFull | YES | `test_receive_rx_ring_full` |
| poll() TearDownLink on MAX_TRIES | YES | `test_poll_max_retries`, `test_max_tries_8_survives_longer` |
| poll() window decrement (loss) | YES | `test_retransmit_doubles_pacing` |
| poll() MD pacing doubling | YES | `test_retransmit_doubles_pacing`, `test_first_retransmit_no_pacing_md` |
| effective_rtt_ms() both branches | YES | `test_srtt_effective_rtt_ms_fallback` |
| recalculate_pacing() in isolation | YES | `test_recalculate_pacing` |
| pacing uses SRTT not handshake RTT | YES | `test_pacing_uses_srtt_not_handshake_rtt` |
| SLOW -> MEDIUM tier promotion | YES | `test_window_adjustment_on_rtt` (RTT=500) |
| MEDIUM -> FAST tier promotion | YES | `test_window_adjustment_on_rtt` (RTT=100) |
| Window increase (AIMD additive) | YES | `test_delivery_recalculates_pacing` (window 5->6) |
| Window decrease (AIMD multiplicative) | YES | `test_retransmit_doubles_pacing` |
| update_window_for_rtt() all tiers | YES | `test_window_adjustment_on_rtt` |
| mark_delivered() SRTT update (Karn) | YES | `test_srtt_first_measurement`, `test_srtt_karn_skips_retransmits` |
| mark_delivered() window adjustment | YES | `test_delivery_recalculates_pacing` |
| adjust_window + recalculate_pacing interplay | PARTIAL | `test_delivery_recalculates_pacing` (mark_delivered path only) |
| **poll() with empty tx_ring** | **MISSING** | — |
| **poll() with no SENT-state messages** | **MISSING** | — |
| **FAST tier guarded by handshake RTT, not SRTT** | **MISSING** | — |
| **Window floor enforcement (window_min)** | **MISSING** | — |
| **adjust_window(true) direct test** | **MISSING** | — |

**Summary**: 23 tested, 5 missing. The FAST-tier guard gap is critical — the v0.5.19 fix (tiers use handshake RTT while pacing uses SRTT) has no test proving that SRTT < 180ms with handshake RTT >= 180ms does NOT promote to FAST.

---

### A2. Link (link/mod.rs) — 42 tests

| Feature | Tested? | Test Name(s) |
|---------|---------|--------------|
| Link creation (outgoing) | YES | `test_link_creation` |
| Link creation (incoming) | YES | `test_new_incoming_link`, `test_new_incoming_link_invalid_request` |
| Link request data layout | YES | `test_link_request_data`, `test_link_request_with_mtu` |
| Link ID calculation | YES | `test_link_id_calculation`, `test_link_id_same_for_header1_and_header2` |
| Full handshake (initiator) | YES | `test_full_handshake_simulation` |
| Full handshake (responder) | YES | `test_full_handshake_responder_side` |
| Bidirectional data after handshake | YES | `test_bidirectional_data_after_handshake` |
| Key derivation | YES | `test_key_derivation` |
| Encrypt/decrypt | YES | `test_link_encrypt_decrypt`, `test_link_decrypt_tampered` |
| Data packet building | YES | `test_build_data_packet`, `test_build_data_packet_not_active` |
| Proof packet building | YES | `test_build_proof_packet`, `_wrong_state`, `_from_initiator` |
| Proof processing (error paths) | YES | `test_process_proof_invalid_state`, `_too_short`, `_no_destination_key` |
| RTT processing | YES | `test_process_rtt`, `test_process_rtt_wrong_state` |
| Keepalive calculation from RTT | YES | `test_keepalive_calculation_from_rtt`, `test_update_keepalive_from_rtt` |
| Keepalive sending trigger | YES | `test_should_send_keepalive` |
| Keepalive packet building | YES | `test_build_keepalive_packet` |
| Keepalive processing | YES | `test_process_keepalive`, `test_process_keepalive_wrong_byte` |
| Stale detection | YES | `test_is_stale_and_should_close` |
| Close packet building | YES | `test_build_close_packet` |
| Close processing | YES | `test_process_close_valid`, `test_process_close_invalid_link_id` |
| State transitions | YES | `test_link_state_transitions` |
| Timestamp recording | YES | `test_record_timestamps` |
| Link request with transport header | YES | `test_build_link_request_with_transport`, `_flags` |
| Responder keepalive suppressed | YES | `test_should_send_keepalive` (responder branch) |
| **attached_interface routing verification** | **MISSING** | — |
| **Keepalive timer reset on inbound data** | **MISSING** | — |
| **State: Active -> Stale -> Closed full cycle** | **MISSING** | — |
| **Stale link recovery (Stale -> Active)** | **MISSING** | — |

**Summary**: 24 tested features, 4 missing. The Link struct itself is well-tested. The gaps are in lifecycle transitions that require LinkManager coordination.

---

### A3. LinkManager (link/manager.rs) — 19 tests

| Feature | Tested? | Test Name(s) |
|---------|---------|--------------|
| Manager creation | YES | `test_new_manager` |
| Destination registration | YES | `test_register_destination` |
| Link initiation | YES | `test_initiate_link` |
| Pending link timeout | YES | `test_link_timeout` |
| Full handshake | YES | `test_full_handshake` |
| Proof strategy on accept | YES | `test_proof_strategy_set_on_link_via_accept` |
| PROVE_ALL auto-generation | YES | `test_prove_all_generates_proof_on_data_receive` |
| PROVE_APP event emission | YES | `test_prove_app_emits_proof_requested_event` |
| Send with receipt tracking | YES | `test_send_with_receipt_tracks_packet` |
| Channel accessor | YES | `test_channel_immutable_accessor` |
| Data receipt count/expiry | YES | `test_data_receipts_count`, `test_data_receipts_expire_after_timeout` |
| Channel proof generation | YES | `test_channel_proof_generated_with_proof_strategy_none`, `_by_initiator` |
| Retransmit receipt update | YES | `test_retransmit_registers_new_receipt_and_removes_old` |
| RxRingFull proof suppression | YES | `test_channel_proof_suppressed_on_rx_ring_full` |
| Local close (close_local) | YES | `test_close_link` |
| **close() sends close packet** | **MISSING** | — |
| **check_stale_links() stale cycle** | **MISSING** | — |
| **check_keepalives() generation** | **MISSING** | — |
| **check_channel_timeouts() isolated** | **MISSING** | — |
| **Concurrent links (2+ active)** | **MISSING** | — |
| **Memory cleanup on close (all maps)** | **MISSING** | — |
| **Stale link recovery** | **MISSING** | — |
| **Peer close packet processing** | **MISSING** | — |
| **Keepalive timer reset on data receipt** | **MISSING** | — |

**Summary**: 14 tested features, 9 missing. LinkManager has 19 tests for a complex module — significant gaps in lifecycle management, concurrent links, and cleanup verification.

---

### A4. Transport (transport.rs) — 129 tests

| Feature | Tested? | Test Name(s) |
|---------|---------|--------------|
| Path management (add/lookup) | YES | `test_path_management` |
| Path expiry | YES | `test_path_expiry`, `test_expire_path_removes_entry` |
| Announce processing | YES | `test_announce_processing` (large test) |
| Announce deduplication (random blob) | YES | `test_announce_replay_detected_via_random_blob` |
| Announce rate limiting (10 tests) | YES | `test_announce_rate_within_limit_accepted`, `_exceeds_limit_after_grace`, `_penalty_extends_blocking`, `_independent_per_destination`, `_violations_decrement_on_good_rate`, `_recovery_after_block_expires`, `_disabled_by_default`, `_path_response_exempt`, `_table_cleanup`, `_last_ms_not_updated_on_violation` |
| Rebroadcast timing | YES | `test_rebroadcast_fires_after_delay` |
| Rebroadcast correct interfaces | YES | `test_rebroadcast_sent_on_correct_interfaces` |
| Rebroadcast disabled when no transport | YES | `test_no_rebroadcast_when_transport_disabled` |
| Rebroadcast max retries | YES | `test_rebroadcast_stops_after_max_retries` |
| Rebroadcast hop increment | YES | `test_rebroadcast_increments_hops` |
| Local rebroadcast suppression | YES | `test_local_rebroadcast_detection_suppresses` |
| Announce cache | YES | `test_announce_cache_populated` |
| Link table expiry (validated) | YES | `test_link_table_entry_expiry_validated` |
| Link table expiry (unvalidated) | YES | `test_link_table_entry_expiry_unvalidated` |
| Path request sending | YES | `test_request_path_sends_packet` |
| Path request rate limiting | YES | `test_request_path_rate_limited` |
| Path request for local dest | YES | `test_path_request_local_dest_emits_event` |
| Path request from announce cache | YES | `test_path_request_cached_announce_triggers_response` |
| Path request dedup | YES | `test_path_request_tag_dedup` |
| Path request forwarding | YES | `test_path_request_unknown_dest_forwarded` |
| Reverse table expiry | YES | `test_reverse_table_expiry_8_minutes` |
| Packet deduplication | YES | `test_packet_deduplication` |
| Packet cache expiry | YES | `test_packet_cache_expiry` |
| Data packet delivery | YES | `test_data_packet_delivery` |
| Unregistered destination drop | YES | `test_unregistered_destination_dropped` |
| Send on interface (action) | YES | `test_send_on_interface_produces_action` |
| Send to destination (routing) | YES | `test_send_to_destination_produces_send_action`, `_relay_converts_type1_to_type2`, `_type2_not_double_wrapped`, `_no_path_no_action` |
| Broadcast action | YES | `test_send_on_all_interfaces_produces_broadcast_action` |
| Forward on interface | YES | `test_forward_on_interface_produces_send_action` |
| Proof routing (reverse table) | YES | `test_regular_proof_routed_via_reverse_table` |
| Link request type1/type2 stripping | YES | `test_link_request_stripped_to_type1_at_final_hop`, `_type2_when_not_final_hop`, `_forward_type2_to_type1_payload_intact` |
| Link data hop validation | YES | `test_link_data_wrong_hops_dropped`, `_correct_hops_forwarded`, `_correct_hops_from_initiator` |
| Path table forward (header2 transport) | YES | `test_path_table_forward_header2_replaces_transport_id`, `_strips_to_type1_at_final_hop` |
| Announce header2 next_hop | YES | `test_announce_header2_populates_next_hop` |
| Better/worse path replacement | YES | `test_better_hop_announce_replaces_worse_path`, `test_worse_hop_announce_with_newer_emission_updates_path`, `_accepted_when_path_expired` |
| Path state API | YES | `test_path_state_api_basic`, `test_path_state_orphan_cleanup` |
| Unresponsive path handling | YES | `test_unresponsive_path_accepts_same_emission_worse_hop_announce` |
| Link expiry triggers path recovery | YES | `test_full_recovery_cycle`, `test_link_expiry_non_transport_calls_expire_path` |
| Interface down cleanup | YES | `test_link_table_cleaned_when_interface_down`, `test_reverse_table_cleaned_when_interface_down` |
| Deferred hash for link table data | YES | `test_link_table_data_deferred_hash_allows_retry`, `_successful_forward_caches_hash` |
| LR proof handling | YES | `test_lrproof_invalid_length_not_forwarded`, `_not_cached_on_link_table_forward`, `_local_delivery_caches_hash` |
| **Announce signature validation** | **MISSING** | — (validated in announce.rs, not transport) |
| **Hop limit enforcement (>128 hops dropped)** | **MISSING** | — (no test drops packet at PATHFINDER_MAX_HOPS) |
| **register_destination_with_proof()** | **MISSING** | — |
| **create_receipt() / get_receipt()** | **MISSING** | — (receipt API methods, no unit test) |

**Summary**: Transport is comprehensively tested with 129 tests covering routing, rebroadcast, path management, announce rate limiting, link tables, and sans-I/O actions. Only 4 features missing, and 2 of those (signature validation, receipts) are tested at other layers.

---

### A5. NodeCore (node/mod.rs + send.rs + connection.rs) — 40 tests

| Feature | Tested? | Test Name(s) |
|---------|---------|--------------|
| register_destination() | YES | `test_nodecore_register_destination` |
| handle_packet() invalid data | YES | `test_handle_packet_invalid_data` |
| handle_packet() announce | YES | `test_handle_packet_announce`, `_produces_rebroadcast_action` |
| handle_timeout() empty | YES | `test_handle_timeout_empty`, `test_handle_timeout_empty_node` (DUPLICATE) |
| handle_timeout() rebroadcast | YES | `test_handle_timeout_produces_rebroadcast_actions` |
| handle_interface_down() | YES | `test_handle_interface_down_cleans_paths`, `_no_paths` |
| next_deadline() | YES | `test_next_deadline` |
| connect() | YES | `test_connect_queues_send_action` |
| Pending link timeout recovery | YES | `test_pending_link_timeout_triggers_path_recovery`, `_no_recovery_for_transport_nodes`, `_normal_close_no_recovery`, `_recovery_rate_limited` |
| send (no path) | YES | `test_send_no_path_returns_error`, `test_send_reliable_no_path_returns_error` |
| decide_routing() (7 combinations) | YES | All 7 in node/send.rs |
| SendHandle/SendMethod | YES | `test_send_handle_creation`, `test_send_method_variants` |
| Connection struct | YES | `test_connection_new`, `test_connection_compression_toggle` |
| ConnectionError conversions | YES | `test_connection_error_from_link_error`, `_from_channel_error` |
| **accept_connection()** | **MISSING** | — |
| **reject_connection()** | **MISSING** | — |
| **send_on_connection()** | **MISSING** | — |
| **close_connection()** | **MISSING** | — |
| **announce_destination() (node-level)** | **MISSING** | — |
| **Multiple simultaneous connections** | **MISSING** | — |
| **channel_hash_to_seq population/cleanup** | **MISSING** | — |
| **handle_packet() link request** | **MISSING** | — |
| **handle_packet() proof** | **MISSING** | — |
| **handle_packet() link data** | **MISSING** | — |
| **handle_timeout() keepalive generation** | **MISSING** | — |
| **Active links on interface_down** | **MISSING** | — |
| **Full packet flow: wire -> node -> event** | **MISSING** | — |

**Summary**: 14 features tested, 13 missing. The entire reliable messaging pathway through NodeCore is untested: accept, send_on_connection, close are all MISSING. These are tested via interop tests (Python daemon), but have zero unit test coverage at the NodeCore layer.

---

### A6. Error Variant Coverage

Cross-referencing ISSUES.md C1 (dead error variants) with test coverage:

| Enum | Variant | Constructed in prod? | Tested? | Status |
|------|---------|---------------------|---------|--------|
| BuildError | NoIdentity | NO | NO | DEAD |
| BuildError | InvalidConfig | NO | NO | DEAD |
| LinkError | Timeout | NO | NO | DEAD |
| SendError | Timeout | NO | NO | DEAD |
| SendError | InvalidDestination | NO | NO | DEAD |
| ConnectionError | InvalidState | NO | NO | DEAD |
| ConnectionError | TooLarge | NO | NO | DEAD |
| DeliveryError | NoPath | NO (test-only) | Display test only | DEAD |

**Confirmed**: All 8 production dead variants from C1 are verified dead. Additionally:

- `InterfaceError` (6 variants) and `StorageError` (4 variants) are trait definitions with no in-core construction — these are correctly dead in core scope, alive in reticulum-std
- `CloseReason` / `LinkCloseReason` are confirmed identical duplicates (H3)
- `WindowFull` / `PacingDelay` appear in 3 enums each (H5)

---

## Part B: Fragility Assessment — Private Field Access

### B1. Tests that MUST access private fields (no public API for write)

These tests set internal state to specific values before exercising behavior. No public setter exists.

| Test | File:Line | Private Field Written | Suggested `#[cfg(test)]` Accessor |
|------|-----------|----------------------|-----------------------------------|
| `test_send_window_full` | channel/mod.rs:896 | `.window = 1` | `set_window_for_test(w)` |
| `test_send_system_respects_window` | channel/mod.rs:1089 | `.window = 1` | (same) |
| `test_poll_max_retries` | channel/mod.rs:1013 | `.max_tries = 2` | `set_max_tries_for_test(t)` |
| `test_pacing_delay_returned` | channel/mod.rs:1325 | `.pacing_interval_ms`, `.next_send_at_ms` | `set_pacing_for_test(interval, next)` |
| `test_pacing_next_send_set_on_send` | channel/mod.rs:1342 | `.pacing_interval_ms = 50` | (same) |
| `test_window_full_before_pacing` | channel/mod.rs:1355 | `.window`, `.pacing_interval_ms` | (same) |
| `test_pacing_ceiling_on_retransmit` | channel/mod.rs:1423 | `.pacing_interval_ms = 80` | (same) |
| `test_recalculate_pacing` | channel/mod.rs:1441 | `.window = 5/2/0/5` | (same) |
| `test_delivery_recalculates_pacing` | channel/mod.rs:1466 | `.window`, `.window_min`, `.window_max`, `.pacing_interval_ms` | `set_window_bounds_for_test(w, min, max)` |
| `test_live_timeout_uses_current_queue_len` | channel/mod.rs:1511 | `.window = 10` | (same) |
| `test_live_timeout_longer_when_queue_grows` | channel/mod.rs:1557 | `.window = 10` | (same) |
| `test_receive_backward_sequence_wraparound` | channel/mod.rs:1311 | `.next_rx_sequence = 5` | `set_next_rx_sequence_for_test(s)` |
| `test_sequence_wraparound` | channel/mod.rs:850 | `.next_tx_sequence = 0xFFFF` | (already has `force_next_tx_sequence_for_test`) |
| `test_should_send_keepalive` | link/mod.rs:2645 | `.state`, `.keepalive_secs` | `set_state_for_test(s)`, `set_keepalive_for_test(s)` |
| `test_is_stale_and_should_close` | link/mod.rs:2672 | `.keepalive_secs`, `.stale_time_secs`, `.state`, `.last_inbound` | (same) |
| `test_process_proof_invalid_state` | link/mod.rs:1805 | `.state = Active` | (same) |
| `test_close_from_stale_state` | link/mod.rs:2842 | `.state` | (same) |
| `test_close_from_wrong_state` | link/mod.rs:2856 | `.state` | (same) |

### B2. Tests that COULD use public API (getter already exists)

These tests read private fields but public getters exist:

| Test | File:Line | Field Read | Use Instead |
|------|-----------|-----------|-------------|
| `test_retransmit_doubles_pacing` | channel/mod.rs:1380 | `.pacing_interval_ms` | `pacing_interval_ms()` |
| `test_no_pacing_before_first_rtt` | channel/mod.rs:1486 | `.pacing_interval_ms`, `.next_send_at_ms` | `pacing_interval_ms()`, `next_send_at_ms()` |
| `test_pacing_uses_srtt_not_handshake_rtt` | channel/mod.rs:1792 | `.srtt_ms`, `.window` | `srtt_ms()`, `window()` |
| `test_link_request_data` | link/mod.rs:1742 | `.ephemeral_public`, `.verifying_key` | Add `ephemeral_public_bytes()`, `verifying_key_bytes()` |
| `test_link_request_with_mtu` | link/mod.rs:1755 | (same) | (same) |
| `test_receive_rx_ring_full` | channel/mod.rs:1280 | `.rx_ring.is_empty()` | Add `rx_ring_is_empty()` |

### B3. Summary

| Category | Count | Action |
|----------|-------|--------|
| Must write private fields | 18 | Add 6 `#[cfg(test)]` setter methods |
| Could use existing public getter | 4 | Replace direct access with getter call |
| Need new read-only accessor | 2 | Add `ephemeral_public_bytes()`, `rx_ring_is_empty()` |
| **Total** | **24** | |

---

## Part C: Test Consolidation Plan

### C1. Shared test utilities module

**Create `reticulum-core/src/test_utils.rs`** (gated behind `#[cfg(test)]`):

| Item | Currently | Dedup Savings |
|------|-----------|---------------|
| `MockClock` | Defined 4x (transport.rs, node/mod.rs, node/builder.rs, traits.rs) | ~60 LOC |
| `INITIAL_TIME_MS` constant | `1_000_000` appears 55x across 7 files as raw literal | centralize as `pub const TEST_TIME_MS: u64 = 1_000_000` |
| Transport + interface builder | ~80 tests each create Transport + register interface + destination from scratch | ~400 LOC (5 LOC/test x 80 tests) |
| Link handshake helper | 5 tests in link/mod.rs manually duplicate handshake despite `setup_active_link_pair()` existing | ~100 LOC |

**MockClock unification**: The 4 definitions vary slightly:

| Location | Struct | Interior mutability | `advance()` |
|----------|--------|-------------------|----|
| transport.rs:2433 | `MockClock { time_ms: Cell<u64> }` | Cell | `set()` |
| node/mod.rs:1209 | `MockClock(Cell<u64>)` | Cell | `set()` |
| node/builder.rs:176 | `MockClock(Cell<u64>)` | Cell | `set()` |
| traits.rs:266 | `MockClock { time_ms: u64 }` | None (immutable) | None |

Unified version: tuple struct with `Cell<u64>`, matching node/mod.rs pattern. The traits.rs version is different (immutable) and used for a single trivial test — can be replaced.

**Transport builder helper**:

```rust
// In test_utils.rs:
pub fn test_transport<R: CryptoRngCore>(rng: &mut R) -> Transport<MockClock, NoStorage> {
    let clock = MockClock::new(TEST_TIME_MS);
    let storage = NoStorage;
    let mut transport = Transport::new(clock, storage, false);
    transport.register_interface(/* default test interface */);
    transport
}
```

### C2. Tests to delete

| Test | File:Line | Reason |
|------|-----------|--------|
| `test_handle_timeout_empty_node` | node/mod.rs:1388 | Exact duplicate of `test_nodecore_handle_timeout_empty` (line 1274) |

**Total: 1 test (15 LOC)**

### C3. Tests to merge (parameterized)

| Test Group | File | Current Tests | Merge Into |
|-----------|------|---------------|------------|
| Routing decision tests | node/send.rs | 7 tests, each 10 LOC, differ only in params | 1 parameterized test with `[(input, expected)]` array |
| Backward sequence receive | channel/mod.rs | `_reproving`, `_many_ahead`, `_wraparound` | 1 test with 3 scenarios |
| Announce rate limiting | transport.rs | 10 tests | Keep separate (each tests distinct behavior) |

**Estimated savings: ~50 LOC**

### C4. Tests to rewrite (use existing helpers)

These tests in link/mod.rs manually perform the full handshake despite `setup_active_link_pair()` existing. They need the handshake because they test intermediate states — but 3 only need active links:

| Test | File:Line | Issue | Action |
|------|-----------|-------|--------|
| `test_build_data_packet` | link/mod.rs:1939 | Manual handshake, only needs active pair | Use `setup_active_link_pair()` |
| `test_bidirectional_data_after_handshake` | link/mod.rs:2074 | Manual handshake | Use `setup_active_link_pair()` |
| `test_encrypted_size` | link/mod.rs:2144 | Manual handshake, only needs active link | Use `setup_active_link_pair()` |

**Estimated savings: ~90 LOC**

### C5. Magic numbers to replace

| Raw Value | Occurrences | Replace With | Source |
|-----------|------------|--------------|--------|
| `1_000_000` | 55 | `TEST_TIME_MS` | New constant in test_utils.rs |
| `464` | ~20 (in tests) | `MDU` | constants.rs |
| `500` | ~15 (in tests, as MTU) | `MTU` | constants.rs |
| `0xf000` | ~5 | `CHANNEL_MSGTYPE_RESERVED` | constants.rs |
| `0xff00` | ~3 | `STREAM_DATA_MSGTYPE` | constants.rs |
| `8` (max tries) | ~4 | `CHANNEL_MAX_TRIES` | constants.rs |
| `16` (hash bytes) | ~30 | `TRUNCATED_HASHBYTES` | constants.rs (most already use it) |

---

## Part D: Missing Test Categories (Cross-Reference with ISSUES.md)

### D1. Memory Leak B1 — Closed links accumulate

**Test exists?** NO

No test verifies that closed links are ever removed from `LinkManager.links`. The `close()` and `check_stale_links()` paths set `LinkState::Closed` but never remove entries. No periodic GC exists, and no test checks for accumulation over time.

**What a test would look like**: Create 100 links, close them all, verify `links.len() == 0` after GC runs.

---

### D2. Memory Leak B2 — channel_hash_to_seq orphaning

**Test exists?** NO

No test verifies that `NodeCore.channel_hash_to_seq` entries are cleaned up when a link closes. The map is populated in `send_on_connection()` and `ChannelReceiptUpdated` handler, but no cleanup path exists on link close.

**What a test would look like**: Send a message (populates channel_hash_to_seq), close the link, verify map entry removed.

---

### D3. Split-brain A2 — Four parallel LinkId maps

**Test exists?** NO

No test verifies that all 4 maps (`links`, `channels`, `pending_outgoing/incoming`, `connections`) stay in sync. The only cleanup test is `test_close_link` which calls `close_local()` — the one path that does remove from all maps. But:
- `close()` (graceful) doesn't remove from `links`
- `check_stale_links()` doesn't remove from `links`
- `check_channel_timeouts()` TearDownLink removes from `channels` but not `links`

**What a test would look like**: Create link, establish channel, send message, close via each path, verify all maps are empty.

---

### D4. TickOutput dispatch F1 — Silent failure

**Test exists?** NO

No test verifies that discarding a `TickOutput` causes silent failure. `connect()`, `send_on_connection()`, `close_connection()` all return `TickOutput` that must be dispatched. If the caller ignores it, the operation silently fails.

**What a test would look like**: Call `connect()`, discard the TickOutput, verify no link request was sent (link stays pending forever). Or: verify `TickOutput` has `#[must_use]`.

---

### D5. Coverage gap summary table

| ISSUES.md Item | Has Unit Test? | Has Interop Test? | Risk |
|---------------|---------------|-------------------|------|
| A1 Link/Connection naming | N/A (naming) | N/A | — |
| A2 Four parallel LinkId maps | NO | Partial (interop tests exercise full flow) | HIGH |
| A3 channel_hash_to_seq | NO | NO | MEDIUM |
| A4 data_receipts coupling | Partial (receipt tests) | YES | LOW |
| B1 Closed links accumulate | NO | NO | HIGH |
| B2 channel_hash_to_seq leak | NO | NO | MEDIUM |
| B3 Asymmetric cleanup | NO | NO | MEDIUM |
| C1 Dead error variants | Confirmed dead | N/A | LOW |
| D12 Handshake vs active timeout | NO | NO | LOW |
| D13 Channel exhaustion close reason | NO | NO | LOW |
| F1 TickOutput dispatch | NO | NO | MEDIUM |
| F4 mark_channel_delivered return | NO | NO | LOW |
| H1 Destination in 3 maps | NO | N/A | LOW |
| H4 Bidirectional hash/seq maps | NO | NO | MEDIUM |

---

## Summary Statistics

| Category | Count |
|----------|-------|
| **Coverage gaps (MISSING features)** | |
| Channel | 5 |
| Link | 4 |
| LinkManager | 9 |
| Transport | 4 |
| NodeCore | 13 |
| **Total missing features** | **35** |
| | |
| **Private field access** | |
| Must access (no public API) | 18 |
| Could use existing getter | 4 |
| Need new accessor | 2 |
| | |
| **Consolidation savings** | |
| Tests to delete | 1 (15 LOC) |
| Tests to merge | ~50 LOC |
| Tests to rewrite (use helpers) | ~90 LOC |
| MockClock unification | ~60 LOC |
| Transport builder helper | ~400 LOC |
| **Total estimated savings** | **~615 LOC** |
| | |
| **ISSUES.md items with no test** | 10 of 14 checked |
