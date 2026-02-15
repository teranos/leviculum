# Test Review, Round 1: Inventory, Duplication, and Structural Problems

Compiled 2026-02-15. Covers every `#[test]` function across all crates.

---

## 1. Test Inventory

### Grand Total: 938 tests

| Target | Count | Notes |
|--------|-------|-------|
| reticulum-core lib | 594 | Inline `#[cfg(test)]` modules |
| reticulum-core compression_vectors | 7 | Integration test: BZ2 vs Python vectors |
| reticulum-core proptest_crypto | 18 | Property-based crypto tests |
| reticulum-core test_vectors | 31 | Python-generated JSON vector tests |
| reticulum-std lib | 28 | Inline unit tests |
| reticulum-std rnsd_interop | 177 | Integration: Rust ↔ Python daemon |
| reticulum-cli | 31 | selftest verdict + display formatting |
| reticulum-ffi ffi_c_tests | 1 | `#[ignore]` — outdated |
| Doc-tests (core) | 28 | Doctests in core |
| Doc-tests (std) | 4 | Doctests in std |
| Doc-tests (net) | 0 | — |

### 1A. reticulum-core/src/ — Inline Tests (594 tests)

#### Layer 0 — Crypto (84 tests)

| File | Count | What it tests | Setup pattern |
|------|-------|---------------|---------------|
| crypto/aes_cbc.rs | 22 | AES-256-CBC encrypt/decrypt, padding, error cases | API |
| crypto/token.rs | 21 | Fernet-style token encrypt/decrypt, tamper detection | API + Fixture (`make_key()`) |
| crypto/hmac_impl.rs | 20 | HMAC-SHA256, constant-time comparison, RFC 4231 vector | API |
| crypto/hkdf_impl.rs | 18 | HKDF-SHA256, RFC 5869 vector, edge cases | API |
| crypto/hashes.rs | 3 | SHA-256, truncated hash | API |

All crypto tests use direct function calls (API pattern). No private field access. No `#[ignore]`. One `#[should_panic]` test (hkdf output too large).

#### Layer 0 — Framing (14 tests)

| File | Count | What it tests | Setup pattern |
|------|-------|---------------|---------------|
| framing/hdlc.rs | 14 | CRC-16, frame/deframe roundtrip, escape sequences, Python vectors | API + Fixture (`hex_decode()`) |

5 tests verify exact byte output against Python Reticulum vectors.

#### Layer 0 — Traits (3 tests)

| File | Count | What it tests | Setup pattern |
|------|-------|---------------|---------------|
| traits.rs | 3 | Clock deadline, InterfaceMode default, NoStorage | API |

#### Layer 1 — Identity & Addressing (145 tests)

| File | Count | What it tests | Setup pattern |
|------|-------|---------------|---------------|
| identity.rs | 46 | Key generation, sign/verify, encrypt/decrypt, proofs, ratchet integration | API |
| destination.rs | 47 | Destination creation, announce building, ratchet management, proof strategy, DestinationHash ops | API |
| ifac.rs | 16 | IFAC config, apply/verify roundtrip, tamper detection, key derivation | API |
| ratchet.rs | 15 | Ratchet generation, serialization, ECDH, KnownRatchets CRUD, expiry | API |
| announce.rs | 12 | Parse announce, hash computation, random hash, emission tracking | Manual (5), API (4), Fixture (3) |
| receipt.rs | 11 | Receipt creation, expiry, status transitions, proof validation | API |
| packet.rs | 4 | PacketFlags roundtrip, pack/unpack, IFAC flag | API |

#### Layer 2 — Link & Channel (173 tests)

| File | Count | What it tests | Setup pattern |
|------|-------|---------------|---------------|
| link/channel/mod.rs | 46 | Channel send/recv, window, pacing, SRTT, retransmit, message types | Manual (41), API (5) |
| link/mod.rs | 42 | Link lifecycle, handshake, encrypt/decrypt, keepalive, close | Manual (26), API (8), Fixture (8 via `setup_active_link_pair()`) |
| link/channel/buffer.rs | 26 | RawChannelReader/Writer, BufferedChannelWriter, compression | API (12), Manual (14) |
| link/channel/stream.rs | 21 | StreamDataMessage pack/unpack, Python wire format | API |
| link/manager.rs | 19 | LinkManager lifecycle, proof strategy, receipts, retransmit | Manual (3), Fixture (16 via `establish_link_pair()`) |
| link/channel/envelope.rs | 12 | Envelope pack/unpack, error cases | API |

**Helpers defined in link/:**

| Helper | File | Lines | Used by | Usage rate |
|--------|------|-------|---------|------------|
| `setup_active_link_pair()` | link/mod.rs | 35 | 8 tests | 19% of file |
| `establish_link_pair(strategy)` | link/manager.rs | 52 | 16 tests | 84% of file |

#### Layer 3 — Transport (129 tests)

| File | Count | What it tests | Setup pattern |
|------|-------|---------------|---------------|
| transport.rs | 129 | Path management, announce processing, rebroadcast, link tables, header processing, proof routing, rate limiting, sans-I/O types | API (122), Manual (7) |

Organized in nested submodules: `sans_io_types` (9 tests for `InterfaceId`, `Action`, `TickOutput`), `transport_tests` (120 tests for routing logic).

No helper functions — each of the 129 tests is self-contained.

#### Layer 4 — Node (47 tests)

| File | Count | What it tests | Setup pattern |
|------|-------|---------------|---------------|
| node/mod.rs | 27 | NodeCore API, handle_packet/timeout, next_deadline, interface_down, pending link recovery | API (14), Mixed (9), Fixture (4 via `setup_pending_link()`) |
| node/send.rs | 9 | `decide_routing()` — pure routing decision function | Manual (all) |
| node/builder.rs | 5 | NodeCoreBuilder fluent API | API |
| node/connection.rs | 4 | Connection struct, error conversions | Manual |
| node/event.rs | 2 | CloseReason conversion, DeliveryError Copy | Manual |

**Helper:** `setup_pending_link(enable_transport)` in node/mod.rs — 30 lines, used by 4 tests.

### 1B. reticulum-core/tests/ — External Tests (56 tests)

| File | Count | What it tests | Setup pattern |
|------|-------|---------------|---------------|
| test_vectors.rs | 31 | Python-generated vectors: identity, HKDF, token, packet, announce, link proof, IFAC | Fixture (load JSON) |
| proptest_crypto.rs | 18 | Property-based: AES roundtrip, HMAC, HKDF, token, identity encrypt/sign | API + Fixture (`new_identity()`) |
| compression_vectors.rs | 7 | BZ2 compress/decompress vs Python vectors | Fixture (load JSON) |

### 1C. reticulum-std/src/ — Inline Tests (28 tests)

| File | Count | What it tests | Setup pattern |
|------|-------|---------------|---------------|
| driver/builder.rs | 5 | ReticulumNodeBuilder construction | API |
| interfaces/tcp.rs | 5 | TCP interface spawn, connect refused, maybe_corrupt | Manual + Mock |
| storage.rs | 4 | Filesystem storage: raw, serialized, exists, core trait | Fixture (TempDir) |
| driver/stream.rs | 4 | ConnectionStream send/close | Manual |
| driver/endpoint.rs | 3 | PacketEndpoint send, closed channel | Manual |
| clock.rs | 2 | SystemClock, Clock trait methods | API |
| config.rs | 2 | Config default, serialization | Manual |
| reticulum.rs | 1 | Reticulum instance creation | Manual |
| driver/mod.rs | 1 | ReticulumNode builder | Manual |

### 1D. reticulum-std/tests/rnsd_interop/ — Interop Tests (177 tests)

| File | Count | What it tests |
|------|-------|---------------|
| transport_interop_tests.rs | 21 | Path discovery, relay chains (1-2 hop), rebroadcast timing |
| link_manager_tests.rs | 17 | Manager handshake, data exchange, concurrent links, Rust↔Rust via daemon |
| announce_interop_tests.rs | 17 | Announce propagation, dedup, app data, daemon isolation |
| channel_tests.rs | 13 | Channel constants, envelope wire format, window, send/receive |
| link_keepalive_close_tests.rs | 11 | Keepalive, stale detection, graceful close, multi-hop |
| edge_case_tests.rs | 11 | Empty/large app data, MTU boundary, path replacement |
| proof_tests.rs | 10 | Proof creation, validation, strategy, Python prove_all/none |
| node_api_tests.rs | 8 | Node creation, shutdown, restart, announce reception |
| link_tests.rs | 6 | Basic link, encrypted data, echo, proof validation, MTU signaling |
| multihop_tests.rs | 6 | 3-hop topology, path tables, transport status |
| discovery_tests.rs | 5 | Daemon announce, hash derivation, signature, path from announce |
| protocol_tests.rs | 5 | Flags, context bytes, name/dest hash vectors, packet layout |
| ratchet_rotation_tests.rs | 5 | Rotation, interval, active link, multi-hop, link to ratcheted dest |
| stress_tests.rs | 5 | Concurrent links, rapid create/teardown, large payloads |
| flow_tests.rs | 4 | Complete roundtrip, discovery→link, multiple destinations |
| flood_tests.rs | 4 | Announce flood, triangle echo, diamond paths |
| ratchet_tests.rs | 4 | Ratcheted announce Rust→Python, Python→Rust, context flag |
| responder_tests.rs | 4 | Responder handshake, key derivation, bidirectional data |
| comprehensive_network_test.rs | 3 | Network setup, Rust→Python link, comprehensive test |
| harness.rs | 3 | Daemon start/respond, register destination, daemon restart |
| path_recovery_tests.rs | 2 | Announce propagation between daemons, path recovery on timeout |
| relay_integration_tests.rs | 2 | Mixed Python/Rust relay chain, diamond failure recovery |
| lifecycle_tests.rs | 1 | Full link lifecycle through relay |
| responder_node_tests.rs | 1 | Rust node as responder |
| rust_relay_tests.rs | 1 | Rust relay announce and link data |

All interop tests use `TestDaemon::start()` to spawn Python `scripts/test_daemon.py`. Both directions tested (Rust→Python: 100+, Python→Rust: 80+, bidirectional: 60+).

### 1E. reticulum-cli (31 tests)

| File | Count | What it tests | Setup pattern |
|------|-------|---------------|---------------|
| selftest.rs | 18 | selftest verdict logic, parse roundtrip, record_received | API + Manual |
| main.rs (or lib) | 13 | `display_app_data()` formatting: UTF-8, binary, msgpack, LXMF | Manual |

### 1F. reticulum-ffi (1 test, ignored)

| File | Count | What it tests | Setup pattern |
|------|-------|---------------|---------------|
| tests/ffi_c_tests.rs | 1 | C FFI bindings: compile + run C test program | Manual, `#[ignore]` |

---

## 2. Duplicate Groups

### 2A. Strict Duplicates (one test is a subset of another)

| Test A | Test B | Verdict |
|--------|--------|---------|
| hdlc `test_escape_flag_byte` | hdlc `test_frame_to_slice_with_escape` | Overlap: both test FLAG escaping. `test_escape_flag_byte` also tests deframe roundtrip, making it the more complete test. `test_frame_to_slice_with_escape` tests the slice API specifically, so marginally distinct. |
| hdlc `test_frame_roundtrip` | hdlc `test_python_vector_simple` | Overlap: both test frame+deframe of simple data. Python vector test additionally verifies exact byte output matches Python. `test_frame_roundtrip` is a subset of the Python vector tests combined. |
| identity `test_sign_empty_message` | identity `test_sign_large_message` | Near-duplicate: both test sign+verify with only input size varying. Both are trivially covered by `test_sign_verify` + proptest `test_identity_sign_verify_roundtrip`. |
| identity `test_encrypt_empty_plaintext` | identity `test_encrypt_single_byte` | Near-duplicate: both test encrypt+decrypt with only input size varying. Covered by proptest `test_identity_encrypt_decrypt_roundtrip` (range 0..500). |
| identity `test_encrypt_large_plaintext` | identity `test_multiple_encrypt_decrypt_cycles` | Near-duplicate: both test encrypt+decrypt with varied sizes. Covered by proptest. |
| aes_cbc `test_invalid_key_length` | aes_cbc `test_decrypt_invalid_key_length` | Same invariant (wrong key length) tested in both encrypt and decrypt direction. Distinct code paths, but the pattern is duplicated. |
| aes_cbc `test_invalid_iv_length` | aes_cbc `test_decrypt_invalid_iv_length` | Same as above for IV length. |
| node/mod.rs `test_send_no_path_returns_error` | node/mod.rs `test_send_reliable_no_path_returns_error` | Near-duplicate: both test send() with no path. Only difference: `reliable=false` vs `reliable=true`. |
| node/mod.rs `test_nodecore_handle_timeout_empty` | node/mod.rs `test_handle_timeout_empty_node` | Duplicate: both test handle_timeout() on empty node returns no events/actions. Different names, same test. |

### 2B. Near-Duplicate Groups (same behavior, trivially different inputs)

**Group 1: DestinationHash trait impl tests** (destination.rs, 12 tests)

`test_destination_hash_construction`, `test_destination_hash_into_bytes_roundtrip`, `test_destination_hash_from_array`, `test_destination_hash_display`, `test_destination_hash_debug`, `test_destination_hash_equality_with_raw`, `test_destination_hash_inequality`, `test_destination_hash_as_ref`, `test_destination_hash_borrow`, `test_destination_hash_ord`, `test_destination_hash_copy`, `test_destination_hash_btreemap_key`

These 12 tests test individual trait impls on a newtype wrapper. Each is 3-6 lines. Could be consolidated into 2-3 tests but each is trivial enough that consolidation adds no value.

**Group 2: Destination type validation tests** (destination.rs, 7 tests)

`test_plain_destination_cannot_have_identity`, `test_plain_destination_without_identity_succeeds`, `test_single_out_requires_identity`, `test_group_out_requires_identity`, `test_only_single_can_announce`, `test_single_in_can_announce`, `test_plain_out_allowed_without_identity`

All test the same constructor validation matrix. Could be a single parametrized test.

**Group 3: Proof strategy interop tests** (proof_tests.rs + link_manager_tests.rs)

- `test_python_prove_none_no_proof` + `test_channel_proof_generated_with_proof_strategy_none` (same behavior)
- `test_python_prove_all_sends_proof` + `test_prove_all_generates_proof_on_data_receive` (same behavior, different layers)

Each pair tests the same proof strategy from different angles (interop vs unit). Not strict duplicates because they exercise different code paths.

---

## 3. Repeated Setup Patterns

### 3A. Identity Creation

| Pattern | Count | Lines each | Helper exists? |
|---------|-------|------------|----------------|
| `Identity::generate(&mut OsRng)` | ~120 tests | 1 | No (it's already 1 line) |
| `Identity::from_public_key(bytes)` | ~40 tests | 1-3 | No |
| `Identity::from_private_key(bytes)` | ~15 tests (test_vectors.rs) | 3-5 | No |

No issue — Identity construction is already minimal.

### 3B. Channel Creation

| Pattern | Count | Lines each | Helper exists? |
|---------|-------|------------|----------------|
| `Channel::new(512)` then manual send/receive | 46 tests (channel/mod.rs) | 3-10 | No |

All 46 channel tests construct channels inline. The setup is 1-3 lines (new + optional send). No helper needed for the simple case.

### 3C. Link Pair Setup (Handshake)

| Pattern | Count | Lines each | Helper exists? |
|---------|-------|------------|----------------|
| Full handshake: 2 identities + outgoing + incoming + proof | 8 tests (link/mod.rs) | 35 | **Yes**: `setup_active_link_pair()` |
| Full manager handshake with event draining | 16 tests (link/manager.rs) | 52 | **Yes**: `establish_link_pair()` |
| Manual handshake (inline, not using helper) | 5 tests (link/mod.rs) | 30-67 | Helper exists but not used |

**Finding:** 5 tests in link/mod.rs manually duplicate the handshake flow that `setup_active_link_pair()` already provides: `test_full_handshake_simulation`, `test_link_encrypt_decrypt`, `test_link_decrypt_tampered`, `test_bidirectional_data_after_handshake`, `test_full_handshake_responder_side`. These predate the helper.

### 3D. Transport + Announce Setup

| Pattern | Count | Lines each | Helper exists? |
|---------|-------|------------|----------------|
| `Transport::new(config, clock, storage)` + `register_interface()` + `register_destination()` | ~80 tests (transport.rs) | 5-15 | **No** |
| Above + build announce + `handle_packet()` | ~40 tests (transport.rs) | 15-30 | **No** |

The 80+ transport tests each construct a Transport from scratch. The pattern is:
```rust
let clock = MockClock::new(1_000_000);
let storage = NoStorage;
let mut transport = Transport::new(TransportConfig::default(), &clock, &storage);
let iface0 = transport.register_interface(500, 0, false);
// ... register destination, build announce, etc.
```

This 5-15 line setup is repeated in every transport test with no shared helper.

### 3E. NodeCore Builder Setup

| Pattern | Count | Lines each | Helper exists? |
|---------|-------|------------|----------------|
| `NodeCoreBuilder::new().build(&mut OsRng, clock, storage)` | ~27 tests (node/mod.rs) | 3-8 | **No** (but builder is already short) |
| Above + register destination + build announce + inject | ~10 tests (node/mod.rs) | 15-30 | **No**, but `setup_pending_link()` covers a subset (4 tests) |

### 3F. MockClock Creation

| Pattern | Count | Lines each | Helper exists? |
|---------|-------|------------|----------------|
| `MockClock::new(1_000_000)` or similar | ~200+ tests across transport.rs, node/, channel | 1 | No (it's 1 line) |
| `MockClock` struct + `Cell<u64>` + `Clock` impl | Defined in transport.rs, node/mod.rs, node/builder.rs, traits.rs | 5-8 each | **Defined 4 times** |

**Finding:** `MockClock` is defined independently in 4 locations. The implementations are identical (`struct MockClock(Cell<u64>)` + `Clock` impl returning `self.0.get()`). Should be a single shared test utility.

### 3G. TestDaemon Setup (Interop)

| Pattern | Count | Lines each | Helper exists? |
|---------|-------|------------|----------------|
| `TestDaemon::start()` + connect + register_destination | 177 tests | 5-20 | **Yes**: `harness.rs` provides `TestDaemon` |
| `DaemonTopology::linear(n)` for multi-hop | ~15 tests | 3-5 | **Yes**: topology builder in harness |

The interop test infrastructure is well-factored. `TestDaemon` and `DaemonTopology` abstract daemon lifecycle.

### Setup Pattern Summary

| Pattern | Occurrences | Lines duplicated per test | Helper exists? |
|---------|-------------|--------------------------|----------------|
| MockClock definition | 4 separate defs | 5-8 | **No shared def** |
| Transport + interface + dest | ~80 | 5-15 | **No** |
| Transport + announce inject | ~40 | 15-30 | **No** |
| Link handshake (manual) | 5 | 30-67 | **Yes, unused** |
| Link manager handshake | 16 | 52 | **Yes, used** |
| NodeCore + dest + announce | ~10 | 15-30 | **Partial** (4 tests) |

---

## 4. Anti-Patterns

### 4A. Private Field Access in Tests

24 tests directly access private struct fields (`link.state`, `channel.window`, `channel.pacing_delay_ms`, `channel.srtt_ms`, `link.rtt_us`, etc.):

| File | Tests | Fields accessed |
|------|-------|----------------|
| link/mod.rs | 3 | `.state`, `.rtt_us` |
| link/manager.rs | 5 | `.links`, `.channels`, `.data_receipts` |
| link/channel/mod.rs | 16 | `.window`, `.pacing_delay_ms`, `.srtt_ms`, `.seq`, `.next_send_ms`, `.queue_len` |

These tests would break on any internal restructuring without indicating a real bug. The channel tests (16) are the most fragile — they directly assert internal pacing/SRTT state.

### 4B. Tests With No Meaningful Assertions

| Test | File | Issue |
|------|------|-------|
| `test_connection_stream_close_idempotent` | driver/stream.rs | Only asserts that calling close() twice doesn't panic |
| `test_reticulum_node_builder_creates_node` | driver/mod.rs | Only asserts the builder doesn't panic during construction |
| `test_create_instance` | reticulum.rs | Only asserts `Reticulum::new()` doesn't panic |

### 4C. Hardcoded Magic Numbers

Common unexplained constants in transport tests:

| Number | Meaning | Occurrences |
|--------|---------|-------------|
| 1_000_000 | Initial clock time (ms) | ~80 tests |
| 500 | Interface MTU | ~60 tests |
| 20_000 | Rebroadcast delay window | ~10 tests |
| 1600 | Receipt timeout (ms) | ~5 tests |
| 480_000 | Link table unvalidated expiry (ms) | ~5 tests |

These are protocol constants defined elsewhere (`constants.rs`), but the tests use raw numbers rather than referencing the constants.

### 4D. Very Large Tests (>80 LOC)

| Test | File | LOC | Issue |
|------|------|-----|-------|
| `test_retransmit_registers_new_receipt_and_removes_old` | link/manager.rs | 137 | Tests 3 retransmit cycles, receipt cleanup, AND delivery confirmation |
| `test_multiple_retransmits_clean_up_receipts` | link/manager.rs | 109 | Tests 3 retransmit cycles with receipt cleanup |
| `test_pending_link_recovery_rate_limited` | node/mod.rs | 86 | Tests rate limiting AND multiple path requests |
| `test_channel_proof_suppressed_on_rx_ring_full` | link/manager.rs | 84 | Tests proof suppression at rx_ring capacity |

These tests combine multiple concerns. The 137-line retransmit test exercises receipts, retransmission, cleanup, and delivery in a single function.

### 4E. Duplicate Test Names (Same Behavior)

| Test A | Test B | Status |
|--------|--------|--------|
| `test_nodecore_handle_timeout_empty` (node/mod.rs:1274) | `test_handle_timeout_empty_node` (node/mod.rs:1388) | **Exact duplicate** |
| `test_connection_new` (node/mod.rs:1322) | `test_connection_new` (node/connection.rs:132) | **Same name, different files**, testing same struct |

### 4F. `#[ignore]` Without Active Plan

| Test | File | Reason |
|------|------|--------|
| `test_c_identity_bindings` | reticulum-ffi/tests/ffi_c_tests.rs | `#[ignore = "FFI crate is outdated — will be redesigned after core stabilizes"]` |

Only one ignored test. The reason is documented and valid.

### 4G. Tests That Duplicate Production Logic

| Test | File | Issue |
|------|------|-------|
| `test_destination_hash` (test_vectors.rs) | test_vectors.rs | Manually recomputes `truncated_hash(name_hash + identity_hash)` to verify — this reimplements `Destination::hash()` logic |
| `test_announce_payload_parsing` (test_vectors.rs) | test_vectors.rs | Manually slices payload at hardcoded offsets (0..64, 64..74, etc.) — reimplements announce parsing |

These are vector tests, so the reimplementation serves as an independent verification. Acceptable pattern for interop validation.

---

## 5. Interop Test Summary

### Infrastructure

- **Python daemon:** `scripts/test_daemon.py` (1,080 lines)
- **Rust harness:** `reticulum-std/tests/rnsd_interop/harness.rs`
- **Run with:** `cargo test --package reticulum-std --test rnsd_interop`
- **Python:** Spawns real Python Reticulum instance per test
- **Communication:** TCP interface + JSON-RPC command channel (48 RPC methods)
- **Topology support:** `DaemonTopology::linear(n)`, `.star(n)` for multi-hop chains

### Direction Coverage

| Direction | Tests | Status |
|-----------|-------|--------|
| Rust → Python | 100+ | Full coverage |
| Python → Rust | 80+ | Full coverage |
| Rust ↔ Python bidirectional | 60+ | Full coverage |
| Rust ↔ Rust via Python relay | 40+ | Full coverage |

### Protocol Feature Coverage

| Feature | Interop tests | Coverage |
|---------|--------------|----------|
| Announces (propagation, dedup, hop counting) | 40+ | Excellent |
| Link establishment (handshake, encryption) | 50+ | Excellent |
| Data transfer (encrypted, large payload) | 40+ | Excellent |
| Transport/routing (path discovery, relay) | 60+ | Excellent |
| Proof strategy (none, app, all) | 10+ | Good |
| Ratchets (enable, rotate, in active link) | 10+ | Good |
| Keepalive/close | 11 | Good |
| Multi-hop relay chains (2-3 hops) | 15+ | Good |
| Error/edge cases (malformed, timeout, reconnect) | 15+ | Good |
| Stress (concurrent links, rapid fire) | 5 | Fair |

### Missing Protocol Features in Interop Tests

| Feature | Status |
|---------|--------|
| Resource transfers (segmented large data) | **Not tested** — Resource not yet implemented |
| Interface modes (AP, Roaming, Boundary) | **Not tested** — Not yet implemented |
| Shared instance | **Not tested** — No Rust shared instance concept |
| Group destinations | **Not tested** — Only SINGLE type exercised |
| Path request rate limiting across relays | **Not tested** |
| Announce rate limiting (per-destination) | Unit-tested only, no interop |

### Test Daemon RPC Methods (48 total)

Categories: core (2), path/route (5), destination (5), interface (3), announce (3), ratchet (3), link (7), proof (2), trace/debug (8), reverse (2), packet (5), other (3).
