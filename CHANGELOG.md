# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.7] - 2026-02-04

### Added
- Transport interop test coverage: data echo through two relays, PATH_REQUEST dedup, link close verification through relay
- New test `test_path_request_forwarding_to_local_destination` for PATH_REQUEST forwarding to unannounced local destinations
- New test `test_path_request_dedup` verifying duplicate PATH_REQUEST suppression
- Identity table in Transport for storing identities extracted from announces
- Automatic announce cache response when a PATH_REQUEST arrives for a locally registered destination
- 15 new transport unit tests covering proof routing, hop validation, header stripping, interface cleanup, announce replay protection, and path request response

### Changed
- Move `proof_strategy` and `dest_signing_key` from `LinkManager`'s per-destination `DestinationEntry` to the `Link` struct, reducing duplicated state across components
- `LinkManager::accept_link()` now takes a `proof_strategy: ProofStrategy` parameter instead of reading it from destination registration
- Replace `LinkManager`'s destination tracking from `BTreeMap<DestinationHash, DestinationEntry>` to `BTreeSet<DestinationHash>` (acceptance-only, no metadata)
- `ReverseEntry` now tracks both `receiving_interface_index` and `outbound_interface_index` for correct bidirectional proof routing
- `PathEntry` now tracks `random_blobs` for announce replay detection
- `path_request_tags` changed from `Vec` to `VecDeque` for O(1) eviction of oldest entries
- Reverse table entries are now populated at forwarding time (in `forward_packet` and `handle_data`) instead of at receive time, ensuring the outbound interface is known

### Removed
- `LinkManager::register_destination_with_strategy()` — proof strategy is now passed at `accept_link()` time
- `LinkManager::proof_strategy()` query — proof strategy is now stored on the `Link` itself
- `DestinationEntry` struct from `LinkManager` — replaced by simple `BTreeSet`

### Fixed
- Fix PLAIN destination hash computation: was using `name_hash` padded with zeros instead of `full_hash(name_hash)[:16]`, causing PATH_REQUEST packets to use wrong destination hash and be silently ignored by Python Reticulum
- Set `mode = gateway` on test daemon's TCPServerInterface and dynamically-added TCPClientInterface, enabling PATH_REQUEST forwarding for unknown destinations
- Fix flaky `test_concurrent_links_through_relay` by switching from batch send to sequential per-link send+verify
- Fix 16 ignored doc-tests across reticulum-core and reticulum-std: 9 made fully runnable, 5 converted to compile-only (`no_run`), 1 made runnable (was `ignore`), 1 converted to `text` block (private function)
- Fix incorrect types in IFAC module doc example (`String` vs `&str`, missing `Result` handling)
- Fix missing `Message` trait import in `StreamDataMessage` doc example
- Add concrete values and self-contained examples to Channel/Envelope doc-tests
- Fix reverse table proof routing: proofs for regular (non-link) packets are now routed back via the reverse table, matching Python Reticulum behavior
- Fix announce retransmit delay: was scaling linearly with hop count (`(hops+1) * 1000ms`), now uses random jitter only (`0..PATHFINDER_RW`), matching Python Reticulum
- Fix missing hop count validation for link-routed packets: data and proof packets forwarded via the link table now verify hop count matches the expected value
- Fix LRPROOF (link proof) forwarding without size validation: link proofs are now checked for correct size (99 bytes) before forwarding
- Fix link request not stripped to Header Type 1 at final hop: when the destination is directly connected, the transport header is now removed before forwarding
- Fix link and reverse table entries not cleaned up when their interfaces go offline
- Fix announce replay not detected: announces with previously-seen random blobs are now rejected even if they bypass the packet cache and rate limit

## [0.2.6] - 2026-02-03

### Fixed
- Keepalive packets are no longer encrypted, matching Python Reticulum behavior — Python sends keepalive bytes as plaintext, so Rust's encrypted 64-byte payload was rejected by Python peers
- `test_multiple_daemon_announces` rewritten using high-level Node API to fix HDLC deframing issue that caused only 1 of 3 announces to be received

### Changed
- `Link::build_keepalive_packet()` no longer requires a `Context` parameter (no encryption/RNG needed)
- `Link::process_keepalive()` reads raw data directly instead of decrypting
- `LinkManager::check_keepalives()` no longer requires a `Context` parameter

## [0.2.5] - 2026-02-03

### Changed
- `DestinationHash` is now a newtype struct (like `LinkId`), providing compile-time distinction between destination hashes and raw byte arrays
- Removed `Deref<Target=[u8; 16]>` from both `LinkId` and `DestinationHash` for full type safety — use `.as_bytes()` or `.into_bytes()` for byte access
- `LinkId` is now a newtype struct instead of a type alias for `[u8; 16]`, providing compile-time distinction between link IDs and destination hashes
- Removed `as_bytes_mut()` from `DestinationHash` and `LinkId` — newtypes should be constructed, not mutated in place
- Replaced implicit `.into()` with explicit `DestinationHash::new()` in transport receipt creation
- Added `DestinationHash` import in `link/mod.rs`, replacing 7 fully-qualified paths
- Removed duplicate `compute_destination_hash` helpers in test code, using `Destination::compute_destination_hash()` instead
- Unified five separate packet queues in `LinkManager` into a single `PendingPacket` enum queue, simplifying `send_pending_packets()` from five separate drain loops into one match
- Moved timeout constants (`LINK_PENDING_TIMEOUT_MS`, `DATA_RECEIPT_TIMEOUT_MS`, `ANNOUNCE_RATE_LIMIT_MS`, `PACKET_CACHE_EXPIRY_MS`, `REVERSE_TABLE_EXPIRY_MS`) from module-local definitions to centralized `constants.rs`
- Replaced magic numbers `500` and `1` with `MTU` and `MODE_AES256_CBC` constants in proof packet construction
- Removed dead `LinkManagerExt` trait that always returned an empty iterator
- Improved code style: `get_or_insert_with` instead of manual `if/unwrap`, `let-else` instead of `if/unwrap`, clearer `expect` messages in AES-CBC
- Test daemon bind retry logic to handle TOCTOU races with parallel tests

### Removed
- `KeepaliveReceived` event from `LinkEvent` (keepalives are internal bookkeeping, not application-visible)
- `has_pending_rtt_packet()` from `LinkManager` (superseded by unified queue)
- Module-local timeout constants from `manager.rs` and `transport.rs` (moved to `constants.rs`)

## [0.2.4] - 2026-02-03

### Added
- Link-level data proof system with `ProofStrategy` support in `LinkManager`
- `LinkManager::register_destination_with_strategy()` for PROVE_ALL/PROVE_APP/PROVE_NONE
- `LinkManager::send_with_receipt()` for tracked data delivery with proof confirmation
- `LinkManager::send_data_proof()` for application-driven proof generation (PROVE_APP)
- `LinkEvent::DataDelivered` and `LinkEvent::ProofRequested` events
- `NodeEvent::LinkDeliveryConfirmed` and `NodeEvent::LinkProofRequested` events
- `Link::validate_data_proof()` and `Link::verify_peer_signature()` for proof validation
- `Link::create_data_proof_with_signing_key()` for proof generation
- `Identity::ed25519_signing_key()` getter for accessing the signing key
- `packet::packet_hash()` and `packet::truncated_packet_hash()` using correct hashable part
- `packet::get_hashable_part()` matching Python Reticulum's packet hash computation
- New interop tests for link-level data proofs (PROVE_ALL and PROVE_APP)
- Comprehensive network test module

### Changed
- Consolidate duplicate constants: remove `DATA_PROOF_SIZE` (use `PROOF_DATA_SIZE` from constants), remove local `MS_PER_SECOND` from transport
- Rename shadowing `PROOF_DATA_SIZE` (99 bytes, link establishment) to `LINK_PROOF_SIZE` to avoid confusion with `PROOF_DATA_SIZE` (96 bytes, data proof) in constants
- `LinkManager` destination tracking uses `BTreeMap` with `DestinationEntry` instead of `BTreeSet`

### Fixed
- Packet hash computation now uses hashable part (stripping routing info) instead of raw SHA256, matching Python Reticulum behavior
- Stricter test assertions: exact counts instead of minimum thresholds in link manager tests

## [0.2.3] - 2026-02-01

### Added
- High-level Node API in reticulum-core (`NodeCore`, `NodeCoreBuilder`)
- Unified event handling via `NodeEvent` enum
- `SendOptions` for controlling delivery (reliable/unreliable, compression)
- `Connection` abstraction wrapping Link + Channel
- Smart routing: automatic selection of single-packet vs Link/Channel
- `ReticulumNode` async wrapper in reticulum-std
- `ReticulumNodeBuilder` with TCP interface configuration
- `ConnectionStream` with async send/recv methods
- Three examples: `simple_send.rs`, `echo_server.rs`, `chat.rs`
- Integration tests for Node API (`node_api_tests.rs`) with 8 interop tests
- Symmetric Channel API: `Channel::receive_message<M: Message>()` for typed message reception
- `Envelope::unpack_body()` for extracting typed messages from envelopes

### Changed
- Consolidate buffer module into reticulum-core, removing redundant reticulum-std/buffer.rs
- Remove bzip2 crate dependency (now using no_std compatible libbz2-rs-sys exclusively)
- Simplify reticulum-std compression feature to just enable reticulum-core/compression
- Channel now tracks pending messages for symmetric send/receive pattern

### Fixed
- Inefficient vector initialization in compression module (clippy slow_vector_initialization)

## [0.2.2] - 2026-02-01

### Added
- StreamDataMessage (MSGTYPE 0xff00) for binary stream transfer over channels
- `StreamDataMessage` struct with wire-compatible format matching Python Reticulum
- Stream header encoding: 14-bit stream_id + compressed flag + EOF flag
- `Channel::send_system()` method for sending system messages (bypasses MSGTYPE validation)
- Buffer system in reticulum-std for stream I/O over channels
- `RawChannelReader` for receiving and buffering StreamDataMessage data
- `RawChannelWriter` for sending data as StreamDataMessage chunks
- `BufferedChannelWriter` implementing `std::io::Write` for convenient buffered sending
- BZ2 compression support via optional `compression` feature (enabled by default)
- Stream constants: `STREAM_DATA_MSGTYPE`, `STREAM_ID_MAX`, `STREAM_FLAG_COMPRESSED`, `STREAM_FLAG_EOF`
- Channel system for reliable, ordered message delivery over Links
- `Channel` struct with window-based flow control and automatic retransmission
- `Message` trait for typed channel messages with pack/unpack
- `Envelope` for wire format (msgtype + sequence + length + data)
- `ChannelAction` enum for retransmit and tear-down actions
- `LinkManager::channel_send()` and `get_channel()` for channel access
- `LinkEvent::ChannelMessageReceived` for incoming channel messages
- `Link::rtt_ms()` helper for RTT in milliseconds with default fallback
- Channel constants: window sizes, RTT thresholds, timeout parameters
- Packet proof system for cryptographic delivery confirmation
- `ProofStrategy` enum with `None`, `App`, `All` variants (0x21, 0x22, 0x23)
- `Destination::proof_strategy()` getter and `set_proof_strategy()` setter
- `Identity::create_proof()` for generating proofs (packet hash + signature)
- `Identity::verify_proof()` for validating incoming proofs
- `PacketReceipt` module for tracking sent packets awaiting proof
- `ReceiptStatus` enum (Sent, Delivered, Failed)
- `TransportEvent::ProofRequested` for PROVE_APP callback
- `TransportEvent::ProofReceived` when proof arrives
- `TransportEvent::ReceiptTimeout` when receipt expires
- `Transport::send_proof()` for app-driven proof generation
- `build_proof_packet()` for constructing proof packets
- Proof-related constants: `PROVE_NONE`, `PROVE_APP`, `PROVE_ALL`, `PROOF_DATA_SIZE`, `RECEIPT_TIMEOUT_DEFAULT_MS`
- Test daemon RPC methods: `set_proof_strategy`, `get_proof_strategy`
- New test module `proof_tests` with 9 interop tests
- `ifac_flag` field in `PacketFlags` for Interface Access Code support at packet level
- Embedded target documentation (`doc/EMBEDDED_TARGETS.md`) with Meshtastic device reference
- Build infrastructure for embedded targets (`rust-toolchain.toml`, `.cargo/config.toml`)
- `scripts/check-embedded.sh` for verifying `reticulum-core` compiles on ARM targets
- `ratchet` module for forward secrecy key management
- `Ratchet` struct with X25519 key pair generation and ECDH
- `KnownRatchets` for tracking remote destination ratchets
- `Identity::encrypt_for_destination()` with optional ratchet support
- `Identity::decrypt_with_ratchets()` for trying multiple ratchets
- `Destination::enable_ratchets()` for forward secrecy on IN destinations
- `Destination::encrypt()` and `Destination::decrypt()` with ratchet support
- New interop test modules: `edge_case_tests`, `multihop_tests`, `ratchet_tests`, `ratchet_rotation_tests`, `stress_tests`
- Shared `TestClock` and `make_context()` in test common module
- Link keepalive mechanism with initiator sending 0xFF and responder echoing 0xFE
- `Link::build_keepalive_packet()` and `Link::process_keepalive()` for keepalive exchange
- RTT-based keepalive interval calculation matching Python formula
- Link stale detection with configurable timeout (`is_stale()`, `should_close()`)
- `LinkEvent::LinkStale` and `LinkEvent::KeepaliveReceived` events
- Graceful link close with encrypted LINKCLOSE packets (`build_close_packet()`, `process_close()`)
- `LinkManager::close()` with packet generation and `close_local()` for local-only close
- `LinkManager::drain_keepalive_packets()` and `drain_close_packets()` for pending packets
- `LinkManager::poll()` now checks keepalives, stale links, and close timeouts
- Test daemon RPC methods: `close_link`, `get_link_status`, `wait_for_link_state`
- New test module `link_keepalive_close_tests` with 11 interop tests including multi-hop scenarios

### Changed
- Replace magic numbers with named constants in channel timeout calculation
- Reduce code duplication in `LinkManager` by using `Link::rtt_ms()` helper
- Box `Packet` in `TransportEvent::PacketReceived` to reduce enum size
- Remove unnecessary `async` from `Reticulum::new()` and `Reticulum::with_config()`
- Extract `build_signed_data()` helper in `announce.rs` to reduce code duplication
- Consolidate `wait_for_link_request()`, `wait_for_rtt_packet()`, `wait_for_data_packet()` helpers into `common.rs`
- Standardize test infrastructure naming (`TestClock`, `make_context()`)

### Fixed
- Clippy pedantic warnings: uninlined format args, match same arms, manual let-else, unused async
- Inefficient ratchet trimming using while-loop replaced with `truncate()`
- Add bounds validation for `set_retained_ratchets()` (minimum 1) and `set_ratchet_interval()` (minimum 1000ms)
- `wait_for_data_packet()` now correctly returns raw packet for callers needing full packet structure

## [0.2.1] - 2026-01-30

### Added
- IFAC (Interface Access Code) module for interface-level authentication
- `IfacConfig` struct with key derivation from netname/netkey
- `apply_ifac()` for outbound packet masking
- `verify_ifac()` for inbound packet verification
- IFAC_SALT and size constants
- Python test vector generation for IFAC
- 21 tests (16 unit tests + 5 interop tests against Python Reticulum)

## [0.2.0] - 2026-01-30

### Added
- `Destination::announce()` API for announce creation
- Link responder: accept incoming links
- `LinkManager` high-level API with `initiate()`, `send()`, `close()`
- Event system via `drain_events()`
- Link timeout handling via `poll()`

### Changed
- Phase 2 approximately 75% complete

## [0.1.0] - 2025-XX-XX

### Added
- Cryptography (AES, SHA, HMAC, HKDF, Token)
- Identity management (key pairs, signatures, encrypt/decrypt)
- Packet structures (all types, Header 1/2)
- Announce creation and validation
- Link state machine (initiator)
- HDLC framing (no_std + alloc)
- TCP client interface
- Async runtime (Tokio wrapper)
- Transport layer (routing, paths, deduplication)
- Full interoperability with Python rnsd

[Unreleased]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.7...HEAD
[0.2.7]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.6...v0.2.7
[0.2.6]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.5...v0.2.6
[0.2.5]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.4...v0.2.5
[0.2.4]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.3...v0.2.4
[0.2.3]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.2...v0.2.3
[0.2.2]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.1...v0.2.2
[0.2.1]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.0...v0.2.1
[0.2.0]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.1.0...v0.2.0
[0.1.0]: https://codeberg.org/Lew_Palm/leviculum/releases/tag/v0.1.0
