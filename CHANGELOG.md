# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.4...HEAD
[0.2.4]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.3...v0.2.4
[0.2.3]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.2...v0.2.3
[0.2.2]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.1...v0.2.2
[0.2.1]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.0...v0.2.1
[0.2.0]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.1.0...v0.2.0
[0.1.0]: https://codeberg.org/Lew_Palm/leviculum/releases/tag/v0.1.0
