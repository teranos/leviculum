# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

[Unreleased]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.1...HEAD
[0.2.1]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.0...v0.2.1
[0.2.0]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.1.0...v0.2.0
[0.1.0]: https://codeberg.org/Lew_Palm/leviculum/releases/tag/v0.1.0
