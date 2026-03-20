# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-03-20

### Added
- Link request retry (E34) — 3 attempts on establishment timeout with exponential backoff
- Proof re-send on duplicate link request for shared medium resilience
- 3-node shared medium LoRa integration tests (bidirectional, contention, transfer)
- LoRa test coverage: size sweep, frame loss, link-under-loss, bidirectional, 16-test cross-impl matrix
- Proxy rule `max_size`, `min_size`, and `skip` filters for targeting specific packet types
- File transfer test framework: fetch mode, auth, negative testing, jail violation tests
- `lncp` fetch mode (`-f`, `-F`, `-j`) with jail path restriction and identity-based auth
- `lncp` physical layer rate display (`-P`), compression toggle (`-C`), silent flag (`-S`)
- `lncp` standalone binary — shared instance client for rncp-compatible file transfer via Unix socket
- Link request/response protocol for single-packet RPC over established links
- Link identity verification (`link.identify()`) with Ed25519 signature proof
- Resource transfer progress display with real-time speed and percentage
- Send queue priority for LoRa — link traffic before announces on half-duplex interfaces
- First-hop timeout for link establishment on slow interfaces (LoRa airtime-aware)
- RTT packet retry for LoRa — up to 5 retries, confirmed by inbound traffic
- Discovery path request with retry for LoRa resilience
- Interface backpressure with retry queue and congestion flag for LoRa buffer management
- Per-hop link establishment timeout scaling with hop count
- Reduced responder handshake timeout from 360s to 54s (RTT retry makes long waits unnecessary)
- Env-var radio overrides (`LORA_BANDWIDTH`, `LORA_SF`, `LORA_TIMEOUT_SCALE`) for LoRa test profiles
- 10-node dual-cluster LoRa integration tests and late-announce escalation tests (2-10 nodes)
- Ratchet selftest modes, integration tests, and disk persistence (Python-compatible msgpack)
- Local client destination expiry after 6 hours
- Negative assertion support (`expect_result = "no_path"/"fail"`) in integration tests
- Shared instance: registration delay, reconnect re-announce, fresh path response, interface recovery
- Link failure simulation via iptables (`block_link`/`restore_link`) with recovery test
- Docker-based integration test framework (`reticulum-integ`) with TOML-defined scenarios
- Re-announce on new TCP peer connection to prevent startup races
- RPC server for Python CLI tool compatibility (`rnstatus`, `rnpath`, `rnprobe`)
- Probe responder, per-interface I/O counters, announce frequency tracking
- LocalInterface (Unix socket IPC) with local client routing gates
- AutoInterface zero-config LAN discovery via IPv6 multicast (7 integration tests)
- SIGUSR1 diagnostic dump (memory summary of all protocol collections + RSS)

### Fixed
- Resource retransmit timing matched to Python — adaptive timeout, progressive backoff, grace times
- Receiver retransmit REQ rebuilt with only missing parts (was re-requesting already-received data)
- Resource retransmit timeout not resetting between retries (all fired immediately)
- Shared-instance resource retransmissions blocked by packet dedup
- Multi-segment resource receive (E31) — dynamic buffer, correct hashmap length, metadata parsing
- `lncp` listener rejected incoming links (missing `set_accepts_links(true)`)
- Resource API action draining — ADV/REQ packets dispatched immediately
- RNode serial heartbeat fixes idle-correlated LoRa failures after 12+ min silence
- Channel RTT=0 retransmit storm — SRTT seeded to 5000ms with LoRa-appropriate pacing
- Selftest no longer overwrites daemon's transport_identity
- Re-originate path requests instead of forwarding (matches Python, fixes multi-hop interop)
- Hops incremented on receipt matching Python — direct neighbors are hops=1
- Cached announce forwarding to local clients (Header1-to-Header2 conversion)
- Path request response for local clients (transport gate, routing, delay fixes)
- AutoInterface peer identity, source port, ephemeral ports, link-local discovery
- Announce replay allows better-hop paths; rate-limited announces still update path table
- Vendored Python RNS `ingress_control` inheritance fix and update to 1.1.4

### Changed
- Jitter ceiling is now airtime-based; announce collision fixes with 3 retries and exponential backoff
- Renamed `WindowFull` to `Busy` across all error types
- Storage trait refactoring — all Transport/NodeCore collections behind type-safe Storage trait
- `MemoryStorage` as production embedded impl, `FileStorage` wraps it with persistence
- Immediate announce rebroadcast (removes ~600ms per-hop latency)
- FileStorage packet_cache switched to HashSet; default identity cap lowered to 50k

## [0.5.19] - 2026-02-15

### Fixed
- Pacing interval used handshake RTT instead of measured SRTT

## [0.5.18] - 2026-02-15

### Changed
- Live timeout computation using current queue length instead of frozen send-time values
- Smoothed RTT (SRTT) from proof round-trips using RFC 6298 with Karn's algorithm
- `CHANNEL_MAX_TRIES` increased from 5 to 8; first retransmit skips pacing decrease

## [0.5.17] - 2026-02-14

### Added
- Sender-side pacing with AIMD congestion control — even spacing across RTT instead of burst-until-busy

## [0.5.16] - 2026-02-14

### Fixed
- Retransmitted messages permanently rejected when proof lost (sequence wrap-around)

## [0.5.15] - 2026-02-14

### Fixed
- Channel retransmissions never triggered — unified duplicate Channel instances into one per link

## [0.5.14] - 2026-02-13

### Fixed
- ConnectionStream silently dropped messages when busy — now returns WouldBlock
- Selftest closed links before messages confirmed; burst counted Busy as permanent failure

## [0.5.13] - 2026-02-13

### Fixed
- `/peers` hop count always showing `?` and garbled app_data from Python msgpack formats

## [0.5.12] - 2026-02-12

### Added
- `PacketEndpoint` handle for single-packet fire-and-forget destinations

### Fixed
- Single-packet delivery broken through relays — Type1-to-Type2 conversion for relay paths

## [0.5.11] - 2026-02-12

### Changed
- `Identity::encrypt()` returns `Result` instead of panicking on failure
- Selective re-exports from `reticulum-std` instead of `pub use reticulum_core::*`

## [0.5.10] - 2026-02-12

### Changed
- `ConnectionStream` is send-only — received data delivered exclusively via `NodeEvent`

## [0.5.9] - 2026-02-12

### Fixed
- Channel data proofs not generated on responder (signing key gated on proof strategy)
- Channel data proofs not generated on initiator (wrong signing key consulted)

## [0.5.8] - 2026-02-12

### Added
- `lns connect` interactive CLI for diagnostics, link management, and data exchange

### Fixed
- Stale-to-Active link recovery on inbound traffic (matching Python)

## [0.5.6] - 2026-02-11

### Fixed
- `MessageReceived` events silently dropped — Channel data never reached `ConnectionStream`

## [0.5.5] - 2026-02-11

### Fixed
- Link-addressed Data and proof packets dropped on non-transport nodes
- Channel `mark_delivered()` never called — full proof delivery chain now works
- `ConnectionStream::close()` did not send LINKCLOSE

## [0.5.4] - 2026-02-11

### Fixed
- `PathRequestReceived` emitted incorrect `PathFound` event with fabricated data

## [0.5.3] - 2026-02-11

### Fixed
- Multi-hop link initiation from non-transport nodes (wrong header format)
- LRPROOF delivery to local pending links (silently dropped)

## [0.5.2] - 2026-02-11

### Fixed
- 4 hop off-by-one bugs in forwarding thresholds (Python/Rust hop semantics mismatch)

## [0.5.1] - 2026-02-11

### Fixed
- Multi-hop link forwarding through mixed relay chains (premature header stripping, wrong transport_id)

## [0.5.0] - 2026-02-11

### Changed
- All `NodeCore` mutation methods return `TickOutput` for immediate action dispatch

## [0.4.4] - 2026-02-10

### Added
- Per-destination announce rate limiting matching Python (violation/grace/penalty)

## [0.4.3] - 2026-02-10

### Fixed
- Path rediscovery was dead code — event handler was empty

## [0.4.2] - 2026-02-09

### Added
- Path recovery mechanism — expired links trigger path rediscovery with unresponsive state

## [0.4.1] - 2026-02-08

### Added
- `NodeCore::announce_destination()` for broadcasting registered destinations

### Fixed
- Outbound packets not cached for dedup — node learned paths to itself via echo

## [0.4.0] - 2026-02-07

### Added
- `reticulum-nrf` embedded skeleton for Heltec Mesh Node T114 (nRF52840 + SX1262)
- Channel-based `InterfaceHandle`/`InterfaceRegistry`; async `select!` event loop

## [0.3.1] - 2026-02-06

### Fixed
- `send_on_connection()` dropped first packet; `connect()` link request never sent

## [0.3.0] - 2026-02-06

### Changed
- Sans-I/O architecture — `handle_packet()`, `handle_timeout()`, `Action` enum; driver owns I/O
- `Context` trait removed — all functions take direct `rng` and `now_ms` parameters

## [0.2.8] - 2026-02-04

### Fixed
- `enable_transport` not wired; relay hop count, destination hash, proof routing, announce replay

## [0.2.6] - 2026-02-03

### Fixed
- Keepalive packets encrypted instead of plaintext (rejected by Python peers)

## [0.2.5] - 2026-02-03

### Added
- Link-level data proof system (PROVE_ALL/PROVE_APP/PROVE_NONE)

### Changed
- `DestinationHash` and `LinkId` are now newtypes; unified packet queues in `LinkManager`

## [0.2.3] - 2026-02-01

### Added
- High-level Node API (`NodeCore`, `NodeCoreBuilder`, `ReticulumNode`, `ConnectionStream`)
- Channel system, packet proofs, ratchets, IFAC, link keepalive, graceful close

## [0.2.0] - 2026-01-30

### Added
- `Destination::announce()`, link responder, `LinkManager` API, event system

## [0.1.0] - 2025-XX-XX

### Added
- Cryptography, identity, packets, announce, link state machine, HDLC framing, TCP, transport
- Full interoperability with Python rnsd

[0.6.0]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.19...v0.6.0
[0.5.19]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.18...v0.5.19
[0.5.18]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.17...v0.5.18
[0.5.17]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.16...v0.5.17
[0.5.16]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.15...v0.5.16
[0.5.15]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.14...v0.5.15
[0.5.14]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.13...v0.5.14
[0.5.13]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.12...v0.5.13
[0.5.12]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.11...v0.5.12
[0.5.11]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.10...v0.5.11
[0.5.10]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.9...v0.5.10
[0.5.9]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.8...v0.5.9
[0.5.8]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.6...v0.5.8
[0.5.6]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.5...v0.5.6
[0.5.5]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.4...v0.5.5
[0.5.4]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.3...v0.5.4
[0.5.3]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.2...v0.5.3
[0.5.2]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.1...v0.5.2
[0.5.1]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.0...v0.5.1
[0.5.0]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.4.4...v0.5.0
[0.4.4]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.4.3...v0.4.4
[0.4.3]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.4.2...v0.4.3
[0.4.2]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.4.1...v0.4.2
[0.4.1]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.4.0...v0.4.1
[0.4.0]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.3.1...v0.4.0
[0.3.1]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.3.0...v0.3.1
[0.3.0]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.8...v0.3.0
[0.2.8]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.6...v0.2.8
[0.2.6]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.5...v0.2.6
[0.2.5]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.3...v0.2.5
[0.2.3]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.0...v0.2.3
[0.2.0]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.1.0...v0.2.0
