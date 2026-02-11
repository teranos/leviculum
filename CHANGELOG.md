# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.5] - 2026-02-11

### Fixed
- **Link-addressed Data packets dropped on non-transport nodes** (C8) — `Transport::handle_data()` silently dropped link-addressed Data packets when `enable_transport` was false and the link ID wasn't in `destinations`. This blocked all incoming link data, keepalive echoes, LINKCLOSE, and channel ACKs from reaching `LinkManager`. Now emits `TransportEvent::PacketReceived` for link-addressed packets, matching Python Transport.py:1969-1994.
- **Link-addressed data proofs dropped on non-transport nodes** — `Transport::handle_proof()` only routed LRPROOF (link establishment) proofs to local links, silently dropping data proofs (96 bytes, context=None). Broadened the fallthrough to catch all link-addressed proofs, enabling channel ACK delivery.
- **Channel `mark_delivered()` never called** (C9) — Channel messages accumulated in the TX ring because: (1) the receiver never generated proofs for CHANNEL packets, (2) the sender never registered data receipts for channel messages, and (3) the `DataDelivered` event handler didn't call `mark_delivered()`. Now the full proof delivery chain works: receiver generates proof unconditionally (matching Python Link.py:1173), sender registers receipts with sequence mapping, and `DataDelivered` calls `mark_delivered()` to remove from the TX ring.
- **`ConnectionStream::close()` didn't send LINKCLOSE** (D12) — `close()` only set a local flag without signaling the core. Now sends an empty-data sentinel through the outgoing channel, which the event loop dispatches as `NodeCore::close_connection()`.

### Added
- Interop test `test_full_link_lifecycle_through_relay` — end-to-end lifecycle test exercising all three v0.5.5 fixes through a Python relay: bidirectional data delivery (Fix 1), channel ACK delivery confirmations (Fix 2), graceful close from both Rust and Python sides (Fix 3)
- `Channel::last_sent_sequence()` for tracking the most recently sent channel sequence number
- `Connection::last_sent_sequence()` delegate for accessing channel sequence from the node layer
- `LinkManager::register_data_receipt()` for external receipt registration (used by NodeCore for channel messages)
- `ReticulumNodeImpl::close_connection()` for graceful link teardown from the driver layer
- `NodeCore::channel_hash_to_seq` mapping for correlating data proofs with channel sequences

## [0.5.4] - 2026-02-11

### Fixed
- **PathRequestReceived emitted incorrect PathFound event** — when a remote node requested the path to a local destination, `NodeCore` emitted `NodeEvent::PathFound { hops: 0, interface_index: 0 }` with fabricated data. Applications receiving this would incorrectly believe a direct path existed. Replaced with a proper `NodeEvent::PathRequestReceived` that correctly identifies the event as informational (auto-re-announce is handled internally by the transport layer).
- **TCPServerInterface silently discarded** — calling `add_tcp_server()` on the builder would silently skip server creation at startup with only a warning log. Now returns `Error::Config` so callers know the feature is not yet implemented (see ROADMAP Milestone 2.4).

### Added
- `NodeEvent::PathRequestReceived { destination_hash }` variant for informational path request events
- MTU signaling added to ROADMAP "Kleinere Lücken" (non-blocking for v1.0)

### Changed
- All orphaned TODOs now reference ROADMAP items
- Removed "for now" / "silently ignore" language from 5 comments across core and std, replacing with explanations of the intentional design decisions

## [0.5.3] - 2026-02-11

### Fixed
- **Multi-hop link initiation from non-transport nodes** — `connect()` used `None` for `next_hop` even on multi-hop paths, causing link requests to use HEADER_1 (direct) instead of HEADER_2 (transport) format. Relays couldn't forward the link request because it lacked the transport_id. Now uses `PathEntry::needs_relay()` to select the correct header format and passes the relay's transport_id.
- **LRPROOF delivery to local pending links** — Link proofs returning to the initiator on non-transport nodes were silently dropped at the end of `process_incoming_packet()`. Added LRPROOF delivery path that caches the packet and emits a `PacketReceived` event, matching Python Transport.py:2054-2073.

### Changed
- Path recovery interop test redesigned — replaced relay-kill topology with LRPROOF-dropping approach that keeps TCP alive, directly exercising the `expire_path()` + `request_path()` timeout handler without interference from `handle_interface_down()`

### Added
- LRPROOF drop/restore RPCs in test daemon for targeted packet dropping in interop tests
- Channel message support (`RawBytesMessage`) in test daemon for Rust-Python channel communication
- Packet tracing and debugging RPCs in test daemon (`enable_inbound_trace`, `enable_lrproof_trace`, `get_link_table_detail`)

## [0.5.2] - 2026-02-11

### Fixed
- **4 hop off-by-one bugs in forwarding thresholds** — Python increments `packet.hops += 1` on receipt (Transport.py:1319), so "directly connected" = `hops == 1` in Python but `hops == 0` in Rust. Thresholds copied from Python without adjusting for this difference were wrong:
  1. PLAIN/GROUP packet filter used `hops > 1` instead of `hops > 0` — allowed 1-hop PLAIN/GROUP packets through instead of dropping them (only direct neighbors should receive these)
  2. `clean_link_table` destination proximity check used `hops_to() == Some(1)` instead of `Some(0)` — failed to mark directly-connected destinations as unresponsive on link expiry
  3. `clean_link_table` initiator proximity check used `entry.hops == 1` instead of `entry.hops == 0` — failed to mark directly-connected initiators as unresponsive
  4. `clean_link_table` local-client sub-case (`entry.hops == 0`) was missing `mark_path_unresponsive()` call — merged with the initiator sub-case after fix

### Added
- `PathEntry::is_direct()` — returns true when destination is directly connected (hops == 0), preventing future off-by-one bugs by encoding the Python/Rust hop semantics difference in one place
- `PathEntry::needs_relay()` — returns true when destination requires relay forwarding and next hop is known (hops > 0 && next_hop is Some)

### Changed
- Refactored `handle_link_request` and `forward_packet` to use `PathEntry::needs_relay()` instead of raw hop comparisons — eliminates local `remaining_hops`/`next_hop` variables and makes forwarding logic self-documenting
- Merged `clean_link_table` sub-cases: old 4-case structure (path missing, local client, 1-hop dest, 1-hop initiator) simplified to 3 cases (path missing, dest is_direct, initiator direct) with consistent `mark_path_unresponsive` behavior

## [0.5.1] - 2026-02-11

### Fixed
- **Multi-hop link request forwarding failed through mixed Rust/Python relay chains** — two bugs in `handle_link_request` and `forward_packet`:
  1. HEADER_1 stripping threshold was `remaining_hops <= 1` instead of `remaining_hops == 0`. Python increments hops on receipt (Transport.py:1319), Rust does not — so Rust's `hops == 0` corresponds to Python's `hops == 1` (directly connected). The off-by-one caused premature stripping one hop too early, dropping the transport header before the packet reached the final relay.
  2. Intermediate-hop `transport_id` was set to the forwarding relay's own identity hash instead of `path.next_hop` (the next relay's identity). The next relay checks `transport_id == own_identity` (Transport.py:1428) and ignored packets addressed to the wrong relay.
- Same threshold bug fixed in `forward_packet` for general data packet forwarding
- 3 unit tests updated from testing buggy behavior to testing correct behavior: `PathEntry` fixtures now include proper `next_hop` values, and stripping threshold assertions match `remaining_hops == 0`

### Added
- `TestDaemon::restart()` for killing and restarting a Python test daemon on the same ports (enables relay failure/recovery testing)
- 2 comprehensive relay integration tests (`relay_integration_tests` module):
  - `test_diamond_relay_and_failure_recovery` — single Rust relay bridging two Python daemons with bidirectional link+data, then relay failover to a second Rust relay with path recovery
  - `test_mixed_python_rust_relay_chain` — 3-hop mixed chain (Py-A ↔ Rust-R ↔ Py-M ↔ Py-B) verifying announce propagation, hop counts, link establishment, and data delivery through both relay types

## [0.5.0] - 2026-02-11

### Changed
- **Breaking:** `NodeCore::connect()` returns `(LinkId, TickOutput)` instead of `LinkId` — actions are flushed and returned immediately
- **Breaking:** `NodeCore::accept_connection()` returns `Result<TickOutput, ConnectionError>` instead of `Result<(), ConnectionError>`
- **Breaking:** `NodeCore::close_connection()` returns `TickOutput` instead of `()`
- **Breaking:** `NodeCore::send_on_connection()` returns `Result<TickOutput, SendError>` instead of `Result<(), SendError>`
- **Breaking:** `NodeCore::send_single_packet()` returns `Result<([u8; 16], TickOutput), SendError>` instead of `Result<[u8; 16], SendError>`
- **Breaking:** `NodeCore::announce_destination()` returns `Result<TickOutput, AnnounceError>` instead of `Result<(), AnnounceError>`
- **Breaking:** `ReticulumNodeImpl::announce_destination()` returns `Result<(), Error>` instead of `Result<(), AnnounceError>` — the driver-level method now propagates dispatch failures alongside core errors
- `TickOutput` now implements `Default` (replaces manual `empty()` constructor for trait compliance)
- Event loop Branch 2 (`send_on_connection`) no longer uses `handle_timeout()` as a flush workaround — dispatches returned `TickOutput` directly

### Added
- `TickOutput::merge()` for combining multiple outputs when batching operations
- `action_dispatch_tx` channel in std driver for dispatching `TickOutput` from `connect()` and `announce_destination()` (called outside the event loop) to the event loop for immediate interface dispatch

### Removed
- `pending_connects` mechanism from std driver — dead scaffolding that was never wired up (oneshot sender never used, entries never removed, orphaned tasks on every `connect()` call)
- "Deferred dispatch" docstrings from the six affected methods — callers now receive actions directly instead of relying on a subsequent `handle_timeout()` to flush them

## [0.4.4] - 2026-02-10

### Added
- **Per-destination announce rate limiting** matching Python Transport.py:1692-1719 — tracks violations when a destination announces too frequently and blocks rebroadcast after exceeding a configurable grace threshold, with optional penalty-based blocking window extension
- `AnnounceRateEntry` struct for per-destination rate tracking (violations, blocking window)
- `TransportConfig` fields: `announce_rate_target_ms` (None = disabled, default), `announce_rate_grace`, `announce_rate_penalty_ms`
- `Transport::check_announce_rate()` implementing the Python violation/grace/penalty escalation algorithm
- `Transport::clean_announce_rate_table()` for cleanup during `poll()` (removes entries for expired paths)
- `Transport::announce_rate_table_count()` public accessor for stats/testing
- `ANNOUNCE_RATE_GRACE` and `ANNOUNCE_RATE_PENALTY_MS` constants
- 10 new transport unit tests covering rate acceptance, grace-exceeded blocking, penalty extension, per-destination independence, violation decrement, recovery after block expiry, disabled-by-default behavior, PATH_RESPONSE exemption, table cleanup, and last_ms anchoring

## [0.4.3] - 2026-02-10

### Fixed
- **Path rediscovery was dead code** — `TransportEvent::PathRediscoveryNeeded` was emitted by `clean_link_table()` but the node layer had an empty match arm and no driver handler existed, so path rediscovery never actually triggered. Now `request_path()` is called directly from core during link table cleanup, making the path recovery mechanism from v0.4.2 functional.

### Removed
- `TransportEvent::PathRediscoveryNeeded` variant — path rediscovery is now handled entirely within core via direct `request_path()` calls, eliminating the unnecessary core/driver boundary crossing

## [0.4.2] - 2026-02-09

### Added
- **Path recovery mechanism** matching Python Reticulum's `Transport.py:618-699` — when unvalidated link entries expire, the transport layer marks paths as unresponsive and triggers path rediscovery
- `PathState` enum (`Unknown`, `Unresponsive`, `Responsive`) for tracking path quality
- Path state API: `mark_path_unresponsive()`, `mark_path_responsive()`, `mark_path_unknown_state()`, `path_is_unresponsive()`, `expire_path()`
- `TransportEvent::PathRediscoveryNeeded` for signalling the driver to issue `request_path()` on appropriate interfaces, with optional `blocked_iface` to exclude the failed interface
- Unresponsive path acceptance in `handle_announce()`: when a path is marked unresponsive, same-emission announces with higher hop counts are accepted as alternative routes
- Automatic path state reset to `Unknown` when a normal announce updates the path table
- Orphan `path_states` cleanup during `poll()` for destinations no longer in `path_table`
- `destination_hash` field in `LinkEntry` for path rediscovery (link table keys are link IDs, not destination hashes)
- Path rediscovery sub-cases in `clean_link_table()`: missing path, local client link, 1-hop destination, 1-hop initiator — each with appropriate `mark_path_unresponsive` and `blocked_iface` behavior
- Non-transport nodes call `expire_path()` on unvalidated link expiry to allow accepting higher-hop-count announces
- 15 new transport unit tests covering the full path recovery mechanism

## [0.4.1] - 2026-02-08

### Added
- `NodeCore::announce_destination()` for broadcasting registered destinations on all interfaces, with deferred dispatch via the Action system
- `ReticulumNodeImpl::announce_destination()` driver-level wrapper for the new core API
- `AnnounceError::PacketTooLarge` and `AnnounceError::DestinationNotFound` error variants
- 4 flood/loop prevention interop tests (`flood_tests` module): triangle echo prevention, diamond originator echo, diamond link redundant paths, announce destination smoke
- Unit test `test_send_on_all_interfaces_caches_packet_for_dedup` for outbound dedup cache

### Fixed
- **Outbound packets not cached for dedup** — `send_on_all_interfaces()` did not add the packet hash to `packet_cache`, so echoes returning via redundant network paths were processed instead of dropped, causing the node to learn a path to itself. Now matches Python Reticulum's `Transport.py:1168-1169`.

## [0.4.0] - 2026-02-07

### Added
- **`reticulum-net` crate** — new `no_std + alloc` crate with shared interface data types (`IncomingPacket`, `OutgoingPacket`, `InterfaceInfo`, `InterfaceKind`) for the boundary between interface tasks and the event loop
- **`reticulum-nrf` embedded skeleton** — Embassy-based firmware crate for Heltec Mesh Node T114 (nRF52840 + SX1262) with complete pin mappings and heartbeat firmware
- **USB composite CDC-ACM** in `reticulum-nrf` — two USB serial ports (debug log output + Reticulum transport placeholder) replacing defmt/RTT, enabling probeless debug logging via `picocom /dev/ttyACM0`
- `info!`/`warn!` logging macros for embedded firmware — fixed 256-byte messages, bounded channel (capacity 16), non-blocking `try_send`, no heap allocation in the log path
- FICR-based unique USB serial number from nRF52840 factory-programmed device ID
- udev rules (`udev/99-leviculum.rules`) for stable `/dev/leviculum-debug` and `/dev/leviculum-transport` symlinks
- `tools/flash-and-read.sh` — flash firmware and verify debug output against expected pattern with configurable timeout
- Smart USB port detection in `tools/uf2-runner.sh` — identifies debug and transport ports by VID:PID (`1209:0001`) and USB interface number
- `InterfaceHandle` and `InterfaceRegistry` in `reticulum-std` — channel-based interface dispatch replacing the previous enum-based `AnyInterface`/`InterfaceSet`
- `spawn_tcp_interface()` — connects synchronously, then spawns a tokio task for bidirectional HDLC-framed I/O through channels
- `recv_any()` — round-robin channel poller for the event loop using `poll_fn` + `poll_recv`

### Changed
- **Breaking:** `TcpClientInterface` removed from public API — interface I/O is now internal to spawned tasks, accessed only through channels
- **Breaking:** `interfaces::tcp` module visibility changed from `pub` to `pub(crate)`
- TCP interface I/O now runs as an independent tokio task instead of being polled by the event loop directly — enables better separation of concerns and prepares for multi-platform interface dispatch
- Event loop `dispatch_output()` uses `try_send()` on interface channels instead of direct `InterfaceSet::send()`/`broadcast()` calls

### Removed
- `AnyInterface` enum — replaced by spawned interface tasks communicating through channels
- `InterfaceSet` struct — replaced by `InterfaceRegistry` with channel-based handles
- `TcpClientInterface` struct — responsibilities absorbed into `spawn_tcp_interface()` + `tcp_interface_task()`
- `pub use interfaces::TcpClientInterface` re-export from `reticulum-std`
- `defmt`, `defmt-rtt`, `panic-probe` dependencies from `reticulum-nrf` — replaced by USB CDC-ACM logging
- `tests/on_device.rs` defmt-test harness from `reticulum-nrf` — requires SWD debug probe, to be rewritten over USB-CDC

## [0.3.2] - 2026-02-07

### Changed
- **Event loop rewritten with async `select!`** — replaces 50ms polling with immediate wakeup on socket readability, outgoing data, or timer expiry; eliminates up to 50ms latency per packet and reduces idle CPU usage
- `TcpClientInterface` now uses `tokio::net::TcpStream` instead of `std::net::TcpStream`, enabling async readability notification via `poll_recv_packet()`
- Interface dispatch uses concrete `AnyInterface` enum and `InterfaceSet` instead of `Vec<Box<dyn Interface + Send>>` trait objects
- `ConnectionStream` outgoing channel is now shared (`mpsc::Sender<(LinkId, Vec<u8>)>`) instead of per-connection, waking the event loop immediately when data is sent

### Removed
- `DEFAULT_POLL_INTERVAL_MS` constant (no longer needed — event loop wakes on demand)
- `process_outgoing()` function (outgoing data now handled via dedicated `select!` branch)

## [0.3.1] - 2026-02-06

### Added
- `Link::attached_interface` field mirroring Python's `Link.attached_interface` — tracks which interface a link is bound to for correct outbound routing
- `interface_index` parameter to `LinkManager::process_packet()` for propagating receiving interface to links
- Deferred-dispatch docstrings on `connect()`, `accept_connection()`, `send_on_connection()`, `send_single_packet()`
- 7 new action-coverage tests: `test_forward_on_interface_produces_send_action`, `test_forward_on_all_except_produces_broadcast_action`, `test_send_proof_produces_send_action`, `test_request_path_produces_action`, `test_handle_path_request_produces_broadcast_action`, `test_handle_packet_announce_produces_rebroadcast_action`, `test_connect_queues_send_action`

### Fixed
- **`send_on_connection()` dropped first packet** — `process_outgoing()` ignored the `Ok(Vec<u8>)` return value; now routes through the Action system via `attached_interface`
- **`connect()` link request never sent** — returned raw bytes that the caller couldn't dispatch; now routes through transport (path lookup with broadcast fallback)
- `accept_connection()` proof routing now uses `attached_interface` instead of returning raw bytes
- `send_pending_packets()` (keepalive, channel, proof) now routes via `attached_interface` instead of always using path lookup

### Changed
- **Breaking:** `NodeCore::connect()` returns `LinkId` instead of `(LinkId, Vec<u8>)` — packet is now routed internally
- **Breaking:** `NodeCore::accept_connection()` returns `Result<(), ConnectionError>` instead of `Result<Vec<u8>, ConnectionError>`
- **Breaking:** `NodeCore::send_on_connection()` returns `Result<(), SendError>` instead of `Result<Vec<u8>, SendError>`
- **Breaking:** `LinkManager::process_packet()` takes an additional `interface_index: usize` parameter
- `ReticulumNode::connect()` returns `Result<ConnectionStream, Error>` instead of `Result<(ConnectionStream, Vec<u8>), Error>`

### Removed
- `Transport::is_interface_online()` — always returned true; driver uses `handle_interface_down()` instead
- Dead `|| !self.is_interface_online(...)` clauses in `clean_link_table()` and `clean_reverse_table()`

## [0.3.0] - 2026-02-06

### Added
- **Sans-I/O architecture** for `reticulum-core`: core is now a pure state machine that never performs I/O directly
- `InterfaceId` newtype for opaque interface identification in core
- `Action` enum (`SendPacket`, `Broadcast`) for expressing outbound I/O as return values
- `TickOutput` struct separating I/O actions from protocol events
- `NodeCore::handle_packet(iface, data)` — feed incoming packets to the core engine
- `NodeCore::handle_timeout()` — run periodic maintenance (path expiry, keepalives, rebroadcasts)
- `NodeCore::next_deadline()` — query when the next timeout should fire
- `NodeCore::handle_interface_down(iface)` — notify core of interface disconnection
- `ReticulumNodeBuilder::build_sync()` — synchronous builder for non-async contexts

### Changed
- **Breaking:** `Transport` no longer holds `Box<dyn Interface + Send>` — interfaces are owned by the driver
- **Breaking:** `NodeCore::tick()`, `poll()`, `poll_interfaces()` removed — use `handle_packet()` + `handle_timeout()` instead
- **Breaking:** `NodeCore::register_interface()`, `unregister_interface()` removed — driver manages interfaces directly
- **Breaking:** `NodeCore::send_on_interface()`, `send_to_destination()`, `receive_packet()` removed — use `handle_packet()` and dispatch returned `Action` values
- **Breaking:** `TransportRunner` removed from `reticulum-std` — use `ReticulumNode` instead
- `Transport::send_on_interface()` now emits `Action::SendPacket` instead of calling `Interface::send()`
- `Transport::send_on_all_interfaces()` now emits `Action::Broadcast` instead of iterating interfaces
- `Reticulum` type now wraps `ReticulumNode` instead of the removed `TransportRunner`
- `ReticulumNode` event loop rewritten as sans-I/O driver: polls interfaces, feeds packets to core, dispatches actions
- Transport table entry types (`PathEntry`, `LinkEntry`, `ReverseEntry`, `AnnounceEntry`) reduced from `pub` to `pub(crate)`
- All error types now derive `Debug, Clone, Copy, PartialEq, Eq` and implement `core::fmt::Display`
- Parameter ordering normalized: `rng` always before `now_ms` in all methods
- `LinkManager` removed from crate-root re-exports (access via `reticulum_core::link::LinkManager`)

### Removed
- `TransportRunner` from `reticulum-std` (superseded by `ReticulumNode`)
- `Transport::poll_interfaces()` and `Transport::tick()` (driver's responsibility)
- `InterfaceError` and `InvalidInterface` variants from `TransportError`
- Unused transport table fields: `PathEntry::received_from`, `PathEntry::timestamp_ms`, `LinkEntry::next_hop_transport_id`, `LinkEntry::destination_hash`, `ReverseEntry::received_from`
- Unused transport methods: `paths()`, `link_table_entry()`, `link_table_iter()`
- Unused resource placeholder types: `ResourceState`, `ResourceError`, `ResourceConfig`, `ResourceStats`, `ResourcePart`, `PartHash`

### Fixed
- Misleading comment in `resource.rs` about protocol implementation location

## [0.2.9] - 2026-02-06

### Changed
- **Breaking:** Remove `Context` trait and `PlatformContext` struct entirely — all functions now take direct `rng: &mut impl CryptoRngCore` and `now_ms: u64` parameters
- **Breaking:** `Identity::generate(ctx)` replaced by `Identity::generate(rng)` (unified with former `generate_with_rng`)
- **Breaking:** `Identity::encrypt(plaintext, ctx)` replaced by `Identity::encrypt(plaintext, rng)` (unified with former `encrypt_with_rng`)
- **Breaking:** `Identity::encrypt_for_destination(plaintext, ratchet, ctx)` replaced by `Identity::encrypt_for_destination(plaintext, ratchet, rng)` (unified with former `encrypt_for_destination_with_rng`)
- **Breaking:** `Destination::announce(app_data, ctx)` now takes `announce(app_data, rng, now_ms)`
- **Breaking:** `Destination::enable_ratchets(ctx)` now takes `enable_ratchets(rng, now_ms)`
- **Breaking:** `Destination::rotate_ratchet_if_needed(ctx)` now takes `rotate_ratchet_if_needed(rng, now_ms)`
- **Breaking:** `Destination::encrypt(plaintext, ratchet, ctx)` now takes `encrypt(plaintext, ratchet, rng)`
- **Breaking:** `Ratchet::generate(ctx)` replaced by `Ratchet::generate(rng, now_ms)` (unified with former `generate_with_rng`)
- **Breaking:** `generate_random_hash(ctx)` now takes `generate_random_hash(rng, now_ms)`
- **Breaking:** `build_announce_payload(..., ctx)` now takes `build_announce_payload(..., rng, now_ms)`
- **Breaking:** `Link::new_outgoing_with_rng(dest, rng)` renamed to `Link::new_outgoing(dest, rng)`
- Remove `Context` and `PlatformContext` from `reticulum-core` public re-exports

### Removed
- `Context` trait from `traits.rs`
- `PlatformContext` struct and its `impl Context`
- `Identity::generate_with_rng()` — `generate()` now takes RNG directly
- `Identity::encrypt_with_rng()` — `encrypt()` now takes RNG directly
- `Identity::encrypt_for_destination_with_rng()` — `encrypt_for_destination()` now takes RNG directly
- `Ratchet::generate_with_rng()` — `generate()` now takes RNG and timestamp directly
- `Link::new_outgoing_with_rng()` — `new_outgoing()` now takes RNG directly

### Fixed
- Fix clippy warnings: use dereference instead of `.clone()` on `[u8; 16]` (implements Copy) in transport.rs
- Fix stale README.md: update status, feature lists, test counts, and crate descriptions to reflect v0.2.8 state
- Fix ROADMAP.md `lrns` subcommand checkboxes: only `identity` is implemented, mark `status`/`path`/`probe`/`interfaces` as incomplete
- Add `#[allow(dead_code)]` on `PathEntry::next_hop` in test harness

## [0.2.8] - 2026-02-04

### Added
- Transport relay interop test: Rust node as relay between two Python daemons with bidirectional link establishment and data routing
- `TcpClientInterface::from_stream()` constructor for wrapping already-connected TCP streams
- `relay_daemon` example: standalone transport relay accepting incoming TCP connections
- Transport convenience API: `link_table_iter()`, `link_table_entry()`, `paths()`, `link_table_count()`, `announce_table_count()`, `path_count()`, `is_transport_enabled()`
- `ReticulumNode` convenience methods: `has_path()`, `hops_to()`, `path_count()`, `transport_stats()`, `is_transport_enabled()`

### Changed
- **Breaking:** `NodeCore<C, S>` is now `NodeCore<R, C, S>` — owns its RNG internally instead of borrowing via `Context` trait
- **Breaking:** All `NodeCore` runtime methods (`tick()`, `connect()`, `accept_connection()`, `close_connection()`, `send_on_connection()`, `receive_packet()`) no longer take a `ctx: &mut impl Context` parameter
- **Breaking:** `NodeCoreBuilder::build()` takes `rng: R` (owned) instead of `ctx: &mut impl Context`
- **Breaking:** `LinkManager` methods take `rng: &mut impl CryptoRngCore` and `now_ms: u64` instead of `ctx: &mut impl Context`
- **Breaking:** `Link` methods (`encrypt`, `build_data_packet`, `build_close_packet`, `new_outgoing`, `new_incoming`) take `rng: &mut impl CryptoRngCore` instead of `ctx: &mut impl Context`
- **Breaking:** `Connection` send methods take `rng` and `now_ms` instead of `ctx`
- Remove `_with_rng` suffix from `Link::new_outgoing` and `Link::new_incoming` — these are now the primary constructors
- `ReticulumNode` event loop no longer constructs a `PlatformContext` on each tick
- `StdNodeCore` type alias now includes `OsRng` as the RNG type parameter

### Fixed
- Fix `enable_transport` not wired through `ReticulumNodeBuilder` to `NodeCoreBuilder`, causing transport mode to be silently disabled
- Fix interfaces not registered with Transport when using `ReticulumNode`, preventing packet forwarding (`InvalidInterface` errors)
- Fix transport relay not incrementing hop count when forwarding proofs and link-table data, causing Python peers to reject forwarded packets due to hop count mismatch
- Fix LRPROOF size validation: accept both 96 bytes (without signalling) and 99 bytes (with signalling), matching Python Reticulum behavior
- Fix `test_announce_rebroadcast_hop_count_accuracy`: remove `#[ignore]`, add hard assertion on propagation success, and verify exact hop counts (D3=1, D2=2, D1=3, D0=4) instead of silently passing on propagation failure

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

[Unreleased]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.5...HEAD
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
[0.4.0]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.3.2...v0.4.0
[0.3.2]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.3.1...v0.3.2
[0.3.1]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.3.0...v0.3.1
[0.3.0]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.9...v0.3.0
[0.2.9]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.8...v0.2.9
[0.2.8]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.7...v0.2.8
[0.2.7]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.6...v0.2.7
[0.2.6]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.5...v0.2.6
[0.2.5]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.4...v0.2.5
[0.2.4]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.3...v0.2.4
[0.2.3]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.2...v0.2.3
[0.2.2]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.1...v0.2.2
[0.2.1]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.2.0...v0.2.1
[0.2.0]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.1.0...v0.2.0
[0.1.0]: https://codeberg.org/Lew_Palm/leviculum/releases/tag/v0.1.0
