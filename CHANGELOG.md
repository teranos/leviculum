# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **RPC server for Python CLI tool compatibility** — implements Python's `multiprocessing.connection` wire protocol (length-prefixed framing, bidirectional HMAC handshake) over abstract Unix socket (`\0rns/{instance_name}/rpc`). Enables `rnstatus`, `rnpath`, and `rnprobe` Python CLI tools to query the running Rust daemon as if it were a Python shared instance. Handles: `get_interface_stats`, `get_path_table`, `get_link_count`, `get_next_hop`, `get_first_hop_timeout`, `get_packet_rssi/snr/q`, `drop_path`, `drop_all_via`, `blackhole_identity`. Supports both legacy HMAC-MD5 (Python < 3.12) and modern HMAC-SHA256 (Python >= 3.12) authentication protocols. 28 unit tests + 6 interop tests.
- **Probe responder** — built-in probe responder at the daemon's management destination (`rnstransport.probe`), matching Python's `Transport.probe()`. Enables `rnprobe` connectivity testing against the Rust daemon.
- **Per-interface I/O counters** — `rxb`/`txb` (bytes received/transmitted) tracked per interface, exposed via `interface_stats` RPC for `rnstatus` display.
- **Per-interface announce frequency tracking** — `announce_allowed_at` per-interface rate table exposed via RPC for `rnstatus -a` display.
- **LocalInterface (Unix socket IPC)** — shared instance data channel using abstract Unix sockets (`\0rns/{instance_name}`), matching Python's `LocalClientInterface`/`LocalServerInterface`. HDLC framing over the socket. `spawn_local_server()` accepts local client connections and registers them as `is_local_client` interfaces. Configurable via `share_instance`/`instance_name` in INI config or `ReticulumNodeBuilder`.
- **Local client routing gates** — `handle_link_request()`, `handle_proof()`, and `handle_data()` now route packets for/from local client interfaces even when `enable_transport = false`, matching Python Transport.py:1378-1404. New helpers: `is_for_local_client()` (path hops=0 on local client interface), `is_for_local_client_link()` (link table entry references local client interface). `handle_proof()` refactored from one monolithic `enable_transport` block into two independent blocks (link table + reverse table) each with their own local-client gate conditions. 5 unit tests with `enable_transport=false` verify routing via local client conditions alone.
- **Shared instance interop tests** — 3 Python interop tests validating Unix socket IPC: `test_shared_instance_receive_announce` (Python announces → Rust receives via Unix socket), `test_shared_instance_send_announce` (Rust sends announce → Python creates path), and `test_shared_instance_link_through_daemon` (end-to-end link establishment + bidirectional data through an in-process Rust daemon with Python as shared instance client). Uses `--share-instance`/`--instance-name` flags added to `scripts/test_daemon.py`. Channel message echo in test_daemon.py gated behind `--echo-channel` flag to avoid interfering with tests that receive data in a specific order.
- **Cross-machine AutoInterface interop test** — new test binary (`auto-crossmachine-test`) and orchestrator script (`scripts/test-auto-crossmachine.fish`) that run the Rust node on schneckenschreck (KVM VM) and a Python test daemon on hamster (local). Validates 4 phases: Discovery, Announce, Link, Data — plus RUST_LOG output and Python data receipt. Catches bugs that same-machine testing cannot exercise (wire format, source port mismatch). Script auto-starts the VM via virsh if not running.
- **AutoInterface integration tests (7 tests)** — comprehensive in-process tests covering mutual discovery, announce propagation, link + bidirectional data, MTU negotiation, peer timeout detection, three-node mesh, and group isolation. All tests use ephemeral data ports and unique group IDs for parallel-safe CI execution. No Python daemon required.
- **`multicast_loopback` config passthrough** — the `multicast_loopback` field is now correctly propagated from `AutoInterfaceConfig` through `InterfaceConfig` to the driver. Previously the field was silently dropped and hardcoded to `false`. Parseable from INI config files.
- **SIGUSR1 diagnostic dump** — sending SIGUSR1 to `lrnsd` now prints a memory diagnostic summary to stderr, covering all protocol collections (storage, transport), estimated per-collection overhead, and process RSS.

### Fixed
- **Hops incremented on receipt** — hops are now incremented when a packet is received (matching Python Transport.py:1319), not when forwarded. Direct neighbors are hops=1, not hops=0. All path table, announce table, and forwarding logic updated to reflect the new semantics. Core tests updated.
- **Cached announce forwarding to shared instance local clients** — when responding to a local client's path request with a cached announce, the raw cached bytes had pre-increment wire hops (e.g., hops=0 for a direct neighbor). Fixed by converting cached Header1 announces to Header2 format with the daemon's transport_id and correct receipt-incremented hops when forwarding to local clients.
- **INI config parser ignoring `instance_name` setting** — the `instance_name` field from config file was silently dropped during parsing; now correctly parsed and applied.
- **Proof routing through shared instance** — proofs for destinations behind local clients are now correctly forwarded back through the local client interface.
- **Transport identity persistence** — when `enable_transport=true` and no explicit identity is set, the daemon persists and reloads its transport identity across restarts, maintaining a stable routing identity.
- **Flaky shared instance tests** — tests colliding on the same abstract Unix socket path; fixed by using unique socket names per test.
- **Path request response for local clients** — `rnpath <hash>` against the Rust daemon now works correctly. Three bugs in `handle_path_request()`: (1) cached announce was only checked when `enable_transport=true`, not for local clients; (2) response was routed to all interfaces *except* the requesting local client; (3) unnecessary `PATH_REQUEST_GRACE_MS` delay even for local clients. Fix: local client path requests with a cached announce now get an immediate `SendPacket` directly back. Unknown path requests from local clients are forwarded to network interfaces regardless of `enable_transport`.
- **AutoInterface two-tier peer lookup for cross-machine Python interop** — Python sends unicast data from an ephemeral port (not its advertised data_port), so exact `(ip, port)` lookup failed. Peer data receive now tries exact match first, then falls back to IP-only. Same-machine Rust peers still match exactly. Without this fix, all data from cross-machine Python peers was silently dropped.
- **`lrnsd` now respects RUST_LOG environment variable** — replaced `with_max_level()` with `EnvFilter::try_from_default_env()`, matching the pattern used in the cross-machine test binary. Previously `RUST_LOG=debug lrnsd` had no effect; the `-v`/`-q` flags were the only way to control log level.
- **AutoInterface peer identity by SocketAddrV6** — peers are now identified by `(IPv6 address, data port)` instead of just IPv6 address. Without this, two different Reticulum nodes behind the same IPv6 address (containers, same-machine testing) were treated as one peer, stomping each other's interface handles. Interface names now include the port: `auto/{nic}/{addr}:{port}`.
- **AutoInterface sends via NIC data socket** — eliminated the shared outbound socket; each peer send task now transmits via the NIC's data socket (`Arc<UdpSocket>`). This makes the source port of outgoing data packets equal to our advertised `data_port`, enabling direct peer map lookup by full `SocketAddrV6` on the receiving side. `recv_from_any` made generic via `Borrow<UdpSocket>`.
- **AutoInterface ephemeral data ports** — when `multicast_loopback=true`, data sockets bind to port 0 (system-chosen) to avoid `SO_REUSEPORT` conflicts between same-machine nodes. Discovery packets extended to 42 bytes (`[nonce(8)] + [token(32)] + [data_port(2)]`) with nonce-based self-echo detection replacing IP-based detection.
- **Event loop debug_assert on zero deadline removed** — `debug_assert!(delta > 0)` in `driver/mod.rs` panicked when `next_deadline()` legitimately returned a past timestamp (e.g., during peer timeout processing). The `clamp(1, 1000)` already prevents spin loops; the assertion was unnecessary. Fixes E24.
- **AutoInterface failed to find network interfaces** — the `if-addrs` crate drops IPv6 link-local (fe80::) addresses by default; AutoInterface relies entirely on these for peer discovery. Enabled the `link-local` feature flag. Also added debug/trace logging to `enumerate_nics()` for future troubleshooting.
- **Path request responses sent only to requesting interface** — previously path request responses were broadcast to all interfaces (using a `usize::MAX` hack for `receiving_interface_index`), wasting bandwidth and diverging from Python. Now uses a `target_interface` field on `AnnounceEntry` to emit a targeted `SendPacket` to the requesting interface only (Python Transport.py:1037-1038). 4 unit tests.
- **Local destination announces cached for path request responses** — local announces were sent but never cached, so path requests for local destinations always got "No cached announce". Now caches raw announce bytes at send time in both `announce_destination()` and `check_mgmt_announces()`.
- **Announce replay protection allows better-hop paths through** — when a path response arrives via relay (2+ hops) and the direct announce from the same emission arrives later (0 hops), the direct announce was rejected as replay because it shared the same `random_blob`. Now allows same-emission announces with strictly fewer hops to update the path. 2 unit tests.

### Changed
- **FileStorage packet_cache switched from BTreeSet to HashSet** — ~1.5x overhead per entry instead of ~3x. For 100k entries of 32-byte hashes, this saves ~4.8 MB. Cap lowered from 1M to 100k (real-world usage peaks around 100-200k). Oversized hashlists loaded from disk converge naturally through rotation.
- **Default identity cap lowered from 5M to 50k** — prevents theoretical runaway growth (5M × 144B × 3x = 2 TB). Real-world networks have <15k identities. 50k is generous.
- **Announce cache cleanup moved from Storage to Transport** — `clean_stale_path_metadata()` no longer touches announce_cache. A new `clean_announce_cache(local_destinations)` method on the Storage trait is called from Transport's `clean_path_states()`, preserving cache entries for local destinations (which have no path_table entry but must survive for path request responses).
- **`diagnostic_dump()` split into composable sub-methods** — `diagnostic_dump_packet_cache()` and `diagnostic_dump_non_packet_cache()` on MemoryStorage, enabling FileStorage to report its own HashSet overhead accurately while delegating the rest.

### Added
- **AutoInterface** — zero-configuration LAN discovery via IPv6 multicast, matching Python Reticulum's `AutoInterface`. Nodes on the same LAN discover each other automatically and communicate over UDP. Each discovered peer becomes a separate interface handle with `HW_MTU=1196`. Features: multicast address derivation from group_id, SHA-256 discovery tokens with constant-time verification, per-NIC multicast/unicast/data sockets via socket2, peer timeout (22s) with automatic cleanup via channel-drop cascade, self-echo carrier detection (6.5s), deduplication cache (48 entries, 750ms TTL), reverse peering for bidirectional discovery. Linux only. Configurable via INI (`[[Auto Interface]]`) or builder (`add_auto_interface()`). 38 unit tests + Python-verified test vectors for multicast address and discovery token.

### Fixed
- **Responder-side MTU clamping** — `Link::new_incoming()` now clamps the negotiated MTU to the receiving interface's HW_MTU (`min(signaled_mtu, interface_hw_mtu)`), matching Python `Transport.py:1944-1960`. Previously a peer could negotiate an MTU exceeding the link's actual capacity, causing silent data loss on constrained interfaces.
- **Link MTU discovery compatibility** — transport relay no longer rejects packets larger than the base 500-byte MTU. Python Reticulum 1.1.3 negotiates higher link MTUs over TCP (up to 262 KB), causing resource transfers (e.g. `rncp`) through lrnsd to fail with "packet too long". Removed the hard MTU check from `Packet::unpack()` and `Packet::pack()`, and switched forwarding buffers from fixed `[0u8; 500]` to dynamically-sized `Vec<u8>`.
- **Relay MTU clamping for mixed-interface paths** — Rust transport relays now clamp link request signaling bytes to `min(path_mtu, prev_hop_hw_mtu, next_hop_hw_mtu)` when forwarding, matching Python `Transport.py:1453-1480`. Without this, a link request entering via TCP (HW_MTU=262144) and leaving via UDP (HW_MTU=1064) would negotiate 262144, causing the sender to emit packets that UDP silently drops.

### Added
- **Python-to-Python UDP MTU baseline test (B0)** — new interop test confirming two Python daemons connected via UDP negotiate MTU=500, empirically validating UDPInterface's `AUTOCONFIGURE_MTU=False` / `FIXED_MTU=False` behavior.
- **Python-to-Rust UDP data transfer (B3)** — B3 test now sends a max-channel-payload (425 bytes) from Python to Rust over an established UDP link, verifying bidirectional data flow (previously only verified link establishment and MTU).
- **Link MTU negotiation** — Rust-originated links now negotiate larger MTUs on capable interfaces, matching Python Reticulum 1.1.3. Link requests always include 3-byte signaling bytes encoding the outbound interface's hardware MTU (TCP=262144, UDP=1064). The responder echoes the negotiated MTU in the proof. `Link::mdu()` computes the encrypted link MDU from the negotiated MTU using Python's formula (AES block-aligned). With default MTU=500 the link MDU is 431; with TCP's 262144 it is 262063. Interface HW_MTU is tracked per-interface in Transport and cleaned up on interface-down.
- **Logging quality improvement** — 68 new tracing calls (88 → 156 total) covering transport routing, link lifecycle, and all silent drop paths. `lrnsd -v` now shows routing decisions (path updates, announce rebroadcasts, link establishment/close, forwarding, path requests). `lrnsd -vv` shows per-packet flow with drop reasons (duplicate, rate limit, replay, TTL exceeded, hop mismatch, crypto failure). Every `packets_dropped` increment now has a corresponding log message explaining why.
- **`HexShort` formatter** (`reticulum-core`) — displays first 16 hex chars (8 bytes) for compact log lines, mirroring Python's `prettyhexrep`. Used in debug!/trace! messages; full `HexFmt` retained for warn!/error! where precision matters.
- **Logging section in `doc/ARCHITECTURE.md`** — documents logging philosophy (sentence-style messages inspired by Python rnsd), level mapping (info/debug/trace), message style guide, and per-component logging inventory.

### Changed
- **Transport tracing upgraded from key-value to sentence-style** — existing 5 trace! calls in transport.rs migrated from `HexFmt` to `HexShort` and from terse structured fields to readable sentences (e.g., "Destination <81b22f60...> is now 4 hops away via <ecc35451...> on iface 1"). `forward_packet()` upgraded from trace! to debug! for `-v` visibility.
- **Silent drops eliminated** — all unhappy paths in transport.rs (proof hop mismatch, LRPROOF validation failures, data packet direction detection), link_management.rs (malformed link request, decryption failures, unknown/non-active link), and node/mod.rs (packet parse errors, decrypt failures) now log the drop reason.
- **Startup summary** — `ReticulumNode::start()` now logs interface count and transport enabled/disabled at info! level.

- **Storage trait refactoring (E9)** — all 11 long-lived Transport/NodeCore collections migrated to a type-safe Storage trait (~44 methods). Core is now a pure protocol engine with zero state management — Storage is the single source of truth for routing tables, link entries, announce state, packet dedup, receipts, path requests, known identities, and ratchets.
- **`storage_types` module** (`reticulum-core`) — pure data structs shared between Storage and Transport: `PathEntry`, `PathState`, `ReverseEntry`, `LinkEntry`, `AnnounceEntry`, `AnnounceRateEntry`, `PacketReceipt`, `ReceiptStatus`. All `pub` with `pub` fields (data transfer objects at the Storage API boundary).
- **`MemoryStorage`** (`reticulum-core`, `pub`) — BTreeMap/BTreeSet-backed Storage implementation with configurable per-collection caps. Not `#[cfg(test)]` — this is the production implementation for embedded targets and the test storage for core tests. Two presets: `with_defaults()` (generous for Linux) and `compact()` (small caps for constrained devices).
- **`NoStorage`** (`reticulum-core`) — zero-sized no-op Storage implementation. All lookups return None/false/0, all writes are no-ops. For stubs, FFI, and smoke tests.
- **FileStorage wraps MemoryStorage** (`reticulum-std`) — FileStorage now delegates all ~44 Storage trait methods to an internal MemoryStorage instance. Previously all non-persistent collections had no-op implementations, silently discarding runtime data. Now all collections have real BTreeMap-backed storage.
- **FileStorage persistence** — `Storage::new()` loads known_destinations and packet_hashlist from disk automatically. `flush()` merges runtime identities with on-disk entries (preserving entries from other processes) and writes both files. Python-compatible msgpack formats.
- **`packet_hash_iter()` and `known_identity_iter()`** on MemoryStorage — iterator methods for FileStorage's `flush()` to write persistent data to disk.
- **Zero-delay core, interface-side collision avoidance** — new ARCHITECTURE.md section documenting the design principle: core forwards packets instantly with no artificial delay; collision avoidance is the interface's responsibility. Fast interfaces (TCP, UDP) transmit immediately; future shared-medium interfaces (LoRa, serial) will apply send-side jitter.
- **E10: Interface-specific jitter tracking** — added to `doc/OPEN_ISSUES_TRACKER.md`. Documents the two jitter points needed for shared-medium interfaces (matching Python's `PATHFINDER_RW` values) and the implementation approach (send queue with configurable delay in the interface, not the core).
- **E11: Ratchet migration tracking** — added to `doc/OPEN_ISSUES_TRACKER.md`. Tracks migration of ratchet.rs from legacy generic Storage API to new type-safe methods (B4 scope).

### Changed
- **Transport state fully delegated to Storage** — Transport no longer owns any BTreeMap/BTreeSet fields for long-lived data. All 11 collections (packet_cache, path_table, path_states, reverse_table, link_table, announce_table, announce_cache, announce_rate_table, receipts, path_requests, path_request_tags) accessed via `self.storage.*()` methods.
- **NodeCore state delegated to Storage** — `KnownIdentities` struct removed from NodeCore. Identity lookup via `self.storage().get_identity()`, storage via `self.storage_mut().set_identity()`.
- **Driver simplified** — removed `known_dests_store` and `storage_path` fields from `ReticulumNode`. `save_persistent_state()` now just calls `storage.flush()`. Builder no longer performs separate load-then-feed steps.
- **`KnownDestinationsStore` moved to test-only** — production persistence handled by FileStorage directly.
- **Cleanup methods return evicted entries** — `expire_paths()`, `expire_receipts()`, `expire_link_entries()` return removed entries so Transport can emit corresponding protocol events (PathLost, ReceiptTimeout, path rediscovery).
- **`doc/ARCHITECTURE.md` updated** — new Storage Trait section documenting the trait design, three implementations, and collection inventory.

### Changed
- **Immediate announce rebroadcast** — `handle_announce()` now emits a `Broadcast` action immediately instead of deferring to `poll()` with 0-500ms random jitter. Removes ~600ms per-hop latency from announce propagation through relay chains. Subsequent retransmits use flat `PATHFINDER_G_MS` (5s) intervals without jitter.
- **Event loop recomputes timer after packet handling** — `next_poll` is now updated after every `handle_packet()` call based on `output.next_deadline_ms`, preventing the loop from sleeping on stale deadlines.
- **Event loop timer floor removed** — replaced `delta.clamp(250, 1000)` with `debug_assert!(delta > 0)` + `delta.max(1).min(1000)`. The `debug_assert` catches zero-delta bugs in tests; `.max(1)` prevents spin loops in release.
- **ROADMAP.md rewritten** — removed all LOC counts, test counts, effort estimates, and speculative v1.1 API designs. IFAC and Ratchet moved from "Deferred" to v1.0 Phase 3 (security fundamentals). Resource Transfer moved to v1.1. v1.1 section condensed from ~500 lines to a bullet list.

### Removed
- `PATHFINDER_RW_MS` constant (500ms jitter window) — no longer used; core is zero-delay
- `Transport::jitter_ms()` function — deterministic jitter from hash seed, replaced by immediate dispatch
- `Transport::calculate_retransmit_delay()` function — random delay for first rebroadcast, replaced by immediate dispatch
- Path request response jitter — responses now use deterministic `PATH_REQUEST_GRACE_MS` (400ms) without added randomness

### Added
- **TCP client reconnection** — `spawn_tcp_client_with_reconnect()` wraps TCP client connections with automatic reconnection. The wrapper owns the channel endpoints and keeps them alive across reconnection cycles, so the driver never sees `RecvEvent::Disconnected`. Configurable via `reconnect_interval_secs` (default: 5s) and `max_reconnect_tries` (default: unlimited) on `InterfaceConfig`. Initial connect is async (non-blocking `start()`). Packets queued during disconnect are delivered on the new connection; overflow is dropped with a warning.
- **Two-address selftest** — `lrns selftest` now accepts 1-2 target addresses for multi-daemon topology testing (`lrns selftest addr1 addr2`). Each client connects to its respective daemon, enabling cross-daemon test topologies (A->daemon1->daemon2<-B).
- **Configurable interface buffer size** — `InterfaceConfig::buffer_size` controls the channel buffer size per interface (default: 256 for TCP). Replaces the hardcoded `TCP_INCOMING_CAPACITY` (32) and `TCP_OUTGOING_CAPACITY` (16) constants with a single per-interface default.
- `InterfaceConfig` fields: `reconnect_interval_secs`, `max_reconnect_tries`, `buffer_size`
- 2 new tests: `test_tcp_client_reconnects_after_disconnect` (happy path reconnection with packet delivery), `test_tcp_client_gives_up_after_max_retries` (incoming channel closes after max retries exhausted)

### Changed
- **`tcp_interface_task` returns `mpsc::Receiver<OutgoingPacket>`** — enables channel reuse across reconnection cycles. The reconnect wrapper passes the returned receiver to the next connection attempt, preserving buffered packets. Backwards-compatible: server path ignores the return value.
- **`spawn_tcp_interface()` gated to `#[cfg(test)]`** — production code uses `spawn_tcp_client_with_reconnect()` for clients and `spawn_tcp_server()` for servers. Test-only function retained for existing TCP unit tests.
- **TCPClientInterface uses async reconnect wrapper** — `initialize_interfaces()` now calls `spawn_tcp_client_with_reconnect()` instead of the synchronous `spawn_tcp_interface()`. DNS resolution via `std::net::ToSocketAddrs` (sync, startup-only).
- `selftest` CLI: `addr: String` replaced with `targets: Vec<String>` (`#[arg(num_args = 1..=2)]`)

### Removed
- `TCP_INCOMING_CAPACITY` and `TCP_OUTGOING_CAPACITY` constants from `interfaces/mod.rs` — replaced by per-interface `TCP_DEFAULT_BUFFER_SIZE` (256) in `interfaces/tcp.rs`

### Added
- **TCP Server Interface** — `spawn_tcp_server()` binds synchronously and spawns an async accept loop. Each accepted connection becomes an `InterfaceHandle` sent to the event loop via an `mpsc` channel. Interface IDs use a shared `AtomicUsize` counter (monotonically increasing, initialized at `interfaces.len()`). The listener is NOT registered in `InterfaceRegistry` — it spawns interfaces, matching Python's architecture.
- **Dynamic interface registration in event loop** — new 5th `select!` branch in `run_event_loop()` receives `InterfaceHandle` values from TCP server accept loops and registers them at runtime. `recv_any()` sees new interfaces on the next iteration (verified: `poll_fn` re-reads `registry.handles_mut()` on each poll).
- **Config-driven interface loading** — `Reticulum::with_config()` now iterates `config.interfaces` and wires `TCPClientInterface` and `TCPServerInterface` entries to the builder. Missing required fields produce `Error::Config` with the interface name. Unknown types emit a warning and are skipped.
- **`lrnsd` functional daemon** — added `rns.start().await?` (was missing), SIGTERM handler via `tokio::signal::unix` alongside SIGINT, `-v`/`-q` count-based log level control (TRACE/DEBUG/INFO/WARN/ERROR), compact tracing format with timestamps. Removed dead `--foreground` flag.
- **Transport hot path tracing** — `tracing::trace!` with structured fields at entry of 6 functions: `process_incoming()` (packet type, dest, interface, hops), `handle_announce()` (dest, interface, hops, path_response), `handle_link_request()` (dest, interface, local), `handle_proof()` (dest, interface, proof_len), `handle_data()` (dest, interface, hops, data_len), `forward_packet()` (dest, src/dst interface, hops). Uses `HexFmt` for grep-friendly destination hash formatting.
- `spawn_tcp_interface_from_stream()` — extracted common channel+task setup shared by TCP client and server paths, reusing `tcp_interface_task()` unchanged
- 1 new test: `test_tcp_server_accepts_connection` verifying server bind, client connect, and `InterfaceHandle` delivery via channel
- **Path timestamp refresh on forward** — active paths no longer expire while traffic flows through them. Both `forward_packet()` and `handle_link_request()` now refresh `path.expires_ms` on every forward, matching Python Transport.py:990 and Transport.py:1504. Configurable via `NodeCoreBuilder::path_expiry_secs()` / `ReticulumNodeBuilder::path_expiry_secs()`.
- **LRPROOF Ed25519 signature validation** — transport relays now verify the link proof signature before forwarding, matching Python Transport.py:2021-2033. The responder's Ed25519 signing key is extracted from the announce cache at link creation time and stored on `LinkEntry`. Invalid signatures are dropped with `packets_dropped` incremented. Missing signing keys (announce not cached) emit a `tracing::warn!` and forward anyway.
- **Per-interface announce bandwidth caps** — announce rebroadcasts are now rate-limited per interface based on link bitrate and a configurable cap percentage (default 2%), matching Python Interface.py:25-28 and Transport.py:1091-1104. Excess announces are queued (max 16384 per interface) and drained by priority (lowest hops first, then oldest). Locally-originated announces (hops == 0) bypass caps. TCP interfaces use bitrate=0 (no cap), so the subsystem is dormant until LoRa/serial interfaces are added. API: `Transport::register_interface_bitrate()`, `Transport::unregister_interface_announce_cap()`.
- **32-byte path requests for non-transport nodes** — non-transport nodes now send 32-byte path requests (dest_hash + tag) instead of always sending 48 bytes (which included an unnecessary transport_id), matching Python Transport.py:2541-2557. The handler accepts both formats by extracting the tag from the last 16 bytes.
- `handle_interface_down()` now cleans up announce cap state for downed interfaces
- 23 new unit tests across all 4 path system gaps
- 6 new interop tests: path refresh keeps route alive, idle path expires, path request through Python relay, unknown destination timeout, announce forwarding through transport, burst announces not lost
- `doc/path-gaps-verification-report.md` — verification report answering 15+ questions with exact code references

### Changed
- **`spawn_tcp_interface()` refactored** — sync connect + nodelay + nonblocking, then delegates to `spawn_tcp_interface_from_stream()` (no behavioral change, reduces duplication)
- **`initialize_interfaces()` takes `next_id` and `new_iface_tx` params** — TCPServerInterface config now calls `spawn_tcp_server()` instead of returning an error
- **`lrnsd` logging** — replaced `--verbose` bool + `FmtSubscriber` with `-v`/`-q` `ArgAction::Count` + `tracing_subscriber::fmt().compact()`
- **Remove 14 unused re-exports from `reticulum-core` root** — `generate_random_hash`, `IfacConfig`, `IfacError`, `ChannelAction`, `Envelope`, `MessageState`, `SendHandle`, `SendMethod`, `SendResult`, `PacketReceipt`, `ReceiptStatus`, `KnownRatchets`, `Ratchet`, `RatchetError` were publicly re-exported from `lib.rs` but never imported by any external crate. These types remain accessible via their module paths (e.g. `reticulum_core::ifac::IfacConfig`).
- **Restrict buffer type visibility** — `RawChannelReader`, `RawChannelWriter`, `BufferedChannelWriter` changed from `pub` to `pub(crate)` in `link::channel`. No production code uses them yet (Buffer API not integrated — ROADMAP C10). Removed 2 misplaced unit tests from interop test suite that used these types.

### Removed
- `--foreground` flag from `lrnsd` (dead code — daemon always runs in foreground)

### Added
- **Architecture review documentation** — 3-part architecture audit (`doc/ARCHITECTURE_REVIEW.md`, `ARCHITECTURE_REVIEW2.md`, `ARCHITECTURE_REVIEW3.md`) covering ownership graphs, hot path call chains, split-brain risks, LinkManager dissolution feasibility, core/std layering purity, and API surface quality (16 issues identified)
- **Test review documentation** — 2-part test audit (`doc/TEST_REVIEW.md`, `TEST_REVIEW2.md`) with 938-test inventory, duplicate analysis, coverage gap identification (35 missing test areas), fragility assessment (24 private-field accesses), and consolidation plan (~615 LOC savings)
- **Issue tracking system** — `doc/OPEN_ISSUES_TRACKER.md` with 58 categorized issues from architecture reviews, phased remediation plan (4 phases: tests, quick wins, structural refactoring, post-refactoring), and effort estimates; `doc/ISSUES.md` as consolidated issue catalog by category

## [0.5.19] - 2026-02-15

### Fixed
- **Pacing interval used handshake RTT instead of SRTT** — `recalculate_pacing()` inside `adjust_window()` always used the handshake RTT for the pacing base calculation (`pacing_interval_ms = rtt_ms / window`). When SRTT was measured (e.g. ~200ms) but handshake RTT was high (e.g. 1200ms), pacing was far too conservative — throttling throughput to 1200/window ms between sends when the actual round-trip was much faster. Now `mark_delivered()` and `poll()` overwrite pacing with `effective_rtt_ms()` (SRTT when measured, handshake RTT fallback) after each `adjust_window()` call. Window tier promotion still uses handshake RTT (conservative — SRTT from proof round-trips can underestimate true end-to-end RTT).

### Added
- 1 new test: `test_pacing_uses_srtt_not_handshake_rtt` verifying pacing uses SRTT after measurement

## [0.5.18] - 2026-02-15

### Changed
- **Live timeout computation** — Channel timeouts are now computed fresh in `poll()` using the current `tx_ring.len()` instead of being frozen at send time. Under load changes (deliveries reducing queue, or new sends growing it), timeouts adapt immediately without waiting for the next retransmit cycle. Removes `timeout_at_ms` from `OutboundEnvelope`.
- **Smoothed RTT (SRTT) from proof round-trips** — Per-channel SRTT tracking using RFC 6298 (exponentially weighted moving average) with Karn's algorithm (skip retransmitted messages to avoid ambiguous samples). `effective_rtt_ms()` returns SRTT when measured, falling back to handshake RTT. Used for timeout calculation and pacing in `poll()`.
- **`CHANNEL_MAX_TRIES` increased from 5 to 8** — With exponential backoff (`1.5^(tries-1)`), 8 tries gives a final retry factor of ~17x, providing more patience before link teardown under transient corruption.
- **First retransmit skips pacing multiplicative decrease** — The first retransmit (tries 1→2) may be spurious (jitter, not loss). Window shrink still happens on every retransmit (matches Python), but pacing MD only triggers on 2nd+ retransmits (tries ≥ 2).
- `mark_delivered()` and `mark_channel_delivered()` now take `now_ms` parameter for SRTT measurement

### Removed
- `update_pending_timeouts()` — dead code after live timeout computation (timeouts no longer stored on envelopes)
- `calculate_timeout_ms()` wrapper — callers use the free function `calculate_timeout()` directly
- 3 tests for stored-timeout recalculation (`test_dynamic_timeout_recalculation`, `test_dynamic_timeout_only_shortens`, `test_dynamic_timeout_triggers_earlier_retransmit`)

### Added
- `Channel::srtt_ms()` and `Channel::rttvar_ms()` accessors
- 8 new tests: live timeout with current queue length (2 tests), SRTT first measurement, SRTT convergence, Karn's algorithm skipping retransmits, effective RTT fallback, max_tries=8 survival, first retransmit no pacing MD

## [0.5.17] - 2026-02-14

### Added
- **Sender-side pacing with AIMD congestion control** — Channel now spaces sends evenly across the RTT (`pacing_interval_ms = rtt / window`) instead of bursting until WindowFull. Additive Increase on delivery (window growth naturally decreases pacing interval via `recalculate_pacing()`), Multiplicative Decrease on retransmit (pacing doubled per retransmit, capped at RTT). No wire protocol changes, fully compatible with Python peers.
- `ChannelError::PacingDelay { ready_at_ms }` variant — returned when the caller sends before the pacing interval allows
- `LinkError::PacingDelay` and `SendError::PacingDelay` variants for error propagation
- `Channel::pacing_interval_ms()` and `Channel::next_send_at_ms()` accessors
- `ConnectionStream::send_bytes()` — async method that absorbs pacing delays and window-full conditions by sleeping until ready, only returning errors on fatal conditions (connection lost, stream closed)
- `NodeCore::now_ms()` accessor for reading the transport clock
- `ConnectionStats::pacing_interval_ms` field
- 8 unit tests for pacing: delay returned, next_send_at set, window-full priority, retransmit doubling, ceiling on retransmit, recalculate_pacing, delivery recalculates, no pacing before first RTT

### Changed
- `ConnectionStream::send()` now maps `PacingDelay` to `WouldBlock` (alongside existing `WindowFull` mapping)
- `lrns selftest` `send_msg()` uses `send_bytes()` instead of `send()` for automatic pacing absorption
- `lrns selftest` Phase 6 burst replaced manual WindowFull retry loop with `send_bytes()` + `tokio::time::timeout`

## [0.5.16] - 2026-02-14

### Fixed
- **Retransmitted messages permanently rejected when proof lost on return path** — When a retransmit arrived with a sequence behind `next_rx_sequence`, `sequence_offset()` wrapped around to a huge number (e.g. seq=128 with next_rx=141 → offset=65523), hit the `CHANNEL_RX_RING_MAX` check, returned `Err(RxRingFull)`, and the manager suppressed the proof. The sender never got the proof and kept retransmitting until `max_tries` killed the link. Fixed with half-sequence-space detection (standard TCP technique): offsets >= 32768 are recognized as backward/duplicate sequences and return `Ok(None)` so the caller generates a proof.

### Changed
- Rate-limited `rx_ring full` warnings to once per 5 seconds with aggregated drop counts (was per-message)
- Removed temporary WARN-level diagnostics added for retransmit investigation (GAP_FILLED, RX_RING_FULL, RETRANSMIT age, RETX_SENT, DRAIN)

## [0.5.15] - 2026-02-14

### Fixed
- **Channel retransmissions never triggered (retx=0)** — Connection and LinkManager each owned a separate `Channel` per link. Sent messages accumulated in Connection's Channel tx_ring, but `check_channel_timeouts()` only polled LinkManager's Channel (which had an empty tx_ring), so retransmit timeouts were never detected. Merged into a single Channel per link in LinkManager: `send_on_connection()` now routes through `LinkManager::channel_send()`, and `DataDelivered` calls `LinkManager::mark_channel_delivered()`. Also fixed event loop timer starvation: the per-iteration deadline recomputation was replaced with a persistent `next_poll` instant that only advances after `handle_timeout()` fires, ensuring `channel.poll()` runs every 250ms–1s regardless of packet traffic.

### Changed
- **Breaking: `Connection` no longer owns a `Channel`** — all channel state (tx_ring, rx_ring, window) is now exclusively in `LinkManager::channels`. `Connection` is a lightweight metadata struct (link_id, destination_hash, is_initiator, compression_enabled).

### Added
- `LinkManager::mark_channel_delivered()` for proof-driven delivery confirmation on the unified Channel
- `LinkManager::channel_last_sent_sequence()` for reading the most recent sent sequence number
- `LinkError::WindowFull` variant for propagating channel backpressure through the link layer

### Removed
- `Connection` channel methods: `send_bytes()`, `send_message()`, `send_raw()`, `receive_message()`, `receive_bytes()`, `receive_envelope()`, `get_or_create_channel()`, `channel()`, `channel_mut()`, `last_sent_sequence()`, `has_channel()`, `is_ready_to_send()`, `outstanding_messages()` — all channel operations now go through `LinkManager`

## [0.5.14] - 2026-02-13

### Fixed
- **ConnectionStream silently dropped messages on WindowFull** — `send()` routed data through an mpsc channel to the event loop, which called `send_on_connection()` and silently discarded `WindowFull` errors. The caller received `Ok(())` for messages that were never sent. Now `ConnectionStream` locks the core directly and returns the real error, mapping `WindowFull` to `io::ErrorKind::WouldBlock` (retryable). Matches the lock + dispatch pattern already used by `PacketEndpoint`.
- **Selftest Phase 7 closed links before all messages were confirmed** — used a fixed 2s sleep before closing, which abandoned in-flight messages in the channel tx_ring. Now drains until `confirmed >= sent` (15s timeout).
- **Selftest Phase 6 burst silently counted WindowFull as failures** — burst sends did not retry on `WouldBlock`, permanently losing messages. Now retries with 200ms backoff (10s timeout per message).
- **Interop lifecycle test failed on WindowFull** — rapid 5-message send in `test_full_link_lifecycle_through_relay` now retries on `WouldBlock` with 500ms backoff.

### Removed
- `AsyncWrite` impl from `ConnectionStream` (unused by any caller)
- mpsc-based outgoing channel (Branch 2) from driver event loop — `ConnectionStream` now dispatches actions directly like `PacketEndpoint`

## [0.5.13] - 2026-02-13

### Fixed
- **`/peers` hop count always showing `?`** — `PathFound` events arrived before `AnnounceReceived` in the same batch, but the handler tried to update an entry that didn't exist yet. Fixed by creating the entry on `PathFound` if missing. Also changed `PathFound` to emit on every path update (not just new paths) so re-announces with changed hop counts are reflected.
- **`/peers` garbled app_data display** — Python Reticulum apps (LXMF, Sideband, NomadNet) encode app_data as msgpack structures. Added a multi-strategy parser: scans fixarray elements and fixmap values for the longest valid UTF-8 text, unwraps top-level bin/str wrappers, and falls back to longest printable ASCII run for unknown formats. Pure binary data now shows empty instead of garbled replacement characters.

### Added
- 13 unit tests for `display_app_data` covering plain UTF-8, msgpack fixarray (bin8/fixstr/str8), fixmap value extraction, binary fallback, and embedded text extraction

## [0.5.12] - 2026-02-12

### Fixed
- **Single-packet delivery silently broken through relays** — `send_to_destination()` sent Type1/Broadcast packets as-is, but relays only forward Type2/Transport packets. Now converts Type1 to Type2 when `path.needs_relay()`, inserting the relay's identity hash as `transport_id` — matching Python Transport.py `outbound()` lines 980-991. Type2 packets (e.g., link requests) are left unchanged to avoid double-wrapping.

### Added
- **`PacketEndpoint` handle for single-packet destinations** — self-contained async handle mirroring `ConnectionStream` for link-based communication. Created via `ReticulumNode::packet_endpoint()`, provides `send()` for fire-and-forget delivery and `dest_hash()` accessor. `Clone`-able for use across async boundaries.
- `ReticulumNode::send_single_packet()` method for one-off single-packet sends without creating a handle
- `lrns connect` commands: `/target <hash>` (set single-packet destination), `/untarget` (clear target)
- `lrns connect` displays `PacketReceived` events as `[packet]` messages
- `lrns selftest --mode` flag: `all` (default), `link`, or `packet` to select test phases
- `lrns selftest` Phase 8: single-packet sustained bidirectional exchange through relay with delivery stats and verdict
- 2 transport unit tests for Type1→Type2 conversion and Type2 pass-through
- 3 `PacketEndpoint` unit tests (accessor, no-path error, closed-channel error) and 1 doc-test
- 8 selftest unit tests for single-packet verdict logic and message recording

### Changed
- `lrns connect`: bare text and `/send` now work with both active links and single-packet targets
- `lrns selftest` reports separate verdicts for link and packet phases, exits with worst verdict

## [0.5.11] - 2026-02-12

### Changed
- **Breaking: `Identity::encrypt()`, `encrypt_with_keys()`, `encrypt_for_destination()` now return `Result<Vec<u8>, IdentityError>`** — replaced two `.expect()` calls in token encryption with proper error propagation via new `IdentityError::EncryptionFailed` variant. `Destination::encrypt()` propagates the error through new `DestinationError::EncryptionFailed`. FFI `lrns_identity_encrypt` returns `LRNS_ERR_CRYPTO` on failure.
- **Breaking: `pub use reticulum_core::*` removed from `reticulum-std`** — replaced with selective re-exports of `NodeEvent`, `Destination`, `DestinationHash`, `DestinationType`, `Direction`, `Identity`, `ProofStrategy`. Consumers should import from `reticulum_core::` directly for anything not in this list.
- `Direction` and `DestinationType` re-exported from `reticulum_core` crate root — consumers no longer need to import from `reticulum_core::destination::`
- `resource` module visibility reduced from `pub` to private — the module is empty scaffolding for Phase 3 work
- Removed unused `PATH_REQUEST_GRACE_SECS` constant (f64 duplicate of `PATH_REQUEST_GRACE_MS`)
- Extracted hardcoded bitrate `62500` to named constant `DEFAULT_BITRATE_BPS` in config
- Added rationale comments to `TCP_INCOMING_CAPACITY`, `TCP_OUTGOING_CAPACITY`, and `EVENT_CHANNEL_CAPACITY`
- Simplified imports across 13 files to use crate-root re-exports for `Direction` and `DestinationType`

## [0.5.10] - 2026-02-12

### Changed
- **Breaking: `ConnectionStream` is now send-only** — removed `ConnectionSender`, `ConnectionStream::recv()`, `ConnectionStream::sender()`, and `impl AsyncRead for ConnectionStream`. Data received on a connection is now delivered exclusively via `NodeEvent::DataReceived` / `NodeEvent::MessageReceived` on the event channel. The previous dual-delivery design (event channel + per-stream `incoming_rx`) caused silent "Connection channel full, dropping N bytes" warnings because consumers always used one path and left the other unread. Python Reticulum has exactly one delivery path per packet context — this change aligns with that.
- Removed `ConnectionMap` and per-connection incoming channels from the driver event loop — no more `HashMap<LinkId, mpsc::Sender<Vec<u8>>>` in `ReticulumNodeImpl`
- Interop tests now use `wait_for_data_event()` / `wait_for_connection_closed_event()` helpers on `event_rx` instead of `stream.recv()`
- `lrns selftest` no longer needs drain tasks to prevent channel backpressure

### Removed
- `ConnectionSender` struct
- `ConnectionStream::recv()`, `ConnectionStream::sender()` methods
- `impl AsyncRead for ConnectionStream`
- `CONNECTION_CHANNEL_CAPACITY` constant
- `handle_event()` function in driver (was the incoming data router)

## [0.5.9] - 2026-02-12

### Fixed
- **Channel data proofs silently not generated (responder)** — `accept_link()` gated signing key storage on `proof_strategy != ProofStrategy::None`, but channel proofs are unconditional (Python Link.py:1173). Since the default proof strategy is `None`, the signing key was never stored and channel proofs were silently skipped. Now always stores the signing key regardless of proof strategy.
- **Channel data proofs silently not generated (initiator)** — all three proof generation sites only checked `dest_signing_key()`, which is only set for responders. Initiators have an ephemeral `signing_key` (matching Python's `Link.sig_prv`) that was never consulted. Added `Link::proof_signing_key()` which returns `dest_signing_key` for responders or ephemeral `signing_key` for initiators.
- **Connection stats showed window=0** — `connection_stats()` read the channel window from `LinkManager::channel()` (the inbound/receive-side channel) instead of `Connection::channel()` (the outbound/send-side channel where `mark_delivered` grows the window). Now reads from the correct send-side channel.
- **Selftest final window always 0** — window stats were captured after `close_connection()` destroyed the connection. Now captures stats before closing.

### Changed
- `lrns selftest` no longer reports receipt counts (was always 0 and confusing — receipts are internal to the proof chain, not user-visible)
- `ConnectionStats` no longer includes `data_receipts_count` field

### Added
- `Link::proof_signing_key()` — returns the correct signing key for proof generation on both initiator and responder sides
- `Connection::channel()` immutable accessor for reading channel state without mutation
- Improved channel proof instrumentation — log moved inside success path with proof length, else branches added for missing signing key and build failure

## [0.5.8] - 2026-02-12

### Fixed
- **Stale→Active link recovery** — Rust links could not recover from Stale state, unlike Python (Link.py:987-988) which transitions back to Active on any inbound traffic. Now `LinkManager::try_recover_stale()` recovers Stale links on keepalive, channel, and regular data packets. Keepalive state guards relaxed to allow processing and echo on Stale links, enabling the recovery path.

### Added
- **Proof chain instrumentation** — tracing at three critical points in the data proof delivery chain: receipt registration (`register_data_receipt`), channel proof generation, and proof arrival/validation (`handle_data_proof`). Enables diagnosing why channel proofs may not match receipts.
- **Repack symmetry check** — `TransportEvent::PacketReceived` now carries `raw_hash: Option<[u8; 32]>` (the SHA256 hash of original wire bytes). The node layer compares this against the hash of repacked bytes, logging a `REPACK HASH MISMATCH` warning if they diverge — which would indicate proof chain failure.
- **Channel lifecycle tracing** — debug-level tracing for channel send, delivery, WindowFull, retransmit, max-retries-exceeded, and teardown events, including tx_ring size, window, and sequence numbers.
- `LinkEvent::LinkRecovered` and `NodeEvent::ConnectionRecovered` events for Stale→Active transitions
- `tracing` dependency in `reticulum-core` (`no_std` compatible, `default-features = false`)
- `lrns connect` commands: `/announce` (re-announce destination), `/quiet` (hide announce/path messages), `/verbose` (show announce/path messages)
- `lrns connect` TCP pre-check — verifies TCP connectivity before building the node, failing fast with a clear error instead of silently running with no interfaces
- `RUST_LOG` environment variable support in `lrns` — takes precedence over `-v` flag, enables per-crate log filtering (e.g., `RUST_LOG=reticulum_core=debug`)

### Changed
- `tracing` workspace dependency configured with `default-features = false`; `reticulum-std` and `reticulum-cli` enable `features = ["std"]`
- `tracing-subscriber` now uses `env-filter` feature for `RUST_LOG` support
- `lrns` logging shows module targets (`with_target(true)`) for easier filtering

## [0.5.7] - 2026-02-11

### Added
- **`lrns connect` interactive CLI subcommand** — connects to an rnsd instance and provides an interactive command loop for network diagnostics and link management. Commands: `/peers` (list discovered destinations), `/link <hash>` (initiate link), `/accept` (accept incoming link request), `/send <msg>` (send data), `/close` (close link), `/status` (show node info), `/quit` (exit). Bare text sends as data on active links. Supports ephemeral or file-based identity (`--identity`). Two async tasks (event display + stdin input) communicate via shared `SessionState` for announce tracking, link lifecycle, and remote-close detection.
- `hex_decode()` helper function for parsing hex destination hashes

## [0.5.6] - 2026-02-11

### Fixed
- **`MessageReceived` events silently dropped in driver** — `handle_event()` in `reticulum-std` routed `DataReceived` to `ConnectionStream` but `MessageReceived` (from Channel) fell through `_ => {}`. Since `ConnectionStream::send()` uses Channel internally, Rust-to-Rust data sent via `stream.send()` never reached `stream.recv()`. Now routes `MessageReceived` data to the `ConnectionStream`, matching `DataReceived` handling.

### Added
- `ReticulumNode::accept_connection()` async wrapper — accepts an incoming link request and returns a `ConnectionStream` for async read/write, completing the responder path through the high-level driver API
- `ConnectionError::IdentityNotFound` variant for missing destination identity during `accept_connection()`
- Interop test `test_rust_node_as_responder` — Py-Initiator → Py-Relay → Rust-Responder topology with bidirectional data exchange proving both the `MessageReceived` fix and the new `accept_connection()` API
- Channel message handler in test daemon's `create_link` path — Python initiator can now receive Rust channel messages (was only set up for responder links)

### Changed
- **Breaking:** `NodeCore::accept_connection()` no longer takes an `identity: &Identity` parameter — the destination identity is looked up internally from the registered destination matching the link's destination hash

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

[Unreleased]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.17...HEAD
[0.5.17]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.16...v0.5.17
[0.5.16]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.15...v0.5.16
[0.5.15]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.14...v0.5.15
[0.5.14]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.13...v0.5.14
[0.5.13]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.12...v0.5.13
[0.5.12]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.11...v0.5.12
[0.5.11]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.10...v0.5.11
[0.5.10]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.9...v0.5.10
[0.5.9]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.8...v0.5.9
[0.5.8]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.7...v0.5.8
[0.5.7]: https://codeberg.org/Lew_Palm/leviculum/compare/v0.5.6...v0.5.7
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
