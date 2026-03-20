# leviculum — Issues Tracker

All known issues that cannot be fixed immediately go here.
When an issue is fixed, remove it from this file entirely.

## Status Overview

| ID | P | Phase | Status | Category | Summary |
|----|---|-------|--------|----------|---------|
| E12 | L | post-7 | open | Feature | Periodic flush interval should be configurable (currently hardcoded 3600s) |
| E13 | L | post-7 | open | Design | Storage trait returns references — blocks disk-backed implementations |
| E14 | L | post-7 | open | Design | FileStorage wraps MemoryStorage — cannot use IndexMap for insertion-order eviction |
| E15 | L | post-7 | open | Docs | Git history has 11 commits where FileStorage was no-op — avoid git bisect in that range |
| E16 | L | post-7 | open | Perf | FileStorage writes complete files on every flush — consider delta-based persistence |
| E18 | L | post-7 | open | Feature | UDPInterface `device` parameter (bind to specific NIC) not yet supported |
| E19 | L | post-7 | open | Feature | UDPInterface multiple forward addresses (multipoint) not yet supported |
| E20 | L | post-7 | open | Feature | AutoInterface: macOS/Windows NIC enumeration not implemented |
| E21 | L | post-7 | open | Feature | AutoInterface: NIC hot-plug detection (NICs added/removed at runtime) |
| E22 | L | post-7 | open | Feature | AutoInterface: multiple instances with different group_ids |
| E23 | L | post-7 | open | Docs | AutoInterface: carrier_changed flag set but unused (Python too) |
| E24 | M | post-7 | open | Design | Ingress control should be a per-interface trait with medium-appropriate defaults |
| E25 | L | post-7 | open | Test | Integration tests for shared-instance Blocks B/C need client framework support |
| E26 | M | post-7 | open | Design | Storage trait is a ~60-method God-Interface — split into per-concern sub-traits |
| E27 | M | post-7 | open | Design | FileStorage wraps MemoryStorage — prevents custom eviction, lazy-loading, RAM/disk split |
| E28 | M | post-7 | open | Design | InterfaceMode::multiple_access defined but unused — wire up for E10 (jitter) and E24 (ingress) |
| E32 | L | post-7 | open | Bug | KISS deframer unwrap_or(0) silently masks state machine bugs |
| E33 | L | post-7 | open | Bug | Deferred path response uses 0 hops when announce cache is empty |
| E35 | L | post-7 | open | Test | size_sweep runs without proxy — no loss recovery tested for 5KB/50KB files |
| E36 | L | post-7 | open | Test | lora_lncp_bidir is sequential, not simultaneous — no contention testing |
| E37 | L | post-7 | open | Test | Proxy only supports deterministic drop counts, not random loss rates |
| E38 | M | post-7 | open | Test | Multi-hop LoRa testing requires per-node radio config, multi-RNode nodes, and 4 RNodes |
| E44 | M | post-7 | open | Protocol | Resource completion proof lost — sender passively burns retries, no recovery |
| E45 | H | open | open | Protocol | Ratchet forward secrecy not wired — validation on announce, exchange on link, runtime rotation |
| E46 | L | open | open | Test | Persistence interop test — restart daemon, previously known destinations still reachable |
| E47 | L | open | open | Feature | Buffer/Stream integration in LinkHandle and compression over links (C10) |
| E48 | L | open | open | Feature | `lns` missing subcommands: status, path, probe, interfaces |
| E49 | L | open | open | Test | Fuzzing of packet parsers |
| E50 | L | open | open | Feature | `is_connected_to_shared_instance` semantics for local transport decisions |
| E51 | L | open | open | Feature | RNode stats parsing (RSSI, SNR, battery, temperature) for rnstatus reporting |
| E52 | L | open | open | Feature | Serial Interface and KISS Interface (TNC protocol) |
| E53 | L | open | open | Feature | Multi-segment sending for files exceeding MAX_EFFICIENT_SIZE |
| E54 | L | open | open | Feature | Resource bandwidth adaptation |
| E55 | L | open | open | Feature | C-API expansion (destinations, links, packets, resources, path discovery) |
| E56 | L | open | open | Feature | Debian packaging with systemd unit for lnsd |
| E57 | L | open | open | Feature | Android/Kotlin bindings via UniFFI |
| E58 | L | open | open | Feature | Interface Discovery (auto-connect to discovered TCP/LoRa peers) |
| E59 | L | open | open | Feature | Additional interfaces: I2P (SAM v3), AX.25 KISS, Pipe |
| E60 | L | open | open | Feature | Roaming mode and reachability tracking |

---

## Issues

### E12: Periodic flush interval should be configurable
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Feature
- **Detail:** The periodic storage flush interval is hardcoded to 3600 seconds (1 hour) in `reticulum-std/src/driver/mod.rs` (`FLUSH_INTERVAL_SECS`). The periodic flush is crash protection only — normal shutdown calls `flush()` via the signal handler. This should be configurable via `ReticulumNodeBuilder` or the config file for deployments where a different trade-off between disk I/O and data loss window is desired.
- **Fix:** Add a `flush_interval_secs` field to `ReticulumNodeBuilder` and pass it through to the event loop.
- **Test:** Unit test: verify builder accepts custom flush interval.

### E13: Storage trait returns references — blocks disk-backed implementations
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Design
- **Detail:** Several `Storage` trait methods return `Option<&T>` (e.g., `get_path`, `get_identity`, `get_link_entry`). This requires the storage implementation to hold all data in memory so it can hand out references. A purely disk-backed storage (without an in-memory cache) cannot implement these methods because it would need to return references to temporary values. The current `FileStorage`-wraps-`MemoryStorage` design works around this, but it prevents future pure-disk implementations.
- **Fix:** Change affected trait methods to return owned values (`Option<T>`) or use a cow pattern. This is a breaking API change that touches all `Storage` implementors.
- **Test:** All existing Storage tests should pass after migration.

### E14: FileStorage wraps MemoryStorage — cannot use IndexMap for insertion-order eviction
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Design
- **Detail:** `FileStorage` delegates all runtime collections to `MemoryStorage` (from `reticulum-core`). Because `MemoryStorage` is `no_std`-compatible, it uses `BTreeMap` for all collections. If insertion-order eviction (LRU-style) is ever needed (e.g., for capping the packet hashlist or known_destinations), `BTreeMap` cannot provide it. An `IndexMap` or linked-list-backed map would be needed, but that requires either changing `MemoryStorage` or having `FileStorage` manage those collections directly.
- **Fix:** When eviction is needed, either add an `IndexMap` dependency to the `std` storage or implement a custom ordered map in core.
- **Test:** N/A — design issue, no immediate code change.

### E15: Git history has no-op FileStorage commits — avoid git bisect in that range
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Docs
- **Detail:** During the Storage trait refactoring (E9), commits 0a–11 (between the initial Storage trait introduction and the final FileStorage-wraps-MemoryStorage design) had a FileStorage that was partially or fully no-op for runtime collections. `git bisect` in that range may produce misleading results because storage operations silently did nothing. The affected range is roughly from "Migrate path_table to Storage trait" through "FileStorage wraps MemoryStorage for runtime collections".
- **Fix:** No code change needed. If bisecting a storage-related bug, skip this commit range.
- **Test:** N/A — informational only.

### E16: FileStorage writes complete files on every flush — consider delta-based persistence
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Perf
- **Blocked-by:** Python msgpack format compatibility
- **Detail:** FileStorage rewrites the entire `known_destinations` and `packet_hashlist` files on every flush. On high-traffic nodes these files can reach 14 MB+. Dirty-flag tracking (added Feb 2026) avoids writes when idle, but when dirty the full file is still rewritten. On SD-card-based devices (Raspberry Pi), frequent full rewrites accelerate wear. An append-only or delta-based format would reduce write amplification, but the Python-compatible msgpack format encodes total element count in the file header, making appending impossible without breaking compatibility.
- **Fix:** Requires a new on-disk format (e.g., log-structured or one-value-per-record) with a migration path from the current msgpack format. Python compatibility would need a conversion tool or dual-format support.
- **Test:** Benchmark write amplification before and after format change.

### E18: UDPInterface `device` parameter not yet supported
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Feature
- **Detail:** Python's UDPInterface supports a `device` parameter that binds to a specific network interface (e.g., `eth0`). When set, it uses `get_address_for_if()` and `get_broadcast_for_if()` to resolve the interface's IP and broadcast addresses. The Rust implementation currently only accepts explicit IP addresses.
- **Fix:** Add `device` config parameter, resolve to IP via `getifaddrs` or equivalent.
- **Test:** Manual test on multi-NIC system; unit test for config parsing.

### E19: UDPInterface multiple forward addresses (multipoint) not yet supported
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Feature
- **Detail:** The current Rust UDPInterface supports a single `forward_ip`/`forward_port` pair. Some configurations may benefit from sending to multiple forward addresses (e.g., multiple subnets). Python's UDPInterface also only supports one forward address, so this is a Rust-only enhancement.
- **Fix:** Accept a list of forward addresses and send each outgoing packet to all of them.
- **Test:** Unit test: verify packet is sent to all configured forward addresses.

### E20: AutoInterface: macOS/Windows NIC enumeration not implemented
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Feature
- **Detail:** The AutoInterface NIC enumeration (`enumerate_nics()`) filters for IPv6 link-local addresses and uses `libc::if_nametoindex()` for scope_id resolution. This works on Linux but has not been tested or adapted for macOS (different multicast socket options) or Windows (different NIC enumeration APIs). The `if-addrs` crate is cross-platform, but the socket2 multicast setup and libc calls are Linux-specific.
- **Fix:** Add platform-specific NIC enumeration and socket setup for macOS and Windows. May need conditional compilation (`#[cfg(target_os)]`).
- **Test:** Manual test on macOS/Windows; CI matrix if available.

### E21: AutoInterface: NIC hot-plug detection (NICs added/removed at runtime)
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Feature
- **Detail:** The AutoInterface enumerates NICs once at startup. If a NIC is added or removed at runtime (e.g., USB Ethernet adapter, WiFi reconnect), the orchestrator does not detect the change. Python's AutoInterface has the same limitation.
- **Fix:** Periodic NIC re-enumeration (e.g., every 30s) or netlink socket monitoring on Linux. Add/remove multicast group memberships and data sockets dynamically.
- **Test:** Manual test: plug/unplug NIC while AutoInterface is running.

### E22: AutoInterface: multiple instances with different group_ids
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Feature
- **Detail:** The current implementation supports one AutoInterface instance per node. Python supports multiple `[[Auto Interface]]` sections with different `group_id` values, creating isolated discovery domains on the same LAN. The Rust builder's `add_auto_interface_with_config()` can be called multiple times, but port conflicts would occur since all instances bind the same discovery/data ports.
- **Fix:** Each instance needs unique port allocation or port multiplexing. May require the orchestrator to handle multiple group_ids in a single task.
- **Test:** Two AutoInterface instances with different group_ids on the same node, verify isolation.


### E24: Ingress control should be a per-interface trait with medium-appropriate defaults
- **Status:** open
- **Priority:** M
- **Phase:** post-7
- **Category:** Design
- **Detail:** Python Reticulum's `ingress_control` feature rate-limits unknown-destination announces on new interfaces (< 2 hours old). The burst threshold is `IC_BURST_FREQ_NEW = 3.5s`, with 60s hold + 300s penalty. This is critical for shared-medium interfaces (LoRa, radio) to prevent announce storms, but counterproductive for TCP — it silently suppresses valid announces during rapid startup, causing non-deterministic path table failures in mesh/ring topologies. Currently, integration tests bypass this with `ingress_control = false` in generated Python configs. The real solution is making ingress control a per-interface concern with medium-appropriate defaults: TCP/UDP = off (reliable, point-to-point), LoRa/serial = on (shared medium, bandwidth-constrained).
- **Fix:** Add an `ingress_control` field to the `Interface` trait or config struct. Default to `false` for TCP/UDP interfaces, `true` for shared-medium interfaces (LoRa, serial). Remove the `ingress_control = false` workaround from `reticulum-integ/src/topology.rs` when this is implemented.
- **Test:** Integration test: verify TCP interfaces do not apply ingress limiting. Unit test: verify shared-medium interfaces apply ingress limiting.

### E23: AutoInterface: carrier_changed flag set but unused
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Docs
- **Detail:** The Python AutoInterface sets a `carrier_changed` flag when multicast echo timeout is detected (no self-echo for 6.5s), but this flag is never read by any other code in the Python reference implementation. The Rust implementation logs a warning but does not track the flag. This appears to be dead code in both implementations.
- **Fix:** No code change needed unless a consumer of carrier state is identified. Document as known dead code.
- **Test:** N/A — informational only.

### E25: Integration tests for shared-instance Blocks B/C need client framework support
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Test
- **Detail:** Blocks B (shared instance registration 250ms delay) and C (shared instance reconnect re-announce) have unit tests but no integration tests. Writing integration tests requires the reticulum-integ framework to support running a separate client program inside a container that registers a destination with a running daemon via shared instance (Unix socket IPC). Currently, every node runs a full daemon; there is no concept of a client-only node. Note: the framework now supports negative assertions (`expect_result = "no_path"` and `expect_result = "fail"`), which can be used to verify that client destinations disappear after disconnect/expiry.
- **Fix:** Extend the integration test framework with a client node type (e.g., `type = "rust-client"`) that runs a custom program connecting to a daemon's shared instance socket, registers a destination, and announces it. Then write `shared_instance_announce.toml` and `shared_instance_reconnect.toml` tests.
- **Test:** The tests themselves: verify that a destination registered by a client is discoverable from a remote node, and that a client reconnect results in the destination being re-announced.

### E26: Storage trait is a ~60-method God-Interface — split into per-concern sub-traits
- **Status:** open
- **Priority:** M
- **Phase:** post-7
- **Category:** Design
- **Blocked-by:** No blocker, but low urgency until a partial Storage backend is needed (e.g., ESP32 with external flash)
- **Detail:** The `Storage` trait in `traits.rs` has ~60 methods spanning ~15 logical concerns (Path Table 8, Announce Table 7, Link Table 5, Ratchets 7, Receipts 3, Cleanup 8, Deadlines 2, etc.). This makes implementing a custom Storage backend a monolithic task — even if the node only needs path routing and packet dedup, all 60 methods must be implemented. The trait also mixes two concerns: collection semantics (get/set/remove) and lifecycle management (expire, flush, deadlines). The methods are correctly typed (not generic `load(key) -> bytes`), but typed does not require monolithic. The three existing implementations (NoStorage, MemoryStorage, FileStorage) all implement the full trait, so the current cost is borne only by hypothetical future backends. However, the real architectural limitation is that `NodeCore<R, C, S: Storage>` takes a single `S`, making it impossible to compose backends (e.g., path table on flash, ratchets in RAM).
- **Fix:** Split into per-concern sub-traits (`PathStorage`, `AnnounceStorage`, `RatchetStorage`, `LinkStorage`, etc.) with an umbrella trait: `trait Storage: PathStorage + AnnounceStorage + ... {}` with blanket impl. NodeCore keeps `S: Storage`, so all existing code compiles unchanged. New partial backends only implement the sub-traits they need and compose with MemoryStorage for the rest. Lifecycle methods (expire, flush) can either stay on their respective sub-traits or move to a separate `StorageLifecycle` trait.
- **Test:** All existing Storage tests must pass. New test: verify a composite backend (e.g., custom `PathStorage` + `MemoryStorage` for the rest) works with NodeCore.

### E27: FileStorage wraps MemoryStorage — prevents custom eviction, lazy-loading, RAM/disk split
- **Status:** open
- **Priority:** M
- **Phase:** post-7
- **Category:** Design
- **Related:** E13 (owned return values), E14 (IndexMap eviction), E16 (SD card wear)
- **Detail:** FileStorage delegates ~59 of ~60 Storage methods to an inner `MemoryStorage`. It adds disk persistence for a few collections (ratchets write-through, known_destinations/packet_hashlist flush-on-shutdown). This means: (1) No custom eviction — BTreeMap has no insertion-order, so LRU-style eviction is impossible. (2) No lazy-loading — everything must fit in RAM at startup. (3) No partial RAM/disk split — hot data and cold data are treated identically. (4) SD card wear from full-file rewrites (E16). The wrapping is purely internal — no consumer (NodeCore, Transport, Driver) knows about it. Replacing the inner design is a refactor of one file (storage.rs, ~1500 lines), not an API change. This is technical debt with a clear exit path, not an architectural dead-end. It becomes relevant when: (a) a node manages 10k+ destinations needing LRU eviction, (b) an ESP32 with external flash needs direct disk access, or (c) SD card wear becomes a deployment issue.
- **Fix:** FileStorage implements the Storage trait (or sub-traits, see E26) directly with its own state management. Hot collections stay in RAM (BTreeMap or IndexMap). Cold/large collections use lazy disk access. MemoryStorage remains for embedded and tests. This subsumes E13 (owned values become natural when disk-backed) and E14 (FileStorage can use IndexMap since it's std). E16 (write amplification) can be addressed independently with a log-structured format.
- **Test:** All existing FileStorage tests must pass. Benchmark: memory usage and startup time with 10k+ known_destinations before and after.

### E28: InterfaceMode::multiple_access defined but unused — wire up for E10 and E24
- **Status:** open
- **Priority:** M
- **Phase:** post-7
- **Category:** Design
- **Related:** E10 (send-side jitter), E24 (ingress control)
- **Detail:** The Interface trait already has `fn mode(&self) -> InterfaceMode` with a `multiple_access: bool` flag (traits.rs:69-76), defaulting to false. This is exactly the medium-type discriminator needed for E10 (jitter on shared-medium interfaces) and E24 (ingress control per medium). However: (1) No concrete interface sets it — `InterfaceHandle::mode()` returns `InterfaceMode::default()` (all false), no override anywhere. (2) Core never reads it — no code in transport.rs or node/ checks `mode().multiple_access`. (3) It is effectively dead code. The trait design is correct: `mode()` has a default impl, so adding new flags or changing existing ones does not break implementors. No new enum (e.g., `MediumType`) is needed.
- **Fix:** Three steps: (a) AutoInterface and UDP-broadcast interfaces must override `mode()` to return `InterfaceMode { multiple_access: true, broadcast: true, .. }`. TCP and LocalInterface keep the default (all false). (b) E10 implementation checks `multiple_access` to decide whether to apply send-side jitter. (c) E24 implementation checks `multiple_access` to decide whether ingress control is active by default. Steps (b) and (c) are part of E10/E24 respectively — this issue tracks only the wiring gap (step a) and documents that the extension point exists.
- **Test:** Unit test: verify AutoInterface returns `multiple_access: true`. Unit test: verify TCP returns `multiple_access: false` (default). Integration test deferred to E10/E24.

### E32: KISS deframer unwrap_or(0) silently masks state machine bugs
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Bug
- **Detail:** In `framing/kiss.rs:240`, `finalize_frame()` uses `self.command.unwrap_or(0)` to extract the KISS command byte. The comment claims "command is guaranteed to be Some by the caller", but the fallback silently converts a state machine bug into a valid KISS data frame (command 0). If the precondition is ever violated, corrupted frames would be misclassified rather than rejected.
- **Fix:** Replace `unwrap_or(0)` with a proper error return or debug assertion. `finalize_frame()` could return `Option<KissDeframeResult>`, returning `None` when command is missing.
- **Test:** Unit test: verify that calling `finalize_frame()` without setting command produces an error rather than silently returning command 0.

### E33: Deferred path response uses 0 hops when announce cache is empty
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Bug
- **Detail:** In `transport.rs:3272-3273`, two adjacent `unwrap_or_default()` / `unwrap_or(0)` calls compound: when no cached announce exists, `get_announce_cache()` returns `None` → empty Vec → `Packet::unpack()` fails → `hops` defaults to 0. This makes the placeholder `AnnounceEntry` appear as a 0-hop (local) announce. NodeCore reportedly overwrites this before it matters, but the intermediate state could be observed by concurrent code paths.
- **Fix:** Either skip creating the deferred path response entry when no cached announce exists, or propagate the `None` explicitly so the hop count is clearly unknown rather than silently 0.
- **Test:** Unit test: verify that a deferred path response without cached announce data either skips creation or correctly marks hops as unknown.

### E35: size_sweep runs without proxy — no loss recovery tested for 5KB/50KB files
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Test
- **Found:** Gap 1 implementation
- **Detail:** The size_sweep test was simplified to run without proxy due to proxy rule auto-expiry after count drops. As a result, loss recovery is only tested at 2KB (existing proxy test) and 10KB (4drop/6drop tests). The 5KB and 50KB sizes have no proxy coverage.
- **Fix:** Either extend the proxy to support persistent rules (no auto-expiry), or add dedicated proxy tests for 5KB and 50KB files.
- **Test:** New proxy-enabled transfer tests for 5KB and 50KB file sizes.

### E36: lora_lncp_bidir is sequential, not simultaneous — no contention testing
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Test
- **Found:** Gap 4 implementation
- **Detail:** The bidir test runs a→b and then b→a sequentially. True simultaneous bidirectional transfer (both sides sending at the same time over the same LoRa channel) is not tested. This would require parallel execution support in the test framework. Potential contention, collision, and throughput degradation under simultaneous load is not covered.
- **Fix:** Add parallel file_transfer execution to the test framework, then add a lora_lncp_bidir_simultaneous test.
- **Test:** New test: `lora_lncp_bidir_simultaneous` with both directions running concurrently.

### E37: Proxy only supports deterministic drop counts, not random loss rates
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Test
- **Found:** Coverage audit (Gap 5)
- **Detail:** The proxy drops exactly N frames by count. Real radio channels exhibit probabilistic loss (e.g. 10-20% random frame loss). A `rate=0.2` proxy parameter would allow testing behavior under realistic stochastic loss patterns rather than worst-case deterministic bursts.
- **Fix:** Add `rate=N.N` parameter to proxy rules as a complement to `count=N`. When `rate` is set, each matching frame is independently dropped with probability N.N.
- **Test:** Unit test: verify rate-based dropping produces approximately the expected drop ratio over many frames. Integration test: LoRa transfer with `rate=0.1` proxy rule.

### E38: Multi-hop LoRa testing requires per-node radio config, multi-RNode nodes, and 4 RNodes
- **Status:** open
- **Priority:** M
- **Phase:** post-7
- **Category:** Test
- **Found:** Gap 8 implementation — 3 co-located same-frequency RNodes cannot test multi-hop relay because Reticulum discovers the direct 1-hop path and bypasses the relay.
- **Detail:** True multi-hop LoRa testing (A→B→C where B relays between two separate LoRa links) requires frequency isolation: A↔B on frequency F1, B↔C on frequency F2. Node B must have two RNode interfaces (one per frequency), acting as a frequency bridge. This requires 4 physical RNode devices total: A on F1, B on F1 + F2 (two radios), C on F2. With 3 co-located same-frequency radios, KISS frames carry no sender identity so the proxy cannot filter by source, and Reticulum's hop-count path selection always prefers the direct 1-hop path over the 2-hop relay.
- **Hardware:** 4 RNodes required. A on F1, B with 2 RNodes (F1 + F2), C on F2.
- **Infrastructure changes:**
  1. Per-node radio config: replace global `[radio]` section with per-RNode config inside `[nodes.<name>]` (`topology.rs`: `RadioConfig`, `NodeDef`, `render_config()`)
  2. Multi-RNode nodes: change `NodeDef.rnode: Option<String>` to `rnodes: Vec<RNodeConfig>` with per-entry device path + radio params
  3. Config generator: emit multiple `[[RNode Interface]]` sections per node (`topology.rs`: `render_config()`)
  4. Compose generator: map multiple host devices into one container (`compose.rs`: device list)
- **Scope:** topology.rs, compose.rs, runner.rs, config generation. No core protocol changes needed — Reticulum already supports multiple interfaces per node.
- **Test:** Integration test: `lora_multihop_probe` — A sends probe to C through relay B, verify 2-hop path where A and C are on different frequencies.

### E44: Resource completion proof lost — sender passively burns retries, no recovery
- **Status:** open
- **Priority:** M
- **Phase:** post-7
- **Category:** Protocol
- **Found:** Full suite ×3 baseline run (proof-resend verification), lora_lncp_size_sweep 10KB transfer.
- **Detail:** When the receiver completes a resource transfer, it sends a completion proof (83 bytes). If this proof is lost over LoRa, the sender enters AwaitingProof state and passively increments its retry counter on each timeout (RTT×3 + 10s + retries×0.5s ≈ 22s per retry, 16 retries max ≈ 352s budget). The sender never requests the proof again. The receiver considers the transfer done and has no mechanism to detect proof loss or re-send. Observed: 10KB at 62.5kHz SF7, transfer reached 90.9%, beta sent 83-byte proof at 10:35:03, alpha never received it, 137s radio silence, lncp's hardcoded 300s deadline fires at 10:39:14 (before the 352s retry budget expires). The lncp timeout kills the transfer, not the resource retry budget.
- **Mitigation options:** (1) Sender sends explicit proof re-request after N passive retries; (2) Receiver implements proof delivery confirmation (waits for ACK, re-sends on timeout); (3) Extend lncp timeout beyond resource retry budget (>360s). Option 3 is a band-aid. Options 1/2 require protocol extension.
- **Python behavior:** Same passive AwaitingProof design (Resource.py:638). Not a compatibility constraint — we can improve.
- **Also affects:** lora_rncp_fetch_from_rust (fetch mode, Rust=sender, Python=receiver). Python rncp stalls at "Requesting file from remote" when completion proof is lost — identical AwaitingProof stall from the Rust sender side. Observed once in suite Run 3, 0/5 in isolation. Suite context increases proof loss probability (higher RF load between consecutive tests).
- **Test:** lora_lncp_size_sweep should pass 5/5 after fix. Consider a dedicated proxy test that drops completion proofs.

### E45: Ratchet forward secrecy not wired
- **Status:** open
- **Priority:** H
- **Category:** Protocol
- **Detail:** Ratchet cryptography and disk persistence work and are tested via selftest. However, ratchet validation on announce receipt, ratchet exchange during link establishment, and forward secrecy key rotation at runtime are not activated. Without these, ratchets are stored but never enforced.
- **Test:** Interop test with ratchet-protected announces between Rust and Python.

### E46: Persistence interop test
- **Status:** open
- **Priority:** L
- **Category:** Test
- **Detail:** No test verifies that restarting the Rust daemon preserves known destinations without re-announce. The persistence code exists but lacks end-to-end validation.

### E47: Buffer/Stream integration in LinkHandle and compression over links
- **Status:** open
- **Priority:** L
- **Category:** Feature
- **Detail:** The Buffer/Stream layer (RawChannelReader/Writer) exists but is not integrated into LinkHandle. BZ2 compression over link channels is not yet usable.

### E48: `lns` missing subcommands
- **Status:** open
- **Priority:** L
- **Category:** Feature
- **Detail:** `lns status`, `lns path`, `lns probe`, and `lns interfaces` are stubs. The RPC server already supports the underlying queries.

### E49: Fuzzing of packet parsers
- **Status:** open
- **Priority:** L
- **Category:** Test
- **Detail:** No fuzz testing for Packet::unpack, announce validation, HDLC deframing, or KISS decoding.

### E50: `is_connected_to_shared_instance` semantics
- **Status:** open
- **Priority:** L
- **Category:** Feature
- **Detail:** Python gates several transport decisions on whether the node is connected to a shared instance. Rust supports shared instances via LocalInterface but does not replicate all gated behavior.

### E51: RNode stats parsing
- **Status:** open
- **Priority:** L
- **Category:** Feature
- **Detail:** RNode firmware reports RSSI, SNR, channel time, battery voltage, and temperature. These are not parsed or exposed via rnstatus.

### E52: Serial Interface and KISS Interface
- **Status:** open
- **Priority:** L
- **Category:** Feature
- **Detail:** Generic serial and KISS TNC interfaces are not implemented. RNode uses KISS framing but is a specific implementation, not a generic KISS interface.

### E53: Multi-segment sending
- **Status:** open
- **Priority:** L
- **Category:** Feature
- **Detail:** Files exceeding MAX_EFFICIENT_SIZE (1,048,575 bytes) are received correctly as multiple segments but cannot be sent as multiple segments from Rust.

### E54: Resource bandwidth adaptation
- **Status:** open
- **Priority:** L
- **Category:** Feature
- **Detail:** Resource transfers do not adapt sending rate to available bandwidth. Python has basic rate adaptation.

### E55: C-API expansion
- **Status:** open
- **Priority:** L
- **Category:** Feature
- **Detail:** The C-API covers identity operations only. Destinations, links, packets, resources, and path discovery are not exposed.

### E56: Debian packaging
- **Status:** open
- **Priority:** L
- **Category:** Feature
- **Detail:** No Debian packages or systemd unit for lnsd.

### E57: Android/Kotlin bindings
- **Status:** open
- **Priority:** L
- **Category:** Feature
- **Detail:** No UniFFI bindings or AAR package for Android.

### E58: Interface Discovery
- **Status:** open
- **Priority:** L
- **Category:** Feature
- **Detail:** Python's Discovery.py auto-discovers and connects to TCP/LoRa peers via special announces. Not implemented.

### E59: Additional interfaces (I2P, AX.25, Pipe)
- **Status:** open
- **Priority:** L
- **Category:** Feature
- **Detail:** I2P (SAM v3), AX.25 KISS (amateur radio), and Pipe interfaces are not implemented.

### E60: Roaming mode and reachability tracking
- **Status:** open
- **Priority:** L
- **Category:** Feature
- **Detail:** Python's MODE_ROAMING with reachability tracking is not implemented.

