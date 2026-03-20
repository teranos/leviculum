# leviculum — Open Issues

## Overview

| ID | Priority | Category | Summary |
|----|----------|----------|---------|
| E12 | L | Feature | Storage flush interval is hardcoded to one hour |
| E16 | L | Perf | FileStorage rewrites entire files on every flush |
| E18 | L | Feature | UDPInterface cannot bind to a specific network interface |
| E19 | L | Feature | UDPInterface does not support multiple forward addresses |
| E20 | L | Feature | AutoInterface only works on Linux |
| E21 | L | Feature | AutoInterface does not detect NICs added or removed at runtime |
| E22 | L | Feature | AutoInterface does not support multiple group IDs per node |
| E24 | M | Design | Ingress control needs per-interface defaults based on medium type |
| E25 | L | Test | Shared instance client behavior lacks integration tests |
| E26 | M | Design | Storage trait is monolithic and prevents partial or disk-backed implementations |
| E28 | M | Design | InterfaceMode flags are defined but never set or read |
| E32 | L | Bug | KISS deframer masks state machine errors with a silent fallback |
| E33 | L | Bug | Deferred path response fabricates zero hops when announce cache is empty |
| E35 | L | Test | No proxy coverage for 5KB and 50KB resource transfers |
| E36 | L | Test | Bidirectional LoRa transfer test runs sequentially, not simultaneously |
| E37 | L | Test | Proxy only supports deterministic drop counts, not random loss rates |
| E38 | M | Test | Multi-hop LoRa testing needs frequency isolation and four RNode devices |
| E44 | M | Protocol | Resource completion proof can be lost with no recovery mechanism |
| E45 | H | Protocol | Ratchet forward secrecy is implemented but not enforced |
| E46 | L | Test | No test verifies that daemon restart preserves known destinations |
| E47 | L | Feature | Buffer/Stream layer is not integrated into the link API |
| E48 | L | Feature | Several lns subcommands are stubs |
| E49 | L | Test | No fuzz testing for packet parsers |
| E50 | L | Feature | Shared instance transport decisions do not match Python behavior |
| E51 | L | Feature | RNode radio statistics are not parsed or reported |
| E52 | L | Feature | Generic serial and KISS TNC interfaces are not implemented |
| E53 | L | Feature | Sending files larger than one megabyte as multiple segments is not supported |
| E54 | L | Feature | Resource transfers do not adapt to available bandwidth |
| E55 | L | Feature | C-API only covers identity operations |
| E56 | L | Feature | No Debian packages or systemd service |
| E57 | L | Feature | No Android bindings |
| E58 | L | Feature | Interface auto-discovery is not implemented |
| E59 | L | Feature | I2P, AX.25, and pipe interfaces are not implemented |
| E60 | L | Feature | Roaming mode is not implemented |

---

## Issues

### E12: Storage flush interval is hardcoded to one hour

The periodic storage flush runs every 3600 seconds. This is crash protection only since normal shutdown flushes via the signal handler. Deployments on battery-powered devices or SD cards may want a different interval. The fix is to make this configurable via the builder or config file.

### E16: FileStorage rewrites entire files on every flush

FileStorage rewrites the complete `known_destinations` and `packet_hashlist` files on every flush. On high-traffic nodes these can reach 14 MB. A dirty flag avoids writes when idle, but dirty flushes still rewrite everything. On SD cards this accelerates wear. An append-only or log-structured format would reduce write amplification, but the Python-compatible msgpack format encodes total element count in the header, making appending impossible without a format change.

### E18: UDPInterface cannot bind to a specific network interface

Python's UDPInterface supports a `device` parameter that resolves a NIC name to its IP and broadcast addresses. The Rust implementation only accepts explicit IP addresses.

### E19: UDPInterface does not support multiple forward addresses

The Rust UDPInterface sends to a single forward address. Sending to multiple addresses (for example across subnets) is not supported. Python also only supports one forward address, so this would be a Rust-only enhancement.

### E20: AutoInterface only works on Linux

The NIC enumeration, multicast socket setup, and scope ID resolution use Linux-specific APIs. macOS and Windows are not supported.

### E21: AutoInterface does not detect NICs added or removed at runtime

NICs are enumerated once at startup. Hot-plugging a USB Ethernet adapter or reconnecting WiFi is not detected. Python has the same limitation.

### E22: AutoInterface does not support multiple group IDs per node

Python supports multiple `[[Auto Interface]]` sections with different group IDs, creating isolated discovery domains on the same LAN. The Rust implementation supports only one instance per node because multiple instances would conflict on the discovery and data ports.

### E24: Ingress control needs per-interface defaults based on medium type

Python's ingress control rate-limits announces on new interfaces to prevent storms on shared media like LoRa. This is counterproductive on TCP where it silently suppresses valid announces during startup. The fix is to make ingress control a per-interface setting that defaults to off for TCP/UDP and on for shared-medium interfaces. This depends on E28 for the medium-type discriminator.

### E25: Shared instance client behavior lacks integration tests

The shared instance registration delay and reconnect re-announce logic have unit tests but no integration tests. Writing them requires the test framework to support running a client program inside a container that connects to a daemon via Unix socket IPC.

### E26: Storage trait is monolithic and prevents partial or disk-backed implementations

The Storage trait has roughly 60 methods spanning 15 logical concerns. Implementing a custom backend requires implementing all methods even if only path routing and packet dedup are needed. Several methods return references, which prevents purely disk-backed implementations. FileStorage delegates everything to an in-memory MemoryStorage, which prevents custom eviction strategies, lazy loading, and RAM/disk splitting.

The fix is to split the trait into per-concern sub-traits (PathStorage, AnnounceStorage, RatchetStorage, etc.) with an umbrella trait for backward compatibility, and to change reference-returning methods to return owned values. This is a breaking API change but affects only three existing implementations.

### E28: InterfaceMode flags are defined but never set or read

The Interface trait has a `mode()` method returning `InterfaceMode` with a `multiple_access` flag, but no concrete interface sets it and no code reads it. This flag is the medium-type discriminator needed for send-side jitter on shared media (LoRa, radio) and for per-interface ingress control defaults (E24). The fix is to have AutoInterface and broadcast UDP interfaces return `multiple_access: true`, then wire the flag into jitter and ingress control logic.

### E32: KISS deframer masks state machine errors with a silent fallback

The KISS deframer uses `unwrap_or(0)` to extract the command byte when finalizing a frame. If the command was never set due to a state machine bug, this silently produces a valid data frame (command 0) instead of reporting an error.

### E33: Deferred path response fabricates zero hops when announce cache is empty

When creating a deferred path response without a cached announce, two fallback defaults compound to produce a placeholder entry that appears as a zero-hop local announce. The intermediate state is overwritten before it matters in practice, but it could be observed by concurrent code.

### E35: No proxy coverage for 5KB and 50KB resource transfers

The size sweep test runs without the proxy because proxy rules expire after their drop count. Loss recovery is only tested at 2KB and 10KB. The 5KB and 50KB sizes have no loss recovery coverage.

### E36: Bidirectional LoRa transfer test runs sequentially, not simultaneously

The bidirectional test sends in one direction, then the other. True simultaneous bidirectional transfer over a shared LoRa channel is not tested. This would require parallel execution support in the test framework.

### E37: Proxy only supports deterministic drop counts, not random loss rates

The proxy drops exactly N matching frames. Real radio channels exhibit probabilistic loss. A `rate` parameter would allow testing under realistic stochastic conditions.

### E38: Multi-hop LoRa testing needs frequency isolation and four RNode devices

Three co-located same-frequency radios cannot test multi-hop relay because Reticulum discovers the direct one-hop path and bypasses the relay. True multi-hop testing requires two frequencies (A↔B on F1, B↔C on F2) and four physical RNode devices. The test framework needs per-node radio configuration and support for multi-radio nodes.

### E44: Resource completion proof can be lost with no recovery mechanism

When a resource transfer completes, the receiver sends a completion proof. If this proof is lost over LoRa, the sender enters an AwaitingProof state and passively counts through its retry budget without ever requesting the proof again. The receiver considers the transfer done and has no way to detect proof loss. Observed on the 10KB size sweep test and on the fetch-from-rust test. Python has the same passive design. The fix is either explicit proof re-request from the sender or proof delivery confirmation from the receiver.

### E45: Ratchet forward secrecy is implemented but not enforced

Ratchet key generation, storage, disk persistence, and rotation all work and are tested via selftest. However, ratchet validation is not active on the announce receive path (announces with ratchets are stored but not verified against expected values). Ratchet-based encryption is not used during link establishment. Without enforcement, ratchets provide no actual forward secrecy in production.

### E46: No test verifies that daemon restart preserves known destinations

The persistence code saves and loads known destinations and packet hashes, but no end-to-end test restarts the daemon and verifies that previously known destinations remain reachable without re-announce.

### E47: Buffer/Stream layer is not integrated into the link API

The RawChannelReader, RawChannelWriter, and BufferedChannelWriter exist and are tested in isolation, but they are not wired into LinkHandle. BZ2 compression over link channels is not usable through the public API.

### E48: Several lns subcommands are stubs

The `lns status`, `lns path`, `lns probe`, and `lns interfaces` subcommands are not implemented. The RPC server already supports the underlying queries, so the implementation is straightforward.

### E49: No fuzz testing for packet parsers

Packet::unpack, announce validation, HDLC deframing, and KISS decoding have no fuzz testing.

### E50: Shared instance transport decisions do not match Python behavior

Python gates several transport decisions on whether the node is connected to a shared instance. Rust supports shared instances via LocalInterface but does not replicate all of the gated behavior.

### E51: RNode radio statistics are not parsed or reported

RNode firmware reports RSSI, SNR, channel time, battery voltage, and temperature via KISS commands. These values are not parsed or exposed through rnstatus.

### E52: Generic serial and KISS TNC interfaces are not implemented

The RNode interface uses KISS framing over serial but is specific to RNode firmware. A generic serial interface and a standard KISS TNC interface for use with other radio hardware are not available.

### E53: Sending files larger than one megabyte as multiple segments is not supported

Files exceeding MAX_EFFICIENT_SIZE (1,048,575 bytes) are received correctly as multiple segments, but the sender side does not split outgoing files into multiple segments.

### E54: Resource transfers do not adapt to available bandwidth

Resource transfers send at a fixed rate determined by the channel window. Python has basic bandwidth adaptation that adjusts sending behavior based on measured throughput.

### E55: C-API only covers identity operations

The C-API exposes identity creation, signing, verification, and encryption. Destinations, links, packets, resources, and path discovery are not available through the C interface.

### E56: No Debian packages or systemd service

There are no Debian packages or a systemd unit file for running lnsd as a system service.

### E57: No Android bindings

There are no UniFFI-based Kotlin bindings or an AAR package for integrating leviculum into Android applications.

### E58: Interface auto-discovery is not implemented

Python's Discovery module auto-discovers and connects to TCP and LoRa peers via special announce packets. This is not implemented in Rust.

### E59: I2P, AX.25, and pipe interfaces are not implemented

The I2P interface (SAM v3 protocol), AX.25 KISS interface for amateur radio, and pipe interface for stdin/stdout transport are not available.

### E60: Roaming mode is not implemented

Python's MODE_ROAMING with reachability tracking for mobile nodes is not implemented.
