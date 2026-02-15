# Architecture Review — Round 3: Core/Std Split and API Surface

## Part A: Core/Std Split Audit

### File-by-File Analysis

#### `lib.rs`

| Aspect | Detail |
|--------|--------|
| **std/tokio Dependencies** | None directly. Re-exports from `reticulum_core`. |
| **Protocol Logic Found** | None. Pure module declarations and re-exports. |
| **Movable to Core?** | N/A |

---

#### `clock.rs`

| Aspect | Detail |
|--------|--------|
| **std/tokio Dependencies** | `std::time::Instant` (monotonic clock), `std::thread::sleep` (test only). |
| **Protocol Logic Found** | None. Implements the `Clock` trait from core with `Instant::now().elapsed()`. |
| **Movable to Core?** | N/A — textbook platform glue. |

---

#### `error.rs`

| Aspect | Detail |
|--------|--------|
| **std/tokio Dependencies** | `thiserror::Error` (derives `std::error::Error`), `std::io::Error` (via `#[from]`). |
| **Protocol Logic Found** | None. Pure error type definitions with `From` conversions. |
| **Movable to Core?** | N/A — `thiserror` and `std::error::Error` require std. |

---

#### `storage.rs`

| Aspect | Detail |
|--------|--------|
| **std/tokio Dependencies** | `std::path::{Path, PathBuf}`, `std::fs::{create_dir_all, read, write, rename, remove_file, read_dir}`, `std::fmt::Write`, `serde` + `rmp_serde`. |
| **Protocol Logic Found** | None. All methods are filesystem CRUD operations. |
| **Movable to Core?** | **Low.** `hex_encode`/`hex_decode` (lines 116-134) are pure functions that could theoretically live in core, but only serve filesystem key naming. |

---

#### `config.rs`

| Aspect | Detail |
|--------|--------|
| **std/tokio Dependencies** | `std::collections::HashMap`, `std::path::*`, `std::fs::*`, `std::env::var_os`, `serde`, `toml`. |
| **Protocol Logic Found** | None. Configuration loading/saving and data structures. |
| **Movable to Core?** | **Low.** `DEFAULT_BITRATE_BPS` (62,500) is protocol-relevant but only populates config defaults. |

---

#### `interfaces/mod.rs`

| Aspect | Detail |
|--------|--------|
| **std/tokio Dependencies** | `tokio::sync::mpsc` (channels for `InterfaceHandle`). |
| **Protocol Logic Found** | None. `InterfaceRegistry` manages handles with round-robin fairness — pure async scheduling. |
| **Movable to Core?** | **Low.** Inherently tied to tokio mpsc channels. |

---

#### `interfaces/tcp.rs`

| Aspect | Detail |
|--------|--------|
| **std/tokio Dependencies** | `std::io`, `std::net::ToSocketAddrs`, `std::time::Duration`, `tokio::io::AsyncWriteExt`, `tokio::sync::mpsc`, `tokio::select!`, `tokio::spawn`, `tokio::net::TcpStream`, `rand_core::{OsRng, RngCore}`. |
| **Protocol Logic Found** | None. Reads bytes from TCP, runs through `Deframer` (from core), sends to channel. Outgoing: receives from channel, runs through `frame()` (from core), writes to socket. `maybe_corrupt` is fault injection, not protocol. |
| **Movable to Core?** | None. Framing (`Deframer`, `frame()`) already lives in core. This file only does I/O. |

---

#### `interfaces/hdlc.rs`

| Aspect | Detail |
|--------|--------|
| **std/tokio Dependencies** | None. |
| **Protocol Logic Found** | None. Single-line re-export: `pub use reticulum_core::framing::hdlc::*;` |
| **Movable to Core?** | N/A — already IS core. |

---

#### `driver/mod.rs` — THE EVENT LOOP

| Aspect | Detail |
|--------|--------|
| **std/tokio Dependencies** | `Arc`, `Mutex`, `Poll`, `Duration`, `tokio::{mpsc, watch, spawn, select!, sleep_until, Instant}`, `std::future::{pending, poll_fn}`. |
| **Protocol Logic Found** | **Minimal.** Line 585: `delta.clamp(250, 1000)` — clamps timer interval to [250ms, 1s]. This is a platform-level scheduling decision, not protocol logic. Core's `next_deadline()` returns the actual protocol deadline; the clamp prevents the tokio timer from firing too frequently or too rarely. |
| **Movable to Core?** | **Low.** The clamp could be a configurable builder parameter rather than hardcoded, but it does not represent protocol logic. |

**Detailed event loop analysis:**

The `run_event_loop()` function has exactly four `select!` branches:

1. **Packet from interface** — Calls `core.handle_packet(iface_id, &pkt.data)`, dispatches `TickOutput`. Zero protocol decisions.
2. **External TickOutput** — Receives pre-computed `TickOutput` from `connect()`, `send_on_connection()`, etc. and dispatches it. Zero protocol decisions.
3. **Timer** — Calls `core.handle_timeout()`, dispatches `TickOutput`. Computes next poll time from `core.next_deadline()` with [250ms, 1s] clamp. The clamp is scheduling, not protocol.
4. **Shutdown** — Breaks the loop. Zero protocol decisions.

`dispatch_output()` is a pure mechanical dispatcher: `Action::SendPacket` -> channel send, `Action::Broadcast` -> iterate senders, events -> event channel. Never inspects packet contents, never makes routing decisions, never modifies data.

`recv_any()` is a fair round-robin poller over interface channels. Pure async scheduling.

---

#### `driver/stream.rs` — ConnectionStream

| Aspect | Detail |
|--------|--------|
| **std/tokio Dependencies** | `std::io`, `Arc`, `Mutex`, `tokio::{mpsc, time::sleep}`, `Duration`. |
| **Protocol Logic Found** | **Minimal.** Lines 94-105: Error mapping (`SendError::WindowFull` -> `WouldBlock`, `PacingDelay` -> `WouldBlock`, `NoConnection` -> `NotConnected`). This is error translation, not protocol logic. Line 146: 50ms retry interval for `WindowFull` — a hardcoded platform tuning constant. |
| **Movable to Core?** | **Low.** The retry loop is inherently async. The 50ms constant could be configurable. |

---

#### `driver/endpoint.rs` — PacketEndpoint

| Aspect | Detail |
|--------|--------|
| **std/tokio Dependencies** | `Arc`, `Mutex`, `tokio::sync::mpsc`. |
| **Protocol Logic Found** | None. Locks core, calls `core.send_single_packet()`, dispatches `TickOutput`. |
| **Movable to Core?** | N/A — pure async glue. |

---

#### `driver/builder.rs` — ReticulumNodeBuilder

| Aspect | Detail |
|--------|--------|
| **std/tokio Dependencies** | `std::net::SocketAddr`, `std::path::PathBuf`. Indirectly: `Config::load()`, `Storage::new()`. |
| **Protocol Logic Found** | None. Wires platform dependencies (OsRng, SystemClock, filesystem Storage) into core's `NodeCoreBuilder`. |
| **Movable to Core?** | N/A — platform initialization glue. |

---

#### `reticulum.rs` — Reticulum

| Aspect | Detail |
|--------|--------|
| **std/tokio Dependencies** | `tokio::sync::mpsc` (for `Receiver<NodeEvent>`). Indirectly: `Config`, `ReticulumNode`. |
| **Protocol Logic Found** | None. Loads config from disk or uses default, passes `enable_transport` from config to builder, delegates everything to `ReticulumNode`. |
| **Movable to Core?** | N/A — thin config wrapper. |

---

### Summary Table

| File | std/tokio Dependencies | Protocol Logic | Movable? |
|------|----------------------|----------------|----------|
| `lib.rs` | None | None | N/A |
| `clock.rs` | `Instant` | None | N/A |
| `error.rs` | `thiserror`, `io::Error` | None | N/A |
| `storage.rs` | `fs::*`, `path::*`, `serde`, `rmp_serde` | None | Low (hex helpers) |
| `config.rs` | `HashMap`, `fs::*`, `env`, `serde`, `toml` | None | Low (bitrate constant) |
| `interfaces/mod.rs` | `tokio::mpsc` | None | Low |
| `interfaces/tcp.rs` | `tokio::{io, net, spawn, select!}`, `OsRng` | None | None (framing in core) |
| `interfaces/hdlc.rs` | None | None | N/A (re-export) |
| **`driver/mod.rs`** | `Arc`, `Mutex`, `tokio::{mpsc, watch, spawn, select!, sleep_until}` | **250ms/1s timer clamp** | Low (scheduling param) |
| **`driver/stream.rs`** | `io`, `Arc`, `Mutex`, `tokio::{mpsc, sleep}` | **50ms retry, error mapping** | Low (async retry) |
| `driver/endpoint.rs` | `Arc`, `Mutex`, `tokio::mpsc` | None | N/A |
| `driver/builder.rs` | `SocketAddr`, `PathBuf` | None | N/A |
| `reticulum.rs` | `tokio::mpsc` | None | N/A |

### Overall Assessment

**The core/std split is exceptionally clean.** Out of 13 files in `reticulum-std/src/`:

- **Zero files contain protocol logic.** Every file either implements a core trait with platform facilities, provides async wrappers that delegate to `NodeCore`, manages platform resources, or re-exports core types.
- **Two files have minor hardcoded platform constants**: the 250ms/1s timer clamp in `driver/mod.rs` and the 50ms `WindowFull` retry in `driver/stream.rs`. Neither affects protocol correctness.
- **No protocol logic needs to move to core.** The architecture is achieving its stated goal.

---

## Part B: API Surface Audit

### 1. NodeCore Public Methods

#### Lifecycle

| Method | Description |
|--------|-------------|
| `builder()` | Returns `NodeCoreBuilder` |

#### Configuration

| Method | Description |
|--------|-------------|
| `register_destination()` | Register a destination for receiving packets/links |
| `unregister_destination()` | Remove a registered destination |
| `destination()` | Look up a registered destination |
| `transport()` | Access the internal `Transport` struct |

#### Connection Management

| Method | Description |
|--------|-------------|
| `connect()` | Initiate a connection to a destination |
| `accept_connection()` | Accept an incoming connection request |
| `reject_connection()` | Reject an incoming connection request |
| `close_connection()` | Close an active connection |
| `connection()` | Get immutable reference to a Connection |
| `connection_mut()` | Get mutable reference to a Connection |
| `find_connection_to()` | Find active connection to a destination |
| `active_connection_count()` | Count active connections |
| `pending_connection_count()` | Count pending connections |

#### Messaging

| Method | Description |
|--------|-------------|
| `send_on_connection()` | Send data over an established connection |
| `send_single_packet()` | Send a single packet to a destination (no connection needed) |

#### Path / Routing

| Method | Description |
|--------|-------------|
| `announce_destination()` | Announce a destination to the network |
| `request_path()` | Request a path to a destination |
| `has_path()` | Check if a path to a destination is known |
| `hops_to()` | Get hop count to a destination |

#### Diagnostics

| Method | Description |
|--------|-------------|
| `connection_stats()` | Get statistics for a connection's channel |

#### Sans-I/O Entry Points

| Method | Description |
|--------|-------------|
| `handle_packet()` | Process an incoming packet |
| `handle_timeout()` | Process a timeout event |
| `next_deadline()` | Query when next timeout should fire |
| `handle_interface_down()` | Process an interface going down |

---

### 2. Visibility Issues

| # | Type/Method | Severity | Description |
|---|-------------|----------|-------------|
| 1 | `NodeCore::transport()` | **Medium** | Exposes the entire internal `Transport` struct publicly. Only used by `reticulum-std` for `clock().now_ms()`. Should be `pub(crate)` or provide a narrower accessor (e.g., `now_ms()`). |
| 2 | ~20 re-exported types in `lib.rs` | **Medium** | `SendHandle`, `SendResult`, `SendMethod`, `Link`, `LinkEvent`, `LinkCloseReason`, `LinkState`, `Packet`, `PacketReceipt`, `ReceiptStatus`, `ChannelAction`, `Envelope`, `MessageState`, `KnownRatchets`, `Ratchet`, `RatchetError`, `IfacConfig`, `IfacError`, `generate_random_hash`, `StreamDataMessage` are re-exported from `lib.rs` but never imported by any consumer crate (`reticulum-std`, `reticulum-cli`, `reticulum-ffi`). |
| 3 | `LinkManager` drain methods | **Low** | `take_pending_rtt_packet()`, `drain_close_packets()`, `drain_keepalive_packets()`, `drain_proof_packets()` are `pub` but only used in `#[cfg(test)]` tests. Should be `pub(crate)` or `#[cfg(test)]`. |

---

### 3. Invalid State Creation

| # | Type/Method | Severity | Description |
|---|-------------|----------|-------------|
| 1 | `NodeCore::connect()` without path | **Low** | When no path exists for the destination, `connect()` falls back to broadcast instead of returning an error. This is a silent fallback — the caller doesn't know the link request was broadcast rather than routed. |
| 2 | `Channel::mark_delivered()` return ignored | **Low** | `NodeCore` calls `mark_channel_delivered()` but never checks the `bool` return value. A bogus sequence ACK is silently ignored. |

---

### 4. Temporal Coupling

| # | Coupling | Severity | Description |
|---|---------|----------|-------------|
| 1 | Deferred dispatch | **Medium** | `connect()`, `send_on_connection()`, `close_connection()`, `announce_destination()` all return `TickOutput` that **MUST** be dispatched to interfaces for the operation to take effect. Only `announce_destination()` documents this requirement explicitly. If the caller discards the `TickOutput`, the operation silently fails (no packet sent, no error). |
| 2 | `register_destination()` before `connect()` | **Low** | Must register a destination (with proof strategy) before accepting connections on it. Not enforced — `accept_connection()` returns `ConnectionError::IdentityNotFound` if the destination isn't registered, which is correct but the error name is misleading. |
| 3 | `handle_packet()` / `handle_timeout()` event processing | **Low** | Events are returned in the `TickOutput`. The driver must process both actions (send packets) and events (notify application). If only actions are dispatched and events are dropped, the application never sees connection state changes. This is inherent to the sans-I/O pattern and documented. |

---

### 5. Error Type Audit

#### ChannelError

| Variant | Constructed? | Issue |
|---------|-------------|-------|
| `WindowFull` | Yes | |
| `PacingDelay { ready_at_ms }` | Yes | |
| `TooLarge` | Yes | |
| `InvalidSequence` | Yes | |
| `InvalidState` | Yes | |
| `DuplicateSequence` | Yes | |

No issues. All variants are used.

#### LinkError

| Variant | Constructed? | Issue |
|---------|-------------|-------|
| `InvalidState` | Yes | |
| `Timeout` | **NO** | **Dead variant.** Never constructed. Timeouts produce `LinkCloseReason::Timeout` via the event system instead. |
| `InvalidProof` | Yes | |
| `KeyExchangeFailed` | Yes | |
| `NoDestination` | Yes | |
| `InvalidRequest` | Yes | |
| `NoIdentity` | Yes | |
| `InvalidRtt` | Yes | |
| `NotFound` | Yes | |
| `WindowFull` | Yes | |
| `PacingDelay { ready_at_ms }` | Yes | |

| Issue | Severity |
|-------|----------|
| `LinkError::Timeout` is never constructed | Low |
| `WindowFull`/`PacingDelay` duplicated across `ChannelError`, `LinkError`, `SendError` (3 layers wrapping the same concept) | Low |

#### SendError

| Variant | Constructed? | Issue |
|---------|-------------|-------|
| `NoPath` | Yes | |
| `TooLarge` | Yes | |
| `NoConnection` | Yes | |
| `ConnectionFailed` | Yes (catch-all) | |
| `WindowFull` | Yes | |
| `PacingDelay { ready_at_ms }` | Yes | |
| `Timeout` | **NO** | **Dead variant.** Never constructed. |
| `InvalidDestination` | **NO** | **Dead variant.** Never constructed. |

#### ConnectionError

| Variant | Constructed? | Issue |
|---------|-------------|-------|
| `InvalidState` | **NO** | Dead variant (only reachable via `From<LinkError>` indirectly) |
| `LinkError(LinkError)` | Yes | |
| `ChannelError(ChannelError)` | **NO** | `From<ChannelError>` impl exists but is unused in production; `send_on_connection()` converts channel errors to `SendError` instead |
| `TooLarge` | **NO** | Dead variant |
| `NotFound` | Yes | |
| `IdentityNotFound` | Yes | |

#### BuildError

| Variant | Constructed? | Issue |
|---------|-------------|-------|
| `NoIdentity` | **NO** | `build()` auto-generates an identity, making this unreachable |
| `InvalidConfig` | **NO** | No config validation exists |

| Issue | Severity | Description |
|-------|----------|-------------|
| Both `BuildError` variants are dead | **Medium** | `build()` never fails. The `Result` return type is misleading. Could be infallible. |

#### DeliveryError

| Variant | Constructed? | Issue |
|---------|-------------|-------|
| `NoPath` | **NO** | Dead variant in production |
| `Timeout` | Yes | |
| `ConnectionFailed` | Yes | |

#### Error Type Summary

| Error Type | Total Variants | Dead Variants | Dead Variant Names |
|------------|---------------|---------------|-------------------|
| `ChannelError` | 6 | 0 | — |
| `LinkError` | 11 | 1 | `Timeout` |
| `SendError` | 8 | 2 | `Timeout`, `InvalidDestination` |
| `ConnectionError` | 6 | 3 | `InvalidState`, `ChannelError(_)`, `TooLarge` |
| `BuildError` | 2 | 2 | `NoIdentity`, `InvalidConfig` |
| `DeliveryError` | 3 | 1 | `NoPath` |
| **Total** | **36** | **9** | — |

---

### 6. NodeEvent Clarity

#### Clear and well-documented variants

`AnnounceReceived`, `PathFound`, `PathLost`, `ConnectionRequest`, `ConnectionEstablished`, `ConnectionClosed`, `ConnectionStale`, `ConnectionRecovered`, `InterfaceDown` — all have clear semantics.

#### Confusing variants

| Variant | Severity | Issue |
|---------|----------|-------|
| `PacketReceived { from }` | **Medium** | The `from` field is actually the **destination** hash (the hash we registered), not the sender's identity. Misleading field name. |
| `DataReceived` vs `MessageReceived` | **Medium** | `DataReceived` = raw data on a link without channel framing. `MessageReceived` = channel message with type/sequence. The distinction is correct but the naming is subtle. A new developer might not realize these are different packet paths. |
| `DeliveryConfirmed` vs `LinkDeliveryConfirmed` | **Medium** | `DeliveryConfirmed` = single-packet proof. `LinkDeliveryConfirmed` = link-data proof. Both confirm delivery but for different transport methods. The `Link` prefix is the only distinguishing element. |
| `ProofRequested` vs `LinkProofRequested` | **Medium** | Same pattern: `ProofRequested` for single packets, `LinkProofRequested` for link data. |
| `PathRequestReceived` | **Low** | Documented as informational (transport handles it internally). A developer might think they need to respond to it. |
| `ChannelRetransmit` | **Low** | An observability event. Could be confusing — is the application supposed to do something? |

#### Missing variants

| Missing Event | Severity | Description |
|---------------|----------|-------------|
| Handshake timeout vs active-link timeout | **Low** | Both reported as `ConnectionClosed { reason: Timeout }`. A `ConnectionFailed` variant would distinguish handshake failures. |
| Channel exhaustion | **Low** | When max retries exceeded, link is torn down as `ConnectionClosed`. No specific event for "channel failed due to retransmission exhaustion." |

---

### Complete Issue Table

| # | Type/Method | Category | Severity | Description |
|---|-------------|----------|----------|-------------|
| 1 | `NodeCore::transport()` | visibility | **Medium** | Exposes entire internal `Transport` publicly. Should provide narrower accessor. |
| 2 | ~20 re-exported types in `lib.rs` | visibility | **Medium** | Never imported by any consumer crate. |
| 3 | `BuildError` (both variants) | error-quality | **Medium** | Both dead. `build()` never fails. `Result` return type misleading. |
| 4 | Deferred dispatch undocumented | temporal-coupling | **Medium** | `connect()`, `send_on_connection()`, `close_connection()` return `TickOutput` that MUST be dispatched. Only `announce_destination()` documents this. |
| 5 | `NodeEvent::PacketReceived { from }` | clarity | **Medium** | `from` field contains the destination hash, not the sender. |
| 6 | `DataReceived` vs `MessageReceived` | clarity | **Medium** | Subtle naming distinction for different packet paths. |
| 7 | `DeliveryConfirmed` vs `LinkDeliveryConfirmed` | clarity | **Medium** | Easy to confuse. Both confirm delivery for different transport paths. |
| 8 | `ProofRequested` vs `LinkProofRequested` | clarity | **Medium** | Same confusion pattern. |
| 9 | `LinkError::Timeout` | error-quality | **Low** | Dead variant. Timeouts go through event system. |
| 10 | `SendError::Timeout`, `SendError::InvalidDestination` | error-quality | **Low** | Dead variants. |
| 11 | `ConnectionError::InvalidState/TooLarge/ChannelError` | error-quality | **Low** | Dead variants in production. |
| 12 | `DeliveryError::NoPath` | error-quality | **Low** | Dead variant. |
| 13 | `WindowFull`/`PacingDelay` at 3 layers | error-quality | **Low** | Same concept wrapped in `ChannelError`, `LinkError`, `SendError`. |
| 14 | `NodeCore::connect()` without path | invalid-state | **Low** | Silent broadcast fallback instead of error. |
| 15 | `mark_channel_delivered()` return ignored | invalid-state | **Low** | Bogus sequence ACK silently ignored. |
| 16 | `LinkManager` drain methods | visibility | **Low** | `pub` but only used in tests. |

---

## Part C: Naming and Conceptual Clarity

### Naming Divergence Table

| Concept | Python Name | Core Internal | Core Public API | reticulum-std | Confusing? |
|---------|-------------|--------------|-----------------|---------------|------------|
| Verified point-to-point session | `Link` | `Link` | `Connection` (NodeEvent, NodeCore methods) | `ConnectionStream` | **YES** — 4 names for 1 concept |
| Session identifier | `link.link_id` | `LinkId` | `link_id` (field in NodeEvent) | `link_id` (field) | **Moderate** — events say "Connection" but fields say `link_id` |
| Session states | `Link.PENDING/HANDSHAKE/ACTIVE/STALE/CLOSED` | `LinkState::Pending/Handshake/Active/Stale/Closed` | Not exposed directly | Not exposed | No — internal match is exact |
| Close reasons | `Link.TIMEOUT/INITIATOR_CLOSED/DESTINATION_CLOSED` | `LinkCloseReason::Normal/Timeout/InvalidProof/PeerClosed/Stale` | `CloseReason::Normal/Timeout/InvalidProof/PeerClosed/Stale` | N/A | **Moderate** — Python 3 reasons, Rust 5. Identical enums duplicated as `LinkCloseReason` + `CloseReason`. |
| Initiate session | `Link(destination)` | `LinkManager::initiate()` | `NodeCore::connect()` | `ReticulumNode::connect()` -> `ConnectionStream` | **YES** — Python: `Link(dest)`, Rust: `connect()` |
| Accept session | `Destination.set_link_established_callback()` (implicit) | `LinkManager::accept_link()` | `NodeCore::accept_connection()` | `ReticulumNode::accept_connection()` -> `ConnectionStream` | **YES** — Python auto-accepts; Rust requires explicit accept. `accept_link` vs `accept_connection`. |
| Reject session | N/A (no explicit reject) | `LinkManager::reject_link()` | `NodeCore::reject_connection()` | N/A | No |
| Close session | `Link.teardown()` | `LinkManager::close()` | `NodeCore::close_connection()` | `ConnectionStream::close()` | **Moderate** — `teardown` vs `close_connection` |
| Send data on session | `Packet(link, data).send()` | N/A (via channel) | `NodeCore::send_on_connection()` | `ConnectionStream::send()` / `send_bytes()` | **Moderate** — Python uses `Packet`, Rust has direct method |
| Reliable message channel | `Link.get_channel()` -> `Channel` | `Channel` (in `LinkManager`) | Implicit via `send_on_connection()` | Implicit via `ConnectionStream` | **YES** — Python exposes `Channel` explicitly; Rust hides it |
| Channel message type | `MessageBase` (class) | `Message` (trait) | Not exposed at NodeCore | Not exposed | **Moderate** — `MessageBase` vs `Message`; NodeCore hides the concept |
| Incoming session request | `Destination.set_link_established_callback()` | `LinkEvent::LinkRequestReceived` | `NodeEvent::ConnectionRequest` | Via event channel | **YES** — callback vs event; `Link` vs `Connection` |
| Session established | Callback `link_established(link)` | `LinkEvent::LinkEstablished` | `NodeEvent::ConnectionEstablished` | Via event channel | **Moderate** — consistent pattern but `Link` vs `Connection` |
| Session stale | `Link.status == Link.STALE` | `LinkEvent::LinkStale` | `NodeEvent::ConnectionStale` | Via event channel | Same divergence |
| Session closed | Callback `link_closed(link)` | `LinkEvent::LinkClosed` | `NodeEvent::ConnectionClosed` | Via event channel | Same divergence |
| Destination | `Destination` | `Destination` | `Destination` | `Destination` | No — consistent |
| Announce | `Destination.announce()` | `Destination::announce()` | `NodeCore::announce_destination()` | `ReticulumNode::announce_destination()` | No |
| Identity | `Identity` | `Identity` | `Identity` | `Identity` | No |
| Transport/Routing | `Transport` (static class) | `Transport<C, S>` | Internal to `NodeCore` | Internal to driver | No |
| Packet | `Packet` | `Packet` | Not directly exposed | N/A | No |
| PacketReceipt | `PacketReceipt` | `PacketReceipt`, `ReceiptStatus` | `DeliveryConfirmed` / `DeliveryFailed` events | Via event channel | **Moderate** — Python has an object you poll; Rust has events |
| Resource | `Resource` (full transfer protocol) | Stub only (`resource.rs` empty) | Not implemented | Not implemented | N/A |
| Single-packet send | `Packet(destination, data).send()` | `Transport::send_to_destination()` | `NodeCore::send_single_packet()` | `PacketEndpoint::send()` | **Moderate** — Python uses `Packet` object; Rust has dedicated methods |
| Send handle for single packets | `Packet` / `PacketReceipt` | N/A | `SendHandle` | `PacketEndpoint` | **YES** — `PacketEndpoint` doesn't represent an endpoint |
| Connection metadata | Fields on `Link` | Fields on `Link` struct | `Connection` struct (thin wrapper) | N/A | **Moderate** — Python has one rich object; Rust splits `Link` from `Connection` |
| Error types for link ops | Exceptions | `LinkError` | `ConnectionError` (wraps `LinkError` + `ChannelError`) | `std::io::Error` (converted) | **Moderate** — 3 layers of error wrapping |
| Proof strategy | `PROVE_NONE/PROVE_APP/PROVE_ALL` | `ProofStrategy::None/App/All` | `ProofStrategy` | Same | No |
| Buffer/Stream I/O | `RNS.Buffer` | `RawChannelReader`, `RawChannelWriter`, `BufferedChannelWriter` | Not exposed at NodeCore | `ConnectionStream` partially fills role | **Moderate** — types exported but no path to use them from main API |

---

### Actively Misleading Names

#### 1. `ConnectionStream` does NOT implement `Stream`

**File**: `reticulum-std/src/driver/stream.rs`

The name strongly suggests it implements `tokio::io::AsyncRead`, `tokio::io::AsyncWrite`, or `futures::Stream`. It implements **none of them**. It is a send-only handle with custom `send()` and `send_bytes()` methods. Incoming data arrives via `NodeEvent` on a separate event channel.

**Better name**: `ConnectionHandle` or `ConnectionSender`.

#### 2. `PacketEndpoint` does NOT represent an endpoint

**File**: `reticulum-std/src/driver/endpoint.rs`

In networking, "endpoint" means one side of a communication link — a source or destination address. `PacketEndpoint` is a send handle that holds a `DestinationHash` and fires single packets. It doesn't listen, receive, or represent an addressable entity.

**Better name**: `PacketSender` or `SinglePacketHandle`.

#### 3. `Connection` is a nearly-empty metadata wrapper

**File**: `reticulum-core/src/node/connection.rs`

Contains only `link_id`, `destination_hash`, `is_initiator`, and `compression_enabled`. All actual connection state (crypto keys, RTT, keepalive, channel) lives in the `Link` inside `LinkManager`. The name creates an expectation that `Connection` is the primary object for connection operations, when in fact it's just a metadata tag.

#### 4. NodeEvent says "Connection" but fields say `link_id`

**File**: `reticulum-core/src/node/event.rs`

Every "Connection" event carries a `link_id: LinkId` field: `ConnectionRequest { link_id }`, `ConnectionEstablished { link_id }`, etc. The dual terminology leaks into every event consumer. Documentation tries to bridge ("The link/connection ID") but this is a code smell.

#### 5. `CloseReason` vs `LinkCloseReason` — identical enum duplicated

**File**: `reticulum-core/src/node/event.rs`

Both have identical variants (`Normal`, `Timeout`, `InvalidProof`, `PeerClosed`, `Stale`) with a mechanical `From` impl. The duplication exists solely to maintain the "Connection" naming at the node layer.

#### 6. `send()` vs `send_bytes()` on `ConnectionStream` — unclear distinction

**File**: `reticulum-std/src/driver/stream.rs`

`send()` returns `WouldBlock` on pacing/window-full. `send_bytes()` retries internally until data goes through. Both take `&[u8]`. The difference (non-blocking vs blocking-retry) is invisible from the names.

**Better names**: `try_send()` / `send()`, or `send_nonblocking()` / `send()`.

#### 7. `initiate()` vs `connect()` — same action, different names at different layers

`LinkManager::initiate()` (link layer) becomes `NodeCore::connect()` (node layer) becomes `ReticulumNode::connect()` (std layer). Python uses `Link(destination)`. The `initiate` -> `connect` inconsistency means a developer tracing code across layers must mentally translate.

#### 8. `accept_link()` vs `accept_connection()` — same divergence for accept

`LinkManager::accept_link()` becomes `NodeCore::accept_connection()`. Same concept, different vocabulary at different layers.

#### 9. `ReticulumNodeImpl` aliased as `ReticulumNode`

**File**: `reticulum-std/src/driver/mod.rs` line 82

```rust
pub type ReticulumNode = ReticulumNodeImpl;
```

Both names are exported. A grep finds both, leading to confusion about which is canonical.

#### 10. `RawChannelReader` / `RawChannelWriter` / `BufferedChannelWriter` — exported but unreachable

**File**: `reticulum-core/src/link/channel/buffer.rs` (re-exported from `lib.rs`)

These buffer types are publicly exported but never appear in `NodeCore` methods or `NodeEvent`. They exist for a Python `Buffer`-like pattern not yet wired into the node API. Public types with no path to use them from the main API are confusing.

---

### The Core Naming Problem

**The "Link = Connection" split is the dominant naming issue.** A single Reticulum concept (a verified, encrypted, bidirectional session between two peers) is called:

1. **`Link`** — in Python, in `reticulum-core`'s internal types (`Link`, `LinkId`, `LinkEvent`, `LinkManager`, `LinkState`, `LinkCloseReason`, `LinkError`)
2. **`Connection`** — in `NodeEvent` variants, `NodeCore` methods, the `Connection` struct, `ConnectionError`, `ConnectionStats`
3. **`ConnectionStream`** — in `reticulum-std`'s async handle
4. **`link_id`** — the field name everywhere, even inside "Connection" events

Python Reticulum uses `Link` everywhere, consistently. The Rust codebase's decision to rename `Link` to `Connection` at the application layer creates a vocabulary split that currently provides no benefit (the `Connection` struct is a trivial metadata wrapper) while imposing a cognitive tax on every contributor.
