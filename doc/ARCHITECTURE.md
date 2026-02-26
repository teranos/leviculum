# Leviculum Architecture

## Design Principles

1. **Sans-I/O core** — `reticulum-core` is a pure state machine; all I/O is expressed as `Action` return values
2. **All protocol logic in core** — Transport, routing, announces, links, channels, action dispatch
3. **no_std + alloc in core** — Runs on ESP32, nRF52840, RP2040, Linux, macOS
4. **Thin platform drivers** — Only I/O, framing, and event loop in `reticulum-std`

## Crate Structure

```
leviculum/
├── reticulum-core/          # no_std + alloc — ALL protocol logic (sans-I/O)
│   ├── src/
│   │   ├── lib.rs
│   │   ├── constants.rs     # Protocol constants
│   │   ├── traits.rs        # Platform traits: Clock, Storage, Interface; NoStorage
│   │   ├── storage_types.rs # Data types shared by Storage and Transport
│   │   ├── memory_storage.rs # MemoryStorage (pub, BTreeMap-backed, configurable caps)
│   │   ├── crypto/          # Cryptographic primitives
│   │   ├── framing/         # HDLC framing, KISS encoding
│   │   ├── identity.rs      # Identity (X25519 + Ed25519 keypairs)
│   │   ├── destination.rs   # Addressable endpoints with hash-based addressing
│   │   ├── packet.rs        # Packet encoding/decoding
│   │   ├── announce.rs      # Announce creation/validation
│   │   ├── ratchet.rs       # Forward-secrecy ratchet keys
│   │   ├── ifac.rs          # Interface authentication codes
│   │   ├── receipt.rs       # Delivery receipts and proofs
│   │   ├── link/            # Link state machine + channels
│   │   │   ├── mod.rs       # Link establishment, encryption, teardown
│   │   │   └── channel/     # Reliable ordered messaging over links
│   │   ├── transport.rs     # Sans-I/O routing engine + dispatch_actions()
│   │   ├── resource.rs      # Segmented data transfer (stub)
│   │   └── node/            # High-level unified API
│   │       ├── mod.rs       # NodeCore: ties everything together
│   │       ├── send.rs      # Outbound message routing decisions
│   │       ├── link_management.rs # Link lifecycle (accept, close, keepalive, cleanup)
│   │       └── event.rs     # NodeEvent enum and helpers
│   └── Cargo.toml
│
├── reticulum-std/           # std — Platform driver for desktop/server
│   ├── src/
│   │   ├── lib.rs
│   │   ├── interfaces/      # Concrete interface implementations
│   │   │   ├── mod.rs       # InterfaceHandle (implements Interface trait), InterfaceRegistry
│   │   │   ├── hdlc.rs      # HDLC framing codec
│   │   │   ├── tcp.rs       # TCP client + server with HDLC framing
│   │   │   ├── udp.rs       # UDP point-to-point/broadcast, no framing
│   │   │   ├── local.rs     # Unix abstract socket IPC (shared instance), HDLC-framed
│   │   │   └── auto_interface/  # Zero-config IPv6 multicast LAN discovery
│   │   │       ├── mod.rs       # Config, constants, dedup cache
│   │   │       └── orchestrator.rs  # Per-NIC sockets, peer lifecycle, discovery
│   │   ├── driver/          # Sans-I/O driver (event loop)
│   │   │   ├── mod.rs       # ReticulumNode: owns interfaces, drives NodeCore
│   │   │   ├── builder.rs   # ReticulumNodeBuilder
│   │   │   ├── sender.rs    # PacketSender for fire-and-forget packets
│   │   │   └── stream.rs    # LinkHandle (async send handle)
│   │   ├── rpc/             # RPC server for Python CLI tools (rnstatus, rnpath, rnprobe)
│   │   │   ├── mod.rs       # RPC listener setup
│   │   │   ├── connection.rs # Python multiprocessing.connection wire protocol
│   │   │   ├── pickle.rs    # Pickle serialization/deserialization
│   │   │   ├── handlers.rs  # Request dispatch (get_status, probe, path, etc.)
│   │   │   └── error.rs     # RPC error types
│   │   ├── reticulum.rs     # High-level entry point with config
│   │   ├── clock.rs         # SystemClock implementation
│   │   ├── storage.rs       # FileStorage: MemoryStorage + disk persistence
│   │   ├── config.rs        # Structured Config type with serde support
│   │   ├── ini_config.rs    # Python-format INI config parser → Config
│   │   ├── known_destinations.rs  # msgpack persistence (Python-compatible)
│   │   ├── packet_hashlist.rs     # msgpack persistence (Python-compatible)
│   │   └── error.rs         # Error types (thiserror)
│   └── Cargo.toml
│
├── reticulum-integ/         # Docker-based integration test framework
│
├── reticulum-nrf/           # Embedded driver for nRF52840 (T114 board, SX1262 LoRa)
│
├── reticulum-ffi/           # C-API bindings
└── reticulum-cli/           # Command-line tools (lrns, lrnsd)
```

### reticulum-std Module Responsibilities

| Module | Responsibility |
|--------|---------------|
| `driver/` | Sans-I/O driver: owns interfaces, runs async event loop, feeds packets to NodeCore, dispatches Action results |
| `driver/builder.rs` | `ReticulumNodeBuilder` — fluent config, builds `ReticulumNode` |
| `driver/sender.rs` | `PacketSender` — fire-and-forget packet sending from outside event loop |
| `driver/stream.rs` | `LinkHandle` — async send handle for established links |
| `interfaces/mod.rs` | `InterfaceHandle` (implements Interface trait via tokio channel), `InterfaceRegistry` (round-robin recv) |
| `interfaces/tcp.rs` | TCP client with HDLC framing + reconnection, TCP server accept loop |
| `interfaces/udp.rs` | UDP interface: point-to-point or broadcast, no framing |
| `interfaces/local.rs` | LocalInterface: Unix abstract socket IPC for shared instance, HDLC-framed |
| `interfaces/auto_interface/` | AutoInterface: IPv6 multicast peer discovery, per-NIC sockets, peer lifecycle |
| `interfaces/hdlc.rs` | Re-exports HDLC framing codec from reticulum-core |
| `rpc/` | RPC server: Python `multiprocessing.connection` wire protocol, HMAC auth, pickle ser/de |
| `reticulum.rs` | High-level entry point wrapping `ReticulumNode` with config-driven setup |
| `config.rs` | Structured `Config` type with serde support |
| `ini_config.rs` | Python-format INI config parser → `Config` struct |
| `clock.rs` | `SystemClock` implementation of `Clock` trait |
| `storage.rs` | `FileStorage`: wraps `MemoryStorage` + Python-compatible disk persistence |
| `known_destinations.rs` | msgpack decode/encode for known_destinations file |
| `packet_hashlist.rs` | msgpack decode/encode for packet_hashlist file |
| `error.rs` | Error types (thiserror) |

## Sans-I/O Architecture

The core engine never performs I/O directly. It operates as a pure state machine:

```
                     ┌─────────────────────────────────┐
                     │         reticulum-core           │
                     │                                  │
  handle_packet() ──►│  NodeCore<R, C, S>               │──► TickOutput {
  (iface_id, data)   │    ├── Transport (routing)       │      actions: Vec<Action>,
                     │    ├── Links + Channels           │      events: Vec<NodeEvent>,
  handle_timeout() ─►│    └── Destinations              │    }
                     │                                  │
  next_deadline() ──►│  Returns: Option<u64>            │
                     └─────────────────────────────────┘

  Action::SendPacket { iface, data }     — send to one interface
  Action::Broadcast { data, exclude }    — send to all interfaces (except one)
```

The **driver** (in `reticulum-std` or an embedded crate) owns the interfaces and runs the event loop.
The `reticulum-std` driver has 6 `select!` branches:

```rust
loop {
    select! {
        // 1. Packet received from any interface
        (iface_id, data) = registry.recv_any() => {
            output = core.handle_packet(iface_id, &data);
            dispatch_output(output);
        }

        // 2. External action (connect, send, announce from app thread)
        output = action_dispatch_rx.recv() => {
            dispatch_output(output);
        }

        // 3. Timer fires at next_deadline()
        _ = sleep_until(next_poll) => {
            output = core.handle_timeout();
            dispatch_output(output);
        }

        // 4. Shutdown signal
        _ = shutdown.changed() => break

        // 5. New interface registered (TCP server accept, local client connect)
        handle = new_interface_rx.recv() => {
            registry.register(handle);
            output = core.handle_interface_up(iface_idx);
            dispatch_output(output);
        }

        // 6. Periodic storage flush (crash protection, every 3600s)
        _ = sleep_until(next_flush) => {
            core.storage_mut().flush();
        }
    }
}
```

Branch 5 handles dynamic interface registration — when a TCP server accepts a
new connection or a local client connects via Unix socket, the handle arrives on
a channel and is registered with the interface registry. The driver then calls
`handle_interface_up()` to send cached announces to the new peer.

Branch 6 is crash protection only — normal shutdown calls `flush()` via the
signal handler. Lost data from a crash is recovered via fresh announces.

## Interface Design

### Send/Receive Asymmetry

The `Interface` trait covers only the **send side**:

```rust
pub trait Interface {
    fn id(&self) -> InterfaceId;
    fn name(&self) -> &str;
    fn mtu(&self) -> usize;
    fn is_online(&self) -> bool;
    fn try_send(&mut self, data: &[u8]) -> Result<(), InterfaceError>;
}
```

The **receive side** is intentionally absent. Sending is synchronous and non-blocking
(`try_send` either accepts or drops), while receiving is inherently async and
driver-specific: tokio uses `mpsc::Receiver::poll_recv()`, Embassy uses interrupt-driven
DMA, bare-metal uses polling loops. Forcing both into one trait would either make the
trait async (unusable on `no_std`) or require a sync `recv()` that wastes CPU in a
busy-loop.

### Why `try_send()` is fire-and-forget

Reticulum is a best-effort transport protocol. There is no TCP-style backpressure —
if a link is congested, packets are dropped and retransmitted at a higher layer (link
channels handle retransmission). This makes `try_send()` the natural API:

- `Ok(())` — packet accepted for delivery
- `Err(BufferFull)` — non-fatal, packet dropped (expected on constrained links)
- `Err(Disconnected)` — interface dead, driver must call `handle_interface_down()`

### Concrete Interface Implementations

| Interface | Crate | Transport | HW_MTU | Framing |
|-----------|-------|-----------|--------|---------|
| TCP | std | TCP stream | 262144 | HDLC |
| UDP | std | UDP datagram | 1064 | None |
| LocalInterface | std | Unix abstract socket | 262144 | HDLC |
| AutoInterface | std | IPv6 multicast + unicast UDP | 1196 | None |

TCP and LocalInterface use HDLC framing to delimit packets on their stream-oriented
transports. UDP and AutoInterface send one packet per datagram so no framing is needed.

### Zero-delay core, interface-side collision avoidance

The core processes and forwards packets with zero artificial delay. All collision
avoidance and send-timing is the responsibility of the interface implementation.
Fast interfaces (TCP, UDP) transmit immediately. Slow shared-medium interfaces
(LoRa, serial) apply configurable send-side jitter to prevent synchronized
rebroadcast storms. This differs from Python Reticulum which applies universal
jitter in the core regardless of interface type.

When the core emits a `Broadcast` or `SendPacket` action (e.g., an announce
rebroadcast), the action is dispatched to interfaces instantly. A TCP interface
calls `try_send()` and the packet goes on the wire within microseconds. A LoRa
interface receives the same action at the same speed, but holds the packet in a
send queue and applies a random delay (0-500ms for first rebroadcast, matching
Python's `PATHFINDER_RW`) before keying the radio. This keeps the sans-I/O core
interface-agnostic while preserving collision avoidance where it matters.

### Why `dispatch_actions()` lives in core

Action routing (which interface to send on, broadcast exclusion) is **protocol
knowledge**, not platform glue. By putting it in core as a free function:

```rust
pub fn dispatch_actions(
    interfaces: &mut [&mut dyn Interface],
    actions: &[Action],
) -> Vec<(InterfaceId, InterfaceError)>
```

Every driver — tokio, Embassy, bare-metal — gets broadcast-exclusion and interface
selection for free. The driver's only responsibilities after calling this are:

1. **React to errors** — log `BufferFull`, call `handle_interface_down()` for `Disconnected`
2. **Forward events** — push `NodeEvent`s to the application channel
3. **Update timer** — schedule `handle_timeout()` from `output.next_deadline_ms`

### How the driver wraps channels behind the trait

In `reticulum-std`, `InterfaceHandle` wraps a `tokio::sync::mpsc::Sender<OutgoingPacket>`
behind the `Interface` trait:

```rust
impl Interface for InterfaceHandle {
    fn try_send(&mut self, data: &[u8]) -> Result<(), InterfaceError> {
        match self.outgoing.try_send(OutgoingPacket { data: data.to_vec() }) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(InterfaceError::BufferFull),
            Err(TrySendError::Closed(_)) => Err(InterfaceError::Disconnected),
        }
    }
}
```

An embedded driver would implement the trait directly on a radio struct, calling SPI
to transmit the packet synchronously.

## Writing a Driver

A driver bridges `NodeCore` (pure state machine) with actual hardware. Every driver
must fulfill the same contract, regardless of platform (tokio, Embassy, bare-metal).

### 1. Create interface objects

Implement the `Interface` trait on whatever holds your outbound channel:

- **tokio**: wrap an `mpsc::Sender` (see `InterfaceHandle` in `reticulum-std`)
- **Embassy**: implement directly on a radio/UART struct with sync SPI/DMA send
- **bare-metal**: implement on a ring buffer that an interrupt handler drains

Register interfaces with the driver's own bookkeeping (e.g., `InterfaceRegistry`).
Core does not own interfaces — it only references them by `InterfaceId`.

### 2. Run the event loop

The minimum event loop has 3-4 branches (A–D below), all feeding into the same
post-dispatch sequence. The `reticulum-std` driver adds two more (see the 6-branch
`select!` in "Sans-I/O Architecture" above):

```
loop {
    select! {
        // A. Receive: data arrives from an interface
        (iface_id, data) = receive_from_interfaces() => {
            output = core.handle_packet(iface_id, &data);
            post_dispatch(output);
        }

        // B. Action dispatch: deferred operations (connect, send, announce)
        output = action_channel.recv() => {
            post_dispatch(output);
        }

        // C. Timer: periodic maintenance (keepalives, retransmits, cleanup)
        _ = sleep_until(next_deadline) => {
            output = core.handle_timeout();
            post_dispatch(output);
        }

        // D. Shutdown (optional)
        _ = shutdown_signal => break
    }
}
```

### 3. Post-dispatch: the four steps after every core call

Every branch produces a `TickOutput`. The driver must always do the same four things:

1. **Route actions to interfaces** — call `dispatch_actions(&mut ifaces, &output.actions)`.
   This is protocol logic (broadcast exclusion, interface selection) that lives in core.

2. **React to dispatch errors** — `BufferFull`: log it (non-fatal, expected on constrained
   links). `Disconnected`: call `core.handle_interface_down(iface_id)` and clean up
   the interface.

3. **Forward events to the application** — iterate `output.events` and deliver each
   `NodeEvent` to the application (channel, callback, queue — platform-specific).

4. **Update the timer** — read `output.next_deadline_ms` and schedule the next
   `handle_timeout()` accordingly. Cap at 1s maximum but do not add a floor —
   the core may request sub-millisecond wakeups for urgent forwarding.

### 4. Handle the receive path

The receive path is driver-specific and not part of the `Interface` trait:

- **tokio**: `mpsc::Receiver::poll_recv()` with round-robin fairness across interfaces
- **Embassy**: interrupt-driven DMA into a packet buffer, signal the event loop
- **bare-metal**: poll radio FIFO in the main loop

When a complete packet arrives, call `core.handle_packet(iface_id, &data)` and run
the post-dispatch sequence.

When an interface disconnects (channel closed, link down, hardware fault), call
`core.handle_interface_down(iface_id)`, run post-dispatch, then remove the interface
from the driver's registry.

## Integration Test Framework (reticulum-integ)

Docker-based multi-node test framework for exercising real routing behavior
across mixed Rust/Python topologies.

**TOML-defined scenarios** specify topology and step-by-step assertions:

```toml
[nodes.relay]
type = "python"

[nodes.client]
type = "rust"

[links]
client_relay = { a = "client", b = "relay" }

[[steps]]
type = "wait_for_path"
node = "client"
destination = "relay"

[[steps]]
type = "rnprobe"
node = "client"
destination = "relay"
```

**Pipeline**: parse TOML → assign TCP interfaces → generate per-node configs →
generate `docker-compose.yml` → start containers → poll readiness → execute
steps → teardown.

**Step types**:
- `wait_for_path` — poll until a node discovers a path to a destination (supports `expect_result = "no_path"` for negative assertions)
- `rnprobe` — send a probe and verify round-trip success (supports `expect_result = "fail"` for expected failures)
- `rnpath` / `rnstatus` — query path or status via RPC
- `sleep` — fixed delay for timing-sensitive scenarios
- `restart` — stop and restart a container mid-test
- `exec` — run an arbitrary command inside a container
- `block_link` / `restore_link` — iptables-based link failure simulation

Each test run uses unique container names (PID-based) for parallel safety.

## Layer Architecture

```
Layer 4 (entry):    node/
                      │
Layer 3 (infra):    transport
                      │
Layer 2 (conn):     link/ ── link/channel/
                      │
Layer 1 (addr):     identity, destination, announce, ratchet, receipt, packet, ifac
                      │
Layer 0 (prims):    crypto/, framing/, constants, traits
```

| Layer | May Import | Must NOT Import |
|-------|-----------|----------------|
| Layer 0 | Only other Layer 0 modules | Layers 1–4 |
| Layer 1 | Layer 0 | Layers 2–4 |
| Layer 2 | Layers 0–1 | Layers 3–4 |
| Layer 3 | Layers 0–2 | Layer 4 |
| Layer 4 | Layers 0–3 | — |

## Platform Traits

Core uses three platform abstractions, injected as generic parameters:

| Trait | Purpose | std impl | Embedded impl |
|-------|---------|----------|---------------|
| `Clock` | Monotonic timestamps | `SystemClock` | Hardware timer |
| `Storage` | Type-safe collection storage | `FileStorage` | `MemoryStorage` / `NoStorage` |
| `CryptoRngCore` | Randomness (from `rand_core`) | `OsRng` | Hardware RNG |

The `Interface` trait is defined in core and used by `dispatch_actions()` to route packets.
The driver implements it on whatever holds the outbound channel.

### Storage Trait

The `Storage` trait (`traits.rs`) is the single source of truth for all long-lived
protocol collections. Core is a pure protocol engine with zero state management —
it asks Storage questions ("have you seen this hash?", "what's the path to this
destination?"), tells Storage to remember things, and Storage decides capacity,
eviction, and persistence strategy.

**~44 type-safe methods** organized by collection:

| Collection | Methods | Purpose |
|------------|---------|---------|
| Packet dedup | `has_packet_hash`, `add_packet_hash` | Duplicate packet detection |
| Path table | `get_path`, `set_path`, `remove_path`, `path_count`, `expire_paths`, `earliest_path_expiry` | Routing table |
| Path state | `get_path_state`, `set_path_state` | Path quality tracking (responsive/unresponsive) |
| Reverse table | `get_reverse`, `set_reverse`, `remove_reverse` | Proof return routing |
| Link table | `get_link_entry`, `set_link_entry`, `remove_link_entry` | Active link tracking |
| Announce table | `get_announce`, `set_announce`, `remove_announce`, `announce_keys` | Pending rebroadcasts |
| Announce cache | `get_announce_cache`, `set_announce_cache` | Raw announce packet storage |
| Announce rate | `get_announce_rate`, `set_announce_rate` | Per-destination rate limiting |
| Receipts | `get_receipt`, `set_receipt`, `remove_receipt` | Delivery tracking |
| Path requests | `get_path_request_time`, `set_path_request_time`, `check_path_request_tag` | Dedup and timing |
| Known identities | `get_identity`, `set_identity` | Identity-to-destination mapping |
| Ratchets | `load_ratchet`, `store_ratchet`, `list_ratchet_keys` | Forward secrecy keys |
| Cleanup | `expire_reverses`, `expire_receipts`, `expire_link_entries`, etc. | Time-based eviction |
| Deadlines | `earliest_receipt_deadline`, `earliest_link_deadline` | Timer scheduling |
| Lifecycle | `flush` | Persist dirty state to disk |

Data types shared between Storage and Transport live in `storage_types.rs` (Layer 0):
`PathEntry`, `PathState`, `ReverseEntry`, `LinkEntry`, `AnnounceEntry`,
`AnnounceRateEntry`, `PacketReceipt`, `ReceiptStatus`.

**Three implementations:**

| Type | Crate | Backing | Use case |
|------|-------|---------|----------|
| `NoStorage` | core | Zero-sized no-op | Stubs, FFI, smoke tests |
| `MemoryStorage` | core | `BTreeMap`/`BTreeSet`, configurable caps | Embedded, core tests |
| `FileStorage` | std | Wraps `MemoryStorage` + disk persistence | Desktop/server |

`MemoryStorage` is `pub` (not `#[cfg(test)]`) — it is the production implementation
for embedded targets. `FileStorage` wraps `MemoryStorage` internally for all
runtime collections (no no-ops) and adds Python-compatible disk persistence for
`known_destinations` (msgpack map) and `packet_hashlist` (msgpack array of 32-byte
hashes). Non-persistent collections (paths, reverses, links, announces, receipts)
are RAM-only and lost on restart.

## Key Types

| Type | Crate | Purpose |
|------|-------|---------|
| `NodeCore<R, C, S>` | core | Unified sans-I/O protocol engine |
| `InterfaceId` | core | Opaque identifier for interfaces in routing tables |
| `Action` | core | Outbound I/O instruction (SendPacket or Broadcast) |
| `TickOutput` | core | Return type: actions + events from any core method |
| `NodeEvent` | core | Application-visible protocol events |
| `Interface` | core (trait) | Send-only interface contract for `dispatch_actions()` |
| `Storage` | core (trait) | Type-safe collection storage (~44 methods) |
| `MemoryStorage` | core | BTreeMap-backed storage with configurable caps |
| `NoStorage` | core | Zero-sized no-op storage for stubs and tests |
| `dispatch_actions()` | core | Routes Actions to interfaces (protocol logic) |
| `ReticulumNode` | std | Async driver that owns interfaces and drives NodeCore |
| `InterfaceHandle` | std | Implements `Interface` via tokio channel sender |
| `FileStorage` | std | Wraps MemoryStorage + Python-compat disk persistence |

## Packet Flow

### Incoming

```
TCP socket
  │
  ▼
tcp_interface_task()              [reticulum-std]
  │  deframe HDLC → IncomingPacket → mpsc channel
  ▼
recv_any() polls channels         [reticulum-std driver]
  │
  ▼
NodeCore::handle_packet(iface, data)  [reticulum-core]
  │  Transport::process_incoming()
  │  Link/Channel packet processing
  │  drain pending packets → Actions
  ▼
TickOutput { actions, events }
  │
  ├─► dispatch_actions() routes to interfaces  [reticulum-core]
  │     └─► InterfaceHandle::try_send()        [reticulum-std]
  │           └─► mpsc channel → tcp_interface_task → socket
  └─► Events forwarded to application
```

### Outgoing

```
Application calls connect() / send() / announce()
  │
  ▼
NodeCore returns TickOutput with Actions
  │  (sent to event loop via action_dispatch channel)
  ▼
dispatch_actions() routes to interfaces  [reticulum-core]
  │
  ▼
InterfaceHandle::try_send()              [reticulum-std]
  │  wraps in OutgoingPacket → mpsc channel
  ▼
tcp_interface_task()                     [reticulum-std]
  │  HDLC frame → TCP socket
  ▼
Network
```

### Local Client (Shared Instance)

```
Local application (lrns, user program)
  │
  ▼
Unix abstract socket → LocalInterface     [reticulum-std]
  │  HDLC-framed, same as TCP
  ▼
recv_any() polls alongside TCP/UDP        [reticulum-std driver]
  │
  ▼
NodeCore::handle_packet(iface, data)      [reticulum-core]
  │  Packets from local clients are marked is_local_client=true
  │  so the core knows not to loop them back to the originator.
  │  Announces from local clients update local_client_known_dests
  │  (timestamp refresh for expiry tracking, 6h TTL).
  ▼
TickOutput dispatched normally
```

### RPC Queries (rnstatus, rnpath, rnprobe)

```
Python CLI tool (rnstatus, rnpath, rnprobe)
  │
  ▼
Unix socket → RPC server                  [reticulum-std/rpc]
  │  Python multiprocessing.connection wire protocol
  │  HMAC authentication, pickle ser/de
  ▼
RPC handler queries NodeCore state        [reticulum-std/rpc/handlers.rs]
  │  or triggers probe via action_dispatch channel
  ▼
Pickle-encoded response → Unix socket → CLI tool
```

## Logging

### Philosophy

Log messages should let a developer follow the communication flow on the wire
by running `lrnsd -v`. The logging style is inspired by Python rnsd: messages
read as informative sentences that combine context (destination, interface,
hop count) into a single line explaining what happened and why.

Good:
```
Destination <81b22f6033435068> is now 4 hops away via <ecc35451ae3cfe26> on iface 1
Rebroadcasting announce for <81b22f6033435068> with hop count 4
Incoming link request <a3f79c021b4e8d12> for <51cd62fda20433ba> accepted on iface 0
Answering path request for <4c0c6c7f420da5df> on iface 1, path is known
Rebroadcasted announce for <e0685699d98f2174> has been passed on to another node, no further tries needed
```

Bad (too terse, no context):
```
path updated dest=81b22f60 hops=4
announce rebroadcast
link request accepted
```

### Levels

The `tracing` crate provides five levels. Leviculum maps them as follows:

| Level | CLI | What to log | Volume |
|-------|-----|-------------|--------|
| `error!` | always | Persistent failures, unrecoverable errors | rare |
| `warn!`  | always | Recoverable errors, degraded operation | occasional |
| `info!`  | default | Startup, shutdown, major lifecycle events | few per run |
| `debug!` | `-v` | Routing decisions, path updates, link lifecycle, forwarding | per-event |
| `trace!` | `-vv` | Every packet received, drop reasons, queue ops, keepalives | per-packet |

**debug!** is the primary developer-facing level. A developer running `-v` should
see every routing decision: path updates, announce rebroadcasts, link establishment,
forwarding decisions, path request responses.

**trace!** is for full packet flow. Every packet that enters `process_incoming()`
is logged at trace, and every drop reason (duplicate, rate limit, replay, TTL
exceeded) is logged at trace so a developer can understand why packets disappear.

### Message Style

- **Sentence-style**: Messages read as explanations, not key-value dumps
- **Include context inline**: destination hash, hop count, interface, and reason
  are woven into the message text
- **Hashes**: Use `HexShort` (first 16 hex chars) for readability in log lines;
  use full `HexFmt` only in warn!/error! where precision matters
- **Interface references**: `iface {N}` where N is the InterfaceId index (core
  does not know interface names; the driver logs names separately at registration)
- **Link references**: `link <{hash}>` using HexShort
- **Explain the decision**: Don't just say "dropped" — say why: "rate limited",
  "no path known", "duplicate packet", "TTL exceeded"

### Where to Log

| Component | What | Level |
|-----------|------|-------|
| `transport.rs` process_incoming | Each packet type dispatched | `trace!` |
| `transport.rs` process_incoming | Each drop reason (dup, filter, TTL) | `trace!` |
| `transport.rs` handle_announce | Path update (accepted) | `debug!` |
| `transport.rs` handle_announce | Rebroadcast decision | `debug!` |
| `transport.rs` handle_announce | Rebroadcast suppression (passed on) | `trace!` |
| `transport.rs` handle_path_request | Request received, response type | `debug!` |
| `transport.rs` forward_packet | Forwarding decision | `debug!` |
| `node/link_management.rs` | Link accepted, established, closed, stale | `debug!` |
| `node/link_management.rs` | Keepalive sent | `trace!` |
| `driver/mod.rs` | Startup summary, interface registration | `info!` |
| `interfaces/*.rs` | Connection events, I/O errors | `info!`/`warn!` |

### no_std Compatibility

`tracing` is used with `default-features = false` in reticulum-core, making all
macros (trace!, debug!, info!, warn!, error!) available without std. The subscriber
(which formats and emits the output) is initialized only in reticulum-std/reticulum-cli.
When no subscriber is registered (embedded without tracing), all macros are no-ops
with zero runtime cost.
