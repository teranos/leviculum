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
│   │   ├── traits.rs        # Platform traits: Clock, Storage, Interface
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
├── reticulum-net/           # no_std + alloc — Shared interface data types
│   └── src/lib.rs           # IncomingPacket, OutgoingPacket, InterfaceInfo
│                            # Separate crate to avoid circular deps between core and drivers
│
├── reticulum-std/           # std — Platform driver for desktop/server
│   ├── src/
│   │   ├── lib.rs
│   │   ├── interfaces/      # Concrete interface implementations
│   │   │   ├── mod.rs       # InterfaceHandle (implements Interface trait), InterfaceRegistry
│   │   │   ├── hdlc.rs      # HDLC framing codec
│   │   │   └── tcp.rs       # TCP client with HDLC framing
│   │   ├── driver/          # Sans-I/O driver (event loop)
│   │   │   ├── mod.rs       # ReticulumNode: owns interfaces, drives NodeCore
│   │   │   ├── builder.rs   # ReticulumNodeBuilder
│   │   │   ├── sender.rs    # PacketSender for fire-and-forget packets
│   │   │   └── stream.rs    # LinkHandle (async send handle)
│   │   ├── reticulum.rs     # High-level entry point with config
│   │   ├── clock.rs         # SystemClock implementation
│   │   ├── storage.rs       # Filesystem-backed persistence
│   │   ├── config.rs        # Config file parsing
│   │   └── error.rs         # Error types (thiserror)
│   └── Cargo.toml
│
├── reticulum-nrf/           # Embedded driver for nRF52840 (T114 board, SX1262 LoRa)
│
├── reticulum-ffi/           # C-API bindings
└── reticulum-cli/           # Command-line tools (lrns, lrnsd)
```

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

The **driver** (in `reticulum-std` or an embedded crate) owns the interfaces and runs the event loop:

```rust
loop {
    select! {
        // Poll interfaces for incoming data
        (iface_id, data) = recv_any(&mut registry) => {
            let output = core.handle_packet(iface_id, &data);
            dispatch_output(output, &mut registry, &event_tx);
        }
        // Dispatch deferred operations (connect, send, announce)
        output = action_dispatch_rx.recv() => {
            dispatch_output(output, &mut registry, &event_tx);
        }
        // Timer fires at next_deadline()
        _ = sleep_until(next_poll) => {
            let output = core.handle_timeout();
            dispatch_output(output, &mut registry, &event_tx);
        }
        _ = shutdown => break
    }
}
```

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

The event loop has 3-4 branches, all feeding into the same post-dispatch sequence:

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
   `handle_timeout()` accordingly. Clamp to a reasonable range (e.g., 250ms..1s).

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
| `Storage` | Key-value persistence | `FileStorage` | Flash storage / `NoStorage` |
| `CryptoRngCore` | Randomness (from `rand_core`) | `OsRng` | Hardware RNG |

The `Interface` trait is defined in core and used by `dispatch_actions()` to route packets.
The driver implements it on whatever holds the outbound channel.

## Key Types

| Type | Crate | Purpose |
|------|-------|---------|
| `NodeCore<R, C, S>` | core | Unified sans-I/O protocol engine |
| `InterfaceId` | core | Opaque identifier for interfaces in routing tables |
| `Action` | core | Outbound I/O instruction (SendPacket or Broadcast) |
| `TickOutput` | core | Return type: actions + events from any core method |
| `NodeEvent` | core | Application-visible protocol events |
| `Interface` | core (trait) | Send-only interface contract for `dispatch_actions()` |
| `dispatch_actions()` | core | Routes Actions to interfaces (protocol logic) |
| `ReticulumNode` | std | Async driver that owns interfaces and drives NodeCore |
| `InterfaceHandle` | std | Implements `Interface` via tokio channel sender |

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
