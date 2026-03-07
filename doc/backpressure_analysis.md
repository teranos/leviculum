# Backpressure Analysis: Send Paths from Origin to Wire

## 1. All Packet Origination Paths

| # | Originator | Function | Action Type | Retriable? | Must-Deliver? | Notes |
|---|-----------|----------|-------------|------------|---------------|-------|
| P1 | App: announce_destination | `NodeCore::announce_destination()` (node/mod.rs:358) -> `Transport::send_on_all_interfaces()` (transport.rs:1036) | Broadcast(exclude=None) | No | Best-effort | Locally-originated announce. Re-announced on interface_up. |
| P2 | App: connect (link request) | `NodeCore::connect()` (node/link_management.rs:175) -> `Transport::send_to_destination()` or `send_on_all_interfaces()` | SendPacket (if path known) or Broadcast (no path) | No | Must-deliver (but link will timeout if lost) | Link request packet. Fallback: link establishment timeout fires. |
| P3 | App: accept_link (link proof) | `NodeCore::accept_link()` (node/link_management.rs:239) -> `Transport::send_on_interface()` or `send_on_all_interfaces()` | SendPacket (attached iface) or Broadcast | No | Must-deliver | LRPROOF. If lost, initiator times out and retries connect. |
| P4 | App: send_on_link (channel data) | `NodeCore::send_on_link()` (node/link_management.rs:361) -> `Transport::send_on_interface()` or `send_to_destination()` | SendPacket | Yes (channel retransmit) | Must-deliver | Channel handles retransmit via tx_ring. WindowFull/PacingDelay returned to caller. |
| P5 | App: send_single_packet | `NodeCore::send_single_packet()` (node/mod.rs:421) -> `Transport::send_to_destination()` | SendPacket | No | Best-effort | Fire-and-forget encrypted packet. |
| P6 | App: close_link | `NodeCore::close_link()` (node/link_management.rs:309) -> `route_link_packet()` -> `Transport::send_on_interface()` | SendPacket | No | Best-effort | LINKCLOSE packet. Peer will timeout if not received. |
| P7 | Timer: keepalive | `check_keepalives()` (node/link_management.rs:1144) -> `route_link_packet()` -> `Transport::send_on_interface()` | SendPacket | No | Best-effort | Initiator-side keepalive. Stale detection covers loss. |
| P8 | Timer: channel retransmit | `check_channel_timeouts()` (node/link_management.rs:1223) -> `route_link_packet()` -> `Transport::send_on_interface()` | SendPacket | Yes (this IS the retry) | Must-deliver | Retransmission of unacked channel envelope. TearDownLink if max tries exceeded. |
| P9 | Timer: announce rebroadcast | `check_announce_rebroadcasts()` (transport.rs:3210) -> `forward_on_all_except()` or `broadcast_announce_with_caps()` or SendPacket (targeted) | Broadcast(exclude=source) or SendPacket (targeted path response) | Yes (up to PATHFINDER_RETRIES) | Best-effort | Transport node rebroadcasts received announces. Suppressed by local_rebroadcasts. |
| P10 | Timer: announce queue drain | `drain_announce_queues()` (transport.rs:3367) -> SendPacket per capped interface | SendPacket | No (one shot from queue) | Best-effort | Dequeues announces that were rate-limited on capped (LoRa) interfaces. |
| P11 | Timer: mgmt announce | `check_mgmt_announces()` (node/mod.rs:548) -> `Transport::send_on_all_interfaces()` | Broadcast(exclude=None) | No (next fires in 2 hours) | Best-effort | Periodic probe destination announce. |
| P12 | Incoming: packet forwarding | `forward_packet()` (transport.rs:2403) -> `forward_on_interface()` -> `send_packet_on_interface()` | SendPacket | No | Best-effort (transport relay) | Transport node relays data packets to next hop. |
| P13 | Incoming: proof forwarding | `handle_proof()` (transport.rs:1911) -> `send_packet_on_interface()` | SendPacket | No | Must-deliver (but proof timeout handles loss) | Transport node relays LRPROOF along link table. |
| P14 | Incoming: path request forwarding | `handle_path_request()` (transport.rs:2936) -> `send_on_all_interfaces_except()` or `send_on_interface()` | Broadcast(exclude=source) or SendPacket (targeted response) | No | Best-effort | Path request flood or targeted path response. |
| P15 | Incoming: data proof generation | `handle_link_data_proof()` in link_management.rs -> `route_link_packet()` -> `send_on_interface()` | SendPacket | No | Must-deliver (but sender retransmits) | Auto-proof for received channel data. Lost proof triggers sender retransmit. |
| P16 | Interface up: re-announce | `handle_interface_up()` (node/mod.rs:745) -> `Transport::send_on_all_interfaces()` | Broadcast(exclude=None) | No | Best-effort | Re-announces local destinations when interface recovers. |
| P17 | Incoming: announce to local clients | transport.rs:3133-3148 -> `send_on_all_interfaces_except()` + per-client `send_on_interface()` | Broadcast + SendPacket (per local client) | No | Best-effort | Transport node forwards announces to IPC clients. |


## 2. Buffer Chain per Interface Type

### 2.1 Generic Buffer Pipeline

```
Originator (app thread or timer)
    |
    v
NodeCore.{method}() -- locks Arc<Mutex<StdNodeCore>>
    |
    v
Transport.pending_actions: Vec<Action>    [unbounded, in-memory Vec]
    |
    v
process_events_and_actions() -> drain_actions() -> TickOutput
    |
    v  (for app-thread calls)
action_dispatch_tx.send(TickOutput)       [tokio mpsc, capacity=256]
    |
    v  (event loop receives on action_dispatch_rx)
dispatch_output() -> dispatch_actions()
    |
    v
Interface::try_send(data)                 [per-interface, see below]
    |
    v
interface outgoing mpsc channel           [per-interface, see below]
    |
    v
interface I/O task -> wire
```

For **event-loop-internal** paths (handle_packet, handle_timeout, handle_interface_up, reconnect):
the TickOutput is dispatched immediately in `dispatch_output()`, skipping the
`action_dispatch` channel entirely.

For **app-thread** paths (connect, accept_link, send_on_link, send_single_packet,
close_link, announce_destination): the TickOutput is sent through
`action_dispatch_tx.send()` (async, will await if full), then the event loop
dispatches it in Branch 2.

### 2.2 Per-Interface Buffer Sizes

| Interface Type | outgoing mpsc capacity | I/O task internal queue | Total buffer depth |
|---------------|----------------------|------------------------|-------------------|
| **TCP Client** | 256 (TCP_DEFAULT_BUFFER_SIZE, tcp.rs:30) | None (writes directly to TcpStream) | 256 packets |
| **TCP Server connection** | 256 (tcp.rs:30) | None | 256 packets |
| **UDP** | 256 (UDP_DEFAULT_BUFFER_SIZE, udp.rs:23) | None | 256 packets |
| **AutoInterface peer** | 64 (PEER_CHANNEL_BUFFER, orchestrator.rs:32) | None | 64 packets |
| **Local (IPC)** | 256 (LOCAL_DEFAULT_BUFFER_SIZE, local.rs:25) | None | 256 packets |
| **RNode (LoRa)** | 64 (RNODE_DEFAULT_BUFFER_SIZE, rnode.rs:88) | VecDeque send_queue, cap 64 (FLOW_CONTROL_QUEUE_LIMIT, rnode.rs:93) | 64 (mpsc) + 64 (send_queue) = 128 packets |

Note: TCP, UDP, Local, and AutoInterface buffer sizes are configurable via
`config.buffer_size`. The values above are defaults.


### 2.3 RNode Detailed Buffer Chain

```
dispatch_actions()
    |
    v
InterfaceHandle::try_send()          [mpsc try_send, capacity=64]
    |                                 Returns BufferFull if mpsc full
    v
rnode_io_task outgoing_rx.recv()     [dequeues from mpsc]
    |
    v
send_queue: VecDeque<(Vec<u8>, u64)> [cap=64, drops OLDEST on overflow]
    |
    v  (jitter timer: 0-500ms first packet, 50ms spacing)
port.write_all()                     [serial port, blocks until bytes written]
    |
    v  (if flow_control: waits for CMD_READY from device)
LoRa radio                           [CSMA in firmware]
```


## 3. Current Failure Behavior at Each Stage

### Stage 1: Transport::pending_actions (Vec<Action>)
- **File**: `reticulum-core/src/transport.rs:556`
- **Type**: `Vec<Action>` (unbounded, heap-allocated)
- **Failure mode**: Cannot fail. Vec grows as needed. All `send_on_interface()`,
  `send_on_all_interfaces()`, `send_on_all_interfaces_except()` unconditionally
  push to this Vec.
- **Current behavior**: No backpressure. Actions accumulate without limit during
  a single `handle_packet()` or `handle_timeout()` call.

### Stage 2: action_dispatch channel (app-thread only)
- **File**: `reticulum-std/src/driver/mod.rs:245`
- **Type**: `tokio::sync::mpsc::channel(256)` (EVENT_CHANNEL_CAPACITY)
- **Failure mode**: `.send()` is **async** -- it awaits until space is available.
  This means the app thread blocks if the event loop is slow to drain.
- **Current behavior**: Natural backpressure on the app thread. If the event loop
  is processing slowly, `connect()`, `send_on_link()`, `announce_destination()`,
  etc. will block. However, this is **async await**, not CPU spin -- tokio yields.
- **Exception**: `PacketSender::send()` and `LinkHandle::send()/try_send()` also
  use this channel. `LinkHandle::send()` has a retry loop for WindowFull/PacingDelay
  at the channel level (sleeping 50ms), but the `action_dispatch_tx.send()` itself
  is still async-awaiting.

### Stage 3: dispatch_actions() -> Interface::try_send()
- **File**: `reticulum-core/src/transport.rs:192-222`
- **Type**: Free function, iterates actions and calls `try_send()` on each interface
- **Failure mode**: Collects `Vec<(InterfaceId, InterfaceError)>` of all errors.
- **Current behavior at caller** (dispatch_output, driver/mod.rs:1089-1115):
  - **BufferFull**: logs `warn!` "packet dropped". **Packet is silently lost.**
    No retry. No notification back to the originator.
  - **Disconnected**: logs `warn!`. Actual cleanup happens when `recv_any()` detects
    channel closure in the next event loop iteration.
- **Key observation**: The return value of `dispatch_actions()` (the errors vector)
  is logged but **never propagated** back to the originator. There is no mechanism
  to tell a channel message sender "your packet was dropped at the interface level."

### Stage 4: InterfaceHandle::try_send() -> outgoing mpsc
- **File**: `reticulum-std/src/interfaces/mod.rs:165-176`
- **Type**: `tokio::sync::mpsc::Sender::try_send()` (non-blocking)
- **Failure mode**:
  - `TrySendError::Full` -> `InterfaceError::BufferFull`
  - `TrySendError::Closed` -> `InterfaceError::Disconnected`
- **Current behavior**: Returns error to `dispatch_actions()`. The error is logged
  and the packet is lost (see Stage 3).

### Stage 5: Interface I/O task -> wire

#### TCP/UDP/Local/Auto:
- I/O task calls `outgoing_rx.recv()` and writes directly to socket.
- If socket write fails: I/O task returns, channel closes, event loop detects
  disconnect.
- No internal queueing beyond the mpsc channel.

#### RNode:
- **File**: `reticulum-std/src/interfaces/rnode.rs:383-563`
- I/O task receives from `outgoing_rx`, wraps in KISS data frame, enqueues in
  `send_queue` (VecDeque, cap 64).
- **On send_queue full** (rnode.rs:500-503): `pop_front()` (drops oldest packet),
  logs `warn!`. New packet is then pushed.
- **Jitter**: First packet gets 0-500ms random delay. Subsequent packets spaced
  at `MIN_SPACING_MS` (50ms by default, from rnode module constants).
- **Flow control** (if enabled): waits for `CMD_READY` from device firmware
  before sending next packet. This means the send_queue can back up while
  waiting for the radio.
- **Write failure**: `port.write_all()` error causes I/O task to return,
  triggering reconnect cycle.


## 4. Backpressure Analysis per Origination Path

### P1: announce_destination (App -> Broadcast)
- **Who should slow down**: The application calling `announce_destination()`.
- **Current feedback**: None at interface level. The action_dispatch channel
  provides async backpressure (awaits if full), but once dispatched, BufferFull
  is silently swallowed.
- **What "slow down" means**: Announces are best-effort. Dropping under pressure
  is acceptable. The announce will be re-sent periodically via mgmt_announces
  or on interface_up.
- **Needed**: Nothing urgent. Current behavior is acceptable for best-effort.

### P2: connect (App -> SendPacket or Broadcast)
- **Who should slow down**: The application calling `connect()`.
- **Current feedback**: action_dispatch async backpressure only. BufferFull at
  interface level is swallowed.
- **What "slow down" means**: Link request is lost. Link establishment will
  timeout after `establishment_timeout_ms`. Application gets `LinkClosed(Timeout)`.
- **Needed**: Current behavior is adequate -- timeout covers the loss case.
  Could log more prominently.

### P3: accept_link (App -> SendPacket)
- **Who should slow down**: The application calling `accept_link()`.
- **Current feedback**: Same as P2.
- **What "slow down" means**: Link proof is lost. Initiator times out and may
  retry. This is a must-deliver packet but has implicit retry (initiator retries).
- **Needed**: Current behavior is adequate.

### P4: send_on_link (App -> SendPacket) -- CRITICAL PATH
- **Who should slow down**: The application calling `send_on_link()` via LinkHandle.
- **Current feedback**:
  - Channel level: `WindowFull` and `PacingDelay` are returned to the caller.
    `LinkHandle::send()` (stream.rs:108-142) retries with sleep on both.
    `LinkHandle::try_send()` returns the error immediately.
  - Interface level: **NO feedback.** If `try_send()` on the interface returns
    `BufferFull`, the packet is logged and dropped. The channel's tx_ring still
    has the envelope marked as Sent. The channel will eventually retransmit
    (check_channel_timeouts), but:
    1. The retransmit timeout is RTT-based and can be many seconds.
    2. Multiple drops compound -- each dropped retransmit resets the timer.
    3. On LoRa, where BufferFull is most likely, RTT is already long.
- **What "slow down" means**: The channel layer provides flow control (window),
  but the channel does not know the interface dropped the packet. This causes
  unnecessary retransmit delay.
- **Needed**: This is the most important gap. Options:
  1. Feed BufferFull back to the channel to trigger immediate retransmit
  2. Queue the packet at the interface level (RNode already does this)
  3. Return BufferFull from dispatch_output to the caller somehow
  4. Have dispatch_actions return per-action success so NodeCore can re-queue

### P5: send_single_packet (App -> SendPacket)
- **Who should slow down**: The application.
- **Current feedback**: action_dispatch async backpressure only.
- **What "slow down" means**: Packet silently lost. Fire-and-forget by design.
- **Needed**: Nothing. This is explicitly best-effort.

### P6: close_link (App -> SendPacket)
- **Who should slow down**: N/A.
- **Current feedback**: None needed.
- **What "slow down" means**: Peer doesn't get LINKCLOSE, times out naturally.
- **Needed**: Nothing.

### P7: keepalive (Timer -> SendPacket)
- **Who should slow down**: N/A (timer-driven).
- **Current feedback**: None.
- **What "slow down" means**: Keepalive lost. Stale detection handles this
  after `KEEPALIVE_TIMEOUT`.
- **Needed**: Nothing. Best-effort by design.

### P8: channel retransmit (Timer -> SendPacket) -- CRITICAL PATH
- **Who should slow down**: Cannot slow down -- this IS the retry mechanism.
- **Current feedback**: None. If the retransmit is also dropped by BufferFull,
  the channel increments `tries` and schedules another retransmit with
  exponential backoff.
- **What "slow down" means**: Retransmit dropped. Next retry scheduled at
  `BACKOFF_BASE^(tries-1) * timeout`. After `CHANNEL_MAX_TRIES` (5),
  `ChannelAction::TearDownLink` is emitted and the link is closed.
- **Needed**: This is the second most important gap. A retransmit that is dropped
  at the interface level wastes a try count and delays delivery. On LoRa with a
  64-packet buffer, this can cascade into a "retransmit death spiral" where
  retransmits fill the buffer, causing more drops, causing more retransmits.

### P9: announce rebroadcast (Timer -> Broadcast or SendPacket)
- **Who should slow down**: Transport timer.
- **Current feedback**: None. The announce system has its own retry logic
  (`retransmit_at_ms`, `PATHFINDER_RETRIES`).
- **What "slow down" means**: Rebroadcast dropped. Will retry at next
  `PATHFINDER_G_MS` interval, up to `PATHFINDER_RETRIES` times. Also
  suppressed by `local_rebroadcasts` from neighbors.
- **Needed**: Acceptable. The announce system is designed for lossy networks.

### P10: announce queue drain (Timer -> SendPacket)
- **Who should slow down**: N/A (per-interface rate limited by bandwidth cap).
- **Current feedback**: None.
- **What "slow down" means**: Dequeued announce dropped. It's already been
  removed from the queue. Lost.
- **Needed**: Minor concern. Could re-queue on BufferFull, but the announce
  cap system is designed for slow interfaces and the queue is bounded
  (`MAX_QUEUED_ANNOUNCES_PER_INTERFACE`).

### P11: mgmt announce (Timer -> Broadcast)
- **Who should slow down**: N/A.
- **What "slow down" means**: Probe announce lost. Next fires in 2 hours.
- **Needed**: Nothing. Best-effort.

### P12: packet forwarding (Incoming -> SendPacket) -- IMPORTANT
- **Who should slow down**: Cannot -- this is a relay responding to incoming traffic.
- **Current feedback**: None.
- **What "slow down" means**: Forwarded packet dropped. Sender's reliability
  layer (channel retransmit) handles recovery.
- **Needed**: On transport nodes with LoRa, this can be a bottleneck. Consider:
  1. Not forwarding if the outgoing interface is known to be congested
  2. Priority queueing (proofs > data > announces)

### P13: proof forwarding (Incoming -> SendPacket) -- IMPORTANT
- **Who should slow down**: Cannot -- relay responding to proof transit.
- **Current feedback**: None.
- **What "slow down" means**: Proof dropped in transit. The channel sender
  will retransmit the data, generating a new proof. But on LoRa, each
  retransmit + proof cycle takes many seconds of airtime.
- **Needed**: Proofs should have priority over other traffic. Currently
  they compete equally in the same mpsc buffer.

### P14: path request forwarding (Incoming -> Broadcast or SendPacket)
- **Who should slow down**: N/A.
- **What "slow down" means**: Path request lost. Requestor will re-request
  after `PATH_REQUEST_MIN_INTERVAL_MS`.
- **Needed**: Nothing. Best-effort by design.

### P15: data proof generation (Incoming -> SendPacket)
- **Who should slow down**: Cannot.
- **Current feedback**: None.
- **What "slow down" means**: Proof for received data not sent. Remote sender
  retransmits. Same cascading concern as P13.
- **Needed**: Same as P13 -- proofs should be prioritized.

### P16: interface up re-announce (Event -> Broadcast)
- **Who should slow down**: N/A.
- **What "slow down" means**: Some announces lost on the recovered interface.
  Mgmt announce timer will cover it within 2 hours, or the app can re-announce.
- **Needed**: Nothing. Best-effort.

### P17: announce to local clients (Incoming -> Broadcast + SendPacket)
- **Who should slow down**: N/A.
- **What "slow down" means**: Local IPC client doesn't get the announce.
  Client can request path to recover.
- **Needed**: Nothing. Local IPC has 256-packet buffer, unlikely to fill.


## 5. Must-Deliver vs Best-Effort Classification

### Must-Deliver (has retransmit or will break if lost)

| Path | Packet Type | Recovery Mechanism | Backpressure Gap? |
|------|------------|-------------------|-------------------|
| P4 | Channel data | Channel retransmit (tx_ring, exponential backoff) | YES -- BufferFull not fed back to channel |
| P8 | Channel retransmit | Same (this is the retry) | YES -- dropped retransmit wastes try count |
| P13 | Proof forwarding | Sender retransmits data | YES -- proof loss causes unnecessary retransmit |
| P15 | Data proof (local) | Sender retransmits data | YES -- same as P13 |
| P2 | Link request | Establishment timeout -> app retries | Minor -- timeout covers it |
| P3 | Link proof | Initiator establishment timeout | Minor -- timeout covers it |

### Best-Effort (safe to drop under pressure)

| Path | Packet Type | Why dropping is OK |
|------|------------|-------------------|
| P1 | Local announce | Re-announced on interface_up, mgmt timer |
| P5 | Single packet | Fire-and-forget by design |
| P6 | Link close | Peer times out naturally |
| P7 | Keepalive | Stale detection covers loss |
| P9 | Announce rebroadcast | Retransmit timer, suppression by neighbors |
| P10 | Announce queue drain | Already rate-limited, bounded queue |
| P11 | Mgmt announce | Periodic, 2-hour interval |
| P12 | Packet forwarding | Sender reliability layer handles it |
| P14 | Path request forwarding | Requestor retries |
| P16 | Interface up re-announce | Mgmt timer covers it |
| P17 | Announce to local clients | Client can request path |


## 6. Summary of Key Findings

### 6.1 The Fundamental Gap

The architecture has a clean sans-I/O design with good separation, but there is
a **one-way information flow** problem: `dispatch_actions()` calls `try_send()`
and collects errors, but those errors are **logged and discarded** in
`dispatch_output()` (driver/mod.rs:1104-1115). The originator of the packet
**never learns** that its packet was dropped.

This matters most for:
1. **Channel data** (P4): The channel has a sophisticated window-based flow
   control system, but it operates at the channel layer. It does not know
   that the interface layer dropped the packet.
2. **Channel retransmits** (P8): A dropped retransmit wastes a try count
   (max 5 before link teardown) and delays delivery by RTT * backoff.
3. **Proof forwarding** (P13): A dropped proof causes an unnecessary data
   retransmit from the sender, doubling airtime usage.

### 6.2 The RNode Double Buffer

The RNode interface has two levels of buffering:
1. mpsc channel (64 packets) -- `try_send()` returns `BufferFull` when full
2. Internal send_queue (64 packets) -- drops oldest when full

This means the RNode can buffer up to 128 packets, but the two buffers
have **different overflow behaviors**: mpsc returns an error (which is logged
and swallowed), while send_queue drops the oldest silently. There is no
coordination between them.

### 6.3 Priority Dispatch (implemented)

The `Interface` trait now has `try_send_prioritized(data, high_priority)` with
a default impl calling `try_send()`. `dispatch_actions()` marks SendPacket as
high priority and Broadcast as normal. The RNode send queue inserts high-priority
packets before normal-priority ones, preventing announce rebroadcasts from
starving link requests and proofs on constrained LoRa links.

### 6.4 No "Ready to Send" Signaling

The `Interface` trait has no mechanism for signaling "I have
buffer space now." There is no `poll_ready()`, no `Waker` registration, no
callback. Once `try_send()` returns `BufferFull`, the only recovery is:
- The retry queue (implemented) — failed SendPackets are retried on the next tick
- The originator retries later (channel retransmit timer)

### 6.5 The action_dispatch Channel Is the Only Backpressure Point

The `action_dispatch_tx.send()` (async, capacity 256) is the only place where
natural backpressure exists. If the event loop is slow, app-thread callers
(connect, send_on_link, announce) will await. But this protects against
event-loop congestion, not interface congestion. A fast event loop draining
into a slow interface (LoRa) will happily dispatch packets that get dropped
by `BufferFull`.

### 6.6 Event Loop Internal Paths Have No Backpressure At All

Packets generated inside the event loop (handle_packet responses, handle_timeout
timer outputs, handle_interface_up announces) bypass the action_dispatch channel
entirely. They go directly from `process_events_and_actions()` to
`dispatch_output()` to `try_send()`. If the interface buffer is full, the packet
is lost with only a log warning.

This is fine for best-effort packets (announces, keepalives) but problematic for
must-deliver packets generated inside the event loop:
- Channel retransmits (P8): Generated by `check_channel_timeouts()` inside
  `handle_timeout()`. If dropped by BufferFull, a try count is wasted.
- Proof generation (P15): Generated by `handle_link_data_proof()` inside
  `handle_packet()`. If dropped, sender retransmits unnecessarily.
