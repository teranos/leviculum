# Design: Interface Backpressure

## Problem

When `try_send()` on an interface returns `BufferFull`, the driver logs a
warning and drops the packet. The originator never learns. On LoRa (730ms
per packet, 64-slot buffer), this causes:

- Channel data lost → retransmit timer waits RTT×backoff (10-30s on LoRa)
- Retransmits lost → try count wasted → link torn down after max tries
- Proofs lost → sender retransmits data → doubles airtime

## Design

Two mechanisms, implemented together as one change:

### 1. Retry Queue (protects event-loop-internal packets)

When `dispatch_actions()` calls `try_send()` and gets `BufferFull` on a
**SendPacket** action, the driver does NOT drop the packet. Instead it
puts it in a per-interface retry queue (`VecDeque<Vec<u8>>`). On every
event loop tick, before dispatching new actions, the driver tries to
drain the retry queue first.

When `dispatch_actions()` calls `try_send()` and gets `BufferFull` on a
**Broadcast** action, the packet IS dropped for that interface. This is
correct — broadcasts are flooding (announces, path requests, keepalives).
They all have built-in recovery (re-announce timers, retry intervals,
stale detection). Dropping one broadcast on one interface is normal
network behavior.

The distinction already exists in the Action enum. No priority field,
no annotation, no new metadata. SendPacket has a target interface →
someone made a routing decision → don't drop. Broadcast has no target →
flooding → droppable.

### 2. Congested Flag (protects app-originated packets)

When the retry queue for interface X becomes non-empty, the driver sets
a congested flag on the core:

```
core.set_interface_congested(iface_id, true)
```

When the retry queue for interface X is fully drained, the driver clears
it:

```
core.set_interface_congested(iface_id, false)
```

Any core send function that routes over a specific interface checks this
flag. If the target interface is congested, it returns `Err(Busy)`
to the caller instead of building the packet and pushing an Action.

The app sees `Err(Busy)` and decides: retry later, wait, or give up.

### Why these belong together

The retry queue without the congested flag works — but the app keeps
pumping packets, the retry queue grows without bound, and eventually
memory is exhausted.

The congested flag without the retry queue works for the app — but
event-loop-internal packets (retransmits, proofs, forwards) still get
dropped, because they have no caller that could check a flag.

One mechanism protects internal packets. The other protects external
callers. Both are triggered by the same event (BufferFull) and linked
by the same state (retry queue empty/non-empty).

## What changes where

### reticulum-core (minimal changes)

**transport.rs — new congestion state:**

```rust
// New field on Transport
interface_congested: BTreeMap<InterfaceId, bool>,

// New methods
pub fn set_interface_congested(&mut self, id: InterfaceId, congested: bool);
pub fn is_interface_congested(&self, id: InterfaceId) -> bool;
```

This is the same pattern as `is_online()` — a driver-written flag that
the core reads. No I/O, no Sans-I/O violation.

**node/send.rs, node/link_management.rs — congestion check on routed sends:**

Every function that resolves a destination to a specific interface and
then creates a SendPacket action checks congestion BEFORE building the
packet:

```rust
// In send_on_link, send_single_packet, etc.
// After resolving the target interface from the path table:
if self.transport.is_interface_congested(target_iface) {
    return Err(SendError::Busy);
}
// ... build packet, push Action
```

This applies ONLY to app-originated sends that route over a known path.
It does NOT apply to:
- Broadcasts (they skip congested interfaces naturally — drop is ok)
- Event-loop-internal sends (retransmits, proofs — they use the retry queue)

The check happens right before packet construction, after path lookup.
If the path goes through a congested interface, we don't waste CPU
building and encrypting a packet that can't be sent.

**New error variant:**

```rust
// Rename existing WindowFull to Busy everywhere.
// No new variant needed — Busy covers both channel window
// and interface congestion.
Busy
```

### reticulum-std/src/driver/mod.rs (main changes)

**New retry queue state:**

```rust
// Per-interface retry queue
let mut retry_queues: BTreeMap<InterfaceId, VecDeque<Vec<u8>>> = BTreeMap::new();
```

**Modified dispatch_output():**

```rust
// BEFORE dispatching new actions, drain retry queues
for (iface_id, queue) in &mut retry_queues {
    while let Some(data) = queue.front() {
        match registry.get_mut(iface_id).try_send(data) {
            Ok(()) => { queue.pop_front(); }
            Err(BufferFull) => break,  // still full, stop draining
            Err(Disconnected) => { queue.clear(); break; }
        }
    }
}

// Update congestion flags
for (iface_id, queue) in &retry_queues {
    let congested = !queue.is_empty();
    core.set_interface_congested(*iface_id, congested);
}

// THEN dispatch new actions (existing logic, modified error handling)
let errors = dispatch_actions(&mut ifaces, &output.actions);
for (iface_id, action_data, error) in errors {
    match error {
        BufferFull => {
            match action {
                SendPacket { .. } => {
                    // Don't drop — queue for retry
                    retry_queues
                        .entry(iface_id)
                        .or_default()
                        .push_back(action_data);
                }
                Broadcast { .. } => {
                    // Drop is fine, log at trace level
                    tracing::trace!("Broadcast dropped on congested iface {}", iface_id);
                }
            }
        }
        Disconnected => {
            // existing behavior: handle_interface_down
        }
    }
}

// Update congestion flags again (new failures may have added to queues)
for (iface_id, queue) in &retry_queues {
    core.set_interface_congested(*iface_id, !queue.is_empty());
}
```

**Note on dispatch_actions() return type:**

Today `dispatch_actions()` returns `Vec<(InterfaceId, InterfaceError)>`.
It needs to also return the packet data for failed SendPackets so the
driver can queue it. Change the return type to include the data:

```rust
pub struct DispatchError {
    pub iface: InterfaceId,
    pub error: InterfaceError,
    pub data: Vec<u8>,         // the packet that failed
    pub was_broadcast: bool,   // so the driver knows whether to retry or drop
}
```

This is a change to the dispatch_actions() signature in core, but it's
mechanical — the function already has the data, it just needs to return
it instead of discarding it.

### Retry queue safety

**Bounded size:** The retry queue per interface MUST have a maximum size.
If the interface is down for an extended period, the queue would grow
without bound. Set a generous cap (e.g., 256 packets per interface —
enough for several minutes of LoRa traffic). When the cap is reached,
drop the oldest entry and log a warning. This should be rare in practice
because the congested flag stops new app-originated packets from entering
the pipeline.

**Disconnected interface:** When an interface disconnects, clear its
retry queue entirely. The packets are for a dead link.

**Timer interaction:** The retry queue drain runs at the top of every
event loop tick. This means retries happen at event loop frequency
(sub-millisecond when active, up to 1s when idle). For LoRa with 730ms
per packet, this is more than fast enough.

## Error Rename: WindowFull → Busy

Today the channel returns `WindowFull` when the send window is exhausted.
With this design, the same situation arises when the target interface is
congested. From the caller's perspective, the reaction is identical:
"can't send right now, try again later."

Rename `WindowFull` to `Busy` everywhere. One error, one meaning: the
send path is occupied, regardless of whether it's the channel window or
the interface buffer. The caller doesn't need to know which layer is
full — only that it should back off.

This means `Err(Congested)` as described above becomes `Err(Busy)` —
the same variant the channel already returns. No new error type needed.

```rust
// Before (two different errors for the same caller reaction)
Err(WindowFull)   // channel window exhausted
Err(Congested)    // interface buffer full  ← would be new

// After (one error, one reaction)
Err(Busy)         // send path is occupied, try later
```

The `PacingDelay` variant (channel is pacing between sends) stays
separate — it has different semantics (wait a specific duration, not
just "try later").

## Acknowledged Minor Points

**Retry queue ordering.** Old packets drain before new ones. A fresh
proof sits behind queued data. But this is the same queuing delay that
the RNode send_queue produces anyway. The difference: today the proof
is dropped and the sender retransmits after 10s+ timeout. With the retry
queue, the proof waits in line and gets sent. Strictly better.

**Keepalives and link closes are SendPacket.** They route via
route_link_packet() → SendPacket. They're best-effort by nature but
get retry-queued. This is benign — a late keepalive is better than a
dropped one (avoids spurious stale detection). Cost: one retry queue
slot per keepalive.

**Relay forwarding fills the retry queue.** A transport node relaying
TCP→LoRa produces SendPacket actions for forwarded data. These get
retry-queued. With 256 cap, that's ~3 minutes of LoRa traffic. This is
strictly better than today (immediate drop). The congested flag stops
app-originated traffic, so queue growth is limited to event-loop-internal
traffic (retransmits, proofs, forwards). No unbounded growth.

**Retry queue cap for LoRa.** 256 is generous. For LoRa interfaces,
32-64 would cover 23-47s of traffic and is more appropriate. Consider
making the cap configurable per interface type, defaulting to 256 for
TCP/UDP and 64 for LoRa.

**Total buffer depth with RNode.** Retry queue (64) + mpsc (64) +
send_queue (64) = 192 potential packets for LoRa. Sounds like a lot,
but congested flag limits inflow. In practice, expect 20-30 packets
in the retry queue under sustained load.

## Send queue priority (added post-design)

The retry queue + congestion flag design above solved buffer-full drops.
A separate problem remained: on LoRa, announce rebroadcasts (Broadcast
actions) filled the RNode send queue, delaying link requests and proofs
(SendPacket actions) past their establishment timeout (40% failure rate
at SF10).

**Solution: priority dispatch through the Interface trait.**

- `Interface::try_send_prioritized(&mut self, data: &[u8], high_priority: bool)`
  added to the trait with a default impl that calls `try_send()`.
- `dispatch_actions()` calls `try_send_prioritized(data, true)` for
  `SendPacket` (directed traffic) and `try_send_prioritized(data, false)`
  for `Broadcast` (announce rebroadcasts).
- `OutgoingPacket` carries `high_priority: bool` through the mpsc channel.
- RNode send queue inserts high-priority packets before the first
  normal-priority packet instead of appending to the back.

TCP/UDP interfaces ignore the priority hint (default impl). Only
constrained half-duplex interfaces like LoRa benefit.

SF10 lora_link_rust pass rate: 3/5 → 5/5 after this change.

## What does NOT change

- **Action enum:** No priority field. Broadcast vs SendPacket is the
  distinction — `dispatch_actions()` maps this to the priority hint.
- **Core protocol logic:** No `report_send_failures()`, no ActionTag, no
  feedback from I/O into core protocol state.
- **Channel internals:** No envelope state changes, no window manipulation.
  The channel doesn't know about interface congestion. It only knows that
  `send_on_link()` returned `Err(Busy)`.
- **Fast interfaces:** TCP/UDP with 256-slot buffers will almost never
  hit BufferFull. The retry queue stays empty, the congested flag stays
  false. Zero overhead.

## Packet flow examples

### Channel data on congested LoRa (app-originated)

```
App calls send_on_link("hello")
  → Core resolves path → interface 3 (LoRa)
  → Core checks: is_interface_congested(3)? → YES
  → Core returns Err(Busy)
  → App decides to retry in 100ms
  → Meanwhile, retry queue drains, flag clears
  → App retries → succeeds
```

### Retransmit on congested LoRa (event-loop-internal)

```
handle_timeout() fires channel retransmit
  → Core builds packet, pushes Action::SendPacket(iface=3)
  → dispatch_actions() calls try_send(3) → BufferFull
  → Driver puts packet in retry_queues[3]
  → Next tick: driver drains retry_queues[3] → try_send(3) → Ok
  → Packet sent. No try count wasted.
```

### Broadcast announce on congested LoRa

```
handle_timeout() fires announce rebroadcast
  → Core pushes Action::Broadcast(exclude=2)
  → dispatch_actions() calls try_send on all interfaces
  → iface 0 (TCP): Ok
  → iface 1 (UDP): Ok
  → iface 3 (LoRa): BufferFull
  → Driver drops the broadcast for iface 3. Logged at trace.
  → Announce reached TCP and UDP peers. LoRa peers get it on
    the next rebroadcast cycle.
```

## Testing strategy

### Unit tests (reticulum-core)

1. `test_busy_flag_blocks_send`: Set interface congested, verify
   send_on_link returns Err(Busy).
2. `test_busy_flag_clear_allows_send`: Clear flag, verify send works.
3. `test_dispatch_returns_failed_sendpacket_data`: Verify dispatch_actions
   returns packet data on BufferFull for SendPacket.
4. `test_dispatch_does_not_return_failed_broadcast_data`: Verify dispatch
   drops broadcast data on BufferFull.

### Unit tests (reticulum-std)

5. `test_retry_queue_drain`: Fill retry queue, mock interface accepting
   packets, verify queue drains.
6. `test_retry_queue_sets_busy_flag`: Verify flag is set when queue
   non-empty, cleared when empty.
7. `test_retry_queue_cap`: Fill to cap, verify oldest dropped.
8. `test_retry_queue_cleared_on_disconnect`: Disconnect interface, verify
   queue purged.

### Integration tests (reticulum-integ)

9. LoRa selftest sustained: Two nodes, selftest with --duration 10,
   verify >95% delivery (vs ~60% today).
10. LoRa dual-cluster with selftest: 10-node topology, rnprobes + selftest,
    verify no link teardowns from exhausted retransmit tries.
