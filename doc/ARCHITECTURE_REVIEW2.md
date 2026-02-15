# Architecture Review — Round 2

## Part A: Split-Brain Risk Analysis

Analysis of the four parallel BTreeMap pairs keyed by LinkId, plus the duplicate destination registries, examining whether they can diverge.

---

### Pair 1: `links` and `channels` (both in LinkManager)

#### Insertions into `links`

| Location | Line | Context |
|----------|------|---------|
| `manager.rs:243` | `self.links.insert(link_id, link)` | `initiate_with_path()` — outgoing link creation |
| `manager.rs:924` | `self.links.insert(link_id, link)` | `handle_link_request()` — incoming link creation |

#### Insertions into `channels`

| Location | Line | Context |
|----------|------|---------|
| `manager.rs:555` | `self.channels.insert(*link_id, channel)` | `get_channel()` — lazy creation on first mutable access |
| `manager.rs:632` | `self.channels.insert(*link_id, channel)` | `channel_send()` — lazy creation on first send |
| `manager.rs:1179` | `self.channels.entry(link_id).or_insert_with(...)` | `handle_data()` on CHANNEL context — lazy creation on first receive |

#### Removals from `links`

| Location | Line | Context |
|----------|------|---------|
| `manager.rs:324` | `self.links.remove(link_id)` | `reject_link()` — rejecting incoming link request |
| `manager.rs:518` | `self.links.remove(link_id)` | `close_local()` — local-only close |
| `manager.rs:974` | `self.links.remove(&link_id)` | `handle_proof()` — invalid proof on outgoing link |
| `manager.rs:1378` | `self.links.remove(&link_id)` | `check_timeouts()` — outgoing pending link timed out |
| `manager.rs:1390` | `self.links.remove(&link_id)` | `check_timeouts()` — incoming pending link timed out |

**NOT removed from `links` in these paths:**

| Location | Line | Context |
|----------|------|---------|
| `manager.rs:485-507` | `close()` | Sets link state to Closed but does NOT remove from `self.links` |
| `manager.rs:1478-1496` | `check_stale_links()` | Sets link state to Closed but does NOT remove from `self.links` |
| `manager.rs:1144-1155` | `handle_data()` LINKCLOSE | Emits `LinkClosed(PeerClosed)` but does NOT remove from `self.links` |
| `manager.rs:1561-1580` | `check_channel_timeouts()` TearDownLink | Removes from `channels` but does NOT remove from `self.links` (only calls `link.close()`) |

#### Removals from `channels`

| Location | Line | Context |
|----------|------|---------|
| `manager.rs:519` | `self.channels.remove(link_id)` | `close_local()` — paired with link removal |
| `manager.rs:1573` | `self.channels.remove(&link_id)` | `check_channel_timeouts()` TearDownLink |

#### Analysis

**When does a `links` entry exist without a `channels` entry?**
This is the normal state. Links exist from creation. Channels are lazily created only when first needed (via `get_channel()`, `channel_send()`, or on receipt of a CHANNEL packet). A link can be Active without ever having a channel if only raw data (not channel-framed messages) is exchanged.

**When does a `channels` entry exist without a `links` entry?**
This can happen in several scenarios:

1. **`close()` (line 485-507)**: Marks the link as Closed but does NOT remove from `self.links` or `self.channels`. The link entry persists in Closed state. This is NOT an orphan case since both survive.

2. **`check_stale_links()` (line 1478-1496)**: Same as `close()` — link transitions to Closed but neither map is cleaned. Both persist.

3. **`handle_data()` LINKCLOSE (line 1144-1155)**: Same — emits event, link remains in `links`, channel remains in `channels`. Both persist as zombie entries.

4. **`check_channel_timeouts()` TearDownLink (line 1561-1580)**: Removes `channels` entry but NOT `links` entry (only calls `link.close()`). This leaves a Closed link in `links` with no channel.

**What happens if `channels` has an entry for a LinkId that `links` doesn't?**
Looking at `check_channel_timeouts()` (line 1502-1584): the code first collects `self.channels.keys()`, then for each, looks up `self.links.get(&link_id)` to get RTT. If the link is missing, it uses a default RTT value (line 1513-1514). The `channel.poll()` call proceeds, which may produce `ChannelAction::Retransmit` — but the retransmit handler also checks `self.links.get(&link_id)` (line 1532) and skips if None. `TearDownLink` action also checks `self.links.get_mut(&link_id)` (line 1564) and proceeds to remove the channel. So an orphaned channel is not dangerous but will waste CPU polling a dead channel until TearDownLink fires.

**Is removal always paired?**
No. The `close()` and `check_stale_links()` paths do not remove either entry. The `check_channel_timeouts()` TearDownLink path removes `channels` but not `links`. No periodic cleanup removes Closed-state links from `self.links`. This means **Closed links accumulate indefinitely** in `self.links`.

#### Risk Rating: **Medium**

Evidence: Closed links accumulate in `self.links` without any cleanup mechanism. For long-running nodes with many connections over time, this is a memory leak. The `channels` map is cleaned up on TearDownLink, but `links` entries in Closed state persist forever. The functional impact is limited (Closed links are filtered out by most queries), but the memory leak is real and grows unbounded.

---

### Pair 2: `links` (LinkManager) and `connections` (NodeCore)

#### Insertions into `connections`

| Location | Line | Context |
|----------|------|---------|
| `mod.rs:349` | `self.connections.insert(link_id, conn)` | `connect()` — initiator creates connection immediately |
| `mod.rs:411` | `self.connections.insert(*link_id, conn)` | `accept_connection()` — responder creates connection on accept |
| `mod.rs:1035` | `self.connections.insert(link_id, conn)` | `handle_link_event()` LinkEstablished — ensures connection exists if not already created |

#### Removals from `connections`

| Location | Line | Context |
|----------|------|---------|
| `mod.rs:448` | `self.connections.remove(link_id)` | `close_connection()` — explicit application close |
| `mod.rs:1073` | `self.connections.remove(&link_id)` | `handle_link_event()` LinkClosed — on any close reason |

#### Analysis

**When does a link exist without a connection?**

1. **Pending incoming links before `accept_connection()`**: When `handle_link_request()` in LinkManager creates a link (line 924) and emits `LinkRequestReceived`, the application receives `ConnectionRequest` via NodeCore. At this point the link exists in `links` but no connection exists in `connections`. The connection is created only when the application calls `accept_connection()` (line 411). If the application calls `reject_link()` instead, the link is removed from `links` (line 324) without ever creating a connection. This is correct.

2. **Rejected incoming links**: `reject_link()` removes from `links`, no connection ever existed. Correct.

3. **After close via LinkManager but before event propagation**: If a link closes in LinkManager (e.g., timeout, stale close, peer close), the `LinkClosed` event is emitted. NodeCore processes this in `handle_link_event()` (line 1071-1101) which removes the connection. The key question is: can a connection be accessed between the link closing and the event being processed? No — events are processed synchronously in `process_events_and_actions()`. The link manager's events are drained and processed in the same call. So there is no window.

**Can a connection outlive its link?**

Yes, and this is the primary concern.

1. **`close()` (LinkManager line 485-507)**: Marks the link as Closed but does NOT remove it from `self.links`. The connection is removed in NodeCore's `close_connection()` (line 448) which also calls `self.link_manager.close()`. So the connection is removed, but the link persists as a Closed entry. After this, the link exists without a connection.

2. **`check_stale_links()` (line 1478-1496)**: Closes the link, emits `LinkClosed(Stale)`. NodeCore processes `LinkClosed` and removes the connection. But the link persists in Closed state in `self.links`.

3. **`handle_data()` LINKCLOSE (line 1144-1155)**: Emits `LinkClosed(PeerClosed)`. NodeCore removes the connection. Link persists.

In all these cases, the connection is properly removed. However, the connection in NodeCore will be removed but the link in LinkManager will NOT be removed (it stays in Closed state). This means `find_connection_to()` (line 677-687) correctly skips these since `is_active()` returns false for Closed links.

**What happens if `connections` has a stale entry?**
If `connections` somehow retained an entry for a link that was removed from `links`:
- `send_on_connection()` (line 622-673): Checks both `self.connections.get(link_id)` AND `self.link_manager.link(link_id)`. If link is missing, returns `SendError::NoConnection`. Safe.
- `connection_stats()` (line 862-871): Checks `self.connections.get(link_id)`, then queries `self.link_manager.channel(link_id)`. Would return Some with zeroed stats. Benign.
- `find_connection_to()` (line 677-687): Checks `self.link_manager.is_active(link_id)`. Would return false for missing link. Safe.

#### Risk Rating: **Low**

Evidence: The removal paths are well-synchronized. Every `LinkClosed` event from LinkManager is processed by NodeCore which removes the connection. The reverse is also true: `close_connection()` calls `link_manager.close()`. The one asymmetry is that links persist in Closed state after connections are removed, but this doesn't cause functional issues since all access paths check link state. The only residual issue is the same memory leak from Pair 1 (Closed links accumulating in `self.links`).

---

### Pair 3: `channel_hash_to_seq` (NodeCore) and `channels` (LinkManager)

#### Insertions into `channel_hash_to_seq`

| Location | Line | Context |
|----------|------|---------|
| `mod.rs:660` | `self.channel_hash_to_seq.insert(full_hash, seq)` | `send_on_connection()` — after registering channel receipt for initial send |
| `mod.rs:1136` | `self.channel_hash_to_seq.insert(new_hash, sequence)` | `handle_link_event()` ChannelReceiptUpdated — on retransmit, maps new hash to sequence |

#### Removals from `channel_hash_to_seq`

| Location | Line | Context |
|----------|------|---------|
| `mod.rs:1109` | `self.channel_hash_to_seq.remove(&packet_hash)` | `handle_link_event()` DataDelivered — proof received, lookup and remove mapping |
| `mod.rs:1133` | `self.channel_hash_to_seq.remove(&old)` | `handle_link_event()` ChannelReceiptUpdated — removes old hash when retransmit creates new hash |

#### Analysis

**What happens if Channel is removed but `channel_hash_to_seq` still has entries?**

Channels are removed from LinkManager in two places:
1. `close_local()` (line 519): removes channel
2. `check_channel_timeouts()` TearDownLink (line 1573): removes channel

In both cases, a `LinkClosed` event is emitted. NodeCore processes the event at `handle_link_event()` (line 1071-1101) and removes the connection. However, **there is no cleanup of `channel_hash_to_seq` on link close**.

The orphaned entries in `channel_hash_to_seq` will persist until:
- A `DataDelivered` event arrives for one of the hashes (unlikely after link close)
- A `ChannelReceiptUpdated` event replaces an old hash (impossible after channel removal)

Neither will happen after the link/channel is gone. These entries are leaked permanently.

However, the functional impact is limited:
- `DataDelivered` handler (line 1103-1123): If a proof somehow arrives for an orphaned hash, it calls `self.channel_hash_to_seq.remove(&packet_hash)`, gets `Some(sequence)`, then calls `self.link_manager.mark_channel_delivered(&link_id, ...)`. Since the channel is gone, `mark_channel_delivered()` returns false. The event `LinkDeliveryConfirmed` is still emitted, but this is harmless since the connection is also gone.

**Size of the leak**: Each entry is `[u8; 32] + u16` = 34 bytes. For typical usage with moderate channel traffic before link close, this could be a handful of entries per closed link. Not catastrophic but unbounded over time.

There is also a secondary issue: `channel_receipt_keys` in LinkManager is cleaned on close paths (via `retain`), but the corresponding `channel_hash_to_seq` in NodeCore is not. These two maps serve related purposes and should ideally be cleaned together.

#### Risk Rating: **Low**

Evidence: The entries are small, the functional impact on a stale lookup is benign (returns harmlessly), and typical usage involves relatively few outstanding channel messages at link close time. However, for very long-running nodes with high churn, the leak is unbounded.

---

### Pair 4: `Transport.destinations` and `NodeCore.destinations`

#### Modifications to `Transport.destinations`

| Location | Line | Context |
|----------|------|---------|
| `transport.rs:590` | `self.destinations.insert(hash, DestinationEntry{...})` | `register_destination()` — simple registration |
| `transport.rs:614` | `self.destinations.insert(hash, DestinationEntry{...})` | `register_destination_with_proof()` — registration with proof strategy |
| `transport.rs:626` | `self.destinations.remove(hash)` | `unregister_destination()` |

#### Modifications to `NodeCore.destinations`

| Location | Line | Context |
|----------|------|---------|
| `mod.rs:243` | `self.destinations.insert(hash, dest)` | `register_destination()` |
| `mod.rs:250` | `self.destinations.remove(hash)` | `unregister_destination()` |

#### Analysis

**Can they diverge?**

NodeCore's `register_destination()` (line 225-243) does three things atomically:
1. Calls `self.transport.register_destination_with_proof(hash, ...)` (inserts into Transport.destinations)
2. Calls `self.link_manager.register_destination(hash)` (inserts into accepted_destinations)
3. Inserts into `self.destinations`

NodeCore's `unregister_destination()` (line 247-251) does the reverse:
1. Calls `self.transport.unregister_destination(hash)` (removes from Transport.destinations)
2. Calls `self.link_manager.unregister_destination(hash)` (removes from accepted_destinations)
3. Removes from `self.destinations`

Since all three operations happen synchronously in the same method call, and there is no other code path that inserts into or removes from either destinations map directly (from the NodeCore context), they **cannot diverge** through normal API usage.

**Key difference in what they store:**
- `Transport.destinations` stores `DestinationEntry { accepts_links, proof_strategy, identity }` — used for packet routing and proof generation at the transport level
- `NodeCore.destinations` stores `Destination` — the full destination object with identity, used for link management and proof signing at the node level

**Note on identity:**
`register_destination_with_proof()` is called with `identity: None` (line 235) because Identity doesn't implement Clone. The actual Identity is stored in the `Destination` object in `NodeCore.destinations`. This means Transport.destinations has `identity: None` for all destinations registered through NodeCore.

#### Risk Rating: **None**

Evidence: The only code paths that modify these maps are the paired `register_destination()` / `unregister_destination()` methods in NodeCore, which synchronously update all three registries (Transport, LinkManager, NodeCore). The maps serve different purposes (routing vs. full destination state) but are always kept in sync through the single entry point.

---

### Split-Brain Summary

| Pair | Risk | Issue |
|------|------|-------|
| 1. `links` / `channels` | **Medium** | Closed links accumulate indefinitely in `self.links`. `close()`, `check_stale_links()`, and PeerClosed paths set link state to Closed but never remove the entry. No periodic cleanup exists. Channels are lazily created and partially cleaned up. |
| 2. `links` / `connections` | **Low** | Removal is well-synchronized via events. Every `LinkClosed` event triggers connection removal. The asymmetry (Closed links persisting in LinkManager) doesn't cause functional issues since all access checks link state. |
| 3. `channel_hash_to_seq` / `channels` | **Low** | `channel_hash_to_seq` entries are never cleaned up when a link/channel closes. The entries are small and stale lookups are benign, but they leak indefinitely. |
| 4. `Transport.destinations` / `NodeCore.destinations` | **None** | Always modified atomically through paired methods. Cannot diverge through normal API usage. |

### Root Cause

The underlying issue for Pairs 1-3 is the same: **`LinkManager.close()` and `check_stale_links()` do not remove entries from `self.links`**. They only set the state to Closed. There is no periodic garbage collection for Closed-state links. This causes:
- `links` entries to accumulate (Pair 1)
- `channels` entries to sometimes survive their link (Pair 1, though usually cleaned by TearDownLink)
- `connections` to be properly cleaned but their corresponding `links` entries to persist (Pair 2)
- `channel_hash_to_seq` entries to be orphaned with no cleanup path (Pair 3)

A single fix — adding periodic removal of Closed-state links from `self.links` (and their associated `channels` and `data_receipts` entries keyed by that LinkId) — would address the memory leak across all three pairs. NodeCore would also need to clean `channel_hash_to_seq` entries for LinkIds that are no longer present in LinkManager.

---

## Part B: LinkManager Dissolution Analysis

Analysis of each state item in LinkManager: where it could move, what difficulty, and what breaks.

---

### Current State

`LinkManager` (`reticulum-core/src/link/manager.rs`) holds 10 fields:

```rust
pub struct LinkManager {                                          // line 84
    links: BTreeMap<LinkId, Link>,                                // line 86
    channels: BTreeMap<LinkId, Channel>,                          // line 88
    pending_outgoing: BTreeMap<LinkId, PendingOutgoing>,          // line 90
    pending_incoming: BTreeMap<LinkId, PendingIncoming>,          // line 92
    accepted_destinations: BTreeSet<DestinationHash>,             // line 94
    events: Vec<LinkEvent>,                                       // line 96
    pending_packets: Vec<PendingPacket>,                          // line 98
    data_receipts: BTreeMap<[u8; TRUNCATED_HASHBYTES], DataReceipt>, // line 100
    channel_receipt_keys: BTreeMap<(LinkId, u16), [u8; TRUNCATED_HASHBYTES]>, // line 102
    rx_ring_full_count: u64,                                      // line 104
    rx_ring_full_last_log_ms: u64,                                // line 106
}
```

NodeCore (`reticulum-core/src/node/mod.rs`, line 163) holds `link_manager: LinkManager` as a single opaque field and calls into it via 18 distinct call sites.

---

### 1. `links: BTreeMap<LinkId, Link>`

**Proposed destination**: NodeCore

Nearly **every** method in LinkManager touches both `links` and at least one other field. The critical cross-references:

| Method | Line | `links` + which other state |
|--------|------|------------------------------|
| `initiate_with_path()` | 215-246 | `links` + `pending_outgoing` |
| `accept_link()` | 280-317 | `links` + `pending_incoming` |
| `close()` | 485-507 | `links` + `pending_packets` + `pending_outgoing` + `pending_incoming` + `channel_receipt_keys` + `events` |
| `close_local()` | 513-528 | `links` + `channels` + `channel_receipt_keys` + `pending_outgoing` + `pending_incoming` + `events` |
| `handle_link_request()` | 883-931 | `links` + `accepted_destinations` + `events` |
| `handle_proof()` | 934-1008 | `links` + `pending_outgoing` + `events` + `pending_packets` |
| `handle_data()` | 1083-1351 | `links` + `channels` + `events` + `pending_packets` |
| `check_timeouts()` | 1373-1404 | `links` + `pending_outgoing` + `pending_incoming` + `events` + `data_receipts` + `channel_receipt_keys` |
| `check_channel_timeouts()` | 1502-1584 | `links` + `channels` + `pending_packets` + `events` + `channel_receipt_keys` |

**Borrow checker issues**: The fundamental issue is that `handle_data()` (line 1083) and `check_channel_timeouts()` (line 1502) need simultaneous mutable access to `links` AND `channels` AND `events` AND `pending_packets`. In the current design, `&mut self` on LinkManager provides a single mutable borrow that covers all fields. If `links` were a separate `BTreeMap` field on NodeCore, every method that currently mutably borrows `self.links` alongside `self.channels` would need to be rewritten to take separate `&mut BTreeMap` parameters, or use a split-borrow pattern.

**Difficulty: Hard**

The `links` map is the central data structure accessed by virtually every method, always in combination with at least one other field. Moving it out forces a rewrite of the entire LinkManager method set.

---

### 2. `channels: BTreeMap<LinkId, Channel>`

**Proposed destination**: `Option<Channel>` on Link

Channel could be `Option<Channel>` on Link. This is the most natural fit architecturally since a Channel is conceptually "the reliable messaging layer of a Link."

**Lifecycle alignment**: Links are created during handshake (Pending state), while Channels are created lazily only after the link becomes Active. `Option<Channel>` on Link naturally models "no channel until needed."

**Borrow checker conflict in `handle_data()` (line 1083-1290)**:
1. Gets `&mut Link` from `self.links` (line 1093) to decrypt data
2. Then gets `&mut Channel` from `self.channels` (line 1179) to process the envelope
3. Then gets `&Link` from `self.links` again (line 1253) to build the proof

If Channel were inside Link, step 2 would require `&mut link.channel` while step 3 requires `&link`. This is sequential access so it would actually work fine — you just need to avoid holding both borrows simultaneously.

**Borrow checker conflict in `channel_send()` (line 611-652)**:
1. Gets `&Link` (line 619) to check state, get MDU and RTT
2. Gets `&mut Channel` (line 635) to call `channel.send()`
3. Gets `&Link` again (line 650) to build the data packet

If Channel were inside Link, getting `&mut link.channel` and then calling `link.build_data_packet_with_context()` would be a simultaneous mutable + immutable borrow on the same Link. Solvable by extracting MDU/RTT/state into local variables before mutating channel.

**Difficulty: Medium**

The lifecycle alignment is natural. The main obstacle is a handful of methods where `&mut Channel` and `&Link` are needed quasi-simultaneously. These are solvable by extracting Link data into local variables before touching the channel. No architectural redesign needed, just local refactoring of 3-4 methods.

---

### 3. `pending_outgoing` / `pending_incoming`

**Proposed destination**: Phase data on Link

Both are trivially small — each holds a single timestamp:

```rust
struct PendingOutgoing { created_at_ms: u64 }
struct PendingIncoming { proof_sent_at_ms: u64 }
```

These map naturally to Link state. A state enum with associated data would be ideal:

```rust
enum LinkPhase {
    PendingOutgoing { created_at_ms: u64 },
    PendingIncoming { proof_sent_at_ms: u64 },
    Active,
    Stale,
    Closed,
}
```

If the timestamps moved into Link itself, every method that currently maintains parallel maps would simply check the link's state/phase instead. `pending_link_count()` would iterate `links` filtering by state. `next_deadline()` already iterates `links` — it would just read the embedded timestamp.

**Difficulty: Easy**

These are tiny, one-field structs in 1:1 correspondence with Link instances. The parallel maps create a consistency burden (every removal from `links` must also remove from `pending_outgoing`/`pending_incoming`). Moving them into Link as phase data eliminates an entire class of bugs and simplifies every method that touches them.

---

### 4. `data_receipts` + `channel_receipt_keys`

**Proposed destination**: Stay together (NodeCore or dedicated struct)

`data_receipts` maps truncated packet hashes to receipt data. `channel_receipt_keys` maps `(link_id, sequence)` to truncated hashes, enabling cleanup when a channel message is retransmitted.

**Why per-link storage fails**: `data_receipts` is keyed by packet hash, not by link. Incoming data proofs are matched by hash without knowing the link_id upfront (`handle_data_proof()` at line 1015 looks up by truncated hash first, then verifies link_id matches). This global lookup is the primary obstacle to per-link storage.

**Methods accessing them**: `send_with_receipt()`, `register_channel_receipt()`, `handle_data_proof()`, `check_timeouts()`, `close()`, `close_local()`, `check_stale_links()`, `check_channel_timeouts()`.

`check_channel_timeouts()` (line 1502-1584) accesses `channels` for polling AND `data_receipts` + `channel_receipt_keys` for receipt registration on retransmit, AND `links` for packet building. This is the tightest coupling.

**Difficulty: Hard**

`data_receipts` requires global hash-based lookup, which conflicts with per-link storage. These two maps are tightly coupled to each other and to both `links` and `channels`. The benefit is marginal compared to the complexity.

---

### 5. `accepted_destinations: BTreeSet<DestinationHash>`

**Proposed destination**: NodeCore (use existing `destinations` map)

NodeCore already has `destinations: BTreeMap<DestinationHash, Destination>` (line 171) and the `accepts_links()` flag is already on Destination. The `register_destination()` method at line 239-240 writes to both `destinations` and `link_manager.accepted_destinations` redundantly.

Only checked in one place: `handle_link_request()` at `manager.rs:893`.

**Difficulty: Easy**

This set is pure configuration state with no interaction with other LinkManager fields except a single `contains` check. If `handle_link_request` were given a `bool accepts_links` parameter instead of checking internally, this field could be removed entirely from LinkManager.

---

### 6. `events: Vec<LinkEvent>` and `pending_packets: Vec<PendingPacket>`

**Proposed destination**: Eliminated (push directly to NodeCore/Transport)

These drain buffers exist solely because LinkManager is a separate object that cannot call Transport directly. If LinkManager's methods became methods on NodeCore:

1. **Eliminate `LinkEvent`** — link-handling code would emit `NodeEvent` directly (currently every `LinkEvent` is translated 1:1 to a `NodeEvent` in `handle_link_event()`)
2. **Eliminate `PendingPacket`** — link-handling code would call `self.transport.send_on_interface()` directly
3. **Eliminate `ChannelReceiptUpdated`** — this is a purely internal coordination event; the update would happen inline

**Difficulty: Easy** (as a consequence of dissolving LinkManager — these buffers exist solely because LinkManager is a separate object that cannot access Transport directly)

---

### 7. `rx_ring_full_count` / `rx_ring_full_last_log_ms`

**Proposed destination**: NodeCore (diagnostic state)

Trivial counters with no coupling to other state.

**Difficulty: Easy**

---

### Dissolution Summary

| State | Destination | Difficulty | Key Obstacle |
|-------|-------------|------------|--------------|
| `links` | NodeCore | **Hard** | Every method uses it alongside other state; borrow checker conflicts with channels |
| `channels` | `Option<Channel>` on Link | **Medium** | 3-4 methods need refactoring for split borrows between channel and link crypto |
| `pending_outgoing` / `pending_incoming` | Phase data on Link | **Easy** | Pure simplification, no obstacles |
| `data_receipts` + `channel_receipt_keys` | Stay together (NodeCore or dedicated struct) | **Hard** | Global hash-based lookup prevents per-link storage; tight coupling across links+channels |
| `accepted_destinations` | NodeCore (use existing `destinations` map) | **Easy** | Already redundant with NodeCore's `destinations` |
| `events` + `pending_packets` | Eliminated (push directly to NodeCore/Transport) | **Easy** | Exist only because LinkManager cannot access Transport |
| `rx_ring_full_count` / `rx_ring_full_last_log_ms` | NodeCore (diagnostic state) | **Easy** | Trivial counters, no coupling |

### Recommended Staged Approach

1. Move `pending_outgoing`/`pending_incoming` into Link (phase enum)
2. Move `accepted_destinations` to NodeCore's destination lookup
3. Move Channel into Link as `Option<Channel>`
4. Inline event emission (eliminate `LinkEvent`, push `NodeEvent` directly)
5. Inline packet routing (eliminate `PendingPacket`, call Transport directly)
6. What remains is `links` + `data_receipts` + `channel_receipt_keys` + helper methods — effectively a slimmed-down `LinkTable` struct on NodeCore

---

## Part C: Event Cascade Analysis

Complete mapping of TransportEvent -> LinkEvent -> NodeEvent, identifying which translations are 1:1 pass-throughs.

---

### TransportEvent (9 variants)

**Definition**: `reticulum-core/src/transport.rs:309-380`

| # | Variant | Handler (node/mod.rs) | Result | 1:1? |
|---|---------|----------------------|--------|------|
| 1 | `AnnounceReceived` | :887-894 | `NodeEvent::AnnounceReceived` — fields passed through unchanged | Yes |
| 2 | `PacketReceived` | :915-963 | Routes to `link_manager.process_packet()` or `NodeEvent::PacketReceived` — significant branching logic inspecting packet type | **No** |
| 3 | `PathFound` | :897-906 | `NodeEvent::PathFound` — wraps in `DestinationHash::new()` | Yes |
| 4 | `PathLost` | :909-912 | `NodeEvent::PathLost` — wraps in `DestinationHash::new()` | Yes |
| 5 | `PathRequestReceived` | :1002-1007 | `NodeEvent::PathRequestReceived` — wraps in `DestinationHash::new()` | Yes |
| 6 | `InterfaceDown` | :966-967 | `NodeEvent::InterfaceDown` | Yes |
| 7 | `ProofRequested` | :970-977 | `NodeEvent::ProofRequested` — wraps in `DestinationHash::new()` | Yes |
| 8 | `ProofReceived` | :980-992 | `NodeEvent::DeliveryConfirmed` or `NodeEvent::DeliveryFailed` — semantic split based on `is_valid` field | **No** |
| 9 | `ReceiptTimeout` | :995-999 | `NodeEvent::DeliveryFailed` with `DeliveryError::Timeout` — adds typed error discriminant | **No** |

**6 out of 9 TransportEvent variants are 1:1 translations** (with only trivial `DestinationHash::new()` wrapping).

---

### LinkEvent (11 variants)

**Definition**: `reticulum-core/src/link/mod.rs:192-286`

| # | Variant | Handler (node/mod.rs) | Result | 1:1? |
|---|---------|----------------------|--------|------|
| 1 | `LinkRequestReceived` | :1014-1023 | `NodeEvent::ConnectionRequest` — field renaming only | Yes |
| 2 | `LinkEstablished` | :1026-1042 | Creates `Connection` object, inserts into `self.connections`, then `NodeEvent::ConnectionEstablished` | **No** |
| 3 | `DataReceived` | :1045-1046 | `NodeEvent::DataReceived` — fields unchanged | Yes |
| 4 | `LinkStale` | :1063-1064 | `NodeEvent::ConnectionStale` — renamed | Yes |
| 5 | `LinkRecovered` | :1067-1068 | `NodeEvent::ConnectionRecovered` — renamed | Yes |
| 6 | `ChannelMessageReceived` | :1049-1060 | `NodeEvent::MessageReceived` — renamed | Yes |
| 7 | `LinkClosed` | :1071-1100 | Removes connection, path recovery on timeout, then `NodeEvent::ConnectionClosed` | **No** |
| 8 | `DataDelivered` | :1103-1122 | Updates `channel_hash_to_seq`, calls `mark_channel_delivered()`, then `NodeEvent::LinkDeliveryConfirmed` | **No** |
| 9 | `ChannelReceiptUpdated` | :1125-1137 | **No NodeEvent emitted.** Pure internal bookkeeping of hash-to-sequence mappings. | **No** |
| 10 | `ChannelRetransmit` | :1139-1148 | `NodeEvent::ChannelRetransmit` — fields unchanged | Yes |
| 11 | `ProofRequested` | :1151-1160 | `NodeEvent::LinkProofRequested` — renamed | Yes |

**7 out of 11 LinkEvent variants are 1:1 translations.**

---

### Non-Trivial LinkEvent Handlers (4 variants with real logic)

**1. LinkEstablished** (node/mod.rs:1026-1042)
- Creates a `Connection` wrapper in `self.connections`
- Needs access to `self.link_manager.link()` and `self.connections` — both node-layer state

**2. LinkClosed** (node/mod.rs:1071-1100)
- Removes connection state from `self.connections`
- Performs path recovery (expire + re-request) on initiator timeout for non-transport nodes
- Accesses `self.connections`, `self.transport`

**3. DataDelivered** (node/mod.rs:1103-1122)
- Looks up `packet_hash` in `self.channel_hash_to_seq`
- Calls back into `self.link_manager.mark_channel_delivered()` to update channel tx_ring/RTT

**4. ChannelReceiptUpdated** (node/mod.rs:1125-1137)
- Pure internal bookkeeping: updates `self.channel_hash_to_seq` mapping
- **Does not emit any NodeEvent** — exists solely for intra-system coordination

---

### Verdict: Should LinkEvent Be Eliminated?

**No.** Despite 7 of 11 variants being pure translations, the remaining 4 variants encode essential orchestration logic that belongs in the node layer, not the link layer:

- **Connection lifecycle management** (create/destroy `Connection` objects)
- **Cross-subsystem coordination** (path recovery on link timeout via Transport)
- **Channel delivery tracking** (hash-to-sequence mapping, calling back into LinkManager)
- **Internal bookkeeping** with no application-visible equivalent (`ChannelReceiptUpdated`)

Eliminating LinkEvent would either push node-layer responsibilities down into the link layer (violating the Layer 2 / Layer 4 dependency hierarchy), or require LinkManager to accept callbacks/closures for the orchestration side effects (adding complexity without reducing the total code).

The 7 pass-through translations are the cost of clean layering. They are mechanically simple, type-checked at compile time, and serve as explicit documentation of the event flow.

---

### Event Flow Diagram

```
                Transport (Layer 3)
                    |
          TransportEvent (9 variants)
          6 pure pass-through ---------> NodeEvent (to application)
          3 with logic:
            PacketReceived -----------> link_manager.process_packet()
            ProofReceived ------------> DeliveryConfirmed / DeliveryFailed
            ReceiptTimeout -----------> DeliveryFailed(Timeout)
                    |
                    v
              LinkManager (Layer 2)
                    |
           LinkEvent (11 variants)
           7 pure pass-through -------> NodeEvent (to application)
           4 with logic:
             LinkEstablished ---------> create Connection + ConnectionEstablished
             LinkClosed --------------> remove Connection + path recovery + ConnectionClosed
             DataDelivered -----------> channel_hash_to_seq update + mark_delivered + LinkDeliveryConfirmed
             ChannelReceiptUpdated ---> channel_hash_to_seq update (NO NodeEvent)
                    |
                    v
               NodeCore (Layer 4)
                    |
            NodeEvent (19 variants)
                    |
                    v
              Application / Driver
```
