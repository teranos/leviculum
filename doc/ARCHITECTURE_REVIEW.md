# Architecture Review — Ownership Graph & Hot Path Call Chains

## Part A: Ownership Graph

```
Reticulum                                          reticulum-std/src/reticulum.rs:17
├── config: Config                                 (owned, immutable after init)
└── node: ReticulumNode                            (owned, alias for ReticulumNodeImpl)

ReticulumNodeImpl                                  reticulum-std/src/driver/mod.rs:102
├── inner: Arc<Mutex<StdNodeCore>>                 [shared: Arc<Mutex>]
│   └── StdNodeCore = NodeCore<OsRng, SystemClock, Storage>
│       ├── rng: OsRng                             (owned)
│       ├── transport: Transport<SystemClock, Storage>
│       │   ├── config: TransportConfig
│       │   ├── clock: SystemClock
│       │   ├── _storage: Storage
│       │   ├── identity: Identity                 (THE node identity)
│       │   ├── path_table: BTreeMap<[u8;16], PathEntry>
│       │   ├── path_states: BTreeMap<[u8;16], PathState>
│       │   ├── announce_table: BTreeMap<[u8;16], AnnounceEntry>
│       │   ├── link_table: BTreeMap<[u8;16], LinkEntry>
│       │   ├── reverse_table: BTreeMap<[u8;16], ReverseEntry>
│       │   ├── destinations: BTreeMap<[u8;16], DestinationEntry>
│       │   ├── packet_cache: BTreeMap<[u8;16], u64>
│       │   ├── receipts: BTreeMap<[u8;16], PacketReceipt>
│       │   ├── identity_table: BTreeMap<[u8;16], Identity>
│       │   ├── announce_rate_table: BTreeMap<[u8;16], AnnounceRateEntry>
│       │   ├── announce_cache: BTreeMap<[u8;16], Vec<u8>>
│       │   ├── path_request_tags: VecDeque<[u8;32]>
│       │   ├── path_requests: BTreeMap<[u8;16], u64>
│       │   ├── stats: TransportStats
│       │   ├── events: Vec<TransportEvent>        (drain buffer)
│       │   └── pending_actions: Vec<Action>        (drain buffer)
│       │
│       ├── link_manager: LinkManager
│       │   ├── links: BTreeMap<LinkId, Link>
│       │   │   └── Link
│       │   │       ├── id: LinkId
│       │   │       ├── state: LinkState
│       │   │       ├── ephemeral keys (X25519, Ed25519)
│       │   │       ├── peer keys (optional)
│       │   │       ├── link_key: Option<[u8;64]>
│       │   │       ├── destination_hash: DestinationHash
│       │   │       ├── rtt_us, keepalive, stale timers
│       │   │       ├── proof_strategy: ProofStrategy
│       │   │       └── attached_interface: Option<usize>
│       │   ├── channels: BTreeMap<LinkId, Channel>
│       │   │   └── Channel
│       │   │       ├── tx_ring: VecDeque<OutboundEnvelope>
│       │   │       │   └── OutboundEnvelope
│       │   │       │       ├── envelope: Envelope {msgtype, sequence, data}
│       │   │       │       ├── state: MessageState
│       │   │       │       ├── tries: u8
│       │   │       │       └── sent_at_ms: u64
│       │   │       ├── rx_ring: VecDeque<Option<Envelope>>
│       │   │       ├── window/window_min/window_max: usize
│       │   │       ├── pacing_interval_ms, next_send_at_ms: u64
│       │   │       └── srtt_ms, rttvar_ms: f64
│       │   ├── pending_outgoing: BTreeMap<LinkId, PendingOutgoing>
│       │   ├── pending_incoming: BTreeMap<LinkId, PendingIncoming>
│       │   ├── accepted_destinations: BTreeSet<DestinationHash>
│       │   ├── data_receipts: BTreeMap<[u8;16], DataReceipt>
│       │   ├── channel_receipt_keys: BTreeMap<(LinkId,u16), [u8;16]>
│       │   ├── events: Vec<LinkEvent>             (drain buffer)
│       │   └── pending_packets: Vec<PendingPacket> (drain buffer)
│       │
│       ├── destinations: BTreeMap<DestinationHash, Destination>
│       │   └── Destination
│       │       ├── hash, name_hash, identity
│       │       ├── dest_type, direction, proof_strategy
│       │       └── ratchets: Vec<Ratchet>
│       │
│       ├── connections: BTreeMap<LinkId, Connection>
│       │   └── Connection {link_id, destination_hash, is_initiator, compression_enabled}
│       │
│       ├── events: Vec<NodeEvent>                 (drain buffer)
│       └── channel_hash_to_seq: BTreeMap<[u8;32], u16>
│
├── event_tx/event_rx: mpsc channel for NodeEvent
├── action_dispatch_tx: mpsc::Sender<TickOutput>   (cloned into streams)
├── shutdown_tx: Option<watch::Sender<bool>>
└── runner_handle: Option<JoinHandle<()>>

InterfaceRegistry                                  (owned by event loop task, NOT ReticulumNodeImpl)
└── handles: Vec<InterfaceHandle>
    └── InterfaceHandle
        ├── info: InterfaceInfo {id, name, kind}
        ├── incoming: mpsc::Receiver<IncomingPacket>
        └── outgoing: mpsc::Sender<OutgoingPacket>

ConnectionStream                                   (owned by application, created per connect/accept)
├── link_id: LinkId
├── inner: Arc<Mutex<StdNodeCore>>                 [shared — same Arc]
├── action_dispatch_tx: mpsc::Sender<TickOutput>
└── closed: bool

PacketEndpoint                                     (owned by application, Clone)
├── dest_hash: DestinationHash
├── inner: Arc<Mutex<StdNodeCore>>                 [shared — same Arc]
└── action_dispatch_tx: mpsc::Sender<TickOutput>
```

### Shared ownership — exhaustive list

The **only** shared ownership is the single `Arc<Mutex<StdNodeCore>>`:

| Holder | How acquired |
|--------|-------------|
| `ReticulumNodeImpl.inner` | Original |
| `run_event_loop()` closure | `Arc::clone`, moved into spawned task |
| Each `ConnectionStream` | `Arc::clone`, per connection |
| Each `PacketEndpoint` | `Arc::clone`, per endpoint (also `Clone`) |

All access serialized through one Mutex. No other `Arc`/`Rc`/`RefCell` in protocol state. The entire core is single-owner, `no_std` compatible.

### Parallel maps with same key (LinkId)

Four maps share `LinkId` as key with different lifecycles:

| Map | Created | Removed |
|-----|---------|---------|
| `link_manager.links` | `initiate_with_path` / `handle_link_request` | link close |
| `link_manager.channels` | Lazily on first `channel_send` | link close |
| `link_manager.pending_outgoing/incoming` | `initiate` / `accept` | proof received / RTT received |
| `node.connections` | `connect` / `accept_connection` | link close |

### Duplicate registries

`Transport.destinations` (keyed `[u8;16]`) mirrors `NodeCore.destinations` (keyed `DestinationHash`). The Transport copy stores `DestinationEntry {accepts_links, proof_strategy, identity}` while NodeCore stores the full `Destination`. `register_destination()` at `node/mod.rs:225-243` populates both.

### Key design properties

1. **Single ownership root**: All protocol state is reachable from `NodeCore`. `Transport` and `LinkManager` are owned fields, not shared references.

2. **No cross-references**: `LinkManager` does not hold a reference to `Transport` and vice versa. `NodeCore` mediates all interaction via `process_events_and_actions()`.

3. **Drain buffers for cross-layer communication**: Events flow via drain buffers (`Vec<TransportEvent>`, `Vec<LinkEvent>`, `Vec<PendingPacket>`, `Vec<Action>`) that are consumed and cleared each cycle.

4. **Identity is effectively immutable**: The same logical Identity can exist as multiple structs (in `identity_table` from announces, in `Destination.identity` for local destinations). No consistency issue because Identity fields are never modified after creation.

---

## Part B: Hot Path Call Chains

### Path 1 — Send (application → wire)

```
ConnectionStream::send_bytes()                     stream.rs:120
  ├─ LOCK Arc<Mutex<StdNodeCore>>                  stream.rs:127
  ├─ NodeCore::send_on_connection()                node/mod.rs:622
  │   ├─ connections.get(link_id)                  (BTreeMap lookup)
  │   ├─ link_manager.link(link_id)                (BTreeMap lookup, read-only)
  │   ├─ LinkManager::channel_send()               manager.rs:611
  │   │   ├─ links.get(link_id)                    (read rtt_ms, mdu)
  │   │   ├─ channels.get_or_insert(link_id)       (lazy Channel::new)
  │   │   ├─ Channel::send()                       channel/mod.rs:366
  │   │   │   └─ Channel::send_internal()          channel/mod.rs:401  ⚑ PURE DELEGATION
  │   │   │       ├─ window/pacing checks
  │   │   │       ├─ Envelope::new(), pack()
  │   │   │       └─ push to tx_ring
  │   │   └─ Link::build_data_packet_with_context() link/mod.rs:1411
  │   │       └─ link.encrypt() + assemble wire bytes
  │   ├─ link_manager.register_channel_receipt()
  │   ├─ Transport::send_on_interface()             transport.rs:892
  │   │   └─ push Action::SendPacket to pending_actions
  │   └─ process_events_and_actions()              node/mod.rs:799
  │       └─ drain_actions() → TickOutput
  ├─ UNLOCK
  └─ action_dispatch_tx.send(TickOutput)           stream.rs:133
      └─ Event loop Branch 2                       driver/mod.rs:558
          └─ dispatch_output()                     driver/mod.rs:605
              └─ registry.get_sender(iface).try_send()  → TCP socket
```

**Flags:**
- `data: &[u8]` passes through **4 struct boundaries** unchanged (ConnectionStream → NodeCore → LinkManager → Channel)
- `link_id` passes through **3+ boundaries** unchanged
- `Channel::send()` is **pure delegation** to `send_internal()` (adds only msgtype validation)
- **Lock-and-read** at stream.rs:139: on `PacingDelay`, re-acquires Mutex just to read `core.now_ms()`

### Path 2 — Receive (wire → application)

```
TCP interface task                                 tcp.rs (spawned)
  └─ mpsc::send(IncomingPacket)
Event loop Branch 1 / recv_any()                   driver/mod.rs:478-539
  ├─ LOCK Arc<Mutex<StdNodeCore>>                  driver/mod.rs:531
  ├─ NodeCore::handle_packet()                     node/mod.rs:701
  │   ├─ Transport::process_incoming()             transport.rs:812
  │   │   ├─ Packet::unpack(raw)
  │   │   ├─ dedup, filter, dispatch by type
  │   │   └─ Transport::handle_data()              transport.rs:1584
  │   │       └─ push TransportEvent::PacketReceived
  │   └─ process_events_and_actions()              node/mod.rs:799
  │       ├─ drain transport events
  │       │   └─ handle_transport_event(PacketReceived) node/mod.rs:915
  │       │       └─ LinkManager::process_packet()  manager.rs:676  ⚑ PURE DELEGATION
  │       │           └─ handle_data()              manager.rs:1083
  │       │               ├─ link.decrypt()
  │       │               ├─ Channel::receive()     channel/mod.rs
  │       │               ├─ push LinkEvent::ChannelMessageReceived
  │       │               └─ generate channel proof → PendingPacket::Proof
  │       ├─ drain link events
  │       │   └─ handle_link_event(ChannelMessageReceived) node/mod.rs:1049  ⚑ PURE DELEGATION
  │       │       └─ push NodeEvent::MessageReceived  (1:1 translation)
  │       ├─ send_pending_packets()                (routes proof via attached_interface)
  │       └─ drain_actions() → TickOutput
  ├─ UNLOCK
  └─ dispatch_output()
      ├─ Action::SendPacket (proof) → TCP socket
      └─ event_tx.try_send(NodeEvent::MessageReceived) → application
```

**Flags:**
- `interface_index: usize` passes through **5+ boundaries** unchanged (event loop → NodeCore → Transport → TransportEvent → NodeCore → LinkManager)
- `LinkManager::process_packet()` is **pure delegation** (match dispatcher)
- `handle_link_event(ChannelMessageReceived)` is **pure delegation** (1:1 event translation)

### Path 3 — Proof delivery (proof → mark_delivered)

```
Wire → event loop → LOCK
NodeCore::handle_packet()                          node/mod.rs:701
  └─ Transport::process_incoming()                 transport.rs:812
      └─ handle_proof()                            transport.rs:1419
          └─ falls through to link-addressed proof
              └─ push TransportEvent::PacketReceived
process_events_and_actions()
  └─ handle_transport_event(PacketReceived)        node/mod.rs:915
      └─ LinkManager::process_packet()             manager.rs:676
          └─ handle_proof()                        manager.rs:934
              └─ handle_data_proof()               manager.rs:1011
                  ├─ extract hash, lookup receipt in data_receipts
                  ├─ link.validate_data_proof()
                  └─ push LinkEvent::DataDelivered
  └─ handle_link_event(DataDelivered)              node/mod.rs:1103
      ├─ channel_hash_to_seq.remove(&packet_hash)
      ├─ link_manager.link(&link_id) → rtt_ms
      └─ LinkManager::mark_channel_delivered()     manager.rs:574  ⚑ PURE DELEGATION
          └─ Channel::mark_delivered()             channel/mod.rs:627
              ├─ find in tx_ring by sequence
              ├─ Karn's algorithm → update_srtt()
              ├─ remove from tx_ring
              ├─ adjust_window(true, rtt_ms)
              └─ recalculate_pacing(eff_rtt)       ← v0.5.19 fix
```

**Flags:**
- `LinkManager::mark_channel_delivered()` is **pure delegation** (BTreeMap lookup + delegate)
- `sequence: u16` passes through **3 boundaries** (NodeCore → LinkManager → Channel)
- `rtt_ms: u64` passes through **3 boundaries** unchanged (read from Link at NodeCore, passed through LinkManager to Channel)

### Path 4 — Poll/timeout (timer → retransmit)

```
Event loop Branch 3: timer fires                   driver/mod.rs:567
  ├─ LOCK Arc<Mutex<StdNodeCore>>                  driver/mod.rs:569
  ├─ NodeCore::handle_timeout()                    node/mod.rs:719
  │   ├─ transport.poll()                          (announce rebroadcast, table cleanup)
  │   ├─ LinkManager::poll()                       manager.rs:713
  │   │   ├─ check_timeouts()                      (pending link expiry)
  │   │   ├─ check_keepalives()
  │   │   ├─ check_stale_links()
  │   │   └─ check_channel_timeouts()              manager.rs:1502
  │   │       ├─ for each (link_id, channel):
  │   │       │   ├─ links.get(link_id) → rtt_ms
  │   │       │   └─ Channel::poll()               channel/mod.rs:676
  │   │       │       ├─ effective_rtt_ms(rtt_ms)
  │   │       │       ├─ check each tx_ring entry timeout
  │   │       │       ├─ increment tries, update sent_at_ms
  │   │       │       ├─ produce ChannelAction::Retransmit
  │   │       │       ├─ adjust_window(false, rtt_ms)
  │   │       │       ├─ recalculate_pacing(eff_rtt)  ← v0.5.19 fix
  │   │       │       └─ multiplicative decrease on pacing
  │   │       └─ link.build_data_packet_with_context()  (re-encrypt)
  │   │           → push PendingPacket::Channel
  │   └─ process_events_and_actions()
  │       └─ send_pending_packets() → transport.send_on_interface()
  │           → Action::SendPacket
  ├─ UNLOCK
  ├─ dispatch_output()                             → TCP socket
  ├─ LOCK AGAIN                                    driver/mod.rs:580  ⚑ LOCK-AND-READ
  │   ├─ core.next_deadline()
  │   └─ core.transport().clock().now_ms()
  └─ UNLOCK
```

**Flags:**
- **Lock-and-read** at driver/mod.rs:580-585: After `handle_timeout()` releases the Mutex, it's immediately re-acquired solely to read `next_deadline()` and `now_ms()`. These two locks could be combined.
- `now_ms: u64` passes through **4 boundaries** (NodeCore → LinkManager::poll → check_channel_timeouts → Channel::poll)
- `rng: &mut R` passes through **4 boundaries** (only used deep inside for `build_data_packet_with_context`)

### Path 5 — Link establishment (request → link ready)

```
═══ INITIATOR SIDE ═══
ReticulumNodeImpl::connect()                       driver/mod.rs:281
  ├─ LOCK
  ├─ NodeCore::connect()                           node/mod.rs:319
  │   ├─ transport.path() → next_hop, hops
  │   ├─ LinkManager::initiate_with_path()         manager.rs:215
  │   │   ├─ Link::new_outgoing(dest_hash, rng)    link/mod.rs:451
  │   │   ├─ link.build_link_request_packet_with_transport()
  │   │   ├─ link.set_destination_keys()
  │   │   └─ store in pending_outgoing + links
  │   ├─ Connection::new() → store in connections
  │   ├─ transport.send_to_destination() or send_on_all_interfaces()
  │   └─ process_events_and_actions() → TickOutput
  ├─ UNLOCK
  ├─ action_dispatch_tx.send(TickOutput) → wire
  └─ return ConnectionStream::new(link_id, Arc::clone(inner), ...)

    ──── link request travels through network ────

═══ RESPONDER SIDE ═══
handle_packet() → Transport::process_incoming()
  └─ handle_link_request()                         transport.rs:1319
      └─ push TransportEvent::PacketReceived
handle_transport_event() → LinkManager::process_packet()
  └─ handle_link_request()                         manager.rs:883
      ├─ check accepted_destinations
      ├─ Link::new_incoming()                      link/mod.rs:504
      ├─ link.set_attached_interface()
      └─ push LinkEvent::LinkRequestReceived
handle_link_event(LinkRequestReceived)             node/mod.rs:1014  ⚑ PURE DELEGATION
  └─ push NodeEvent::ConnectionRequest             (1:1 translation)

    ──── application calls accept_connection() ────

ReticulumNodeImpl::accept_connection()             driver/mod.rs:312
  ├─ LOCK
  ├─ NodeCore::accept_connection()                 node/mod.rs:382
  │   ├─ link_manager.link() → dest_hash
  │   ├─ look up identity from registered destination
  │   ├─ LinkManager::accept_link()                manager.rs:280
  │   │   ├─ link.build_proof_packet(identity, ...)
  │   │   └─ store in pending_incoming
  │   ├─ Connection::new() → store in connections
  │   └─ transport.send_on_interface() → proof packet
  ├─ UNLOCK → proof travels to initiator

═══ INITIATOR RECEIVES PROOF ═══
handle_packet() → Transport::handle_proof()
  └─ falls through → TransportEvent::PacketReceived
handle_transport_event() → LinkManager::process_packet()
  └─ handle_proof()                                manager.rs:934
      ├─ link.process_proof() — verify sig, X25519 DH, derive link_key
      ├─ compute RTT from pending_outgoing timestamp
      ├─ link.mark_established()
      ├─ link.build_rtt_packet() → PendingPacket::Rtt
      └─ push LinkEvent::LinkEstablished {is_initiator: true}

    ──── RTT packet travels to responder ────

═══ RESPONDER RECEIVES RTT ═══
handle_data() — Lrrtt context                      manager.rs:1098
  ├─ link.process_rtt() — decrypt, extract RTT float
  ├─ link.mark_established()
  └─ push LinkEvent::LinkEstablished {is_initiator: false}

═══ BOTH SIDES: LinkState::Active, NodeEvent::ConnectionEstablished ═══
```

**Flags:**
- `handle_link_event(LinkRequestReceived)` is **pure delegation** (1:1 event translation)
- `dest_signing_key: &[u8;32]` passes through **3 boundaries** unchanged (ReticulumNode → NodeCore → LinkManager → Link)

---

## Summary of Flagged Patterns

### Pure Delegation (5 instances)

| Location | Method | What it delegates to |
|----------|--------|---------------------|
| `channel/mod.rs:366` | `Channel::send()` | `send_internal()` (adds only msgtype validation) |
| `manager.rs:676` | `LinkManager::process_packet()` | `handle_link_request/proof/data` (pure match dispatcher) |
| `manager.rs:574` | `LinkManager::mark_channel_delivered()` | `Channel::mark_delivered()` (BTreeMap lookup + delegate) |
| `node/mod.rs:1014` | `handle_link_event(LinkRequestReceived)` | 1:1 → `NodeEvent::ConnectionRequest` |
| `node/mod.rs:1049` | `handle_link_event(ChannelMessageReceived)` | 1:1 → `NodeEvent::MessageReceived` |

### Pass-Through Data (6 instances)

| Parameter | Boundaries | Path |
|-----------|-----------|------|
| `data: &[u8]` | 4 | ConnectionStream → NodeCore → LinkManager → Channel |
| `link_id: &LinkId` | 3+ | ConnectionStream → NodeCore → LinkManager → Channel lookup |
| `now_ms: u64` | 4 | NodeCore → LinkManager::poll → check_channel_timeouts → Channel::poll |
| `rng: &mut R` | 4 | NodeCore → LinkManager::poll → check_channel_timeouts → build_data_packet |
| `interface_index: usize` | 5 | event loop → NodeCore → Transport → TransportEvent → NodeCore → LinkManager |
| `dest_signing_key` | 3 | ReticulumNode → NodeCore → LinkManager → Link |

### Lock-and-Read (3 instances)

| Location | What is read |
|----------|-------------|
| `stream.rs:139` | `core.now_ms()` — single u64 on PacingDelay retry |
| `driver/mod.rs:580-585` | `next_deadline()` + `now_ms()` after handle_timeout (second lock could be combined) |
| `driver/mod.rs:348-468` | 6 one-liner accessors (`has_path`, `hops_to`, `path_count`, `transport_stats`, `connection_stats`, `is_transport_enabled`) |
