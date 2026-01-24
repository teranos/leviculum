# Chapter 11: Transport Layer

The **Transport** layer is the central coordinator of a Reticulum node. It manages interfaces, routes packets, maintains tables, and connects all the components we've discussed. This chapter explains how it all fits together.

## 11.1 Transport Overview

The Transport instance is responsible for:

- **Interface management**: Adding, removing, and monitoring interfaces
- **Packet routing**: Forwarding packets toward their destinations
- **Table maintenance**: Path table, link table, announce table
- **Destination registry**: Tracking local destinations
- **Deduplication**: Preventing packet loops

```c
typedef struct Transport {
    // Identity
    uint8_t identity_hash[16];
    Identity *identity;

    // Interfaces
    Interface **interfaces;
    size_t interface_count;

    // Tables
    PathTable path_table;
    LinkTable link_table;
    AnnounceTable announce_table;
    ReverseTable reverse_table;
    RateLimiter rate_limiter;

    // Local destinations
    Destination **destinations;
    size_t destination_count;

    // Deduplication
    uint8_t packet_hashes[1024][32];
    size_t packet_hash_count;

    // Configuration
    bool transport_enabled;
    TransportMode mode;
} Transport;

typedef enum {
    TRANSPORT_MODE_BOUNDARY,     // Default - route between interfaces
    TRANSPORT_MODE_ACCESS_POINT, // Shorter path TTL
    TRANSPORT_MODE_ROAMING,      // Very short path TTL
} TransportMode;
```

**Transport modes** affect how long path entries are cached:

| Mode | Path TTL | Use Case |
|------|----------|----------|
| BOUNDARY | 7 days | Fixed infrastructure nodes that route between networks |
| ACCESS_POINT | 2 days | Semi-mobile nodes (e.g., vehicle gateway) |
| ROAMING | 1 hour | Mobile nodes that frequently change location |

Shorter TTLs cause more frequent path rediscovery but handle mobility better.

## 11.2 Packet Flow

### Inbound Packet Processing

When a packet arrives on an interface:

```c
void transport_receive(Transport *t, Interface *iface,
                       const uint8_t *raw, size_t raw_len) {
    // 1. Parse packet
    Packet pkt;
    if (!parse_packet(raw, raw_len, &pkt)) {
        return;  // Invalid packet
    }

    // 2. IFAC verification (if enabled)
    if (iface->ifac_enabled) {
        if (!verify_ifac(&pkt, iface->ifac_key)) {
            return;  // Auth failed
        }
        // Remove IFAC tag from packet
        strip_ifac(&pkt);
    }

    // 3. Deduplication
    uint8_t packet_hash[32];
    compute_packet_hash(&pkt, packet_hash);

    if (is_duplicate(t, packet_hash)) {
        return;  // Already seen
    }
    add_packet_hash(t, packet_hash);

    // 4. Process by packet type
    switch (pkt.packet_type) {
    case PACKET_DATA:
        process_data_packet(t, iface, &pkt, packet_hash);
        break;
    case PACKET_ANNOUNCE:
        process_announce_packet(t, iface, &pkt);
        break;
    case PACKET_LINKREQUEST:
        process_link_request(t, iface, &pkt);
        break;
    case PACKET_PROOF:
        process_proof_packet(t, iface, &pkt);
        break;
    }

    // 5. Consider forwarding
    if (pkt.hops < MAX_HOPS && should_forward(t, &pkt, iface)) {
        pkt.hops++;
        forward_packet(t, &pkt, iface);
    }
}
```

### Outbound Packet Processing

When sending a packet:

```c
bool transport_send(Transport *t, Packet *pkt) {
    // 1. Determine outbound interface(s)
    if (pkt->destination_type == DEST_LINK) {
        // Link packets - use link table
        return send_link_packet(t, pkt);
    }

    // 2. Check path table for route
    PathEntry *path = path_table_lookup(&t->path_table, pkt->destination);

    if (path != NULL && !path_expired(path)) {
        // Known path - use it
        if (path->hops > 0) {
            // Multi-hop: add transport header
            pkt->header_type = 1;  // Header Type 2
            memcpy(pkt->transport, path->next_hop, 16);
        }
        return interface_send(path->interface, pkt);
    }

    // 3. No path - broadcast on all interfaces
    bool sent = false;
    for (size_t i = 0; i < t->interface_count; i++) {
        if (t->interfaces[i]->enabled && t->interfaces[i]->online) {
            if (interface_send(t->interfaces[i], pkt)) {
                sent = true;
            }
        }
    }
    return sent;
}
```

## 11.3 Packet Routing

### Header Type 1 vs Header Type 2

**Header Type 1** (single hop or broadcast):
```
+------+------+-------------+---------+---------+
|Header| Hops | Destination | Context | Payload |
+------+------+-------------+---------+---------+
```

**Header Type 2** (routed through transport):
```
+------+------+-------------+-----------+---------+---------+
|Header| Hops | Destination | Transport | Context | Payload |
+------+------+-------------+-----------+---------+---------+
```

The Transport field contains the next-hop's transport identity hash.

### Forwarding Logic

The forwarding logic handles two fundamentally different cases:

**Header Type 2 (Routed) Packets**: These packets have a specific next-hop address in the Transport field. When a node receives such a packet, it first checks if the Transport field matches its own identity hash—if not, the packet isn't meant for this node to route and is ignored. If it matches, the node looks up the final destination in its path table to determine where to send the packet next. If the path table shows zero remaining hops, the destination is directly reachable, so the node converts the packet to Header Type 1 and sends it directly. Otherwise, it updates the Transport field with the next hop's address and forwards.

**Header Type 1 (Broadcast) Packets**: These packets have no specific route and should be flooded to all interfaces except the one they arrived on. This is how announces propagate and how packets reach destinations when no path is known.

```c
void forward_packet(Transport *t, Packet *pkt, Interface *received_from) {
    if (pkt->header_type == 1) {
        // Header Type 2 - routed packet
        if (memcmp(pkt->transport, t->identity_hash, 16) != 0) {
            // Not for us to route - ignore
            return;
        }

        // We're the next hop - look up path
        PathEntry *path = path_table_lookup(&t->path_table, pkt->destination);
        if (path == NULL) {
            return;  // No path
        }

        if (path->hops == 0) {
            // Direct delivery - convert to Header Type 1
            pkt->header_type = 0;
            interface_send(path->interface, pkt);
        } else {
            // More hops - update transport field
            memcpy(pkt->transport, path->next_hop, 16);
            interface_send(path->interface, pkt);
        }
    } else {
        // Header Type 1 - broadcast
        // Forward on all interfaces except the one it came from
        for (size_t i = 0; i < t->interface_count; i++) {
            Interface *iface = t->interfaces[i];
            if (iface != received_from && iface->enabled && iface->online) {
                interface_send(iface, pkt);
            }
        }
    }
}
```

### Remaining Hops Calculation

```c
int remaining_hops(Transport *t, const uint8_t dest[16]) {
    PathEntry *path = path_table_lookup(&t->path_table, dest);
    if (path == NULL) {
        return -1;  // Unknown
    }
    return path->hops;
}
```

## 11.4 Link Table

The link table tracks established links for routing link packets.

**Why a separate table?** Regular packets are routed using the path table, which maps destination hashes to next-hop interfaces. But link packets are addressed to Link IDs, not destination hashes. A Link ID is computed from the link establishment handshake and doesn't appear in any announce—it's only known to nodes that saw the link request pass through them.

The link table serves two purposes:
1. **Forward routing**: When a node originates a packet on a link, the link table tells it which interface and next hop to use
2. **Reverse routing**: When a link request passes through a node, the node records how to send replies (proofs, data) back to the initiator

Each entry stores both directions: `next_hop_transport`/`next_hop_interface` for outbound packets, and `received_interface`/`taken_hops` for routing proofs back to the initiator.

### Link Table Entry

```c
typedef struct {
    uint8_t link_id[16];         // Key
    uint64_t timestamp;
    uint8_t next_hop_transport[16];
    Interface *next_hop_interface;
    int remaining_hops;
    Interface *received_interface;
    int taken_hops;
    uint8_t destination_hash[16];
    bool validated;
    uint64_t proof_timeout;
} LinkTableEntry;

typedef struct {
    LinkTableEntry entries[2048];
    size_t count;
} LinkTable;
```

### Link Packet Routing

```c
bool send_link_packet(Transport *t, Packet *pkt) {
    // Find link in table
    LinkTableEntry *entry = link_table_lookup(&t->link_table, pkt->destination);

    if (entry == NULL) {
        // Unknown link - broadcast
        for (size_t i = 0; i < t->interface_count; i++) {
            interface_send(t->interfaces[i], pkt);
        }
        return true;
    }

    if (entry->remaining_hops == 0) {
        // Direct delivery
        return interface_send(entry->next_hop_interface, pkt);
    } else {
        // Routed
        pkt->header_type = 1;
        memcpy(pkt->transport, entry->next_hop_transport, 16);
        return interface_send(entry->next_hop_interface, pkt);
    }
}
```

### Link Table Population

```c
void populate_link_table(Transport *t, Packet *link_request,
                         Interface *received_from) {
    // Compute link ID
    uint8_t link_id[16];
    compute_link_id(&link_request->header, link_request->destination,
                    link_request->context,
                    link_request->payload, link_request->payload_len,
                    link_id);

    // Add to link table
    LinkTableEntry *entry = link_table_add(&t->link_table, link_id);

    entry->timestamp = time(NULL);
    memset(entry->next_hop_transport, 0, 16);  // Direct for now
    entry->next_hop_interface = received_from;
    entry->remaining_hops = 0;
    entry->received_interface = received_from;
    entry->taken_hops = link_request->hops;
    memcpy(entry->destination_hash, link_request->destination, 16);
    entry->validated = false;
    entry->proof_timeout = time(NULL) + PROOF_TIMEOUT_PER_HOP * (link_request->hops + 1);
}
```

## 11.5 Reverse Table

The reverse table enables proofs and replies to reach their originators.

**The problem it solves**: When Alice sends a packet that gets forwarded through multiple hops to reach Bob, Bob may need to send a proof back to Alice. But Bob doesn't necessarily know a route to Alice—he only received a packet from the final forwarding node, not directly from Alice.

**The solution**: Each forwarding node remembers where packets came from for a short time (8 minutes). When Bob's proof travels back, each node looks up the original packet's hash in its reverse table and sends the proof back toward wherever the original packet came from.

This creates a breadcrumb trail: the proof follows the original packet's path in reverse, even though no explicit "route to Alice" was ever established. After 8 minutes, the breadcrumbs expire—this is enough time for any reasonable proof to arrive, but not so long that memory fills up with stale entries.

### Reverse Table Entry

```c
#define REVERSE_TIMEOUT 480  // 8 minutes

typedef struct {
    uint8_t packet_hash[32];     // Key
    Interface *received_from;
    Interface *outbound_interface;
    uint64_t timestamp;
} ReverseTableEntry;

typedef struct {
    ReverseTableEntry entries[4096];
    size_t count;
} ReverseTable;
```

### Recording Reverse Path

```c
void record_reverse_path(Transport *t, const uint8_t packet_hash[32],
                         Interface *received_from,
                         Interface *outbound_interface) {
    ReverseTableEntry *entry = reverse_table_add(&t->reverse_table, packet_hash);

    entry->received_from = received_from;
    entry->outbound_interface = outbound_interface;
    entry->timestamp = time(NULL);
}
```

### Using Reverse Path for Proofs

```c
void route_proof(Transport *t, Packet *proof_pkt,
                 const uint8_t original_packet_hash[32]) {
    ReverseTableEntry *entry = reverse_table_lookup(&t->reverse_table,
                                                     original_packet_hash);

    if (entry != NULL && !reverse_expired(entry)) {
        // Route back the way it came
        interface_send(entry->received_from, proof_pkt);
    } else {
        // No reverse path - broadcast
        transport_send(t, proof_pkt);
    }
}
```

## 11.6 Destination Registry

### Registering Destinations

```c
void transport_register_destination(Transport *t, Destination *dest) {
    // Add to destination list
    t->destinations = realloc(t->destinations,
                              (t->destination_count + 1) * sizeof(Destination*));
    t->destinations[t->destination_count++] = dest;

    // If desired, announce immediately
    if (dest->auto_announce) {
        send_announce(t, dest);
    }
}

Destination* transport_find_destination(Transport *t, const uint8_t hash[16]) {
    for (size_t i = 0; i < t->destination_count; i++) {
        if (memcmp(t->destinations[i]->hash, hash, 16) == 0) {
            return t->destinations[i];
        }
    }
    return NULL;
}
```

### Delivering to Local Destinations

```c
void deliver_locally(Transport *t, Packet *pkt, const uint8_t packet_hash[32]) {
    Destination *dest = transport_find_destination(t, pkt->destination);

    if (dest == NULL) {
        return;  // Not for us
    }

    // Decrypt if needed
    uint8_t plaintext[PACKET_MTU];
    size_t plain_len;

    switch (dest->type) {
    case DEST_SINGLE:
        if (!decrypt_single(dest, pkt->payload, pkt->payload_len,
                            plaintext, &plain_len)) {
            return;  // Decryption failed
        }
        break;

    case DEST_GROUP:
        if (!decrypt_group(dest, pkt->payload, pkt->payload_len,
                           plaintext, &plain_len)) {
            return;
        }
        break;

    case DEST_PLAIN:
        memcpy(plaintext, pkt->payload, pkt->payload_len);
        plain_len = pkt->payload_len;
        break;

    default:
        return;
    }

    // Invoke callback
    if (dest->on_packet) {
        dest->on_packet(dest, plaintext, plain_len, packet_hash);
    }
}
```

## 11.7 Table Maintenance

### Periodic Jobs

```c
#define TABLES_CULL_INTERVAL 5  // seconds

void transport_job_loop(Transport *t) {
    static uint64_t last_cull = 0;
    uint64_t now = time(NULL);

    // Cull expired entries
    if (now - last_cull >= TABLES_CULL_INTERVAL) {
        cull_path_table(&t->path_table);
        cull_link_table(&t->link_table);
        cull_reverse_table(&t->reverse_table);
        cull_packet_hashes(t);
        last_cull = now;
    }

    // Process pending announces
    process_announce_retransmissions(t);

    // Process pending link proofs
    process_pending_link_proofs(t);
}
```

### Culling Tables

```c
void cull_path_table(PathTable *pt) {
    uint64_t now = time(NULL);
    size_t write_idx = 0;

    for (size_t i = 0; i < pt->count; i++) {
        if (now < pt->entries[i].expires) {
            if (write_idx != i) {
                pt->entries[write_idx] = pt->entries[i];
            }
            write_idx++;
        }
    }
    pt->count = write_idx;
}

void cull_link_table(LinkTable *lt) {
    uint64_t now = time(NULL);
    uint64_t timeout = LINK_STALE_TIME * 1.25;
    size_t write_idx = 0;

    for (size_t i = 0; i < lt->count; i++) {
        if (now - lt->entries[i].timestamp < timeout) {
            if (write_idx != i) {
                lt->entries[write_idx] = lt->entries[i];
            }
            write_idx++;
        }
    }
    lt->count = write_idx;
}

void cull_reverse_table(ReverseTable *rt) {
    uint64_t now = time(NULL);
    size_t write_idx = 0;

    for (size_t i = 0; i < rt->count; i++) {
        if (now - rt->entries[i].timestamp < REVERSE_TIMEOUT) {
            if (write_idx != i) {
                rt->entries[write_idx] = rt->entries[i];
            }
            write_idx++;
        }
    }
    rt->count = write_idx;
}
```

## 11.8 Interface Management

### Adding Interfaces

```c
void transport_add_interface(Transport *t, Interface *iface) {
    t->interfaces = realloc(t->interfaces,
                            (t->interface_count + 1) * sizeof(Interface*));
    t->interfaces[t->interface_count++] = iface;

    // Set up receive callback
    iface->on_receive = transport_receive_callback;
    iface->transport = t;

    // Start interface
    interface_start(iface);
}
```

### Interface Status

```c
typedef struct {
    char *name;
    bool enabled;
    bool online;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t rx_packets;
} InterfaceStatus;

void get_interface_status(Interface *iface, InterfaceStatus *status) {
    status->name = iface->name;
    status->enabled = iface->enabled;
    status->online = iface->online;
    status->tx_bytes = iface->tx_bytes;
    status->rx_bytes = iface->rx_bytes;
    status->tx_packets = iface->tx_packets;
    status->rx_packets = iface->rx_packets;
}
```

## 11.9 Transport Modes

### Boundary Mode (Default)

Standard routing between interfaces:
- Path TTL: 7 days
- Full mesh participation
- Routes packets for others

### Access Point Mode

For gateways that serve clients:
- Path TTL: 1 day (shorter)
- Optimized for client-server patterns
- Faster path expiration

### Roaming Mode

For mobile nodes:
- Path TTL: 6 hours (very short)
- Frequent path updates
- Handles network changes gracefully

```c
uint64_t get_path_ttl(Transport *t, Interface *iface) {
    switch (t->mode) {
    case TRANSPORT_MODE_ACCESS_POINT:
        return 86400;   // 1 day
    case TRANSPORT_MODE_ROAMING:
        return 21600;   // 6 hours
    default:
        return 604800;  // 7 days
    }
}
```

## 11.10 Deduplication

**Why deduplication is essential**: In a mesh network where packets are broadcast and forwarded by multiple nodes, the same packet can arrive at a node multiple times via different paths. Without deduplication:
- A node would process the same packet repeatedly, wasting CPU
- Forwarding nodes would re-broadcast packets they've already forwarded, creating infinite loops
- The network would quickly become saturated with duplicate traffic

**How it works**: Each node maintains a cache of recently-seen packet hashes. When a packet arrives, the node computes its SHA-256 hash and checks if that hash is in the cache. If found, the packet is silently dropped as a duplicate. If not found, the hash is added to the cache and processing continues.

**Cache sizing**: The cache holds 1024 hashes and uses a FIFO eviction policy—when full, the oldest hash is removed to make room. The 5-minute timeout is a fallback; in practice, the FIFO limit is usually hit first on active networks. The cache size balances memory usage against the risk of false negatives (processing duplicates because the hash was evicted).

### Packet Hash Cache

```c
#define MAX_PACKET_HASHES 1024
#define PACKET_HASH_TIMEOUT 300  // 5 minutes

typedef struct {
    uint8_t hash[32];
    uint64_t timestamp;
} PacketHashEntry;

bool is_duplicate(Transport *t, const uint8_t hash[32]) {
    for (size_t i = 0; i < t->packet_hash_count; i++) {
        if (memcmp(t->packet_hashes[i].hash, hash, 32) == 0) {
            return true;
        }
    }
    return false;
}

void add_packet_hash(Transport *t, const uint8_t hash[32]) {
    if (t->packet_hash_count >= MAX_PACKET_HASHES) {
        // Remove oldest
        memmove(&t->packet_hashes[0], &t->packet_hashes[1],
                (MAX_PACKET_HASHES - 1) * sizeof(PacketHashEntry));
        t->packet_hash_count--;
    }

    memcpy(t->packet_hashes[t->packet_hash_count].hash, hash, 32);
    t->packet_hashes[t->packet_hash_count].timestamp = time(NULL);
    t->packet_hash_count++;
}
```

### Computing Packet Hash

```c
void compute_packet_hash(Packet *pkt, uint8_t hash[32]) {
    // Hash the raw packet data
    sha256(pkt->raw, pkt->raw_len, hash);
}
```

## 11.11 Path Selection

When an announce arrives, should it update the path table? This decision is critical for routing efficiency.

### Selection Criteria

Reticulum uses a simple priority order:

1. **Hop count** (primary): Fewer hops always preferred
2. **Emission timestamp** (secondary): More recent announce wins for equal hops
3. **Path responsiveness** (tertiary): Unresponsive paths can be replaced

```c
bool should_update_path(PathTable *pt, const uint8_t dest[16],
                        int new_hops, uint64_t new_emission_time,
                        const uint8_t *new_random_blob) {
    PathEntry *existing = path_table_lookup(pt, dest);

    if (existing == NULL) {
        return true;  // No existing path - accept
    }

    if (path_expired(existing)) {
        return true;  // Existing path expired - accept
    }

    // Check for replay (same random blob)
    if (is_replay(existing, new_random_blob)) {
        return false;  // Reject replay
    }

    if (new_hops < existing->hops) {
        return true;  // Fewer hops - accept
    }

    if (new_hops == existing->hops) {
        // Equal hops: accept if newer emission time
        return new_emission_time > existing->emission_time;
    }

    // More hops - only accept if:
    // 1. Path marked unresponsive, OR
    // 2. Significantly newer emission time
    if (existing->unresponsive) {
        return true;
    }

    return new_emission_time > existing->emission_time;
}
```

### What Path Selection Does NOT Consider

| Factor | Considered? | Notes |
|--------|-------------|-------|
| Hop count | Yes | Primary criterion |
| Emission timestamp | Yes | Tiebreaker |
| Interface bitrate | No | Used for TX ordering, not routing |
| Link quality (RSSI/SNR) | No | Logged but not used for routing |
| Historical reliability | No | No path quality metrics |
| Geographic distance | No | Not available |
| Latency | No | Would require probing |

### Interface Bitrate Ordering

Interfaces are sorted by bitrate for **transmission priority**, not path selection:

```c
// High-bitrate interfaces transmit announces first
void prioritize_interfaces(Transport *t) {
    qsort(t->interfaces, t->interface_count, sizeof(Interface*),
          compare_by_bitrate_desc);
}
```

This affects announce propagation speed, not which path is chosen.

### Limitations

- **Single path only**: Only one path stored per destination (no multi-path)
- **No load balancing**: All traffic uses the single stored path
- **No quality metrics**: Can't route around congested links
- **Future improvement**: Code comments note "Best would be to have full support for alternative paths"

## 11.12 Complete Transport Loop

```c
void transport_run(Transport *t) {
    while (t->running) {
        // 1. Poll all interfaces for incoming packets
        for (size_t i = 0; i < t->interface_count; i++) {
            interface_poll(t->interfaces[i]);
        }

        // 2. Run periodic jobs
        transport_job_loop(t);

        // 3. Small sleep to prevent busy-waiting
        usleep(1000);  // 1ms
    }
}
```

## 11.12 Putting It All Together

### Complete Packet Journey (Outbound)

```
Application
    |
    v
+-------------------+
| Destination       | Encrypt payload
+-------------------+
    |
    v
+-------------------+
| Transport         | Look up route, build packet
+-------------------+
    |
    v
+-------------------+
| Interface         | HDLC frame, send
+-------------------+
    |
    v
[Physical Medium]
```

### Complete Packet Journey (Inbound)

```
[Physical Medium]
    |
    v
+-------------------+
| Interface         | HDLC deframe, IFAC verify
+-------------------+
    |
    v
+-------------------+
| Transport         | Deduplicate, route, forward
+-------------------+
    |
    v
+-------------------+
| Destination       | Decrypt, deliver
+-------------------+
    |
    v
Application
```

## 11.13 Summary

| Table | Key | Purpose | Timeout |
|-------|-----|---------|---------|
| Path Table | Destination hash | Route to destinations | 7 days / 1 day / 6 hours |
| Link Table | Link ID | Route link packets | STALE_TIME * 1.25 |
| Reverse Table | Packet hash | Route proofs back | 8 minutes |
| Announce Table | Destination hash | Pending retransmissions | Until sent |
| Packet Hashes | Packet hash | Deduplication | 5 minutes |

| Transport Mode | Path TTL | Use Case |
|----------------|----------|----------|
| Boundary | 7 days | Default, full mesh |
| Access Point | 1 day | Gateway nodes |
| Roaming | 6 hours | Mobile nodes |

The Transport layer coordinates:
- **Interfaces**: Physical connections to the network
- **Routing**: Finding paths to destinations
- **Forwarding**: Moving packets toward their destinations
- **Tables**: Maintaining network state
- **Delivery**: Getting packets to local destinations

This completes the core Reticulum protocol documentation. [The remaining chapters cover implementation guidance and testing.](12-implementation.md)
