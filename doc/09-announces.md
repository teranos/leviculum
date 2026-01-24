# Chapter 9: Announces and Path Discovery

Reticulum networks are self-configuring. Nodes discover each other through **announces** - broadcast packets that advertise destination availability. This chapter covers the announce system and path discovery.

## 9.1 The Discovery Problem

In a mesh network, how does node A find node G?

```
    [A]----[B]----[C]
     |      |      |
    [D]----[E]----[F]
     |      |      |
    [G]----[H]----[I]
```

Without central coordination, nodes must:
1. Advertise their existence
2. Learn about other nodes
3. Build routing tables
4. Forward packets toward destinations

Reticulum solves this with **announces** and a **path table**.

## 9.2 Announce Packet Structure

An announce broadcasts a destination's identity to the network.

### Packet Layout

```
+------+------+-------------+---------+------------------+
|Header| Hops | Destination | Context | Announce Data    |
| 0x01 | 1B   | 16B         | varies  | variable         |
+------+------+-------------+---------+------------------+

Header 0x01 = BROADCAST + Header1 + SINGLE + ANNOUNCE
```

### Announce Data Structure (Without Ratchet)

```
+-------------+-----------+-------------+-----------+----------+
| Public Key  | Name Hash | Random Hash | Signature | App Data |
| 64 bytes    | 10 bytes  | 10 bytes    | 64 bytes  | variable |
+-------------+-----------+-------------+-----------+----------+

Minimum size: 148 bytes
```

### Announce Data Structure (With Ratchet)

```
+-------------+-----------+-------------+---------+-----------+----------+
| Public Key  | Name Hash | Random Hash | Ratchet | Signature | App Data |
| 64 bytes    | 10 bytes  | 10 bytes    | 32 bytes| 64 bytes  | variable |
+-------------+-----------+-------------+---------+-----------+----------+

Minimum size: 180 bytes
```

### Field Descriptions

| Field | Size | Description |
|-------|------|-------------|
| Public Key | 64 bytes | X25519 (32B) + Ed25519 (32B) public keys |
| Name Hash | 10 bytes | Truncated hash of application name |
| Random Hash | 10 bytes | 5 random bytes + 5-byte timestamp |
| Ratchet | 32 bytes | Optional forward secrecy ratchet public key |
| Signature | 64 bytes | Ed25519 signature |
| App Data | Variable | Application-specific data |

**Ratchet key**: When present, the ratchet field contains an X25519 public key used for forward secrecy on single-packet communication. Senders encrypt to this ratchet key instead of the static identity key. The destination periodically rotates ratchet keys (default: every 30 minutes) and deletes old ones. This ensures that compromise of the static identity key doesn't expose past messages. Ratchet support is optional and indicated by the context flag in the announce packet. See [Chapter 5.10](05-destinations.md#510-ratchets-optional-forward-secrecy) for usage and [Appendix A.8](appendix-a-security.md#a8-ratchet-based-forward-secrecy) for the full cryptographic details.

## 9.3 Random Hash Structure

The random hash serves two purposes: replay prevention and timing.

```
Random Hash (10 bytes):
+----------------+------------------+
| Random Data    | Emission Time    |
| 5 bytes        | 5 bytes (big-endian) |
+----------------+------------------+
```

### Encoding

```c
void create_random_hash(uint8_t random_hash[10]) {
    // 5 random bytes
    randombytes_buf(random_hash, 5);

    // 5-byte Unix timestamp (big-endian)
    uint64_t now = (uint64_t)time(NULL);
    random_hash[5] = (now >> 32) & 0xFF;
    random_hash[6] = (now >> 24) & 0xFF;
    random_hash[7] = (now >> 16) & 0xFF;
    random_hash[8] = (now >> 8) & 0xFF;
    random_hash[9] = now & 0xFF;
}
```

### Decoding

```c
uint64_t extract_emission_time(const uint8_t random_hash[10]) {
    return ((uint64_t)random_hash[5] << 32) |
           ((uint64_t)random_hash[6] << 24) |
           ((uint64_t)random_hash[7] << 16) |
           ((uint64_t)random_hash[8] << 8) |
           ((uint64_t)random_hash[9]);
}
```

## 9.4 Creating Announces

### Signed Data

The signature covers more than what's transmitted:

```
Signed Data:
+------------------+--------------+-----------+-------------+---------+----------+
| Destination Hash | Public Key   | Name Hash | Random Hash | Ratchet | App Data |
| 16 bytes         | 64 bytes     | 10 bytes  | 10 bytes    | 0/32B   | variable |
+------------------+--------------+-----------+-------------+---------+----------+
```

Note: The destination hash is included in signed data but NOT in the transmitted announce data.

### Implementation

```c
typedef struct {
    uint8_t public_key[64];     // X25519 + Ed25519
    uint8_t name_hash[10];
    uint8_t random_hash[10];
    uint8_t ratchet[32];        // Optional
    bool has_ratchet;
    uint8_t signature[64];
    uint8_t *app_data;
    size_t app_data_len;
} AnnounceData;

size_t create_announce(Destination *dest,
                       const uint8_t *app_data, size_t app_data_len,
                       bool include_ratchet,
                       uint8_t *output, size_t max_len) {
    AnnounceData ann;

    // 1. Copy public keys
    memcpy(&ann.public_key[0], dest->identity->x25519_pub, 32);
    memcpy(&ann.public_key[32], dest->identity->ed25519_pub, 32);

    // 2. Compute name hash (truncated to 10 bytes)
    uint8_t full_name_hash[32];
    sha256((uint8_t*)dest->app_name, strlen(dest->app_name), full_name_hash);
    memcpy(ann.name_hash, full_name_hash, 10);

    // 3. Create random hash
    create_random_hash(ann.random_hash);

    // 4. Optional ratchet
    ann.has_ratchet = include_ratchet;
    if (include_ratchet) {
        generate_ratchet_key(ann.ratchet);
    }

    // 5. Build signed data
    uint8_t signed_data[256];
    size_t signed_len = 0;

    // Destination hash (NOT transmitted, but signed)
    memcpy(&signed_data[signed_len], dest->hash, 16);
    signed_len += 16;

    // Public key
    memcpy(&signed_data[signed_len], ann.public_key, 64);
    signed_len += 64;

    // Name hash
    memcpy(&signed_data[signed_len], ann.name_hash, 10);
    signed_len += 10;

    // Random hash
    memcpy(&signed_data[signed_len], ann.random_hash, 10);
    signed_len += 10;

    // Ratchet (if present)
    if (ann.has_ratchet) {
        memcpy(&signed_data[signed_len], ann.ratchet, 32);
        signed_len += 32;
    }

    // App data
    if (app_data && app_data_len > 0) {
        memcpy(&signed_data[signed_len], app_data, app_data_len);
        signed_len += app_data_len;
    }

    // 6. Sign
    crypto_sign_detached(ann.signature, NULL,
                         signed_data, signed_len,
                         dest->identity->ed25519_priv);

    // 7. Build output (transmitted data)
    size_t offset = 0;

    memcpy(&output[offset], ann.public_key, 64);
    offset += 64;

    memcpy(&output[offset], ann.name_hash, 10);
    offset += 10;

    memcpy(&output[offset], ann.random_hash, 10);
    offset += 10;

    if (ann.has_ratchet) {
        memcpy(&output[offset], ann.ratchet, 32);
        offset += 32;
    }

    memcpy(&output[offset], ann.signature, 64);
    offset += 64;

    if (app_data && app_data_len > 0) {
        memcpy(&output[offset], app_data, app_data_len);
        offset += app_data_len;
    }

    return offset;
}
```

### Sending the Announce

```c
void send_announce(Transport *transport, Destination *dest,
                   const uint8_t *app_data, size_t app_data_len) {
    uint8_t announce_data[500];
    size_t announce_len = create_announce(dest, app_data, app_data_len,
                                          false, announce_data, sizeof(announce_data));

    Packet pkt = {
        .destination_type = DEST_SINGLE,
        .packet_type = PACKET_ANNOUNCE,
        .hops = 0,
    };
    memcpy(pkt.destination, dest->hash, 16);
    pkt.context = 0x00;  // FLAG_UNSET (no ratchet)
    pkt.payload = announce_data;
    pkt.payload_len = announce_len;

    transport_send(transport, &pkt);
}
```

## 9.5 Validating Announces

When an announce arrives, the receiver must verify it's authentic and not a replay. This involves several steps, each preventing a different type of attack.

### Verification Overview

1. **Size check**: Reject truncated or malformed announces
2. **Extract fields**: Parse the announce structure
3. **Compute identity hash**: Derive from the announced public keys
4. **Compute destination hash**: Combine name hash with identity hash
5. **Verify destination hash matches**: Ensures the announce is for the claimed destination
6. **Reconstruct signed data**: Include the (non-transmitted) destination hash
7. **Verify signature**: Confirms the sender holds the private key

**Why verify the destination hash?** An attacker might try to announce a valid identity for a different destination (e.g., redirect traffic to a popular service). By verifying the destination hash matches what we'd compute from the announce data, we ensure the announce is for the destination it claims.

**Why reconstruct signed data?** The signature covers data that isn't fully transmitted (the destination hash). We must reconstruct this data identically to how the sender built it.

### Verification Steps

```c
bool validate_announce(const uint8_t dest_hash[16],
                       uint8_t context,
                       const uint8_t *data, size_t data_len,
                       Identity *identity_out) {
    // 1. Check minimum size
    bool has_ratchet = (context == 0x01);  // FLAG_SET
    size_t min_size = has_ratchet ? 180 : 148;
    if (data_len < min_size) {
        return false;
    }

    // 2. Extract components
    size_t offset = 0;

    uint8_t public_key[64];
    memcpy(public_key, &data[offset], 64);
    offset += 64;

    uint8_t name_hash[10];
    memcpy(name_hash, &data[offset], 10);
    offset += 10;

    uint8_t random_hash[10];
    memcpy(random_hash, &data[offset], 10);
    offset += 10;

    uint8_t ratchet[32];
    if (has_ratchet) {
        memcpy(ratchet, &data[offset], 32);
        offset += 32;
    }

    uint8_t signature[64];
    memcpy(signature, &data[offset], 64);
    offset += 64;

    const uint8_t *app_data = &data[offset];
    size_t app_data_len = data_len - offset;

    // 3. Verify destination hash derivation
    uint8_t identity_hash[16];
    {
        uint8_t full_hash[32];
        sha256(public_key, 64, full_hash);
        memcpy(identity_hash, full_hash, 16);
    }

    uint8_t expected_dest[16];
    {
        uint8_t to_hash[26];  // name_hash(10) + identity_hash(16)
        memcpy(to_hash, name_hash, 10);
        memcpy(&to_hash[10], identity_hash, 16);

        uint8_t full_hash[32];
        sha256(to_hash, 26, full_hash);
        memcpy(expected_dest, full_hash, 16);
    }

    if (memcmp(expected_dest, dest_hash, 16) != 0) {
        return false;  // Destination hash mismatch
    }

    // 4. Reconstruct signed data
    uint8_t signed_data[512];
    size_t signed_len = 0;

    memcpy(&signed_data[signed_len], dest_hash, 16);
    signed_len += 16;

    memcpy(&signed_data[signed_len], public_key, 64);
    signed_len += 64;

    memcpy(&signed_data[signed_len], name_hash, 10);
    signed_len += 10;

    memcpy(&signed_data[signed_len], random_hash, 10);
    signed_len += 10;

    if (has_ratchet) {
        memcpy(&signed_data[signed_len], ratchet, 32);
        signed_len += 32;
    }

    if (app_data_len > 0) {
        memcpy(&signed_data[signed_len], app_data, app_data_len);
        signed_len += app_data_len;
    }

    // 5. Verify signature
    uint8_t ed25519_pub[32];
    memcpy(ed25519_pub, &public_key[32], 32);

    if (crypto_sign_verify_detached(signature, signed_data, signed_len,
                                    ed25519_pub) != 0) {
        return false;  // Invalid signature
    }

    // 6. Output identity
    if (identity_out) {
        memcpy(identity_out->x25519_pub, public_key, 32);
        memcpy(identity_out->ed25519_pub, &public_key[32], 32);
        memcpy(identity_out->address_hash, identity_hash, 16);
    }

    return true;
}
```

## 9.6 The Path Table

The path table stores routes to known destinations.

### Path Entry Structure

```c
#define MAX_RANDOM_BLOBS 64

typedef struct {
    uint8_t destination[16];     // Key
    uint64_t timestamp;          // Last update time
    uint8_t next_hop[16];        // Next hop transport ID
    uint8_t hops;                // Hop count
    uint64_t expires;            // Expiration timestamp
    uint8_t random_blobs[MAX_RANDOM_BLOBS][10];  // Anti-replay
    size_t random_blob_count;
    Interface *interface;        // Receiving interface
} PathEntry;

typedef struct {
    PathEntry entries[4096];
    size_t count;
} PathTable;
```

### Path Expiration Times

| Mode | Expiration |
|------|------------|
| Default | 7 days (604,800 seconds) |
| Access Point | 1 day (86,400 seconds) |
| Roaming | 6 hours (21,600 seconds) |

### Path Table Operations

**Lookup**: O(n) linear search. For most deployments with hundreds to thousands of paths, this is acceptable. High-performance implementations could use a hash table.

**Update logic**: When an announce arrives for a known destination:
- Update the path (next hop, hop count, interface)
- Store the random blob for replay detection
- Reset the expiration timer

**Random blob storage**: We store up to 64 random blobs per destination. Why?
- Announces propagate through multiple paths
- The same announce (same random blob) may arrive via different routes
- We need to reject duplicates without rejecting legitimate path updates
- 64 blobs provides a reasonable window for multi-path propagation

**Culling**: Periodically remove expired entries. The compaction algorithm preserves array ordering while removing gaps.

```c
PathEntry* path_table_lookup(PathTable *table, const uint8_t dest[16]) {
    for (size_t i = 0; i < table->count; i++) {
        if (memcmp(table->entries[i].destination, dest, 16) == 0) {
            return &table->entries[i];
        }
    }
    return NULL;
}

void path_table_update(PathTable *table,
                       const uint8_t dest[16],
                       const uint8_t next_hop[16],
                       uint8_t hops,
                       const uint8_t random_blob[10],
                       Interface *interface) {
    PathEntry *entry = path_table_lookup(table, dest);

    if (entry == NULL) {
        // New entry
        entry = &table->entries[table->count++];
        memcpy(entry->destination, dest, 16);
        entry->random_blob_count = 0;
    }

    entry->timestamp = time(NULL);
    memcpy(entry->next_hop, next_hop, 16);
    entry->hops = hops;
    entry->expires = entry->timestamp + get_path_ttl(interface);
    entry->interface = interface;

    // Add random blob
    if (entry->random_blob_count < MAX_RANDOM_BLOBS) {
        memcpy(entry->random_blobs[entry->random_blob_count], random_blob, 10);
        entry->random_blob_count++;
    }
}

void path_table_cull(PathTable *table) {
    uint64_t now = time(NULL);
    size_t write_idx = 0;

    for (size_t i = 0; i < table->count; i++) {
        if (now < table->entries[i].expires) {
            if (write_idx != i) {
                table->entries[write_idx] = table->entries[i];
            }
            write_idx++;
        }
    }
    table->count = write_idx;
}
```

## 9.7 Announce Processing

When an announce arrives, the transport layer must decide whether to:
1. Accept it and update the path table
2. Reject it (invalid, replay, or rate-limited)
3. Retransmit it to other interfaces

**Decision tree:**

```
Announce received
    │
    ├─ Validate signature → FAIL → Drop
    │
    ├─ Check replay (random blob seen?) → YES → Drop
    │
    ├─ Check rate limit → EXCEEDED → Drop
    │
    ├─ Existing path?
    │   ├─ NO → Add new path, schedule retransmit
    │   └─ YES → Compare paths
    │       ├─ New path better (fewer hops or newer) → Update, retransmit
    │       └─ Existing path better → Drop (don't retransmit)
    │
    └─ Store identity for future use
```

**Path comparison**: When we have an existing path, prefer:
1. Fewer hops (shorter paths are more reliable)
2. Among equal hop counts, prefer newer announces (fresher information)

This ensures the network converges on good paths without flooding with redundant announces.

```c
void process_announce(Transport *transport, Packet *pkt, Interface *interface) {
    // 1. Validate announce
    Identity identity;
    if (!validate_announce(pkt->destination, pkt->context,
                           pkt->payload, pkt->payload_len, &identity)) {
        return;  // Invalid announce
    }

    // 2. Extract random blob
    uint8_t random_blob[10];
    memcpy(random_blob, &pkt->payload[64 + 10], 10);

    // 3. Check for replay
    PathEntry *existing = path_table_lookup(&transport->path_table, pkt->destination);
    if (existing) {
        if (is_replay(existing, random_blob)) {
            return;  // Replay attack
        }
    }

    // 4. Decide whether to update path
    bool should_update = false;

    if (existing == NULL) {
        // New destination
        should_update = true;
    } else if (pkt->hops < existing->hops) {
        // Better path (fewer hops)
        should_update = true;
    } else if (pkt->hops == existing->hops) {
        // Same hop count - check emission time
        uint64_t new_time = extract_emission_time(random_blob);
        uint64_t old_time = extract_emission_time(existing->random_blobs[0]);
        if (new_time > old_time) {
            should_update = true;
        }
    } else if (time(NULL) > existing->expires) {
        // Existing path expired
        should_update = true;
    }

    // 5. Update path table
    if (should_update) {
        // For announces, next_hop is the sending interface's identity
        // (or NULL for direct announces)
        uint8_t next_hop[16] = {0};
        if (pkt->hops > 0) {
            // Multi-hop: use interface's transport identity
            memcpy(next_hop, interface->transport_id, 16);
        }

        path_table_update(&transport->path_table,
                          pkt->destination,
                          next_hop,
                          pkt->hops,
                          random_blob,
                          interface);

        // Cache identity
        identity_cache_add(&transport->identity_cache,
                           pkt->destination, &identity);
    }

    // 6. Check rate limiting before retransmission
    if (!check_announce_rate(transport, pkt->destination)) {
        return;  // Rate limited
    }

    // 7. Retransmit announce (propagation)
    if (pkt->hops < MAX_HOPS) {
        schedule_announce_retransmit(transport, pkt, interface);
    }
}

bool is_replay(PathEntry *entry, const uint8_t random_blob[10]) {
    for (size_t i = 0; i < entry->random_blob_count; i++) {
        if (memcmp(entry->random_blobs[i], random_blob, 10) == 0) {
            return true;
        }
    }
    return false;
}
```

## 9.8 Announce Rate Limiting

To prevent network flooding, announces are rate-limited per destination.

### Rate Limiter Structure

```c
#define MAX_RATE_TIMESTAMPS 16

typedef struct {
    uint8_t destination[16];
    uint64_t last_announce;
    uint64_t timestamps[MAX_RATE_TIMESTAMPS];
    size_t timestamp_count;
    int rate_violations;
    uint64_t blocked_until;
} RateEntry;

typedef struct {
    RateEntry entries[1024];
    size_t count;
    uint64_t rate_target;      // Minimum seconds between announces
    int rate_grace;            // Violations before blocking
    uint64_t rate_penalty;     // Penalty seconds
} RateLimiter;
```

### Rate Checking

```c
bool check_announce_rate(Transport *transport, const uint8_t dest[16]) {
    RateLimiter *rl = &transport->rate_limiter;
    uint64_t now = time(NULL);

    // Find or create entry
    RateEntry *entry = NULL;
    for (size_t i = 0; i < rl->count; i++) {
        if (memcmp(rl->entries[i].destination, dest, 16) == 0) {
            entry = &rl->entries[i];
            break;
        }
    }

    if (entry == NULL) {
        // New destination - allow
        entry = &rl->entries[rl->count++];
        memcpy(entry->destination, dest, 16);
        entry->last_announce = now;
        entry->rate_violations = 0;
        entry->blocked_until = 0;
        entry->timestamp_count = 0;
        return true;
    }

    // Check if blocked
    if (now < entry->blocked_until) {
        return false;
    }

    // Check rate
    uint64_t elapsed = now - entry->last_announce;

    if (elapsed < rl->rate_target) {
        // Too fast
        entry->rate_violations++;

        if (entry->rate_violations > rl->rate_grace) {
            // Block
            entry->blocked_until = entry->last_announce +
                                   rl->rate_target +
                                   rl->rate_penalty;
            return false;
        }
    } else {
        // Rate OK - decay violations
        if (entry->rate_violations > 0) {
            entry->rate_violations--;
        }
    }

    // Update tracking
    entry->last_announce = now;

    // Add to timestamp history
    if (entry->timestamp_count < MAX_RATE_TIMESTAMPS) {
        entry->timestamps[entry->timestamp_count++] = now;
    } else {
        // Shift and add
        memmove(entry->timestamps, &entry->timestamps[1],
                (MAX_RATE_TIMESTAMPS - 1) * sizeof(uint64_t));
        entry->timestamps[MAX_RATE_TIMESTAMPS - 1] = now;
    }

    return true;
}
```

## 9.9 Announce Retransmission

Announces propagate through the network via retransmission.

### Announce Table

```c
typedef struct {
    uint8_t destination[16];
    uint64_t timestamp;
    uint64_t retransmit_at;
    int retries_remaining;
    Interface *received_from;
    uint8_t hops;
    Packet packet;
    int local_rebroadcasts;
    bool block_rebroadcast;
} AnnounceEntry;

typedef struct {
    AnnounceEntry entries[256];
    size_t count;
} AnnounceTable;
```

### Scheduling Retransmission

```c
#define PATHFINDER_R 1          // Number of retries
#define PATHFINDER_RW 0.5       // Random window (seconds)
#define LOCAL_REBROADCASTS_MAX 2

void schedule_announce_retransmit(Transport *transport,
                                  Packet *pkt,
                                  Interface *received_from) {
    AnnounceTable *at = &transport->announce_table;

    // Check if already scheduled
    for (size_t i = 0; i < at->count; i++) {
        if (memcmp(at->entries[i].destination, pkt->destination, 16) == 0) {
            return;  // Already pending
        }
    }

    // Add to table
    AnnounceEntry *entry = &at->entries[at->count++];
    memcpy(entry->destination, pkt->destination, 16);
    entry->timestamp = time(NULL);
    entry->retries_remaining = PATHFINDER_R;
    entry->received_from = received_from;
    entry->hops = pkt->hops;
    entry->packet = *pkt;  // Copy packet
    entry->local_rebroadcasts = 0;
    entry->block_rebroadcast = false;

    // Random delay
    double delay = (double)rand() / RAND_MAX * PATHFINDER_RW;
    entry->retransmit_at = entry->timestamp + (uint64_t)(delay * 1000);
}
```

### Processing Retransmissions

```c
void process_announce_retransmissions(Transport *transport) {
    AnnounceTable *at = &transport->announce_table;
    uint64_t now = time(NULL);

    for (size_t i = 0; i < at->count; ) {
        AnnounceEntry *entry = &at->entries[i];

        if (now >= entry->retransmit_at) {
            if (entry->retries_remaining > 0 && !entry->block_rebroadcast) {
                // Retransmit
                entry->packet.hops++;
                retransmit_announce(transport, entry);
                entry->retries_remaining--;

                // Schedule next retry
                double delay = (double)rand() / RAND_MAX * PATHFINDER_RW;
                entry->retransmit_at = now + (uint64_t)(delay * 1000);
                i++;
            } else {
                // Done - remove from table
                at->entries[i] = at->entries[--at->count];
                // Don't increment i
            }
        } else {
            i++;
        }
    }
}

void retransmit_announce(Transport *transport, AnnounceEntry *entry) {
    // Send on all interfaces except the one it came from
    for (size_t i = 0; i < transport->interface_count; i++) {
        Interface *iface = transport->interfaces[i];

        if (iface != entry->received_from && iface->enabled) {
            interface_send(iface, &entry->packet);
        }
    }
}
```

## 9.10 Path Resolution

When sending to a destination, use the path table:

```c
bool resolve_path(Transport *transport,
                  const uint8_t dest[16],
                  uint8_t next_hop[16],
                  Interface **out_interface) {
    PathEntry *entry = path_table_lookup(&transport->path_table, dest);

    if (entry == NULL) {
        return false;  // No path known
    }

    if (time(NULL) > entry->expires) {
        return false;  // Path expired
    }

    memcpy(next_hop, entry->next_hop, 16);
    *out_interface = entry->interface;

    return true;
}
```

### Sending with Transport Headers

For multi-hop routing, use Header Type 2:

```c
bool send_routed_packet(Transport *transport,
                        const uint8_t dest[16],
                        const uint8_t *data, size_t len) {
    uint8_t next_hop[16];
    Interface *interface;

    if (!resolve_path(transport, dest, next_hop, &interface)) {
        return false;  // No route
    }

    PathEntry *entry = path_table_lookup(&transport->path_table, dest);

    if (entry->hops == 0) {
        // Direct - use Header Type 1
        Packet pkt = {
            .header_type = 0,
            .destination_type = DEST_SINGLE,
            .packet_type = PACKET_DATA,
        };
        memcpy(pkt.destination, dest, 16);
        pkt.payload = (uint8_t*)data;
        pkt.payload_len = len;

        return interface_send(interface, &pkt);
    } else {
        // Multi-hop - use Header Type 2
        Packet pkt = {
            .header_type = 1,  // Header Type 2
            .destination_type = DEST_SINGLE,
            .packet_type = PACKET_DATA,
        };
        memcpy(pkt.destination, dest, 16);
        memcpy(pkt.transport, next_hop, 16);  // Next hop
        pkt.payload = (uint8_t*)data;
        pkt.payload_len = len;

        return interface_send(interface, &pkt);
    }
}
```

## 9.11 Summary

| Component | Purpose |
|-----------|---------|
| Announce | Broadcast destination availability |
| Random Hash | Replay prevention + emission timing |
| Path Table | Store routes to destinations |
| Rate Limiter | Prevent announce flooding |
| Announce Table | Track pending retransmissions |

| Announce Field | Size |
|----------------|------|
| Public Key | 64 bytes |
| Name Hash | 10 bytes |
| Random Hash | 10 bytes |
| Ratchet | 0 or 32 bytes |
| Signature | 64 bytes |
| Minimum Total | 148 bytes |

| Path Expiration | Duration |
|-----------------|----------|
| Default | 7 days |
| Access Point | 1 day |
| Roaming | 6 hours |

Key algorithms:
- **Path selection**: Prefer fewer hops, then newer emission time
- **Replay detection**: Store up to 64 random blobs per destination
- **Rate limiting**: Track last 16 timestamps, block after grace violations

[The next chapter covers **resource transfers** - sending large data over established links.](10-resources.md)
