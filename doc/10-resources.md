# Chapter 10: Resource Transfers

Links provide reliable bidirectional channels, but they're designed for small packets. **Resources** extend this to transfer arbitrary-sized data with automatic segmentation, compression, and integrity verification.

## 10.1 The Large Transfer Problem

Link packets have a Maximum Data Unit (MDU) of approximately 430 bytes. Transferring a 10 MB file would require:

```
10,000,000 bytes / 430 bytes ≈ 23,256 packets
```

Resources solve this by providing:
- **Segmentation**: Split large data into transferable parts
- **Flow control**: Adaptive windowing based on link speed
- **Integrity**: Hash verification of each part and the whole
- **Compression**: Optional bz2 compression for efficiency
- **Progress tracking**: Monitor transfer completion

## 10.2 Resource Transfer Overview

### Transfer Flow

```
Sender (Initiator)                    Receiver
    |                                     |
    |---- [RESOURCE_ADV] ---------------->|  Advertisement
    |                                     |
    |<--- [RESOURCE_REQ] -----------------|  Request parts
    |                                     |
    |---- [RESOURCE] -------------------->|  Part 1
    |---- [RESOURCE] -------------------->|  Part 2
    |---- [RESOURCE] -------------------->|  Part N...
    |                                     |
    |<--- [RESOURCE_REQ] -----------------|  Request more parts
    |                                     |
    |---- [RESOURCE] -------------------->|  More parts
    |                                     |
    |<--- [RESOURCE_PRF] -----------------|  Proof (complete)
    |                                     |
```

### Packet Contexts

| Context | Value | Direction | Encrypted |
|---------|-------|-----------|-----------|
| RESOURCE | 0x01 | Sender→Receiver | Yes |
| RESOURCE_ADV | 0x02 | Sender→Receiver | Yes |
| RESOURCE_REQ | 0x03 | Receiver→Sender | Yes |
| RESOURCE_HMU | 0x04 | Sender→Receiver | Yes |
| RESOURCE_PRF | 0x05 | Receiver→Sender | No |
| RESOURCE_ICL | 0x06 | Sender→Receiver | Yes |
| RESOURCE_RCL | 0x07 | Receiver→Sender | Yes |

## 10.3 Resource Data Structure

### Preparing Data

Before transmission, data is prepared:

```c
#define RANDOM_HASH_SIZE 4

typedef struct {
    uint8_t random_hash[RANDOM_HASH_SIZE];
    uint8_t *data;
    size_t data_len;
    bool compressed;
    uint8_t resource_hash[32];
} ResourceData;

void prepare_resource(const uint8_t *input, size_t input_len,
                      ResourceData *res) {
    // 1. Generate random hash
    randombytes_buf(res->random_hash, RANDOM_HASH_SIZE);

    // 2. Try compression
    uint8_t *compressed = NULL;
    size_t compressed_len = 0;
    if (input_len <= AUTO_COMPRESS_MAX_SIZE) {
        compressed = bz2_compress(input, input_len, &compressed_len);
    }

    // 3. Use compressed if smaller
    if (compressed && compressed_len < input_len) {
        res->data = compressed;
        res->data_len = compressed_len;
        res->compressed = true;
    } else {
        res->data = malloc(input_len);
        memcpy(res->data, input, input_len);
        res->data_len = input_len;
        res->compressed = false;
        free(compressed);
    }

    // 4. Compute resource hash
    uint8_t to_hash[res->data_len + RANDOM_HASH_SIZE];
    memcpy(to_hash, res->data, res->data_len);
    memcpy(&to_hash[res->data_len], res->random_hash, RANDOM_HASH_SIZE);
    sha256(to_hash, sizeof(to_hash), res->resource_hash);
}
```

### Prepending Random Hash

The transmitted data includes the random hash:

```
+-------------------+------------------+
| Random Hash       | Resource Data    |
| 4 bytes           | variable         |
+-------------------+------------------+
```

## 10.4 Segmentation

### Service Data Unit (SDU)

The SDU is the maximum data per part, derived from the link's MDU:

```c
#define LINK_MDU 431  // Typical value

size_t get_sdu(Link *link) {
    return link->mdu;  // ~430 bytes
}
```

### Part Generation

```c
#define MAPHASH_LEN 4  // 4 bytes per map hash

typedef struct {
    uint8_t *data;
    size_t len;
    uint8_t map_hash[MAPHASH_LEN];
} ResourcePart;

void generate_parts(ResourceData *res, size_t sdu,
                    ResourcePart **parts_out, size_t *part_count_out) {
    // Prepend random hash
    size_t total_len = RANDOM_HASH_SIZE + res->data_len;
    uint8_t *full_data = malloc(total_len);
    memcpy(full_data, res->random_hash, RANDOM_HASH_SIZE);
    memcpy(&full_data[RANDOM_HASH_SIZE], res->data, res->data_len);

    // Calculate part count
    size_t part_count = (total_len + sdu - 1) / sdu;
    ResourcePart *parts = malloc(part_count * sizeof(ResourcePart));

    // Generate parts and map hashes
    for (size_t i = 0; i < part_count; i++) {
        size_t offset = i * sdu;
        size_t len = (offset + sdu <= total_len) ? sdu : (total_len - offset);

        parts[i].data = malloc(len);
        memcpy(parts[i].data, &full_data[offset], len);
        parts[i].len = len;

        // Compute map hash
        uint8_t hash_input[len + RANDOM_HASH_SIZE];
        memcpy(hash_input, parts[i].data, len);
        memcpy(&hash_input[len], res->random_hash, RANDOM_HASH_SIZE);

        uint8_t full_hash[32];
        sha256(hash_input, sizeof(hash_input), full_hash);
        memcpy(parts[i].map_hash, full_hash, MAPHASH_LEN);
    }

    *parts_out = parts;
    *part_count_out = part_count;
    free(full_data);
}
```

### Hash Map

The hash map contains 4-byte hashes for each part, used for verification:

```c
typedef struct {
    uint8_t *hashes;      // Array of 4-byte hashes
    size_t hash_count;
} ResourceHashMap;

void build_hashmap(ResourcePart *parts, size_t part_count,
                   ResourceHashMap *map) {
    map->hashes = malloc(part_count * MAPHASH_LEN);
    map->hash_count = part_count;

    for (size_t i = 0; i < part_count; i++) {
        memcpy(&map->hashes[i * MAPHASH_LEN], parts[i].map_hash, MAPHASH_LEN);
    }
}
```

## 10.5 Resource Advertisement

### Advertisement Structure

The advertisement is msgpack-encoded as a map with single-letter keys:

| Key | Name | Type | Required | Description |
|-----|------|------|----------|-------------|
| `t` | transfer_size | int | Yes | Size of encrypted/compressed data in bytes |
| `d` | data_size | int | Yes | Total uncompressed data size |
| `n` | num_parts | int | Yes | Number of parts in transfer |
| `h` | hash | bytes(32) | Yes | SHA-256 hash of resource |
| `r` | random | bytes(4) | Yes | Random bytes for uniqueness |
| `o` | original | bytes(32) | Yes | Hash of first segment (for split resources) |
| `i` | index | int | Yes | Current segment number (1-based) |
| `l` | length | int | Yes | Total number of segments |
| `q` | request_id | bytes or nil | No | Request/response correlation ID |
| `f` | flags | int | Yes | Bitfield of boolean flags |
| `m` | hashmap | bytes | Yes | Part hashes (4 bytes each, `n` entries) |

**Wire format overhead**: 134 bytes minimum (plus `n * 4` bytes for hashmap).

```c
typedef struct {
    size_t transfer_size;     // "t" - encrypted data size
    size_t total_size;        // "d" - uncompressed size
    size_t num_parts;         // "n" - part count
    uint8_t resource_hash[32];// "h" - resource hash
    uint8_t random_hash[4];   // "r" - random hash
    uint8_t original_hash[32];// "o" - first segment hash (multi-segment)
    size_t segment_index;     // "i" - current segment (1-based)
    size_t total_segments;    // "l" - total segments
    uint8_t *request_id;      // "q" - request ID (optional, NULL if not present)
    uint8_t flags;            // "f" - flags byte
    uint8_t *hashmap;         // "m" - partial hashmap
    size_t hashmap_len;
} ResourceAdvertisement;
```

### Flags Byte

```c
#define FLAG_ENCRYPTED  0x01  // Bit 0
#define FLAG_COMPRESSED 0x02  // Bit 1
#define FLAG_SPLIT      0x04  // Bit 2 (multi-segment)
#define FLAG_IS_REQUEST 0x08  // Bit 3
#define FLAG_IS_RESPONSE 0x10 // Bit 4
#define FLAG_HAS_METADATA 0x20 // Bit 5

uint8_t build_flags(bool encrypted, bool compressed, bool split,
                    bool is_request, bool is_response, bool has_metadata) {
    return (encrypted ? FLAG_ENCRYPTED : 0) |
           (compressed ? FLAG_COMPRESSED : 0) |
           (split ? FLAG_SPLIT : 0) |
           (is_request ? FLAG_IS_REQUEST : 0) |
           (is_response ? FLAG_IS_RESPONSE : 0) |
           (has_metadata ? FLAG_HAS_METADATA : 0);
}
```

### Hashmap Size Limits

```c
#define ADVERTISEMENT_OVERHEAD 134  // bytes

size_t hashmap_max_len(size_t mdu) {
    // How many hashes fit in one advertisement
    return (mdu - ADVERTISEMENT_OVERHEAD) / MAPHASH_LEN;
}
// For MDU=431: (431 - 134) / 4 = 74 hashes per advertisement
```

### Sending Advertisement

```c
void send_advertisement(Link *link, Resource *res) {
    // Build msgpack advertisement
    uint8_t adv_data[512];
    size_t adv_len = build_advertisement_msgpack(res, adv_data, sizeof(adv_data));

    // Encrypt and send
    link_send(link, adv_data, adv_len, CONTEXT_RESOURCE_ADV);

    res->status = RESOURCE_ADVERTISED;
    res->adv_sent_time = time(NULL);
}

size_t build_advertisement_msgpack(Resource *res, uint8_t *out, size_t max) {
    // Build msgpack map with keys t, d, n, h, r, f, m
    // (Simplified - actual implementation uses msgpack library)

    size_t hashmap_chunk = hashmap_max_len(res->link->mdu) * MAPHASH_LEN;
    if (hashmap_chunk > res->hashmap.hash_count * MAPHASH_LEN) {
        hashmap_chunk = res->hashmap.hash_count * MAPHASH_LEN;
    }

    // Pack: {t, d, n, h, r, f, m}
    // ...msgpack encoding...

    return adv_len;
}
```

## 10.6 Part Requests

### Request Structure

```c
typedef struct {
    uint8_t hashmap_state;    // 0x00 = not exhausted, 0xFF = exhausted
    uint8_t resource_hash[32];
    uint8_t *requested_hashes;
    size_t requested_count;
    uint8_t last_map_hash[4]; // Only if exhausted
} ResourceRequest;
```

### Packet Format

```
If HASHMAP_NOT_EXHAUSTED:
+-------------------+------------------------+
| Resource Hash     | Requested Map Hashes   |
| 32 bytes          | 4 * N bytes            |
+-------------------+------------------------+

If HASHMAP_EXHAUSTED:
+---------------+---------------+-------------------+------------------------+
| State (0xFF)  | Last Map Hash | Resource Hash     | Requested Map Hashes   |
| 1 byte        | 4 bytes       | 32 bytes          | 4 * N bytes            |
+---------------+---------------+-------------------+------------------------+
```

### Sending Requests

```c
#define HASHMAP_NOT_EXHAUSTED 0x00
#define HASHMAP_EXHAUSTED     0xFF

void send_part_request(Resource *res) {
    // Determine which parts to request
    size_t window_start = res->consecutive_completed + 1;
    size_t window_end = window_start + res->window;
    if (window_end > res->part_count) {
        window_end = res->part_count;
    }

    // Collect missing parts in window
    uint8_t requested[256 * MAPHASH_LEN];
    size_t requested_count = 0;

    for (size_t i = window_start; i < window_end && requested_count < 256; i++) {
        if (res->parts[i] == NULL) {
            memcpy(&requested[requested_count * MAPHASH_LEN],
                   &res->hashmap[i * MAPHASH_LEN], MAPHASH_LEN);
            requested_count++;
        }
    }

    // Build request packet
    uint8_t req_data[512];
    size_t offset = 0;

    // Check if we need more hashmap
    if (res->hashmap_index < res->part_count) {
        req_data[offset++] = HASHMAP_EXHAUSTED;
        memcpy(&req_data[offset], &res->hashmap[(res->hashmap_index - 1) * MAPHASH_LEN], 4);
        offset += 4;
    }

    memcpy(&req_data[offset], res->resource_hash, 32);
    offset += 32;

    memcpy(&req_data[offset], requested, requested_count * MAPHASH_LEN);
    offset += requested_count * MAPHASH_LEN;

    link_send(res->link, req_data, offset, CONTEXT_RESOURCE_REQ);

    res->outstanding_parts = requested_count;
}
```

## 10.7 Part Transfer

### How Parts Are Identified

Parts are identified by their **map hash**, not by index. This design choice has important benefits:

1. **Out-of-order delivery**: Parts can arrive in any order and still be matched correctly
2. **Retransmission**: If a part is lost, the receiver simply re-requests that map hash
3. **Deduplication**: Receiving the same part twice is harmless—the hash matches an already-filled slot

**Map hash computation**: For each part, compute `SHA256(part_data || random_hash)[0:4]`. The random hash (from the resource advertisement) ensures that different resources with identical content produce different map hashes.

### Sending Parts

The sender receives a list of requested map hashes and sends the corresponding data. The lookup is O(n×m) for n requested hashes and m total parts, but since parts are typically requested in sliding window order, performance is acceptable.

```c
void send_requested_parts(Resource *res, ResourceRequest *req) {
    for (size_t i = 0; i < req->requested_count; i++) {
        // Find part by hash
        for (size_t j = 0; j < res->part_count; j++) {
            if (memcmp(&res->hashmap[j * MAPHASH_LEN],
                       &req->requested_hashes[i * MAPHASH_LEN],
                       MAPHASH_LEN) == 0) {
                // Send this part
                link_send(res->link, res->parts[j].data, res->parts[j].len,
                          CONTEXT_RESOURCE);
                break;
            }
        }
    }
}
```

### Receiving Parts

When a part arrives, the receiver:
1. Computes the map hash from the received data
2. Searches the hashmap for a matching slot
3. Stores the data in that slot (if not already received)
4. Updates the "consecutive completed" counter

**Consecutive completed tracking**: This counter tracks how many parts from the beginning are complete. When all parts up to index N are received, we can potentially start processing them before the entire resource completes. It also determines when to trigger final assembly.

**Why search from consecutive_completed?** Parts before this index are already received, so we skip them. This optimization matters for large transfers where early parts are typically received first.

```c
void receive_part(Resource *res, const uint8_t *data, size_t len) {
    // Compute map hash for received data
    uint8_t hash_input[len + RANDOM_HASH_SIZE];
    memcpy(hash_input, data, len);
    memcpy(&hash_input[len], res->random_hash, RANDOM_HASH_SIZE);

    uint8_t full_hash[32];
    sha256(hash_input, sizeof(hash_input), full_hash);
    uint8_t map_hash[MAPHASH_LEN];
    memcpy(map_hash, full_hash, MAPHASH_LEN);

    // Find matching slot in hashmap
    for (size_t i = res->consecutive_completed; i < res->hashmap_index; i++) {
        if (memcmp(&res->hashmap[i * MAPHASH_LEN], map_hash, MAPHASH_LEN) == 0) {
            if (res->parts[i] == NULL) {
                // Store part
                res->parts[i] = malloc(len);
                memcpy(res->parts[i], data, len);
                res->part_lens[i] = len;
                res->received_count++;
                res->outstanding_parts--;

                // Update consecutive height
                while (res->consecutive_completed < res->part_count &&
                       res->parts[res->consecutive_completed] != NULL) {
                    res->consecutive_completed++;
                }
            }
            break;
        }
    }

    // Check if complete
    if (res->received_count == res->part_count) {
        assemble_resource(res);
    }
}
```

## 10.8 Hashmap Updates

When the receiver exhausts the initial hashmap, it requests more:

```c
void send_hashmap_update(Resource *res, size_t from_index) {
    // Build HMU packet with next chunk of hashmap
    size_t chunk_size = hashmap_max_len(res->link->mdu);
    size_t remaining = res->part_count - from_index;
    if (chunk_size > remaining) {
        chunk_size = remaining;
    }

    // Msgpack: [segment_index, hashmap_bytes]
    uint8_t hmu_data[512];
    size_t offset = 0;

    // Resource hash
    memcpy(&hmu_data[offset], res->resource_hash, 32);
    offset += 32;

    // Segment index (which chunk of hashmap)
    size_t segment = from_index / hashmap_max_len(res->link->mdu);
    // ... msgpack encode segment and hashmap chunk ...

    link_send(res->link, hmu_data, offset, CONTEXT_RESOURCE_HMU);
}
```

## 10.9 Flow Control

Resource transfers use **window-based flow control** to adapt to link speed. This is similar to TCP congestion control but simpler, designed for Reticulum's diverse link speeds (from 500 bps radio links to fast Internet connections).

### Key Concepts

**Window size**: How many parts to request before waiting for responses. Larger windows improve throughput on fast links; smaller windows prevent overwhelming slow links.

**Rate detection**: The system measures actual throughput and adjusts the maximum window size accordingly:
- **Fast links (>50 Kbps)**: Can handle up to 75 outstanding parts
- **Slow links (<2 Kbps)**: Limited to 4 outstanding parts

**AIMD-like behavior**: On success, grow the window (additive increase). On timeout, shrink it (multiplicative decrease). This classic approach converges to optimal throughput.

### Window Management

```c
#define WINDOW_INIT      4
#define WINDOW_MIN       2
#define WINDOW_MAX_SLOW  10
#define WINDOW_MAX_FAST  75

typedef struct {
    size_t window;
    size_t window_min;
    size_t window_max;
    int fast_rate_rounds;
    int very_slow_rate_rounds;
} FlowControl;

void init_flow_control(FlowControl *fc) {
    fc->window = WINDOW_INIT;
    fc->window_min = WINDOW_MIN;
    fc->window_max = WINDOW_MAX_SLOW;
    fc->fast_rate_rounds = 0;
    fc->very_slow_rate_rounds = 0;
}
```

### Rate Detection

```c
#define RATE_FAST       6250   // bytes/sec (50 Kbps)
#define RATE_VERY_SLOW  250    // bytes/sec (2 Kbps)
#define FAST_RATE_THRESHOLD 8
#define VERY_SLOW_RATE_THRESHOLD 2

void update_flow_control(FlowControl *fc, size_t bytes, double rtt_seconds) {
    double rate = bytes / rtt_seconds;

    if (rate > RATE_FAST) {
        fc->fast_rate_rounds++;
        if (fc->fast_rate_rounds >= FAST_RATE_THRESHOLD) {
            fc->window_max = WINDOW_MAX_FAST;
        }
    } else if (rate < RATE_VERY_SLOW) {
        fc->very_slow_rate_rounds++;
        if (fc->very_slow_rate_rounds >= VERY_SLOW_RATE_THRESHOLD) {
            fc->window_max = WINDOW_MAX_SLOW / 2;  // Cap at 4
        }
    }
}
```

### Window Adjustment

```c
void on_timeout(FlowControl *fc) {
    // Shrink window on timeout
    if (fc->window > fc->window_min) {
        fc->window--;
    }
    if (fc->window_max > fc->window_min + 4) {
        fc->window_max--;
    }
}

void on_success(FlowControl *fc) {
    // Grow window on success
    if (fc->window < fc->window_max) {
        fc->window++;
    }
    if (fc->window - fc->window_min > 3) {
        fc->window_min++;
    }
}
```

## 10.10 Assembly and Verification

### Assembling Parts

```c
void assemble_resource(Resource *res) {
    res->status = RESOURCE_ASSEMBLING;

    // 1. Concatenate all parts
    size_t total_len = 0;
    for (size_t i = 0; i < res->part_count; i++) {
        total_len += res->part_lens[i];
    }

    uint8_t *assembled = malloc(total_len);
    size_t offset = 0;
    for (size_t i = 0; i < res->part_count; i++) {
        memcpy(&assembled[offset], res->parts[i], res->part_lens[i]);
        offset += res->part_lens[i];
    }

    // 2. Strip random hash prefix
    if (total_len < RANDOM_HASH_SIZE) {
        res->status = RESOURCE_CORRUPT;
        free(assembled);
        return;
    }

    uint8_t *data = &assembled[RANDOM_HASH_SIZE];
    size_t data_len = total_len - RANDOM_HASH_SIZE;

    // 3. Decompress if needed
    if (res->flags & FLAG_COMPRESSED) {
        uint8_t *decompressed = NULL;
        size_t decompressed_len = 0;
        if (!bz2_decompress(data, data_len, &decompressed, &decompressed_len)) {
            res->status = RESOURCE_CORRUPT;
            free(assembled);
            return;
        }
        free(assembled);
        assembled = decompressed;
        data = assembled;
        data_len = decompressed_len;
    }

    // 4. Verify hash
    uint8_t hash_input[data_len + RANDOM_HASH_SIZE];
    memcpy(hash_input, data, data_len);
    memcpy(&hash_input[data_len], res->random_hash, RANDOM_HASH_SIZE);

    uint8_t calculated_hash[32];
    sha256(hash_input, sizeof(hash_input), calculated_hash);

    if (memcmp(calculated_hash, res->resource_hash, 32) != 0) {
        res->status = RESOURCE_CORRUPT;
        free(assembled);
        return;
    }

    // 5. Success - store data and send proof
    res->assembled_data = data;
    res->assembled_len = data_len;
    res->status = RESOURCE_COMPLETE;

    send_proof(res);
}
```

### Sending Proof

```c
void send_proof(Resource *res) {
    // Proof is NOT encrypted (context: RESOURCE_PRF)
    // Format: resource_hash (32) + proof_hash (32)

    uint8_t proof_data[64];

    // Resource hash
    memcpy(&proof_data[0], res->resource_hash, 32);

    // Proof hash = SHA256(data + resource_hash)
    uint8_t hash_input[res->assembled_len + 32];
    memcpy(hash_input, res->assembled_data, res->assembled_len);
    memcpy(&hash_input[res->assembled_len], res->resource_hash, 32);

    sha256(hash_input, sizeof(hash_input), &proof_data[32]);

    // Send unencrypted proof
    link_send_raw(res->link, proof_data, 64, CONTEXT_RESOURCE_PRF);
}
```

## 10.11 Cancellation

### Initiator Cancel

```c
void cancel_resource_initiator(Resource *res) {
    uint8_t cancel_data[32];
    memcpy(cancel_data, res->resource_hash, 32);

    link_send(res->link, cancel_data, 32, CONTEXT_RESOURCE_ICL);

    res->status = RESOURCE_FAILED;
}
```

### Receiver Cancel

```c
void cancel_resource_receiver(Resource *res) {
    uint8_t cancel_data[32];
    memcpy(cancel_data, res->resource_hash, 32);

    link_send(res->link, cancel_data, 32, CONTEXT_RESOURCE_RCL);

    res->status = RESOURCE_FAILED;
}
```

## 10.12 Progress Tracking

### Single Segment Progress

```c
double get_progress(Resource *res) {
    if (res->part_count == 0) return 0.0;
    return (double)res->received_count / (double)res->part_count;
}
```

### Multi-Segment Progress

```c
#define MAX_EFFICIENT_SIZE 1048575  // ~1 MB per segment

double get_multi_segment_progress(Resource *res) {
    size_t max_parts_per_segment = (MAX_EFFICIENT_SIZE + res->sdu - 1) / res->sdu;

    size_t prev_parts = (res->segment_index - 1) * max_parts_per_segment;
    double current_factor = (double)max_parts_per_segment / (double)res->part_count;

    double processed = prev_parts + (res->received_count * current_factor);
    double total = res->total_segments * max_parts_per_segment;

    return processed / total;
}
```

## 10.13 Summary

| Constant | Value | Purpose |
|----------|-------|---------|
| RANDOM_HASH_SIZE | 4 bytes | Data identification |
| MAPHASH_LEN | 4 bytes | Per-part verification |
| MAX_EFFICIENT_SIZE | ~1 MB | Segment boundary |
| WINDOW_INIT | 4 | Initial request window |
| WINDOW_MAX_FAST | 75 | Fast link window |
| MAX_RETRIES | 16 | Part request retries |

| Status | Value | Description |
|--------|-------|-------------|
| QUEUED | 0x01 | Waiting to send |
| ADVERTISED | 0x02 | Advertisement sent |
| TRANSFERRING | 0x03 | Parts being sent/received |
| AWAITING_PROOF | 0x04 | Sender waiting for proof |
| ASSEMBLING | 0x05 | Receiver assembling |
| COMPLETE | 0x06 | Transfer successful |
| FAILED | 0x07 | Transfer failed |
| CORRUPT | 0x08 | Hash verification failed |

Resource transfers enable reliable large data transfer over links with:
- Automatic segmentation and reassembly
- Per-part integrity verification via hash maps
- Adaptive flow control based on link speed
- Optional bz2 compression
- Proof of successful receipt

[The next chapter covers the **transport layer** - how all these components work together for packet routing.](11-transport.md)
