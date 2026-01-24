# Chapter 7: Link Establishment

A **link** is a bidirectional encrypted channel between two nodes. This chapter details the protocol for establishing links.

## 7.1 Why Links?

### Single-Packet Communication

Without links, communication works like this:

```
Sender                              Receiver
   |                                    |
   |---- [Encrypted Packet] ----------->|
   |                                    |
```

Each packet:
- Generates new ephemeral keys
- Includes ephemeral public key in payload (32 bytes overhead)
- Cannot receive responses without announcing

### Link-Based Communication

With links:

```
Initiator                            Responder
   |                                    |
   |---- [LINKREQUEST] ---------------->|
   |                                    |
   |<--- [PROOF] -----------------------|
   |                                    |
   |==== [Encrypted channel] ===========|
   |                                    |
   |---- [DATA] ----------------------->|
   |<--- [DATA] ------------------------|
   |---- [DATA] ----------------------->|
   |                                    |
```

Benefits:
- **Efficiency**: Key exchange once, then symmetric encryption
- **Bidirectional**: Both sides can send without announcing
- **State**: Track connection health, RTT, etc.
- **Forward secrecy**: Ephemeral keys per link

## 7.2 Link States

A link progresses through states:

```
    PENDING → HANDSHAKE → ACTIVE → STALE → CLOSED
```

| State | Description |
|-------|-------------|
| PENDING | Link request sent, awaiting proof |
| HANDSHAKE | Received peer keys, computing shared secret |
| ACTIVE | Link established, ready for data |
| STALE | No activity for timeout period |
| CLOSED | Link terminated |

```c
typedef enum {
    LINK_PENDING   = 0,
    LINK_HANDSHAKE = 1,
    LINK_ACTIVE    = 2,
    LINK_STALE     = 3,
    LINK_CLOSED    = 4,
} LinkState;

typedef struct Link {
    uint8_t id[16];              // Link identifier
    LinkState state;

    // Keys
    uint8_t local_x25519_priv[32];
    uint8_t local_x25519_pub[32];
    uint8_t local_ed25519_priv[32];
    uint8_t local_ed25519_pub[32];
    uint8_t peer_x25519_pub[32];
    uint8_t peer_ed25519_pub[32];

    // Derived key for encryption
    uint8_t link_key[32];        // Or 64 for extended Fernet

    // Destination info
    uint8_t destination_hash[16];
    uint8_t destination_ed25519_pub[32];  // For initiator

    // Timing
    uint64_t request_time;
    uint64_t last_activity;
    uint64_t rtt_ms;

    // Callbacks
    void (*on_established)(struct Link *);
    void (*on_data)(struct Link *, const uint8_t *, size_t);
    void (*on_closed)(struct Link *);
} Link;
```

## 7.3 Link ID Computation

The **link ID** uniquely identifies a link throughout its lifetime. Both initiator and responder compute the same link ID independently, which is essential for:

1. **Addressing link packets**: Once established, packets are addressed to the link ID, not the destination hash
2. **Key derivation**: The link ID serves as the salt for HKDF when deriving encryption keys
3. **Proof binding**: The link proof includes the link ID to prevent proof substitution attacks

**Design rationale:**

- **Only first 64 bytes of data**: The link ID is computed from the initiator's public keys (64 bytes), not any MTU signalling bytes. This ensures both sides compute the same ID even if signalling is added/removed.
- **Lower 4 bits of header only**: The IFAC flag (bit 7) varies by interface, so it's excluded. Using only bits 0-3 ensures the same link ID regardless of which interface received the request.
- **Includes destination and context**: This binds the link to a specific destination, preventing an attacker from redirecting a link request to a different destination.

```c
void compute_link_id(const uint8_t header_meta,
                     const uint8_t destination[16],
                     uint8_t context,
                     const uint8_t *data, size_t data_len,
                     uint8_t link_id[16]) {
    // Only use first 64 bytes of data (the public keys)
    size_t hashable_len = data_len > 64 ? 64 : data_len;

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, &header_meta, 1);  // Lower 4 bits of header
    SHA256_Update(&ctx, destination, 16);
    SHA256_Update(&ctx, &context, 1);
    SHA256_Update(&ctx, data, hashable_len);

    uint8_t hash[32];
    SHA256_Final(hash, &ctx);

    // Truncate to 16 bytes
    memcpy(link_id, hash, 16);
}
```

The header meta is `header_byte & 0x0F` (lower 4 bits only).

### Example Link ID Computation

```
LINKREQUEST packet:
  Header:      0x02 (BROADCAST + SINGLE + LINKREQUEST)
  Destination: 0xa1b2c3d4e5f6789012345678abcdef01
  Context:     0x00
  Data:        [32 bytes X25519 pub][32 bytes Ed25519 pub]

Hash input:
  header_meta = 0x02 & 0x0F = 0x02
  = 0x02 || a1b2c3d4e5f6789012345678abcdef01 || 0x00 || [64 bytes keys]

Link ID = SHA256(input)[0:16]
```

## 7.4 The Link Request

### Initiator Actions

To request a link:

1. Generate ephemeral X25519 and Ed25519 key pairs
2. Build LINKREQUEST packet with public keys
3. Compute the link ID from the packet
4. Send the packet
5. Wait for proof

```c
void link_initiate(Link *link, Transport *transport,
                   const uint8_t dest_hash[16],
                   const uint8_t dest_ed25519_pub[32]) {
    // 1. Generate ephemeral keys
    crypto_box_keypair(link->local_x25519_pub, link->local_x25519_priv);
    crypto_sign_keypair(link->local_ed25519_pub, link->local_ed25519_priv);

    // 2. Store destination info (for proof verification)
    memcpy(link->destination_hash, dest_hash, 16);
    memcpy(link->destination_ed25519_pub, dest_ed25519_pub, 32);

    // 3. Build packet payload
    uint8_t payload[64];
    memcpy(&payload[0], link->local_x25519_pub, 32);
    memcpy(&payload[32], link->local_ed25519_pub, 32);

    // 4. Build packet
    Packet pkt = {
        .destination_type = DEST_SINGLE,
        .packet_type = PACKET_LINKREQUEST,
        .hops = 0,
    };
    memcpy(pkt.destination, dest_hash, 16);
    pkt.context = CONTEXT_NONE;
    pkt.payload = payload;
    pkt.payload_len = 64;

    // 5. Compute link ID
    uint8_t header = build_header(&pkt);
    compute_link_id(header & 0x0F, dest_hash, CONTEXT_NONE,
                    payload, 64, link->id);

    // 6. Set state and timing
    link->state = LINK_PENDING;
    link->request_time = get_time_ms();

    // 7. Send
    transport_send(transport, &pkt);
}
```

### Link Request Packet Structure

```
+------+------+-------------+---------+--------------------+
|Header| Hops | Destination | Context | Initiator Keys     |
| 0x02 | 1B   | 16B         | 0x00    | 64B                |
+------+------+-------------+---------+--------------------+

Initiator Keys:
+-------------------+--------------------+
| X25519 Public Key | Ed25519 Public Key |
| 32 bytes          | 32 bytes           |
+-------------------+--------------------+
```

## 7.5 Receiving a Link Request

### Responder Actions

When a destination receives a LINKREQUEST:

1. Validate the packet
2. Generate ephemeral X25519 key pair
3. Compute the link ID
4. Compute shared secret
5. Derive link encryption key
6. Generate proof
7. Send proof
8. Transition to ACTIVE

```c
Link* handle_link_request(Destination *dest, Packet *pkt) {
    // 1. Validate packet
    if (pkt->payload_len < 64) {
        return NULL;  // Too short
    }

    // 2. Extract initiator's public keys
    uint8_t initiator_x25519[32], initiator_ed25519[32];
    memcpy(initiator_x25519, &pkt->payload[0], 32);
    memcpy(initiator_ed25519, &pkt->payload[32], 32);

    // 3. Create link
    Link *link = malloc(sizeof(Link));

    // 4. Generate our ephemeral X25519 key pair
    crypto_box_keypair(link->local_x25519_pub, link->local_x25519_priv);

    // Use the destination's Ed25519 keys for signing
    memcpy(link->local_ed25519_pub, dest->identity->ed25519_pub, 32);
    memcpy(link->local_ed25519_priv, dest->identity->ed25519_priv, 32);

    // 5. Store peer keys
    memcpy(link->peer_x25519_pub, initiator_x25519, 32);
    memcpy(link->peer_ed25519_pub, initiator_ed25519, 32);

    // 6. Compute link ID
    uint8_t header = build_header(pkt);
    compute_link_id(header & 0x0F, pkt->destination, pkt->context,
                    pkt->payload, pkt->payload_len, link->id);

    // 7. Derive link key
    derive_link_key(link);

    // 8. Set state
    link->state = LINK_ACTIVE;

    return link;
}

void derive_link_key(Link *link) {
    // X25519 key exchange
    uint8_t shared_secret[32];
    crypto_scalarmult(shared_secret,
                      link->local_x25519_priv,
                      link->peer_x25519_pub);

    // HKDF with link ID as salt
    hkdf_sha256(link->link_key, sizeof(link->link_key),
                shared_secret, 32,
                link->id, 16,  // salt = link ID
                NULL, 0);

    // Clear shared secret
    sodium_memzero(shared_secret, 32);
}
```

## 7.6 The Link Proof

The responder must prove they control the destination's private key. This prevents man-in-the-middle attacks where an attacker intercepts a link request and responds pretending to be the destination.

### Security Purpose

Without proof verification, this attack is possible:

1. Initiator sends LINKREQUEST to destination
2. Attacker intercepts the request
3. Attacker generates their own ephemeral keys
4. Attacker responds to initiator with their keys
5. Attacker forwards modified request to destination
6. Destination responds to attacker

The initiator would think they're talking to the destination, but the attacker sits in the middle.

**The proof prevents this**: The responder signs with the destination's **long-term Ed25519 private key** (known only to the real destination). The initiator verifies the signature against the destination's public key (from the announce). An attacker cannot forge this signature without the private key.

### Why Sign the Responder's Keys (Not the Initiator's)?

A common mistake: signing the initiator's public keys instead of the responder's.

**Why this is wrong**: If the responder signed the initiator's keys, an attacker who intercepts the link request could:
1. Extract the initiator's public keys from the request
2. Forward the request to the real destination
3. Get a valid signature over those keys
4. Use that signature in their own proof (with the attacker's keys for X25519)

**The correct approach**: The responder signs their OWN ephemeral X25519 public key (used for key exchange) and their Ed25519 public key (which matches the destination's announced key). The initiator verifies:
- The Ed25519 key in the proof matches the destination's announced key
- The signature is valid for the responder's keys
- The X25519 key in the proof is used for the shared secret

This binds the proof to the specific keys being used for this link.

### Proof Structure

Current format (with MTU signalling):
```
+------------------+-------------------+-------------+
| Signature        | Responder X25519  | Signalling  |
| 64 bytes         | 32 bytes          | 3 bytes     |
+------------------+-------------------+-------------+

Total: 99 bytes
```

Legacy format (without signalling):
```
+------------------+-------------------+
| Signature        | Responder X25519  |
| 64 bytes         | 32 bytes          |
+------------------+-------------------+

Total: 96 bytes
```

Implementations should accept both 96-byte and 99-byte proofs for compatibility.

### Signed Data

Current format - the signature covers 83 bytes:

```
+----------+--------------------+---------------------+-------------+
| Link ID  | Responder X25519   | Responder Ed25519   | Signalling  |
| 16 bytes | 32 bytes           | 32 bytes            | 3 bytes     |
+----------+--------------------+---------------------+-------------+
```

Legacy format - 80 bytes (without signalling).

**Critical**: The responder signs with their **own** public keys, not the initiator's!

### Generating the Proof

```c
void build_link_proof(Link *link, uint8_t proof[99]) {
    // 1. Build signed data (83 bytes)
    uint8_t signed_data[83];
    size_t offset = 0;

    // Link ID
    memcpy(&signed_data[offset], link->id, 16);
    offset += 16;

    // Responder's X25519 public key
    memcpy(&signed_data[offset], link->local_x25519_pub, 32);
    offset += 32;

    // Responder's Ed25519 public key
    memcpy(&signed_data[offset], link->local_ed25519_pub, 32);
    offset += 32;

    // Signalling bytes (MTU info)
    uint8_t signalling[3] = {0x00, 0x00, 0x00};  // Default MTU
    memcpy(&signed_data[offset], signalling, 3);
    offset += 3;

    // 2. Sign with Ed25519
    uint8_t signature[64];
    crypto_sign_detached(signature, NULL,
                         signed_data, 83,
                         link->local_ed25519_priv);

    // 3. Build proof (99 bytes)
    offset = 0;
    memcpy(&proof[offset], signature, 64);
    offset += 64;
    memcpy(&proof[offset], link->local_x25519_pub, 32);
    offset += 32;
    memcpy(&proof[offset], signalling, 3);
}
```

### Sending the Proof

```c
void send_link_proof(Link *link, Transport *transport) {
    uint8_t proof_data[99];
    build_link_proof(link, proof_data);

    Packet pkt = {
        .destination_type = DEST_LINK,  // Note: LINK type, not SINGLE
        .packet_type = PACKET_PROOF,
        .hops = 0,
    };
    memcpy(pkt.destination, link->id, 16);  // Addressed to link ID
    pkt.context = CONTEXT_LINK_PROOF;       // 0xFF
    pkt.payload = proof_data;
    pkt.payload_len = 99;

    transport_send(transport, &pkt);
}
```

### Proof Packet Structure

```
+------+------+----------+---------+-----------+
|Header| Hops | Link ID  | Context | Proof     |
| 0x0F | 1B   | 16B      | 0xFF    | 99B       |
+------+------+----------+---------+-----------+

Header 0x0F = BROADCAST + Header1 + LINK + PROOF
Context 0xFF = LINK_PROOF
```

## 7.7 Processing the Proof

### Initiator Verification

When the initiator receives the proof:

```c
bool process_link_proof(Link *link, const uint8_t *proof, size_t proof_len) {
    // 1. Validate length
    if (proof_len < 99) {
        return false;  // Too short
    }

    // 2. Extract proof components
    uint8_t signature[64];
    uint8_t peer_x25519_pub[32];
    uint8_t signalling[3];

    memcpy(signature, &proof[0], 64);
    memcpy(peer_x25519_pub, &proof[64], 32);
    memcpy(signalling, &proof[96], 3);

    // 3. Store peer's X25519 public key
    memcpy(link->peer_x25519_pub, peer_x25519_pub, 32);

    // 4. Reconstruct signed data
    // CRITICAL: Use responder's keys (from proof and destination)
    uint8_t signed_data[83];
    size_t offset = 0;

    // Link ID
    memcpy(&signed_data[offset], link->id, 16);
    offset += 16;

    // Responder's X25519 public key (from proof)
    memcpy(&signed_data[offset], peer_x25519_pub, 32);
    offset += 32;

    // Responder's Ed25519 public key (from destination)
    memcpy(&signed_data[offset], link->destination_ed25519_pub, 32);
    offset += 32;

    // Signalling bytes
    memcpy(&signed_data[offset], signalling, 3);

    // 5. Verify signature
    if (crypto_sign_verify_detached(signature, signed_data, 83,
                                    link->destination_ed25519_pub) != 0) {
        return false;  // Invalid signature
    }

    // 6. Derive link key
    derive_link_key(link);

    // 7. Update state
    link->state = LINK_ACTIVE;
    link->rtt_ms = get_time_ms() - link->request_time;

    // 8. Notify callback
    if (link->on_established) {
        link->on_established(link);
    }

    return true;
}
```

## 7.8 Key Derivation Details

Both sides must derive the same encryption key.

### ECDH Shared Secret

```c
// Both compute the same shared secret
void compute_shared_secret(const uint8_t my_private[32],
                           const uint8_t peer_public[32],
                           uint8_t shared[32]) {
    crypto_scalarmult(shared, my_private, peer_public);
}

// Initiator: X25519(initiator_priv, responder_pub)
// Responder: X25519(responder_priv, initiator_pub)
// Result: Same 32-byte shared secret
```

### HKDF Expansion

```c
void derive_link_key(Link *link) {
    // 1. Compute ECDH shared secret
    uint8_t shared[32];
    crypto_scalarmult(shared, link->local_x25519_priv, link->peer_x25519_pub);

    // 2. HKDF-SHA256 with link ID as salt
    // Output length depends on Fernet mode:
    // - AES-128 Fernet: 32 bytes
    // - AES-256 Fernet: 64 bytes
    hkdf_sha256(link->link_key, LINK_KEY_LENGTH,
                shared, 32,       // Input key material
                link->id, 16,     // Salt = link ID
                NULL, 0);         // No info

    sodium_memzero(shared, 32);
}
```

### Key Usage

The derived key is split for Fernet:
- First half: HMAC key
- Second half: AES key

```c
// For 32-byte key (AES-128 Fernet):
// link_key[0:16]  = HMAC key
// link_key[16:32] = AES key

// For 64-byte key (AES-256 Fernet):
// link_key[0:32]  = HMAC key
// link_key[32:64] = AES key
```

## 7.9 Complete Handshake Example

### Timeline

```
Time    Initiator                         Responder
----    ---------                         ---------
T+0     Generate ephemeral keys
        Build LINKREQUEST
        Compute link_id
        state = PENDING
        Send LINKREQUEST ----------------->
                                          Receive LINKREQUEST
                                          Validate
                                          Generate ephemeral X25519
                                          Compute link_id
                                          Derive link_key
                                          Sign proof (83 bytes)
                                          Build proof (99 bytes)
                                          state = ACTIVE
T+RTT   <------------------------ Send PROOF
        Receive PROOF
        Validate length (99 bytes)
        Extract peer_x25519_pub
        Reconstruct signed_data (83 bytes)
        Verify signature
        Derive link_key
        state = ACTIVE
        Compute RTT

T+RTT+  [Link is active, both sides can send encrypted data]
```

### Byte-Level Example

```
LINKREQUEST:
  02 00 a1b2c3d4e5f6789012345678abcdef01 00
  [32B init_x25519_pub][32B init_ed25519_pub]

  Header:      02 (SINGLE + LINKREQUEST)
  Hops:        00
  Destination: a1b2c3d4e5f6789012345678abcdef01
  Context:     00
  Payload:     64 bytes (two public keys)

PROOF:
  0F 00 [16B link_id] FF
  [64B signature][32B resp_x25519_pub][3B signalling]

  Header:      0F (LINK + PROOF)
  Hops:        00
  Destination: [16-byte link ID]
  Context:     FF (LINK_PROOF)
  Payload:     99 bytes (signature + key + signalling)
```

## 7.10 Error Handling

### Timeout

If no proof arrives within timeout:

```c
#define LINK_TIMEOUT_MS 15000

void check_link_timeout(Link *link) {
    if (link->state == LINK_PENDING) {
        uint64_t elapsed = get_time_ms() - link->request_time;
        if (elapsed > LINK_TIMEOUT_MS) {
            link->state = LINK_CLOSED;
            if (link->on_closed) {
                link->on_closed(link);
            }
        }
    }
}
```

### Invalid Proof

If proof verification fails:

```c
if (!process_link_proof(link, proof, proof_len)) {
    // Invalid proof - close link
    link->state = LINK_CLOSED;
    log_warn("Link proof verification failed for %s",
             bytes_to_hex(link->id, 16));
}
```

### Duplicate Requests

If a destination receives duplicate link requests:

```c
Link* existing = find_link_by_id(link_id);
if (existing && existing->state == LINK_ACTIVE) {
    // Already have this link - ignore duplicate
    return existing;
}
```

## 7.11 Summary

| Step | Initiator | Responder |
|------|-----------|-----------|
| 1 | Generate ephemeral keys | - |
| 2 | Send LINKREQUEST | Receive LINKREQUEST |
| 3 | Wait for proof | Generate ephemeral X25519 |
| 4 | - | Compute link ID |
| 5 | - | Derive link key |
| 6 | - | Sign proof (83B signed data) |
| 7 | Receive proof | Send PROOF (99B payload) |
| 8 | Verify signature | - |
| 9 | Derive link key | - |
| 10 | ACTIVE | ACTIVE |

| Data Structure | Size | Contents |
|----------------|------|----------|
| LINKREQUEST payload | 64 or 67 bytes | keys, optionally + 3 signalling bytes |
| PROOF payload | 96 or 99 bytes | signature + key, optionally + signalling |
| Signed data | 80 or 83 bytes | link_id + keys, optionally + signalling |
| Link key | 32-64 bytes | HKDF(shared_secret, link_id) |

[The next chapter covers **link communication** - sending and receiving encrypted data on established links.](08-link-communication.md)
