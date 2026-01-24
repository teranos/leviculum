# Chapter 5: Destinations

A **destination** is an addressable endpoint in Reticulum. This chapter explains destination types, how they're created, and how they handle incoming packets.

## 5.1 What is a Destination?

In traditional networking, you send data to an IP address and port. In Reticulum, you send data to a **destination**.

A destination combines:
- **Identity**: The cryptographic key pair
- **Application name**: A string identifying the application
- **Aspects**: Optional qualifiers (like sub-services)
- **Type**: How data is encrypted (SINGLE, GROUP, PLAIN)

```c
typedef struct {
    uint8_t  hash[16];           // Destination address hash
    uint8_t  type;               // SINGLE, GROUP, or PLAIN
    char     *app_name;          // Application name string
    char     **aspects;          // Array of aspect strings
    size_t   aspect_count;
    Identity *identity;          // Associated identity
} Destination;
```

## 5.2 Destination Types

### SINGLE Destination

The most common type. Each SINGLE destination has a unique identity.

**Properties**:
- Encrypted with the destination's public key
- Only the destination's private key can decrypt
- Provides confidentiality and authentication

**Use cases**:
- Private messaging
- Secure file transfer
- Any point-to-point communication

```c
Destination* create_single_destination(Identity *identity,
                                       const char *app_name,
                                       const char **aspects,
                                       size_t aspect_count) {
    Destination *dest = malloc(sizeof(Destination));
    dest->type = DEST_SINGLE;  // 0x00
    dest->identity = identity;
    dest->app_name = strdup(app_name);
    // ... copy aspects
    compute_destination_hash(dest);
    return dest;
}
```

### GROUP Destination

Multiple nodes share the same group key. Anyone with the key can encrypt/decrypt.

**Properties**:
- Shared symmetric key for encryption (32 or 64 bytes for AES-128/AES-256)
- All group members can read messages
- No individual authentication
- Cannot announce (only SINGLE destinations can announce)

**Use cases**:
- Group chat rooms
- Broadcast notifications
- Multicast data

```c
Destination* create_group_destination(const uint8_t group_key[32],
                                      const char *app_name) {
    Destination *dest = malloc(sizeof(Destination));
    dest->type = DEST_GROUP;  // 0x01
    memcpy(dest->group_key, group_key, 32);
    dest->app_name = strdup(app_name);
    compute_group_hash(dest);
    return dest;
}
```

**Key distribution**: Reticulum does NOT automatically distribute GROUP keys. The application must share the symmetric key through an out-of-band mechanism:

1. One node generates the key: `destination_create_keys(dest)`
2. Extract the key bytes: `key = destination_get_private_key(dest)`
3. Share `key` securely (e.g., via encrypted SINGLE message, QR code, physical exchange)
4. Other members load the key: `destination_load_private_key(dest, key)`

All members must use identical `app_name` and aspects to compute the same destination hash. There is no built-in key rotation; if compromised, all members must manually update.

### PLAIN Destination

No encryption. Data is sent in cleartext.

**Properties**:
- No encryption of payload
- Transport may still be encrypted (on links)
- Anyone can read the data

**Use cases**:
- Public announcements
- Debugging/testing
- Broadcast beacons

**Warning**: Use sparingly. Encryption should be the default.

```c
Destination* create_plain_destination(const char *app_name) {
    Destination *dest = malloc(sizeof(Destination));
    dest->type = DEST_PLAIN;  // 0x02
    dest->identity = NULL;
    dest->app_name = strdup(app_name);
    compute_plain_hash(dest);
    return dest;
}
```

## 5.3 Destination Hash Computation

Each destination type computes its hash differently.

### SINGLE Destination Hash

```
identity_hash = SHA256(x25519_pub || ed25519_pub)[0:16]
name_hash = SHA256(app_name)[0:16]
aspects_hash = SHA256(aspect1 || aspect2 || ...)[0:16]

If no aspects:
  dest_hash = SHA256(name_hash || identity_hash)[0:16]

If aspects:
  dest_hash = SHA256(name_hash || aspects_hash || identity_hash)[0:16]
```

Implementation:

```c
void compute_single_destination_hash(const char *app_name,
                                     const char **aspects,
                                     size_t aspect_count,
                                     const uint8_t identity_hash[16],
                                     uint8_t dest_hash[16]) {
    uint8_t name_hash[32], aspects_hash[32], temp[32];
    SHA256_CTX ctx;

    // Hash application name
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (uint8_t*)app_name, strlen(app_name));
    SHA256_Final(name_hash, &ctx);

    // Build destination hash
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, name_hash, 16);  // Truncated name hash

    if (aspect_count > 0) {
        // Hash all aspects concatenated
        SHA256_Init(&ctx);
        for (size_t i = 0; i < aspect_count; i++) {
            SHA256_Update(&ctx, (uint8_t*)aspects[i], strlen(aspects[i]));
        }
        SHA256_Final(aspects_hash, &ctx);

        SHA256_Init(&ctx);
        SHA256_Update(&ctx, name_hash, 16);
        SHA256_Update(&ctx, aspects_hash, 16);
    }

    SHA256_Update(&ctx, identity_hash, 16);
    SHA256_Final(temp, &ctx);

    memcpy(dest_hash, temp, 16);
}
```

### GROUP Destination Hash

GROUP destinations use the same hash derivation as PLAIN - the symmetric key is NOT included in the hash:

```
name_hash = SHA256(app_name)[0:10]
dest_hash = SHA256(name_hash)[0:16]
```

The group key is used only for encryption/decryption, not for addressing.

### PLAIN Destination Hash

```
name_hash = SHA256(app_name)[0:10]
dest_hash = SHA256(name_hash)[0:16]
```

## 5.4 Registering Destinations

To receive packets, a destination must be **registered** with the transport layer.

```c
typedef void (*PacketCallback)(Destination *dest,
                               const uint8_t *data,
                               size_t len,
                               const uint8_t *packet_hash);

typedef void (*LinkCallback)(Destination *dest,
                             Link *link);

typedef struct {
    Destination *dest;
    PacketCallback on_packet;
    LinkCallback on_link_established;
} DestinationRegistration;

void register_destination(Transport *transport,
                          Destination *dest,
                          PacketCallback on_packet,
                          LinkCallback on_link) {
    DestinationRegistration reg = {
        .dest = dest,
        .on_packet = on_packet,
        .on_link_established = on_link
    };

    // Add to transport's destination table
    transport_add_destination(transport, &reg);
}
```

When a packet arrives:
1. Transport looks up destination by hash
2. If found, decrypts payload (if needed)
3. Calls the registered callback

## 5.5 Sending to Destinations

Sending data to a destination requires encryption appropriate to the destination type. This section explains the cryptographic flow for each type.

### Sending to a SINGLE Destination

When sending to a SINGLE destination, Reticulum uses **ephemeral key exchange** to provide forward secrecy. Each message gets a fresh keypair, so compromising long-term keys doesn't reveal past messages.

**The encryption flow:**

1. **Generate ephemeral keypair**: Create a one-time X25519 keypair just for this message
2. **Compute shared secret**: Use ECDH between our ephemeral private key and the recipient's long-term public key
3. **Derive encryption key**: Run the shared secret through HKDF to get an AES key
4. **Encrypt with Fernet**: Use the derived key to encrypt the actual data
5. **Prepend ephemeral public key**: The recipient needs our ephemeral public key to decrypt

**Why ephemeral keys?** If an attacker records encrypted traffic and later obtains the recipient's private key, they still cannot decrypt old messages. Each message used a different ephemeral key that was discarded after sending.

**Why include the ephemeral public key in the payload?** The recipient must perform the same ECDH calculation. They use their long-term private key with our ephemeral public key to derive the same shared secret.

```c
bool send_to_single(Transport *transport,
                    Destination *dest,
                    const uint8_t *data,
                    size_t len) {
    // 1. Check if we know the identity
    if (!dest->identity) {
        // Need to wait for announce or request identity
        return false;
    }

    // 2. Create ephemeral key for this message
    uint8_t eph_priv[32], eph_pub[32];
    crypto_box_keypair(eph_pub, eph_priv);

    // 3. Compute shared secret
    uint8_t shared[32];
    crypto_scalarmult(shared, eph_priv, dest->identity->x25519_pub);

    // 4. Derive encryption key
    uint8_t derived[32];
    hkdf_sha256(derived, 32, shared, 32, NULL, 0, NULL, 0);

    // 5. Encrypt with Fernet
    uint8_t payload[PACKET_MTU];
    size_t payload_len = 0;

    // Add ephemeral public key
    memcpy(payload, eph_pub, 32);
    payload_len += 32;

    // Encrypt data
    payload_len += fernet_encrypt(derived, data, len,
                                  &payload[32], sizeof(payload) - 32);

    // 6. Build and send packet
    Packet pkt = {
        .header_type = 0,
        .destination_type = DEST_SINGLE,
        .packet_type = PACKET_DATA,
        .hops = 0,
    };
    memcpy(pkt.destination, dest->hash, 16);
    pkt.context = CONTEXT_NONE;
    pkt.payload = payload;
    pkt.payload_len = payload_len;

    return transport_send(transport, &pkt);
}
```

### Receiving at a SINGLE Destination

On the receiving side, the process mirrors sending:

1. **Extract ephemeral public key**: The first 32 bytes of the payload contain the sender's ephemeral public key
2. **Compute shared secret**: ECDH with our long-term private key and the sender's ephemeral public key produces the same shared secret the sender computed
3. **Derive decryption key**: Same HKDF derivation produces the same AES key
4. **Decrypt Fernet token**: Verify HMAC and decrypt the ciphertext

**Security note**: The HMAC verification happens before decryption. If the HMAC fails, the recipient knows the message was tampered with or incorrectly encrypted, and decryption is aborted.

```c
bool receive_single(Destination *dest,
                    const uint8_t *payload,
                    size_t payload_len,
                    uint8_t *plaintext,
                    size_t *plaintext_len) {
    if (payload_len < 32) return false;  // Need ephemeral key

    // 1. Extract ephemeral public key
    uint8_t eph_pub[32];
    memcpy(eph_pub, payload, 32);

    // 2. Compute shared secret
    uint8_t shared[32];
    crypto_scalarmult(shared, dest->identity->x25519_priv, eph_pub);

    // 3. Derive decryption key
    uint8_t derived[32];
    hkdf_sha256(derived, 32, shared, 32, NULL, 0, NULL, 0);

    // 4. Decrypt Fernet token
    return fernet_decrypt(derived, &payload[32], payload_len - 32,
                          plaintext, plaintext_len);
}
```

## 5.6 Proof Strategies

When you receive a packet, you may want to **prove** receipt to the sender. This provides delivery confirmation without requiring a full response message.

### Why Proofs?

In unreliable networks, senders need to know if their message arrived. TCP uses ACK packets, but Reticulum operates over diverse media where traditional TCP assumptions don't hold. Proofs provide cryptographic confirmation that:

1. The packet reached the destination
2. The destination had the correct keys to decrypt it
3. The destination intentionally acknowledged receipt

### Proof Types

Destinations can choose when to send proofs:

```c
#define PROVE_NONE     0x21  // Never send proofs
#define PROVE_APP      0x22  // Application decides (callback)
#define PROVE_ALL      0x23  // Prove all packets
```

- **PROVE_NONE**: Silent receipt. Use when bandwidth is precious or acknowledgment isn't needed
- **PROVE_APP**: The application's callback decides per-packet. Useful for selective acknowledgment
- **PROVE_ALL**: Always prove. Use when reliable delivery confirmation is essential

### Generating a Proof

A proof is a signature over the packet hash. Only the destination's private key can create this signature, so it proves the destination (not an impostor) received the packet:

```c
void generate_proof(Destination *dest,
                    const uint8_t packet_hash[32],
                    uint8_t proof[64]) {
    // Sign the packet hash
    crypto_sign_detached(proof, NULL,
                         packet_hash, 32,
                         dest->identity->ed25519_priv);
}
```

### Proof Packet

The proof is sent as a PROOF packet addressed to the original sender:

```c
void send_proof(Transport *transport,
                const uint8_t sender_dest[16],
                const uint8_t packet_hash[32],
                Destination *dest) {
    uint8_t proof_sig[64];
    generate_proof(dest, packet_hash, proof_sig);

    Packet pkt = {
        .destination_type = DEST_SINGLE,
        .packet_type = PACKET_PROOF,
        .hops = 0,
    };
    memcpy(pkt.destination, sender_dest, 16);
    pkt.context = CONTEXT_NONE;
    pkt.payload = proof_sig;
    pkt.payload_len = 64;

    transport_send(transport, &pkt);
}
```

## 5.7 Announces

To let others know about your destination, you broadcast an **announce**. Announces distribute the public keys needed to send encrypted messages to your destination.

### Why Announces?

In traditional networking, you know a server's IP address and can connect directly. In Reticulum, destinations are identified by cryptographic hashes, and you need the public keys to communicate. Announces solve this by broadcasting:

1. **Public keys** for encryption (so others can send you messages)
2. **Name hash** for destination hash verification
3. **Signature** proving you own the private keys

### Announce Contents

```
+-------------+-----------+-------------+-----------+----------+
| Public Key  | Name Hash | Random Hash | Signature | App Data |
| 64 bytes    | 10 bytes  | 10 bytes    | 64 bytes  | variable |
+-------------+-----------+-------------+-----------+----------+

Minimum size: 148 bytes (without app data)
```

- **Public Key**: X25519 (32B) + Ed25519 (32B) public keys concatenated
- **Name Hash**: First 10 bytes of SHA256(expanded_name) - saves bandwidth vs full name
- **Random Hash**: 5 random bytes + 5-byte timestamp (explained below)
- **Signature**: Ed25519 signature over specific data (see below)
- **App Data**: Optional application-specific data (service description, version, etc.)

### Random Hash: Replay Prevention

The 10-byte random hash serves two purposes:

1. **Replay prevention**: Each announce has unique random bytes. Receivers store recent random hashes and reject duplicates, preventing attackers from re-broadcasting old announces.

2. **Timing information**: The 5-byte timestamp (seconds since epoch, big-endian) lets receivers:
   - Prefer newer announces over older ones
   - Detect stale announces in path selection
   - Measure approximate announce age for routing decisions

### Signature Security

**Critical design decision**: The signature covers the destination hash, but the destination hash is NOT transmitted in the announce. This prevents a subtle attack:

If an attacker could intercept an announce and re-sign it for a different destination hash, they could redirect traffic. By including the (non-transmitted) destination hash in the signed data, the signature binds the announce to a specific destination. Receivers recompute the destination hash from the transmitted data and verify it matches what was signed.

**Signed data** = dest_hash + public_key + name_hash + random_hash + app_data

**Transmitted data** = public_key + name_hash + random_hash + signature + app_data

The receiver:
1. Extracts public_key and name_hash from the announce
2. Computes dest_hash = SHA256(name_hash || identity_hash)[0:16]
3. Reconstructs the signed_data using the computed dest_hash
4. Verifies the signature with the announced public key

If an attacker modified anything, the signature won't verify.

See [Chapter 9](09-announces.md) for full details on announce processing and propagation.

### Creating an Announce

```c
size_t create_announce(Destination *dest,
                       const uint8_t *app_data,
                       size_t app_data_len,
                       uint8_t *announce,
                       size_t max_len) {
    // Build random hash (5 random + 5-byte timestamp)
    uint8_t random_hash[10];
    randombytes_buf(random_hash, 5);
    uint64_t now = (uint64_t)time(NULL);
    random_hash[5] = (now >> 32) & 0xFF;
    random_hash[6] = (now >> 24) & 0xFF;
    random_hash[7] = (now >> 16) & 0xFF;
    random_hash[8] = (now >> 8) & 0xFF;
    random_hash[9] = now & 0xFF;

    // Build signed data: dest_hash + public_key + name_hash + random_hash + app_data
    uint8_t signed_data[512];
    size_t sign_offset = 0;

    memcpy(&signed_data[sign_offset], dest->hash, 16);          // dest hash (NOT transmitted)
    sign_offset += 16;
    memcpy(&signed_data[sign_offset], dest->identity->x25519_pub, 32);
    sign_offset += 32;
    memcpy(&signed_data[sign_offset], dest->identity->ed25519_pub, 32);
    sign_offset += 32;
    memcpy(&signed_data[sign_offset], dest->name_hash, 10);     // 10 bytes!
    sign_offset += 10;
    memcpy(&signed_data[sign_offset], random_hash, 10);
    sign_offset += 10;
    if (app_data && app_data_len > 0) {
        memcpy(&signed_data[sign_offset], app_data, app_data_len);
        sign_offset += app_data_len;
    }

    // Sign
    uint8_t signature[64];
    crypto_sign_detached(signature, NULL, signed_data, sign_offset,
                         dest->identity->ed25519_priv);

    // Build announce data: public_key + name_hash + random_hash + signature + app_data
    size_t offset = 0;
    memcpy(&announce[offset], dest->identity->x25519_pub, 32);
    offset += 32;
    memcpy(&announce[offset], dest->identity->ed25519_pub, 32);
    offset += 32;
    memcpy(&announce[offset], dest->name_hash, 10);
    offset += 10;
    memcpy(&announce[offset], random_hash, 10);
    offset += 10;
    memcpy(&announce[offset], signature, 64);
    offset += 64;
    if (app_data && app_data_len > 0) {
        memcpy(&announce[offset], app_data, app_data_len);
        offset += app_data_len;
    }

    return offset;  // Minimum 148 bytes without app_data
}
```

### Sending an Announce

```c
void send_announce(Transport *transport, Destination *dest) {
    uint8_t announce_data[PACKET_MTU];
    size_t announce_len = create_announce(dest, NULL, 0,
                                          announce_data, sizeof(announce_data));

    Packet pkt = {
        .destination_type = DEST_SINGLE,
        .packet_type = PACKET_ANNOUNCE,
        .hops = 0,
    };
    memcpy(pkt.destination, dest->hash, 16);
    pkt.context = CONTEXT_NONE;
    pkt.payload = announce_data;
    pkt.payload_len = announce_len;

    transport_send(transport, &pkt);
}
```

### Processing Received Announces

```c
bool process_announce(const uint8_t dest_hash[16],
                      const uint8_t *payload,
                      size_t payload_len) {
    if (payload_len < 64 + 5 + 64) {
        return false;  // Too short
    }

    // Extract public keys
    uint8_t x25519_pub[32], ed25519_pub[32];
    memcpy(x25519_pub, &payload[0], 32);
    memcpy(ed25519_pub, &payload[32], 32);

    // Verify the announced hash matches the keys
    uint8_t computed_hash[16];
    compute_identity_hash(x25519_pub, ed25519_pub, computed_hash);
    // Note: Full verification needs app_name, checking dest_hash derivation

    // Extract signature (last 64 bytes)
    size_t sig_offset = payload_len - 64;
    uint8_t signature[64];
    memcpy(signature, &payload[sig_offset], 64);

    // Build signed data
    uint8_t sign_data[256];
    memcpy(sign_data, dest_hash, 16);
    memcpy(&sign_data[16], payload, sig_offset);

    // Verify signature
    if (crypto_sign_verify_detached(signature, sign_data, 16 + sig_offset,
                                    ed25519_pub) != 0) {
        return false;  // Invalid signature
    }

    // Cache the identity for future use
    cache_identity(dest_hash, x25519_pub, ed25519_pub);

    return true;
}
```

## 5.8 Destination Naming

Application names provide human-readable identification:

```
"myapp"                  → Simple application
"myapp.service"          → With aspect
"myapp.service.v2"       → Multiple aspects
```

### Name Conventions

- Use lowercase
- Separate components with dots
- Keep names short (bandwidth matters)
- Be descriptive but concise

### Reserved Names

Some names are reserved for Reticulum internals:
- `rnstransport` - Transport layer operations
- `rnsresource` - Resource transfers
- `lxmf` - LXMF messaging protocol

## 5.9 Destination Callbacks

### Packet Callback

Called when a packet arrives for this destination:

```c
void my_packet_callback(Destination *dest,
                        const uint8_t *data,
                        size_t len,
                        const uint8_t *packet_hash) {
    printf("Received %zu bytes at destination %s\n",
           len, dest->app_name);

    // Process the data
    process_application_data(data, len);

    // Optionally send a proof
    if (should_prove(dest)) {
        send_proof_for_packet(dest, packet_hash);
    }
}
```

### Link Established Callback

Called when someone establishes a link to this destination:

```c
void my_link_callback(Destination *dest, Link *link) {
    printf("New link established: %s\n",
           bytes_to_hex(link->id, 16));

    // Accept or reject the link
    if (should_accept_link(link)) {
        link_accept(link);

        // Register callbacks for this link
        link_set_data_callback(link, my_link_data_handler);
        link_set_close_callback(link, my_link_close_handler);
    } else {
        link_reject(link);
    }
}
```

## 5.10 Ratchets (Optional Forward Secrecy)

SINGLE destinations normally use the identity's static X25519 key for encryption. If that key is ever compromised, all past messages can be decrypted. **Ratchets** solve this by providing forward secrecy for single-packet communication.

### How Ratchets Work

When ratchets are enabled on a destination:

1. The destination generates and stores rotating X25519 key pairs
2. Announces include the current ratchet public key (32 extra bytes)
3. Senders encrypt to the ratchet key instead of the static identity key
4. The destination rotates keys periodically (default: every 30 minutes)
5. Old ratchet private keys are eventually deleted

```c
// Enable ratchets on a destination
destination_enable_ratchets(dest, "/path/to/ratchets.dat");

// Ratchets are automatically rotated during announce
destination_announce(dest, transport, NULL, 0);
```

### When to Use Ratchets

| Scenario | Use Ratchets? | Why |
|----------|---------------|-----|
| Link-based communication | No | Links already have forward secrecy |
| Single packets, low security | No | Overhead not justified |
| Asynchronous messaging (LXMF) | Yes | Messages stored/forwarded, need FS |
| High-value destinations | Yes | Protect past communications |

### Ratchet Enforcement

Destinations can require senders to use ratchets:

```c
destination_enforce_ratchets(dest);  // Reject packets using static key
```

For the full cryptographic details of how ratchets provide forward secrecy, see [Appendix A: Ratchet-Based Forward Secrecy](appendix-a-security.md#a8-ratchet-based-forward-secrecy).

## 5.11 Summary

| Destination Type | Encryption | Use Case |
|------------------|------------|----------|
| SINGLE (0x00) | Per-identity keys | Private communication |
| GROUP (0x01) | Shared group key | Multicast |
| PLAIN (0x02) | None | Public broadcast |

| Component | Purpose |
|-----------|---------|
| Identity | Cryptographic key pair |
| App Name | Human-readable identifier |
| Aspects | Sub-service qualifiers |
| Hash | 16-byte network address |

Key operations:
- **Register**: Make destination receive packets
- **Announce**: Broadcast existence to network
- **Send**: Transmit data to destination
- **Prove**: Confirm receipt of packet

[The next chapter covers **transport layer framing** - how packets are sent over physical media.](06-framing.md)
