# Chapter 3: Identity and Addressing

In Reticulum, your **identity** is a pair of cryptographic keys. Your **address** is derived from those keys. This chapter explains how identities work and how addresses are computed.

## 3.1 The Identity Concept

### Traditional vs Cryptographic Identity

In traditional networks:
- Your identity is a username in someone else's database
- Your address is assigned by someone else (DHCP, ISP)
- Trust comes from institutions (certificate authorities)

In Reticulum:
- Your identity is a key pair you generate yourself
- Your address is mathematically derived from your public keys
- Trust comes from cryptographic proofs

### What is an Identity?

A Reticulum identity consists of two key pairs:

```
Identity = {
    X25519 key pair:   For key exchange (encryption)
    Ed25519 key pair:  For signatures (authentication)
}
```

Each key pair has:
- **Private key**: 32 bytes, kept secret
- **Public key**: 32 bytes, shared freely

The **public identity** (what others see) is:
```
Public Identity = X25519_public (32 bytes) || Ed25519_public (32 bytes)
                = 64 bytes total
```

### Self-Sovereign Identity

Key insight: **you create your own identity**.

```c
void create_identity(uint8_t priv_x25519[32], uint8_t pub_x25519[32],
                     uint8_t priv_ed25519[32], uint8_t pub_ed25519[32]) {
    // Generate X25519 key pair
    randombytes_buf(priv_x25519, 32);
    crypto_scalarmult_base(pub_x25519, priv_x25519);

    // Generate Ed25519 key pair
    randombytes_buf(priv_ed25519, 32);
    crypto_sign_seed_keypair(pub_ed25519, priv_ed25519_full, priv_ed25519);
}
```

No registration. No permission. No authority. You generate random bytes, and you have an identity.

### Identity Persistence

Identities can be:
- **Ephemeral**: Generated for a single session, then discarded
- **Persistent**: Saved to disk and reused across sessions

For persistent identities, store the private keys securely:

```c
// Save identity (PROTECT THIS FILE!)
void save_identity(const char *path,
                   const uint8_t priv_x25519[32],
                   const uint8_t priv_ed25519[32]) {
    FILE *f = fopen(path, "wb");
    fwrite(priv_x25519, 1, 32, f);
    fwrite(priv_ed25519, 1, 32, f);
    fclose(f);
    chmod(path, 0600);  // Owner read/write only
}
```

**Warning: Never share identity files between nodes.** If two nodes use the same identity (e.g., by copying the identity file), both can announce and receive packets for that destination. This causes:
- **Path instability**: Announces from different network locations overwrite each other
- **Message delivery issues**: Packets may be routed to either node unpredictably
- **No conflict detection**: Reticulum does not warn about duplicate identities (only about hash collisions with *different* keys)

Each node should generate its own unique identity.

## 3.2 Address Hashing

### The Address Problem

Network addresses need to be:
- Globally unique (no collisions)
- Compact (bandwidth is precious)
- Self-certifying (prove ownership)

IP addresses solve uniqueness through central allocation. Reticulum uses **hash-based addressing** instead.

### Computing the Address Hash

The address is derived from the public identity:

```
full_hash = SHA256(X25519_public || Ed25519_public)
address_hash = full_hash[0:16]  // First 128 bits
```

In code:

```c
void compute_address_hash(const uint8_t pub_x25519[32],
                          const uint8_t pub_ed25519[32],
                          uint8_t address[16]) {
    uint8_t full_hash[32];
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, pub_x25519, 32);
    SHA256_Update(&ctx, pub_ed25519, 32);
    SHA256_Final(full_hash, &ctx);

    memcpy(address, full_hash, 16);  // Truncate to 128 bits
}
```

### Properties of Hash-Based Addresses

1. **Deterministic**: Same keys always produce same address
2. **Collision-resistant**: ~2^64 work to find collision (birthday bound)
3. **Self-certifying**: Knowing the address lets you verify public keys

### Why 128 Bits?

Full SHA-256 is 256 bits, but Reticulum truncates to 128 bits. Why?

- **Bandwidth**: 16 bytes vs 32 bytes saves 16 bytes per packet
- **Security**: 128 bits provides ~2^64 collision resistance
- **Practicality**: Finding collisions requires massive computation

For comparison:
- IPv4: 32 bits (4 billion addresses, exhausted)
- IPv6: 128 bits (same as Reticulum)
- Bitcoin addresses: 160 bits

### Address Representation

Addresses are typically shown as hex strings:

```c
void address_to_hex(const uint8_t address[16], char hex[33]) {
    for (int i = 0; i < 16; i++) {
        sprintf(&hex[i*2], "%02x", address[i]);
    }
    hex[32] = '\0';
}

// Example: "a1b2c3d4e5f6789012345678abcdef01"
```

## 3.3 Identity Operations

Identities support several cryptographic operations.

### Signing and Verification

Use Ed25519 to prove authorship:

```c
// Sign data with your identity
void identity_sign(const uint8_t priv_ed25519[32],
                   const uint8_t *data, size_t len,
                   uint8_t signature[64]) {
    // Need full 64-byte private key for signing
    uint8_t full_key[64], pub[32];
    crypto_sign_seed_keypair(pub, full_key, priv_ed25519);
    crypto_sign_detached(signature, NULL, data, len, full_key);
}

// Verify signature against public identity
bool identity_verify(const uint8_t pub_ed25519[32],
                     const uint8_t *data, size_t len,
                     const uint8_t signature[64]) {
    return crypto_sign_verify_detached(signature, data, len, pub_ed25519) == 0;
}
```

### Key Exchange

Use X25519 to establish shared secrets:

```c
// Compute shared secret with another identity
void identity_key_exchange(const uint8_t my_priv_x25519[32],
                           const uint8_t peer_pub_x25519[32],
                           uint8_t shared_secret[32]) {
    crypto_scalarmult(shared_secret, my_priv_x25519, peer_pub_x25519);
}
```

### Encrypting to an Identity

To encrypt data for a specific identity:

1. Generate ephemeral X25519 key pair
2. Compute shared secret with recipient's public key
3. Derive encryption key via HKDF
4. Encrypt with Fernet
5. Include ephemeral public key in output

```c
size_t encrypt_to_identity(const uint8_t recipient_pub_x25519[32],
                           const uint8_t *plaintext, size_t plain_len,
                           uint8_t *output, size_t output_max) {
    // 1. Generate ephemeral key pair
    uint8_t eph_priv[32], eph_pub[32];
    crypto_box_keypair(eph_pub, eph_priv);

    // 2. Compute shared secret
    uint8_t shared[32];
    crypto_scalarmult(shared, eph_priv, recipient_pub_x25519);

    // 3. Derive encryption key
    uint8_t derived[32];
    hkdf_sha256(derived, 32, shared, 32, NULL, 0, NULL, 0);

    // 4. Copy ephemeral public key to output
    memcpy(output, eph_pub, 32);

    // 5. Encrypt with derived key (Fernet format)
    size_t cipher_len = fernet_encrypt(derived, plaintext, plain_len,
                                       output + 32, output_max - 32);

    // 6. Clean up secrets
    sodium_memzero(eph_priv, 32);
    sodium_memzero(shared, 32);
    sodium_memzero(derived, 32);

    return 32 + cipher_len;  // ephemeral_pub + ciphertext
}
```

The recipient decrypts by:
1. Extracting the ephemeral public key
2. Computing the shared secret with their private key
3. Deriving the same encryption key
4. Decrypting the Fernet token

## 3.4 Destination Addresses

In Reticulum, you don't communicate with identities directly. You communicate with **destinations**. A destination's address includes more than just the identity hash.

### Application Names and Aspects

Destinations include:
- **Application name**: String identifying the application
- **Aspect**: Additional qualifier (like a "port")
- **Identity**: The cryptographic identity

### Destination Hash Computation

The name is first "expanded" by concatenating the app name and aspects with dots:
```
expanded_name = "app_name.aspect1.aspect2..."
```

Then the destination hash is computed:
```
name_hash = SHA256(expanded_name_utf8)[0:10]   // First 10 bytes only!
address_hash = SHA256(name_hash || identity_hash)[0:16]
```

Note: The name hash is only **10 bytes** (80 bits), not 16 bytes. This is a Reticulum-specific truncation different from the standard 16-byte address truncation.

### Example

```c
// Application: "myapp", Aspect: "receiver", Identity hash: 0xabcd...

void compute_destination_hash(const char *app_name,
                              const char *aspect,
                              const uint8_t identity_hash[16],
                              uint8_t dest_hash[16]) {
    // Build expanded name: "myapp.receiver"
    char expanded_name[256];
    snprintf(expanded_name, sizeof(expanded_name), "%s.%s", app_name, aspect);

    // Hash expanded name, take first 10 bytes
    uint8_t full_hash[32];
    SHA256((uint8_t*)expanded_name, strlen(expanded_name), full_hash);
    uint8_t name_hash[10];
    memcpy(name_hash, full_hash, 10);  // Only 10 bytes!

    // Combine: name_hash (10 bytes) || identity_hash (16 bytes) = 26 bytes
    uint8_t combined[26];
    memcpy(combined, name_hash, 10);
    memcpy(combined + 10, identity_hash, 16);

    // Final hash, take first 16 bytes
    SHA256(combined, 26, full_hash);
    memcpy(dest_hash, full_hash, 16);
}
```

### Why Include App Name and Aspect?

This design allows:
- **Multiple destinations per identity**: Same identity can host different services
- **Service discovery**: Destination hash encodes what the service is
- **Namespace separation**: Different apps won't collide

## 3.5 Full Hash vs Truncated Hash

Reticulum uses both full (256-bit) and truncated (128-bit) hashes:

| Use Case | Hash Size | Why |
|----------|-----------|-----|
| Address (destination hash) | 128 bits | Bandwidth efficiency |
| Link ID | 128 bits | Bandwidth efficiency |
| Announce hash | 256 bits | Full security |
| Internal operations | 256 bits | No bandwidth constraint |

The truncated hash is always the **first** 128 bits (16 bytes) of the full SHA-256 output.

## 3.6 Identity Recall (Caching)

When you receive an announce or proof, you learn a remote identity's public keys. Reticulum caches these for future use:

```c
typedef struct {
    uint8_t address_hash[16];      // Lookup key
    uint8_t x25519_public[32];     // For encryption
    uint8_t ed25519_public[32];    // For verification
    time_t  last_seen;             // For expiry
} IdentityCache;

// Cache an identity
void cache_identity(IdentityCache *cache, size_t *count,
                    const uint8_t addr[16],
                    const uint8_t x25519[32],
                    const uint8_t ed25519[32]) {
    // Check if already cached
    for (size_t i = 0; i < *count; i++) {
        if (memcmp(cache[i].address_hash, addr, 16) == 0) {
            cache[i].last_seen = time(NULL);
            return;
        }
    }

    // Add new entry
    memcpy(cache[*count].address_hash, addr, 16);
    memcpy(cache[*count].x25519_public, x25519, 32);
    memcpy(cache[*count].ed25519_public, ed25519, 32);
    cache[*count].last_seen = time(NULL);
    (*count)++;
}

// Lookup identity by address
bool lookup_identity(IdentityCache *cache, size_t count,
                     const uint8_t addr[16],
                     uint8_t x25519_out[32],
                     uint8_t ed25519_out[32]) {
    for (size_t i = 0; i < count; i++) {
        if (memcmp(cache[i].address_hash, addr, 16) == 0) {
            memcpy(x25519_out, cache[i].x25519_public, 32);
            memcpy(ed25519_out, cache[i].ed25519_public, 32);
            return true;
        }
    }
    return false;
}
```

This cache is populated by:
- **Announces**: Broadcast identity information
- **Link proofs**: Include responder's public key
- **Explicit recall**: Request identity from network

## 3.7 Hexadecimal Representation

Identities and addresses are often displayed as hex strings:

### Address Hash (16 bytes → 32 hex chars)
```
a1b2c3d4e5f6789012345678abcdef01
```

### Public Identity (64 bytes → 128 hex chars)
```
1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef  (X25519)
fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321  (Ed25519)
```

### Private Identity (64 bytes → 128 hex chars)
**Never share this!**
```
[32 bytes X25519 private][32 bytes Ed25519 private]
```

### Parsing Hex

```c
bool hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    if (strlen(hex) != out_len * 2) return false;

    for (size_t i = 0; i < out_len; i++) {
        char byte[3] = {hex[i*2], hex[i*2+1], '\0'};
        char *end;
        out[i] = strtoul(byte, &end, 16);
        if (*end != '\0') return false;
    }
    return true;
}
```

## 3.8 Summary

| Concept | Size | Description |
|---------|------|-------------|
| Identity | 64 bytes (public) | X25519 pubkey + Ed25519 pubkey |
| Private Identity | 64 bytes | X25519 privkey + Ed25519 privkey |
| Identity Hash | 16 bytes | SHA256(public identity)[0:16] |
| Destination Hash | 16 bytes | SHA256(name + aspects + identity)[0:16] |

Key operations:
- **Sign**: Ed25519(private_key, data) → 64-byte signature
- **Verify**: Ed25519_verify(public_key, data, signature) → bool
- **Key Exchange**: X25519(my_private, peer_public) → 32-byte shared secret
- **Encrypt**: Ephemeral ECDH + HKDF + Fernet

The next chapter explains how data is structured into **packets** for transmission.
