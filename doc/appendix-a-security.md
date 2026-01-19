# Appendix A: Security Concepts for Protocol Implementers

This appendix explains the security concepts underlying Reticulum's design. Understanding these concepts is essential for implementing the protocol correctly and avoiding subtle vulnerabilities.

## A.1 Common Network Attacks

### Eavesdropping (Passive Attack)

**What it is**: An attacker monitors network traffic without modifying it.

```
    Alice ----[Message]----> Bob
                  |
              [Attacker]
              (listening)
```

**What attacker learns**:
- Message contents (if unencrypted)
- Who is communicating with whom (metadata)
- Timing and frequency of communication
- Message sizes

**How Reticulum defends**:
- All payloads encrypted with Fernet (AES-256-CBC + HMAC)
- Destination addresses are hashes (not human-readable)
- Link communication uses derived symmetric keys

**What Reticulum does NOT hide**:
- That communication is happening
- Approximate message sizes
- Network topology (who forwards to whom)

### Man-in-the-Middle (MITM) Attack

**What it is**: Attacker intercepts communication and can modify or inject messages.

```
    Alice -----> [Attacker] -----> Bob
                     |
                (intercepts,
                 modifies,
                 or injects)
```

**Attack scenario**:
```
1. Alice wants to establish link with Bob
2. Attacker intercepts LINKREQUEST
3. Attacker sends own LINKREQUEST to Bob
4. Bob responds with PROOF to Attacker
5. Attacker creates fake PROOF for Alice
6. Alice thinks she's talking to Bob, but talks to Attacker
```

**How Reticulum defends**:
- Link proofs are signed with destination's Ed25519 key
- Alice knows Bob's public key (from announce or out-of-band)
- Alice verifies signature using Bob's known public key
- Attacker cannot forge Bob's signature without Bob's private key

**Critical implementation point**:
```c
// CORRECT: Verify using DESTINATION's known public key
ed25519_verify(proof_signature, signed_data, destination_ed25519_pub);

// WRONG: Verify using key FROM THE PROOF (attacker could substitute their own)
ed25519_verify(proof_signature, signed_data, proof_ed25519_pub);  // INSECURE!
```

### Replay Attack

**What it is**: Attacker records a valid message and retransmits it later.

```
Time T1: Alice ----[Valid Message]----> Bob
                         |
                    [Attacker]
                    (records)

Time T2: Attacker ----[Same Message]----> Bob
         Bob thinks this is a new message from Alice!
```

**Attack scenarios**:
- Replay a "transfer $100" message multiple times
- Replay an old announce to pollute routing tables
- Replay a link request to confuse state machines

**How Reticulum defends against announce replay**:

```
Announce contains:
  - 5 random bytes (unique per announce)
  - 5-byte timestamp (when announce was created)

Receiver stores recent random blobs (up to 64 per destination)
If incoming random blob matches stored one → reject as replay
```

**How Reticulum defends against link replay**:
- Link ID is hash of packet contents including ephemeral keys
- Each link uses fresh ephemeral keys
- Replaying old LINKREQUEST produces same link ID
- Receiver can detect duplicate link IDs

**How Fernet defends against replay**:
- Each Fernet token contains random 16-byte IV
- Same plaintext produces different ciphertext each time
- Application must track seen messages if replay is a concern

### Tampering (Active Attack)

**What it is**: Attacker modifies messages in transit.

```
    Alice ----[Message: "Pay Bob $100"]----> ???
                         |
                    [Attacker]
                    (modifies)
                         |
                    [Message: "Pay Eve $999"]----> Bob
```

**How Reticulum defends**:
- Fernet includes HMAC-SHA256 over ciphertext
- Any modification invalidates the HMAC
- Receiver rejects packets with invalid HMAC

```c
// Fernet verification (simplified)
computed_hmac = HMAC_SHA256(hmac_key, version || iv || ciphertext);
if (memcmp(computed_hmac, received_hmac, 32) != 0) {
    return ERROR_TAMPERED;  // Reject!
}
// Only decrypt AFTER HMAC verification passes
```

### Denial of Service (DoS)

**What it is**: Attacker overwhelms system resources to prevent legitimate use.

**Attack vectors in Reticulum**:
- Flood with announces to fill path tables
- Flood with link requests to exhaust connection state
- Send huge resources to fill memory
- Replay old packets to waste CPU on crypto

**How Reticulum defends**:
- Announce rate limiting (per destination)
- Path table size limits
- Resource flow control (window-based)
- Packet deduplication (reject already-seen packets)
- Hop limit prevents infinite forwarding loops

**What implementations must do**:
```c
// Always have limits
#define MAX_PATH_ENTRIES 4096
#define MAX_PENDING_LINKS 128
#define MAX_PACKET_HASH_CACHE 1024

// Always have timeouts
#define LINK_PROOF_TIMEOUT_MS 15000
#define PATH_ENTRY_TIMEOUT_MS (7 * 24 * 60 * 60 * 1000)
```

## A.2 Cryptographic Security Properties

### Confidentiality

**Definition**: Only the intended recipient can read the message.

**Provided by**: Encryption (AES in Reticulum)

**What it means for implementation**:
- Plaintext never transmitted on wire
- Encryption keys never transmitted in clear
- Memory containing plaintext should be zeroed after use

```c
// After decryption, zero the key
process_plaintext(plaintext, len);
sodium_memzero(decryption_key, 32);  // Clear key from memory
```

### Integrity

**Definition**: Detect if a message was modified in transit.

**Provided by**: Message Authentication Code (HMAC-SHA256 in Fernet)

**What it means for implementation**:
- Always verify HMAC before processing decrypted data
- Use constant-time comparison to prevent timing attacks

```c
// CORRECT: Constant-time comparison
if (sodium_memcmp(computed_hmac, received_hmac, 32) != 0) {
    return ERROR_INTEGRITY;
}

// WRONG: Variable-time comparison (timing attack!)
if (memcmp(computed_hmac, received_hmac, 32) != 0) {  // INSECURE!
    return ERROR_INTEGRITY;
}
```

### Authentication

**Definition**: Verify the identity of the sender.

**Provided by**: Digital signatures (Ed25519 in Reticulum)

**What it means for implementation**:
- Signature verification proves knowledge of private key
- Always verify against a TRUSTED public key
- Don't trust public keys received in the same message as signature

```c
// CORRECT: Verify against known destination public key
bool verified = ed25519_verify(signature, data, destination->ed25519_pub);

// WRONG: Verify against key from unverified source
bool verified = ed25519_verify(signature, data, packet->claimed_pubkey);  // INSECURE!
```

### Non-repudiation

**Definition**: Sender cannot deny having sent the message.

**Provided by**: Digital signatures (optional in Reticulum)

**Note**: Regular link data is encrypted but not signed. The sender could deny sending it. If non-repudiation is needed, application layer must add signatures.

## A.3 Forward Secrecy

### The Problem Without Forward Secrecy

```
Traditional encryption:

Alice has long-term key pair: (alice_priv, alice_pub)
Bob has long-term key pair: (bob_priv, bob_pub)

Message encryption:
  shared = ECDH(alice_priv, bob_pub)  // Same every time!
  ciphertext = encrypt(shared, plaintext)

Attack scenario:
  1. Attacker records all ciphertext (can't decrypt yet)
  2. Years later, attacker compromises alice_priv
  3. Attacker computes: shared = ECDH(alice_priv, bob_pub)
  4. Attacker decrypts ALL recorded messages!
```

### Forward Secrecy Solution

```
With ephemeral keys (what Reticulum does):

Each link establishment:
  Alice generates FRESH key pair: (eph_alice_priv, eph_alice_pub)
  Bob generates FRESH key pair: (eph_bob_priv, eph_bob_pub)

  shared = ECDH(eph_alice_priv, eph_bob_pub)
  link_key = HKDF(shared, link_id)

  // After key derivation, ephemeral private keys are DELETED
  delete(eph_alice_priv)
  delete(eph_bob_priv)

Attack scenario:
  1. Attacker records all ciphertext
  2. Years later, attacker compromises alice's LONG-TERM key
  3. Attacker CANNOT decrypt past link traffic!
  4. Why? The ephemeral keys were deleted. The shared secret
     cannot be reconstructed.
```

### Implementation Requirements

```c
// Ephemeral keys MUST be:
// 1. Generated fresh for each link
// 2. Never stored persistently
// 3. Zeroed from memory after key derivation

void establish_link(Link *link) {
    // Generate ephemeral keys
    uint8_t eph_priv[32], eph_pub[32];
    crypto_box_keypair(eph_pub, eph_priv);

    // ... perform key exchange ...

    // Derive link key
    derive_link_key(link, eph_priv, peer_pub);

    // CRITICAL: Zero ephemeral private key immediately
    sodium_memzero(eph_priv, 32);

    // eph_priv is now gone forever - forward secrecy achieved
}
```

### What Forward Secrecy Protects Against

| Scenario | Without FS | With FS |
|----------|-----------|---------|
| Long-term key compromised | All past messages exposed | Only future messages at risk |
| Server seized by adversary | Historical data decryptable | Historical data safe |
| Key accidentally leaked | Must assume all history compromised | Only new links affected |

## A.4 Why Specific Design Choices Prevent Attacks

### Why Include Destination Hash in Signed Announce Data

```
Announce signature covers:
  destination_hash || public_key || name_hash || random_hash || app_data

But destination_hash is NOT transmitted in announce!
It's derived from public_key by receiver.

Why sign something that's derived?

Attack without destination_hash in signature:
  1. Alice announces destination D1 with keys (pub_x, pub_e)
  2. Attacker creates different destination D2 with SAME keys
     (different app_name produces different destination_hash)
  3. Attacker replays Alice's announce for D2
  4. Receivers think Alice is announcing D2!

Defense:
  - Signature binds specific destination_hash to the keys
  - Attacker can't use signature for different destination
  - Derived destination_hash must match signed destination_hash
```

### Why 83 Bytes Signed vs 99 Bytes in Proof

```
Link proof structure:

SIGNED DATA (83 bytes):
  link_id (16) + responder_x25519 (32) + responder_ed25519 (32) + signalling (3)

PROOF PACKET (99 bytes):
  signature (64) + responder_x25519 (32) + signalling (3)

Why isn't responder_ed25519 in the proof packet?

Answer: The initiator ALREADY KNOWS the responder's Ed25519 key!
  - From the destination's announce, OR
  - From out-of-band configuration

Including it would be:
  1. Redundant (wastes bandwidth)
  2. Potentially dangerous (initiator might use wrong key)

The proof says: "I have the private key for the Ed25519 public key
you already know for this destination."
```

### Why Responder Signs THEIR Keys, Not Initiator's Keys

```
WRONG approach (signing initiator's keys):
  signed_data = link_id + initiator_x25519 + initiator_ed25519 + signalling

  Problem: This only proves responder received initiator's keys.
           Attacker could intercept and create their own response!

CORRECT approach (signing responder's own keys):
  signed_data = link_id + responder_x25519 + responder_ed25519 + signalling

  This proves: "I am the destination. Here are MY ephemeral keys
               for this link. Signed with my identity key."

  Initiator verifies:
    1. Signature valid for known destination public key ✓
    2. Therefore responder has destination's private key ✓
    3. Therefore responder IS the destination ✓
```

### Why Fernet Uses Encrypt-then-MAC

```
Two approaches to authenticated encryption:

MAC-then-Encrypt:
  1. mac = HMAC(key, plaintext)
  2. ciphertext = Encrypt(key, plaintext || mac)

  Decryption:
  1. decrypted = Decrypt(key, ciphertext)  // DECRYPT FIRST
  2. verify mac                             // Then verify

  VULNERABILITY: Padding oracle attack
    - Attacker sends modified ciphertext
    - Server decrypts (before MAC check)
    - Server returns error based on padding validity
    - Error timing/type leaks information about plaintext!

Encrypt-then-MAC (what Fernet uses):
  1. ciphertext = Encrypt(key, plaintext)
  2. mac = HMAC(key, ciphertext)

  Decryption:
  1. verify mac                            // VERIFY FIRST
  2. if invalid: reject immediately        // No decryption attempted
  3. decrypted = Decrypt(key, ciphertext)  // Only if MAC valid

  SECURE: Attacker cannot trigger decryption of modified data
```

### Why Random Blobs Have Timestamps

```
Random blob structure (10 bytes):
  [5 random bytes] [5 byte timestamp]

Why include timestamp?

Scenario: Same path, multiple valid announces

Without timestamp:
  - Announce A1 arrives via 3-hop path
  - Later, Announce A2 arrives via 3-hop path
  - Both have same hop count
  - Which is "better"? Can't tell!

With timestamp:
  - A1 has emission_time = T1
  - A2 has emission_time = T2
  - If T2 > T1, A2 is newer → use A2's path

  Rationale: Newer announce reflects current network state better
```

## A.5 Timing Attacks and Constant-Time Operations

### What is a Timing Attack?

```
Vulnerable comparison:

bool check_password(char *input, char *correct) {
    for (int i = 0; i < strlen(correct); i++) {
        if (input[i] != correct[i]) {
            return false;  // Returns EARLY on mismatch
        }
    }
    return true;
}

Attack:
  - Attacker tries "a000000" → fails at position 0 → fast
  - Attacker tries "p000000" → fails at position 1 → slightly slower
  - Attacker learns first character is 'p'!
  - Repeat for each position
```

### Where Timing Attacks Apply in Reticulum

| Operation | Timing-Sensitive? | Why |
|-----------|------------------|-----|
| HMAC comparison | YES | Reveals how many bytes match |
| Signature verification | Depends on library | Some libraries are constant-time |
| Hash comparison | YES | Same as HMAC |
| Public data comparison | NO | Attacker already knows public data |
| Destination lookup | NO | Destinations are public |

### Constant-Time Implementation

```c
// CORRECT: Constant-time comparison
int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];  // Accumulate differences
    }
    return diff == 0;  // Only check at the end
}

// Or use library function:
#include <sodium.h>
if (sodium_memcmp(computed_hmac, received_hmac, 32) == 0) {
    // Valid
}
```

### Memory Zeroing

```c
// WRONG: Compiler might optimize this away
memset(secret_key, 0, 32);

// CORRECT: Guaranteed to zero memory
sodium_memzero(secret_key, 32);

// Or use volatile:
void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = ptr;
    while (len--) *p++ = 0;
}
```

## A.6 Key Compromise and Recovery

### What Happens If Long-Term Key is Compromised?

**Identity (X25519 + Ed25519) compromised**:

| Impact | Severity | Mitigation |
|--------|----------|------------|
| Attacker can decrypt future messages TO you | HIGH | Generate new identity |
| Attacker can impersonate you (sign announces) | HIGH | Revoke old identity (out-of-band) |
| Attacker can decrypt PAST link traffic | NONE | Forward secrecy protects past |
| Attacker can establish links AS you | HIGH | Generate new identity |

**Link key compromised**:

| Impact | Severity | Mitigation |
|--------|----------|------------|
| Attacker can decrypt that link's traffic | HIGH | Close link, establish new one |
| Other links affected | NONE | Each link has independent key |
| Past links affected | NONE | Forward secrecy |

### Recovery Steps

```
1. Generate new identity (new X25519 + Ed25519 key pairs)
2. Update all systems that trust old identity
3. Announce new identity
4. Old identity should be considered hostile
5. Past traffic remains protected (forward secrecy)
```

## A.8 Ratchet-Based Forward Secrecy

Links provide forward secrecy through ephemeral key exchange during establishment. But what about single packets sent directly to a SINGLE destination without establishing a link?

### The Problem

```
Standard SINGLE destination encryption:

1. Sender knows destination's static X25519 public key (from announce)
2. Sender generates ephemeral key pair
3. shared_secret = ECDH(ephemeral_private, destination_static_public)
4. Encrypt message with derived key

Attack scenario:
  - Attacker records ciphertext + ephemeral public key
  - Later, attacker compromises destination's static private key
  - Attacker computes: shared_secret = ECDH(destination_static_private, ephemeral_public)
  - Attacker decrypts ALL recorded messages!
```

### The Solution: Ratchets

Ratchets are rotating X25519 key pairs that destinations periodically generate and announce:

```
With ratchets enabled:

1. Destination generates ratchet key pair, includes public key in announce
2. Sender encrypts to ratchet public key (not static identity key)
3. Destination rotates ratchet keys periodically (default: 30 min)
4. Old ratchet private keys are eventually deleted

Attack scenario with ratchets:
  - Attacker records ciphertext
  - Later, attacker compromises destination's static private key
  - Attacker CANNOT decrypt: message was encrypted to ratchet key
  - Ratchet private key was deleted after rotation
```

### Ratchet Lifecycle

```
Destination                                    Sender
    |                                            |
    |-- [Announce with ratchet_pub_1] --------->|
    |                                            | stores ratchet_pub_1
    |                                            |
    |<-------- [Packet encrypted to ratchet_1] -|
    |   decrypt with ratchet_prv_1              |
    |                                            |
    |   (30 minutes pass, rotation triggered)   |
    |   generate ratchet_2                      |
    |   keep ratchet_1 for decryption           |
    |                                            |
    |-- [Announce with ratchet_pub_2] --------->|
    |                                            | updates to ratchet_pub_2
    |                                            |
    |<-------- [Packet encrypted to ratchet_2] -|
    |   decrypt with ratchet_prv_2              |
    |                                            |
    |   (many rotations later)                  |
    |   ratchet_1 deleted (beyond retention)    |
```

### Implementation Details

```c
#define RATCHET_INTERVAL_SEC    (30 * 60)   // 30 minutes
#define RATCHET_RETENTION_COUNT 512          // Keep this many old ratchets
#define RATCHET_EXPIRY_SEC      (30 * 24 * 60 * 60)  // 30 days

typedef struct {
    uint8_t private_key[32];  // X25519 private key
    uint64_t created_at;      // Timestamp
} Ratchet;

typedef struct {
    Ratchet *ratchets;        // Array, index 0 = newest
    size_t count;
    uint64_t last_rotation;
    bool enforce_ratchets;    // Reject non-ratchet packets?
} RatchetState;

void rotate_ratchets(Destination *dest) {
    uint64_t now = time(NULL);
    if (now < dest->ratchet_state.last_rotation + RATCHET_INTERVAL_SEC) {
        return;  // Too soon
    }

    // Generate new ratchet
    Ratchet new_ratchet;
    crypto_box_keypair(new_ratchet.public_key, new_ratchet.private_key);
    new_ratchet.created_at = now;

    // Insert at front (newest first)
    insert_ratchet_at_front(&dest->ratchet_state, &new_ratchet);

    // Trim old ratchets
    while (dest->ratchet_state.count > RATCHET_RETENTION_COUNT) {
        remove_oldest_ratchet(&dest->ratchet_state);
    }

    dest->ratchet_state.last_rotation = now;
}
```

### Decryption with Ratchets

```c
bool decrypt_with_ratchets(Destination *dest,
                           const uint8_t *ciphertext, size_t len,
                           uint8_t *plaintext, size_t *out_len) {
    // Extract sender's ephemeral public key from ciphertext
    uint8_t sender_ephemeral[32];
    memcpy(sender_ephemeral, ciphertext, 32);

    // Try each ratchet (newest first)
    for (size_t i = 0; i < dest->ratchet_state.count; i++) {
        uint8_t shared[32];
        crypto_scalarmult(shared,
                          dest->ratchet_state.ratchets[i].private_key,
                          sender_ephemeral);

        if (try_decrypt(shared, ciphertext + 32, len - 32,
                        plaintext, out_len)) {
            return true;  // Success with this ratchet
        }
    }

    // No ratchet worked - try static identity key?
    if (dest->ratchet_state.enforce_ratchets) {
        return false;  // Reject: ratchets required
    }

    // Fallback to static key
    return decrypt_with_static_key(dest, ciphertext, len,
                                   plaintext, out_len);
}
```

### Security Properties

| Property | Without Ratchets | With Ratchets |
|----------|-----------------|---------------|
| Forward secrecy | No | Yes (after key deletion) |
| Static key compromise | All past messages exposed | Only recent messages at risk |
| Announce size | 148+ bytes | 180+ bytes (+32 for ratchet) |
| Receiver state | Stateless | Must store ratchet keys |
| Sender state | Cache destination key | Cache ratchet key |

### When Ratchets Don't Help

Ratchets provide forward secrecy, but with limitations:

1. **Retention window**: Messages encrypted to retained ratchets are still vulnerable
2. **Ratchet key compromise**: If a specific ratchet key is stolen (not the static key), messages to that ratchet are exposed
3. **No link-level protection**: Ratchets protect single packets, not link traffic (links have their own FS)
4. **Receiver must rotate**: If receiver never announces, ratchet never rotates

### Comparison with Link Forward Secrecy

| Aspect | Link FS | Ratchet FS |
|--------|---------|------------|
| Key exchange | Per-link ECDH | Per-announce rotation |
| Granularity | Per link | Per rotation period |
| Bidirectional | Required | Not required |
| Latency | Link establishment overhead | None (use cached ratchet) |
| Best for | Interactive communication | Asynchronous messaging |

## A.9 Security Checklist for Implementers

### Cryptographic Operations

- [ ] Use established crypto libraries (libsodium, OpenSSL)
- [ ] Never implement your own crypto primitives
- [ ] Use constant-time comparison for all secret data
- [ ] Zero sensitive memory after use
- [ ] Generate ephemeral keys fresh for each link
- [ ] Delete ephemeral private keys after key derivation

### Protocol Operations

- [ ] Verify signatures against KNOWN public keys, not received ones
- [ ] Verify HMAC before decryption (encrypt-then-MAC order)
- [ ] Check packet lengths before parsing
- [ ] Implement rate limiting for announces
- [ ] Implement deduplication for packets
- [ ] Set timeouts for all pending operations

### General Security

- [ ] Log security-relevant events (failed verifications, rate limits)
- [ ] Don't log sensitive data (keys, plaintexts)
- [ ] Handle errors without leaking information
- [ ] Test against known attack patterns
- [ ] Review crypto library documentation for proper usage
