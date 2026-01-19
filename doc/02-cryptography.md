# Chapter 2: Cryptographic Primitives

This chapter introduces the cryptographic building blocks used by Reticulum. If you're unfamiliar with cryptography, read this chapter carefully - everything else builds on it.

## 2.1 Hash Functions

A **hash function** takes input of any size and produces output of fixed size. Reticulum uses SHA-256, which always produces 32 bytes (256 bits).

### Properties of Cryptographic Hashes

```
Input:  "Hello, World!" (13 bytes)
SHA-256: ae97eca8f8ae1672bcc5c79e3fbafd8ee86f65f775e2250a291d3788b7a8af95 (32 bytes)

Input:  "Hello, World!!" (14 bytes - one character added)
SHA-256: 629f264d107ccb8966bf751251ea1fed1171809ea1040929584a7d19caef71fd (32 bytes - completely different)
```

Key properties:

1. **Deterministic**: Same input always gives same output
2. **One-way**: Cannot reverse the hash to find the input
3. **Collision-resistant**: Hard to find two inputs with the same hash
4. **Avalanche effect**: Small input changes completely change output

### How Reticulum Uses Hashes

- **Address derivation**: Destination addresses are truncated hashes of public keys
- **Packet identification**: Link IDs are hashes of packet contents
- **Integrity verification**: Detect tampering with data

### Computing SHA-256

In C, you might use OpenSSL:

```c
#include <openssl/sha.h>

void compute_sha256(const uint8_t *input, size_t len, uint8_t output[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input, len);
    SHA256_Final(output, &ctx);
}
```

### Truncated Hashes

Reticulum uses **truncated hashes** for addresses - only the first 16 bytes (128 bits) of the SHA-256 output:

```c
void truncated_hash(const uint8_t *input, size_t len, uint8_t output[16]) {
    uint8_t full_hash[32];
    compute_sha256(input, len, full_hash);
    memcpy(output, full_hash, 16);  // Take first 16 bytes
}
```

Why truncate? 128 bits still provides ~2^64 collision resistance (birthday bound), which is sufficient for addressing. Shorter addresses save bandwidth on constrained links.

## 2.2 Symmetric Encryption

**Symmetric encryption** uses the same key to encrypt and decrypt. Both parties must share the secret key.

### AES (Advanced Encryption Standard)

AES is a **block cipher** that encrypts 16-byte blocks:

```
Key:        32 bytes (for AES-256)
Plaintext:  16 bytes (one block)
Ciphertext: 16 bytes (one block)
```

AES itself only handles 16-byte blocks. To encrypt arbitrary data, we need a **mode of operation**.

### CBC Mode (Cipher Block Chaining)

CBC chains blocks together so identical plaintext blocks produce different ciphertext:

```
    Plaintext Block 1    Plaintext Block 2
           |                    |
           v                    v
        [XOR] <-- IV         [XOR] <-- Ciphertext 1
           |                    |
           v                    v
       [AES-256]            [AES-256]
           |                    |
           v                    v
    Ciphertext Block 1   Ciphertext Block 2
```

The **IV** (Initialization Vector) is a random 16-byte value that ensures the same plaintext encrypts to different ciphertext each time.

### PKCS7 Padding

AES requires input to be a multiple of 16 bytes. PKCS7 padding adds bytes to reach the next multiple:

```
Input:  "Hello" (5 bytes)
Padded: "Hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b" (16 bytes)
        (11 bytes of value 0x0b = 11 added)

Input:  "0123456789ABCDEF" (16 bytes - already aligned)
Padded: "0123456789ABCDEF\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10" (32 bytes)
        (16 bytes of value 0x10 = 16 added - always pad!)
```

### HMAC (Hash-based Message Authentication Code)

HMAC proves that a message hasn't been tampered with:

```
HMAC-SHA256(key, message) → 32-byte authentication tag
```

Unlike a plain hash, HMAC requires the secret key. Only someone with the key can:
- Generate a valid HMAC
- Verify an HMAC is correct

### Fernet Token Format

Reticulum uses a **modified Fernet** format for symmetric encryption. Standard Fernet includes a version byte and 8-byte timestamp, but Reticulum omits both to save bandwidth and avoid leaking timing metadata.

**Reticulum Token Format** (not standard Fernet):
```
+------+------------------+------+
| IV   | Ciphertext       | HMAC |
| 16 B | (variable, padded) | 32 B |
+------+------------------+------+

Overhead: 48 bytes + padding (up to 15 bytes for AES block alignment)
```

1. **IV**: Random 16 bytes for CBC mode
2. **Ciphertext**: AES-CBC encrypted data with PKCS7 padding
3. **HMAC**: HMAC-SHA256 over IV + ciphertext

**Key sizes** (Reticulum supports both):

| Mode | Key Size | Split |
|------|----------|-------|
| AES-128-CBC | 32 bytes | HMAC key (16B) + AES key (16B) |
| AES-256-CBC | 64 bytes | HMAC key (32B) + AES key (32B) |

Links use AES-256-CBC (64-byte derived key) by default.

### Encrypt-then-MAC

Fernet uses **encrypt-then-MAC**: encrypt first, then HMAC the ciphertext. This is important:

```
WRONG (MAC-then-encrypt):
  1. HMAC(plaintext)
  2. Encrypt(plaintext || HMAC)
  Problem: Attacker can modify ciphertext without detection

RIGHT (encrypt-then-MAC):
  1. Encrypt(plaintext) → ciphertext
  2. HMAC(ciphertext)
  Benefit: Tampered ciphertext rejected before decryption
```

## 2.3 Asymmetric Cryptography

**Asymmetric** (or **public-key**) cryptography uses key pairs:
- **Private key**: Secret, never shared
- **Public key**: Can be freely distributed

Reticulum uses two asymmetric algorithms:
- **X25519**: Key exchange (derive shared secrets)
- **Ed25519**: Digital signatures

### Elliptic Curve Cryptography Basics

Both algorithms use **elliptic curves**. An elliptic curve is a mathematical structure where:

```
Private key:  A large random number (scalar)
Public key:   A point on the curve = private_key × G
              where G is a standard "generator point"
```

The security comes from the **discrete logarithm problem**: given the public key (a point), it's computationally infeasible to find the private key (the scalar).

You don't need to understand the math deeply. Just know:
- Keys are 32 bytes each
- Public keys can be computed from private keys (one-way)
- Certain operations are possible with key pairs

### X25519: Key Exchange

X25519 is an **Elliptic Curve Diffie-Hellman (ECDH)** algorithm. It lets two parties derive a shared secret:

```
Alice:                              Bob:
  private_key_a (32 bytes)            private_key_b (32 bytes)
  public_key_a = derive(private_a)    public_key_b = derive(private_b)

        public_key_a  -------->
                      <--------  public_key_b

  shared = X25519(private_a, public_key_b)    shared = X25519(private_b, public_key_a)

  Both compute the SAME 32-byte shared secret!
```

An eavesdropper who sees both public keys **cannot** compute the shared secret.

In C (using libsodium):

```c
#include <sodium.h>

// Generate key pair
uint8_t private_key[32], public_key[32];
crypto_box_keypair(public_key, private_key);

// Compute shared secret
uint8_t shared_secret[32];
uint8_t peer_public[32];  // received from peer
crypto_scalarmult(shared_secret, private_key, peer_public);
```

### Ed25519: Digital Signatures

Ed25519 creates **digital signatures** that prove:
1. The message was created by the private key holder
2. The message hasn't been modified

```
Signing (with private key):
  signature = Ed25519_sign(private_key, message)
  → 64-byte signature

Verification (with public key):
  valid = Ed25519_verify(public_key, message, signature)
  → true/false
```

In C (using libsodium):

```c
#include <sodium.h>

// Generate key pair
uint8_t private_key[64], public_key[32];  // Ed25519 private key is 64 bytes
crypto_sign_keypair(public_key, private_key);

// Sign a message
uint8_t signature[64];
uint8_t message[] = "Hello";
crypto_sign_detached(signature, NULL, message, 5, private_key);

// Verify signature
if (crypto_sign_verify_detached(signature, message, 5, public_key) == 0) {
    // Signature is valid
}
```

### Key Sizes Summary

| Algorithm | Private Key | Public Key | Output |
|-----------|-------------|------------|--------|
| X25519 | 32 bytes | 32 bytes | 32-byte shared secret |
| Ed25519 | 32 bytes (seed) | 32 bytes | 64-byte signature |

**Ed25519 key storage note**: Libraries handle Ed25519 private keys differently:

- **Seed**: 32 bytes - the actual secret, can regenerate everything else
- **libsodium format**: 64 bytes - seed (32B) concatenated with public key (32B)
- **Expanded key**: 64 bytes - internal signing key derived from seed

libsodium's `crypto_sign_keypair()` returns a 64-byte private key (seed + public key). To use a 32-byte seed, use `crypto_sign_seed_keypair()`:

```c
uint8_t seed[32];           // 32-byte seed (the true private key)
uint8_t sk[64], pk[32];     // libsodium's storage format
crypto_sign_seed_keypair(pk, sk, seed);  // Generate from seed
// sk now contains: seed || public_key
```

Reticulum stores identities as the 32-byte seed for each key (X25519 + Ed25519 = 64 bytes total for both keys).

## 2.4 Key Derivation

The output of X25519 is a **shared secret**, but it's not suitable to use directly as an encryption key. We need **key derivation** to:

1. Expand short secrets into longer keys
2. Mix in additional context
3. Derive multiple keys from one secret

### HKDF (HMAC-based Key Derivation Function)

HKDF has two phases:

```
Extract:  PRK = HKDF-Extract(salt, input_key_material)
Expand:   output = HKDF-Expand(PRK, info, length)
```

In practice:

```c
// Derive a 64-byte key from a 32-byte shared secret
uint8_t shared_secret[32];  // from X25519
uint8_t salt[16];           // optional, can be NULL
uint8_t derived_key[64];

HKDF_SHA256(
    derived_key, 64,        // output buffer and length
    shared_secret, 32,      // input key material
    salt, 16,               // salt (or NULL, 0)
    NULL, 0                 // info/context (or NULL, 0)
);
```

### Reticulum's Key Derivation

When establishing a link, Reticulum:

1. Performs X25519 key exchange → 32-byte shared secret
2. Uses HKDF-SHA256 with the link ID as salt
3. Derives 32 or 64 bytes (depending on Fernet mode)

```
shared_secret = X25519(my_private, peer_public)
derived_key = HKDF-SHA256(
    key_material = shared_secret,
    salt = link_id,           // 16-byte link identifier
    info = empty,
    length = 32 or 64 bytes
)
```

The derived key is then used for Fernet encryption on the link.

## 2.5 Putting It Together

Here's how the cryptographic primitives combine in Reticulum:

### Identity Creation

```
1. Generate X25519 key pair:
   - x25519_private (32 bytes) - kept secret
   - x25519_public (32 bytes) - shared

2. Generate Ed25519 key pair:
   - ed25519_private (32 bytes) - kept secret
   - ed25519_public (32 bytes) - shared

3. Compute address hash:
   - full_hash = SHA256(x25519_public || ed25519_public)
   - address = full_hash[0:16]  // truncated to 16 bytes
```

### Link Establishment

```
Initiator:                           Responder:
1. Generate ephemeral X25519         1. Receive request
   key pair                          2. Generate ephemeral X25519
2. Send request with public key         key pair
                                     3. Compute shared secret
    ----[x25519_pub]---->            4. Derive encryption key
                                     5. Sign proof data
    <---[signature + x25519_pub]---  6. Send proof

3. Verify signature
4. Compute shared secret
5. Derive encryption key
6. Link is active
```

### Encrypted Communication

```
1. Sender has derived_key (32 bytes)
2. To send message:
   - Generate random IV (16 bytes)
   - Pad message to block boundary
   - Encrypt with AES-256-CBC
   - Compute HMAC-SHA256
   - Assemble Fernet token

3. Receiver has same derived_key
4. To receive:
   - Verify HMAC (reject if invalid)
   - Decrypt with AES-256-CBC
   - Remove padding
   - Process message
```

## 2.6 Security Considerations

### Random Number Generation

All security depends on **cryptographically secure random numbers**:

```c
// GOOD: Use OS-provided CSPRNG
#include <sodium.h>
randombytes_buf(buffer, length);

// or on Linux:
#include <sys/random.h>
getrandom(buffer, length, 0);

// BAD: Never use these for cryptography
rand();      // predictable
random();    // predictable
time(NULL);  // predictable
```

### Key Management

- Private keys must never be transmitted
- Ephemeral keys provide forward secrecy
- Derived keys should be zeroed after use

```c
// Zero sensitive memory when done
sodium_memzero(private_key, 32);
sodium_memzero(derived_key, 64);
```

### Side-Channel Attacks

Constant-time implementations prevent timing attacks:

```c
// GOOD: Constant-time comparison
if (sodium_memcmp(computed_hmac, received_hmac, 32) == 0) {
    // Valid
}

// BAD: Variable-time comparison leaks information
if (memcmp(computed_hmac, received_hmac, 32) == 0) {
    // Timing attack possible
}
```

## 2.7 Summary

| Primitive | Algorithm | Purpose | Key Size | Output |
|-----------|-----------|---------|----------|--------|
| Hash | SHA-256 | Addressing, integrity | N/A | 32 bytes |
| Symmetric | AES-256-CBC | Encryption | 32 bytes | Variable |
| MAC | HMAC-SHA256 | Authentication | 32 bytes | 32 bytes |
| Key Exchange | X25519 | Shared secrets | 32 bytes | 32 bytes |
| Signatures | Ed25519 | Authentication | 32 bytes | 64 bytes |
| Key Derivation | HKDF-SHA256 | Key expansion | Variable | Variable |

Reticulum combines these into the **Fernet** token format for symmetric encryption and uses X25519+HKDF for key agreement.

The next chapter explains how these primitives are used to construct **Identities** - the foundation of Reticulum's addressing system.
