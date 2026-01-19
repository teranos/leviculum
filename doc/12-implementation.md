# Chapter 12: Building a Reticulum Implementation

This chapter provides practical guidance for implementing Reticulum from scratch. We'll cover the minimum viable implementation, component organization, and considerations for different environments.

## 12.1 Implementation Strategy

### Incremental Approach

Don't try to implement everything at once. Build in layers:

```
Phase 1: Foundation
  └── Cryptographic primitives
  └── Identity handling
  └── Basic packet parsing

Phase 2: Communication
  └── HDLC framing
  └── Single interface (TCP)
  └── Packet send/receive

Phase 3: Destinations
  └── Destination types
  └── Local delivery
  └── Announces

Phase 4: Links
  └── Link establishment
  └── Link communication
  └── Keep-alive

Phase 5: Routing
  └── Path table
  └── Packet forwarding
  └── Multiple interfaces

Phase 6: Advanced
  └── Resource transfers
  └── Rate limiting
  └── Full transport
```

### Test Against Python RNS

At each phase, test interoperability with the Python reference implementation:

```bash
# Start Python rnsd
rnsd -v

# Your implementation connects and exchanges packets
./my_reticulum_impl --connect 127.0.0.1:4242
```

## 12.2 Minimum Viable Implementation

### Required Components

A minimal Reticulum implementation needs:

| Component | Purpose | Priority |
|-----------|---------|----------|
| SHA-256 | Hashing | Required |
| X25519 | Key exchange | Required |
| Ed25519 | Signatures | Required |
| AES-256-CBC | Encryption | Required |
| HMAC-SHA256 | Authentication | Required |
| HKDF-SHA256 | Key derivation | Required |
| HDLC framing | Packet delimiting | Required |
| Packet parser | Wire format | Required |
| Identity | Key management | Required |
| Destination | Addressing | Required |

### Optional Components

These can be added later:

| Component | Purpose | When Needed |
|-----------|---------|-------------|
| Link | Bidirectional channels | For stateful communication |
| Resource | Large transfers | For files > MTU |
| Path table | Routing | For multi-hop networks |
| Announce | Discovery | For dynamic networks |
| IFAC | Interface auth | For secured local networks |
| Compression | Bandwidth savings | For large resources |

## 12.3 Component Organization

### Suggested Module Structure

```
reticulum/
├── crypto/
│   ├── sha256.c        # Hashing
│   ├── aes.c           # Block cipher
│   ├── fernet.c        # Symmetric encryption
│   ├── x25519.c        # Key exchange
│   ├── ed25519.c       # Signatures
│   └── hkdf.c          # Key derivation
├── identity.c          # Identity management
├── packet.c            # Packet parsing/building
├── destination.c       # Destination handling
├── link.c              # Link protocol
├── resource.c          # Resource transfers
├── transport.c         # Routing and coordination
├── interfaces/
│   ├── interface.c     # Base interface
│   ├── tcp.c           # TCP client/server
│   ├── udp.c           # UDP interface
│   └── serial.c        # Serial/UART
├── framing/
│   └── hdlc.c          # HDLC framing
└── tables/
    ├── path_table.c    # Path storage
    ├── link_table.c    # Link storage
    └── announce_table.c # Announce handling
```

### Header Files

```c
// reticulum.h - Main public API
#ifndef RETICULUM_H
#define RETICULUM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Constants
#define RNS_MTU 500
#define RNS_TRUNCATED_HASH_SIZE 16
#define RNS_FULL_HASH_SIZE 32
#define RNS_PUBLIC_KEY_SIZE 32
#define RNS_SIGNATURE_SIZE 64

// Forward declarations
typedef struct rns_identity rns_identity_t;
typedef struct rns_destination rns_destination_t;
typedef struct rns_link rns_link_t;
typedef struct rns_transport rns_transport_t;
typedef struct rns_interface rns_interface_t;

// Identity API
rns_identity_t* rns_identity_create(void);
rns_identity_t* rns_identity_from_bytes(const uint8_t *priv, size_t len);
void rns_identity_destroy(rns_identity_t *id);
const uint8_t* rns_identity_hash(rns_identity_t *id);
bool rns_identity_sign(rns_identity_t *id, const uint8_t *data, size_t len,
                       uint8_t sig[RNS_SIGNATURE_SIZE]);
bool rns_identity_verify(rns_identity_t *id, const uint8_t *data, size_t len,
                         const uint8_t sig[RNS_SIGNATURE_SIZE]);

// Destination API
rns_destination_t* rns_destination_create(rns_identity_t *id,
                                          const char *app_name,
                                          uint8_t type);
void rns_destination_destroy(rns_destination_t *dest);
const uint8_t* rns_destination_hash(rns_destination_t *dest);
void rns_destination_set_callback(rns_destination_t *dest,
                                  void (*cb)(const uint8_t*, size_t, void*),
                                  void *ctx);

// Link API
rns_link_t* rns_link_create(rns_destination_t *dest);
void rns_link_destroy(rns_link_t *link);
bool rns_link_send(rns_link_t *link, const uint8_t *data, size_t len);
void rns_link_set_callback(rns_link_t *link,
                           void (*cb)(const uint8_t*, size_t, void*),
                           void *ctx);

// Transport API
rns_transport_t* rns_transport_create(void);
void rns_transport_destroy(rns_transport_t *t);
void rns_transport_add_interface(rns_transport_t *t, rns_interface_t *iface);
void rns_transport_register_destination(rns_transport_t *t, rns_destination_t *dest);
void rns_transport_run(rns_transport_t *t);

#endif // RETICULUM_H
```

## 12.4 Cryptographic Implementation

### Using Existing Libraries

Don't implement crypto from scratch. Use established libraries:

| Library | Languages | Notes |
|---------|-----------|-------|
| libsodium | C | Excellent, recommended |
| OpenSSL | C | Widely available |
| mbedTLS | C | Good for embedded |
| ring | Rust | Pure Rust, audited |
| RustCrypto | Rust | Pure Rust ecosystem |

### libsodium Example

```c
#include <sodium.h>

// Initialize once at startup
if (sodium_init() < 0) {
    // Panic - can't proceed without crypto
}

// X25519 key exchange
uint8_t my_secret[32], my_public[32];
uint8_t peer_public[32];  // Received from peer
uint8_t shared_secret[32];

crypto_box_keypair(my_public, my_secret);
crypto_scalarmult(shared_secret, my_secret, peer_public);

// Ed25519 signing
uint8_t sign_secret[64], sign_public[32];
uint8_t signature[64];
uint8_t message[] = "Hello";

crypto_sign_keypair(sign_public, sign_secret);
crypto_sign_detached(signature, NULL, message, 5, sign_secret);

// Verify
if (crypto_sign_verify_detached(signature, message, 5, sign_public) == 0) {
    // Valid
}

// SHA-256
uint8_t hash[32];
crypto_hash_sha256(hash, message, 5);

// HMAC-SHA256
uint8_t key[32], mac[32];
crypto_auth_hmacsha256(mac, message, 5, key);
```

### Fernet Implementation

Fernet isn't in libsodium, so implement it:

```c
#include <sodium.h>
#include <string.h>

#define FERNET_VERSION 0x80
#define FERNET_IV_SIZE 16
#define FERNET_HMAC_SIZE 32

// Fernet key: first 16 bytes = HMAC key, last 16 bytes = AES key
// (For AES-256 variant: 32 + 32 = 64 bytes)

size_t fernet_encrypt(const uint8_t key[32],
                      const uint8_t *plaintext, size_t plain_len,
                      uint8_t *output, size_t output_max) {
    // Calculate padded size
    size_t padded_len = ((plain_len / 16) + 1) * 16;
    size_t total_len = 1 + FERNET_IV_SIZE + padded_len + FERNET_HMAC_SIZE;

    if (output_max < total_len) return 0;

    // Version byte
    output[0] = FERNET_VERSION;

    // Random IV
    randombytes_buf(&output[1], FERNET_IV_SIZE);

    // PKCS7 padding
    uint8_t padded[plain_len + 16];
    memcpy(padded, plaintext, plain_len);
    uint8_t pad_value = padded_len - plain_len;
    memset(&padded[plain_len], pad_value, pad_value);

    // AES-CBC encrypt
    // (Using OpenSSL for AES-CBC as libsodium doesn't have it directly)
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, &key[16], &output[1]);
    EVP_CIPHER_CTX_set_padding(ctx, 0);  // We handle padding

    int out_len;
    EVP_EncryptUpdate(ctx, &output[1 + FERNET_IV_SIZE], &out_len,
                      padded, padded_len);
    EVP_CIPHER_CTX_free(ctx);

    // HMAC over version + IV + ciphertext
    crypto_auth_hmacsha256(&output[1 + FERNET_IV_SIZE + padded_len],
                           output, 1 + FERNET_IV_SIZE + padded_len,
                           key);

    return total_len;
}

bool fernet_decrypt(const uint8_t key[32],
                    const uint8_t *token, size_t token_len,
                    uint8_t *plaintext, size_t *plain_len) {
    if (token_len < 1 + FERNET_IV_SIZE + 16 + FERNET_HMAC_SIZE) {
        return false;
    }

    // Verify version
    if (token[0] != FERNET_VERSION) {
        return false;
    }

    size_t cipher_len = token_len - 1 - FERNET_IV_SIZE - FERNET_HMAC_SIZE;

    // Verify HMAC
    uint8_t expected_hmac[32];
    crypto_auth_hmacsha256(expected_hmac, token,
                           token_len - FERNET_HMAC_SIZE, key);

    if (sodium_memcmp(expected_hmac,
                      &token[token_len - FERNET_HMAC_SIZE], 32) != 0) {
        return false;  // HMAC mismatch
    }

    // AES-CBC decrypt
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, &key[16], &token[1]);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int out_len;
    EVP_DecryptUpdate(ctx, plaintext, &out_len,
                      &token[1 + FERNET_IV_SIZE], cipher_len);
    EVP_CIPHER_CTX_free(ctx);

    // Remove PKCS7 padding
    uint8_t pad_value = plaintext[out_len - 1];
    if (pad_value > 16 || pad_value == 0) {
        return false;  // Invalid padding
    }
    *plain_len = out_len - pad_value;

    return true;
}
```

## 12.5 Memory Management

### Static Allocation (Embedded)

For embedded systems without heap:

```c
#define MAX_INTERFACES 4
#define MAX_DESTINATIONS 16
#define MAX_LINKS 32
#define MAX_PATH_ENTRIES 256

typedef struct {
    rns_interface_t interfaces[MAX_INTERFACES];
    size_t interface_count;

    rns_destination_t destinations[MAX_DESTINATIONS];
    size_t destination_count;

    rns_link_t links[MAX_LINKS];
    size_t link_count;

    path_entry_t path_table[MAX_PATH_ENTRIES];
    size_t path_count;

    uint8_t packet_buffer[RNS_MTU * 4];
    size_t packet_buffer_used;
} rns_static_storage_t;

static rns_static_storage_t storage;

rns_link_t* rns_link_alloc(void) {
    if (storage.link_count >= MAX_LINKS) {
        return NULL;  // No space
    }
    return &storage.links[storage.link_count++];
}
```

### Buffer Pools

For packet buffers, use a pool:

```c
#define PACKET_POOL_SIZE 16

typedef struct {
    uint8_t data[RNS_MTU];
    bool in_use;
} packet_buffer_t;

static packet_buffer_t packet_pool[PACKET_POOL_SIZE];

uint8_t* packet_buffer_alloc(void) {
    for (int i = 0; i < PACKET_POOL_SIZE; i++) {
        if (!packet_pool[i].in_use) {
            packet_pool[i].in_use = true;
            return packet_pool[i].data;
        }
    }
    return NULL;  // Pool exhausted
}

void packet_buffer_free(uint8_t *buf) {
    for (int i = 0; i < PACKET_POOL_SIZE; i++) {
        if (packet_pool[i].data == buf) {
            packet_pool[i].in_use = false;
            return;
        }
    }
}
```

## 12.6 Platform Considerations

### Embedded Systems (no_std)

For microcontrollers without standard library:

```c
// Provide minimal dependencies
extern void* platform_malloc(size_t size);
extern void platform_free(void *ptr);
extern uint64_t platform_time_ms(void);
extern void platform_random(uint8_t *buf, size_t len);

// Avoid floating point if possible
// Use integer math for RTT calculations
typedef struct {
    uint32_t rtt_us;  // Microseconds instead of float seconds
} link_timing_t;
```

### Rust no_std

```rust
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

// Use embedded-friendly crypto crates
use sha2::{Sha256, Digest};
use x25519_dalek::{StaticSecret, PublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
```

### Threading Models

**Single-threaded (polling):**
```c
void main_loop(rns_transport_t *t) {
    while (running) {
        // Poll all interfaces
        for (int i = 0; i < t->interface_count; i++) {
            interface_poll(t->interfaces[i]);
        }

        // Process timers
        process_timers(t);

        // Sleep briefly
        platform_sleep_ms(1);
    }
}
```

**Multi-threaded:**
```c
void* interface_thread(void *arg) {
    rns_interface_t *iface = arg;
    while (iface->running) {
        // Blocking read
        uint8_t buf[RNS_MTU];
        ssize_t n = interface_read(iface, buf, sizeof(buf));
        if (n > 0) {
            // Queue for main thread
            queue_push(iface->rx_queue, buf, n);
        }
    }
    return NULL;
}
```

**Async (Rust):**
```rust
async fn interface_task(iface: Interface, tx: Sender<Packet>) {
    loop {
        let packet = iface.recv().await;
        tx.send(packet).await.unwrap();
    }
}
```

## 12.7 Error Handling

### Error Types

```c
typedef enum {
    RNS_OK = 0,
    RNS_ERR_INVALID_ARGUMENT,
    RNS_ERR_OUT_OF_MEMORY,
    RNS_ERR_CRYPTO_FAILED,
    RNS_ERR_INVALID_PACKET,
    RNS_ERR_INVALID_SIGNATURE,
    RNS_ERR_LINK_CLOSED,
    RNS_ERR_TIMEOUT,
    RNS_ERR_INTERFACE_DOWN,
} rns_error_t;

const char* rns_error_string(rns_error_t err) {
    switch (err) {
    case RNS_OK: return "OK";
    case RNS_ERR_INVALID_ARGUMENT: return "Invalid argument";
    case RNS_ERR_OUT_OF_MEMORY: return "Out of memory";
    case RNS_ERR_CRYPTO_FAILED: return "Crypto operation failed";
    case RNS_ERR_INVALID_PACKET: return "Invalid packet";
    case RNS_ERR_INVALID_SIGNATURE: return "Invalid signature";
    case RNS_ERR_LINK_CLOSED: return "Link closed";
    case RNS_ERR_TIMEOUT: return "Timeout";
    case RNS_ERR_INTERFACE_DOWN: return "Interface down";
    default: return "Unknown error";
    }
}
```

### Result Pattern (Rust)

```rust
#[derive(Debug)]
pub enum RnsError {
    InvalidArgument,
    OutOfMemory,
    CryptoFailed,
    InvalidPacket,
    InvalidSignature,
    LinkClosed,
    Timeout,
    InterfaceDown,
}

pub type Result<T> = core::result::Result<T, RnsError>;

impl Link {
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        if self.state != LinkState::Active {
            return Err(RnsError::LinkClosed);
        }
        // ...
        Ok(())
    }
}
```

## 12.8 Logging and Debugging

### Log Levels

```c
typedef enum {
    RNS_LOG_TRACE,
    RNS_LOG_DEBUG,
    RNS_LOG_INFO,
    RNS_LOG_WARN,
    RNS_LOG_ERROR,
} rns_log_level_t;

static rns_log_level_t log_level = RNS_LOG_INFO;

void rns_log(rns_log_level_t level, const char *fmt, ...) {
    if (level < log_level) return;

    va_list args;
    va_start(args, fmt);

    const char *prefix;
    switch (level) {
    case RNS_LOG_TRACE: prefix = "[TRACE]"; break;
    case RNS_LOG_DEBUG: prefix = "[DEBUG]"; break;
    case RNS_LOG_INFO:  prefix = "[INFO] "; break;
    case RNS_LOG_WARN:  prefix = "[WARN] "; break;
    case RNS_LOG_ERROR: prefix = "[ERROR]"; break;
    }

    fprintf(stderr, "%s ", prefix);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");

    va_end(args);
}

#define LOG_TRACE(...) rns_log(RNS_LOG_TRACE, __VA_ARGS__)
#define LOG_DEBUG(...) rns_log(RNS_LOG_DEBUG, __VA_ARGS__)
#define LOG_INFO(...)  rns_log(RNS_LOG_INFO, __VA_ARGS__)
#define LOG_WARN(...)  rns_log(RNS_LOG_WARN, __VA_ARGS__)
#define LOG_ERROR(...) rns_log(RNS_LOG_ERROR, __VA_ARGS__)
```

### Hex Dumping

```c
void hex_dump(const char *label, const uint8_t *data, size_t len) {
    fprintf(stderr, "%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, "%02x ", data[i]);
        if ((i + 1) % 16 == 0) fprintf(stderr, "\n");
    }
    if (len % 16 != 0) fprintf(stderr, "\n");
}

// Usage
LOG_DEBUG("Received packet:");
hex_dump("  Header", packet, 2);
hex_dump("  Destination", &packet[2], 16);
hex_dump("  Payload", &packet[19], payload_len);
```

## 12.9 Configuration

### Runtime Configuration

```c
typedef struct {
    // Network
    uint16_t mtu;
    bool transport_enabled;
    int transport_mode;

    // Timeouts (milliseconds)
    uint32_t link_timeout_ms;
    uint32_t path_ttl_ms;
    uint32_t announce_rate_target_ms;

    // Limits
    size_t max_interfaces;
    size_t max_destinations;
    size_t max_links;
    size_t max_path_entries;

    // Features
    bool enable_compression;
    bool enable_ifac;
} rns_config_t;

rns_config_t rns_default_config(void) {
    return (rns_config_t){
        .mtu = 500,
        .transport_enabled = true,
        .transport_mode = TRANSPORT_MODE_BOUNDARY,
        .link_timeout_ms = 120000,
        .path_ttl_ms = 604800000,
        .announce_rate_target_ms = 0,
        .max_interfaces = 8,
        .max_destinations = 64,
        .max_links = 128,
        .max_path_entries = 1024,
        .enable_compression = true,
        .enable_ifac = false,
    };
}
```

## 12.10 Build System

### CMake Example

```cmake
cmake_minimum_required(VERSION 3.10)
project(reticulum C)

set(CMAKE_C_STANDARD 11)

# Find dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(OPENSSL REQUIRED openssl)

# Library
add_library(reticulum
    src/crypto/sha256.c
    src/crypto/fernet.c
    src/crypto/hkdf.c
    src/identity.c
    src/packet.c
    src/destination.c
    src/link.c
    src/transport.c
    src/interfaces/tcp.c
    src/framing/hdlc.c
)

target_include_directories(reticulum PUBLIC include)
target_link_libraries(reticulum ${SODIUM_LIBRARIES} ${OPENSSL_LIBRARIES})

# Example
add_executable(rns_example examples/simple.c)
target_link_libraries(rns_example reticulum)

# Tests
enable_testing()
add_executable(test_identity tests/test_identity.c)
target_link_libraries(test_identity reticulum)
add_test(NAME identity COMMAND test_identity)
```

### Cargo.toml (Rust)

```toml
[package]
name = "reticulum"
version = "0.1.0"
edition = "2021"

[features]
default = ["std"]
std = []
no_std = ["embedded-hal"]

[dependencies]
sha2 = "0.10"
x25519-dalek = "2.0"
ed25519-dalek = "2.0"
hkdf = "0.12"
aes = "0.8"
cbc = "0.1"
hmac = "0.12"
rand_core = "0.6"

[target.'cfg(feature = "std")'.dependencies]
rand = "0.8"

[target.'cfg(feature = "no_std")'.dependencies]
embedded-hal = { version = "0.2", optional = true }

[dev-dependencies]
hex = "0.4"
```

## 12.11 Summary

### Implementation Checklist

**Phase 1: Foundation**
- [ ] SHA-256 hashing
- [ ] X25519 key exchange
- [ ] Ed25519 signatures
- [ ] AES-256-CBC encryption
- [ ] HMAC-SHA256
- [ ] HKDF-SHA256
- [ ] Fernet token format
- [ ] Identity create/sign/verify

**Phase 2: Communication**
- [ ] HDLC framing
- [ ] Packet parsing
- [ ] Packet building
- [ ] TCP interface (connect)
- [ ] Send/receive packets

**Phase 3: Destinations**
- [ ] SINGLE destination
- [ ] PLAIN destination
- [ ] Destination hash computation
- [ ] Local packet delivery
- [ ] Packet callbacks

**Phase 4: Links**
- [ ] Link request creation
- [ ] Link ID computation
- [ ] Proof verification (83-byte signed data)
- [ ] Key derivation
- [ ] Link encryption/decryption
- [ ] Keep-alive

**Phase 5: Routing**
- [ ] Announce validation
- [ ] Path table
- [ ] Packet forwarding
- [ ] Header Type 2 routing
- [ ] Multiple interfaces

**Phase 6: Advanced**
- [ ] Resource segmentation
- [ ] Resource assembly
- [ ] Flow control
- [ ] Rate limiting
- [ ] Full transport loop

### Key Constants to Get Right

| Constant | Value | Critical For |
|----------|-------|--------------|
| Truncated hash | 16 bytes | All addressing |
| Link proof | 99 bytes | Link establishment |
| Signed data | 83 bytes | Proof verification |
| Link request payload | 64 bytes | Link establishment |
| HDLC flag | 0x7E | Framing |
| HDLC escape | 0x7D | Framing |
| Fernet version | 0x80 | Encryption |

The next chapter provides test vectors and interoperability testing guidance.
