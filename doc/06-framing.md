# Chapter 6: Transport Layer Framing

Reticulum packets must be transmitted over physical media. This chapter explains how packets are framed for transmission and how different interface types work.

## 6.1 The Framing Problem

Packets are variable-length byte sequences. When sending over a byte stream (like TCP or a serial port), we need to answer:

1. **Where does one packet end and the next begin?**
2. **How do we handle corrupted data?**
3. **What if the data looks like a frame boundary?**

Reticulum uses **HDLC-like framing** to solve these problems.

## 6.2 HDLC Framing

HDLC (High-Level Data Link Control) is a classic framing protocol. Reticulum uses a simplified version.

### Frame Structure

```
+------+-----------+------+
| 0x7E | Data      | 0x7E |
| FLAG | (escaped) | FLAG |
+------+-----------+------+
```

- **0x7E** is the frame delimiter (FLAG byte)
- Data is the packet bytes, with special bytes escaped
- No CRC - Reticulum relies on cryptographic integrity

### Special Bytes

Two bytes require special handling:

| Byte | Name | Action |
|------|------|--------|
| 0x7E | FLAG | Escape as 0x7D 0x5E |
| 0x7D | ESCAPE | Escape as 0x7D 0x5D |

### Byte Stuffing (Escaping)

When the data contains 0x7E or 0x7D, we "escape" them:

```
Original: 0x7E → Escaped: 0x7D 0x5E
Original: 0x7D → Escaped: 0x7D 0x5D
```

The pattern: insert 0x7D, then XOR the byte with 0x20.

### Example

Frame a packet containing: `[0x01, 0x7E, 0x02, 0x7D, 0x03]`

```
1. Start with FLAG:        0x7E
2. 0x01 - normal:          0x01
3. 0x7E - escape:          0x7D 0x5E
4. 0x02 - normal:          0x02
5. 0x7D - escape:          0x7D 0x5D
6. 0x03 - normal:          0x03
7. End with FLAG:          0x7E

Result: [0x7E, 0x01, 0x7D, 0x5E, 0x02, 0x7D, 0x5D, 0x03, 0x7E]
```

## 6.3 Framing Implementation

### Framing (Encoding)

```c
#define HDLC_FLAG   0x7E
#define HDLC_ESCAPE 0x7D
#define HDLC_XOR    0x20

size_t hdlc_frame(const uint8_t *packet, size_t packet_len,
                  uint8_t *output, size_t output_max) {
    size_t out_idx = 0;

    // Start flag
    if (out_idx >= output_max) return 0;
    output[out_idx++] = HDLC_FLAG;

    // Frame data with escaping
    for (size_t i = 0; i < packet_len; i++) {
        uint8_t byte = packet[i];

        if (byte == HDLC_FLAG || byte == HDLC_ESCAPE) {
            // Need to escape this byte
            if (out_idx + 2 > output_max) return 0;
            output[out_idx++] = HDLC_ESCAPE;
            output[out_idx++] = byte ^ HDLC_XOR;
        } else {
            // Normal byte
            if (out_idx >= output_max) return 0;
            output[out_idx++] = byte;
        }
    }

    // End flag
    if (out_idx >= output_max) return 0;
    output[out_idx++] = HDLC_FLAG;

    return out_idx;
}
```

### Deframing (Decoding)

Deframing is more complex than framing because we're processing a continuous byte stream and need to handle:

1. **Synchronization**: Finding frame boundaries in potentially corrupted data
2. **State management**: Tracking whether we're inside a frame or between frames
3. **Escape handling**: Properly decoding escaped special bytes
4. **Error recovery**: Gracefully handling malformed data

**The state machine approach:**

- **HUNTING**: We haven't found a start flag yet. Discard bytes until we see 0x7E.
- **RECEIVING**: We're inside a frame, accumulating payload bytes.
- **ESCAPED**: The previous byte was 0x7D, so XOR the next byte with 0x20.

**Why a state machine?** Bytes arrive one at a time (especially on serial links). We can't assume we'll receive a complete frame in one read. The state machine lets us process partial data and resume when more arrives.

**Resynchronization**: If data gets corrupted mid-frame, we'll eventually see a 0x7E flag (either the end of the corrupted frame or the start of a new one). The cryptographic integrity check (Fernet HMAC) will reject corrupted packets, so the state machine just needs to find frame boundaries—not guarantee data integrity.

```c
typedef enum {
    DEFRAME_HUNTING,    // Looking for start flag
    DEFRAME_RECEIVING,  // Accumulating frame data
    DEFRAME_ESCAPED,    // Previous byte was escape
} DeframeState;

typedef struct {
    DeframeState state;
    uint8_t buffer[1024];
    size_t buffer_len;
} Deframer;

void deframer_init(Deframer *d) {
    d->state = DEFRAME_HUNTING;
    d->buffer_len = 0;
}

// Returns: 0 = no frame yet, >0 = frame complete (returns length)
size_t deframer_process_byte(Deframer *d, uint8_t byte,
                              uint8_t *frame_out, size_t max_len) {
    switch (d->state) {
    case DEFRAME_HUNTING:
        if (byte == HDLC_FLAG) {
            d->state = DEFRAME_RECEIVING;
            d->buffer_len = 0;
        }
        // Ignore non-flag bytes while hunting
        return 0;

    case DEFRAME_RECEIVING:
        if (byte == HDLC_FLAG) {
            // End of frame
            if (d->buffer_len > 0) {
                // Complete frame received
                size_t len = d->buffer_len;
                if (len <= max_len) {
                    memcpy(frame_out, d->buffer, len);
                }
                d->buffer_len = 0;
                // Stay in RECEIVING state for next frame
                return len;
            }
            // Empty frame (consecutive flags) - ignore
            return 0;
        }
        if (byte == HDLC_ESCAPE) {
            d->state = DEFRAME_ESCAPED;
            return 0;
        }
        // Normal byte
        if (d->buffer_len < sizeof(d->buffer)) {
            d->buffer[d->buffer_len++] = byte;
        }
        return 0;

    case DEFRAME_ESCAPED:
        // De-escape the byte
        byte ^= HDLC_XOR;
        if (d->buffer_len < sizeof(d->buffer)) {
            d->buffer[d->buffer_len++] = byte;
        }
        d->state = DEFRAME_RECEIVING;
        return 0;
    }
    return 0;
}

// Process multiple bytes at once
void deframer_process(Deframer *d, const uint8_t *data, size_t len,
                      void (*on_frame)(const uint8_t*, size_t, void*),
                      void *ctx) {
    uint8_t frame[1024];
    for (size_t i = 0; i < len; i++) {
        size_t frame_len = deframer_process_byte(d, data[i],
                                                  frame, sizeof(frame));
        if (frame_len > 0) {
            on_frame(frame, frame_len, ctx);
        }
    }
}
```

## 6.4 Why No CRC?

Traditional HDLC includes a CRC (Cyclic Redundancy Check) for error detection. Reticulum omits it because:

1. **Cryptographic integrity**: Encrypted packets use HMAC, which detects tampering
2. **Bandwidth savings**: CRC adds 2-4 bytes per frame
3. **Link-layer reliability**: Most underlying transports have their own error detection

If the underlying medium is unreliable (like radio), the encryption's HMAC will reject corrupted packets anyway.

## 6.5 Interface Types

Reticulum supports various physical media through **interfaces**.

### Interface Abstraction

```c
typedef struct Interface {
    char *name;
    bool enabled;
    bool online;

    // Statistics
    uint64_t tx_bytes;
    uint64_t rx_bytes;

    // Methods
    bool (*send)(struct Interface *iface, const uint8_t *data, size_t len);
    void (*receive)(struct Interface *iface, const uint8_t *data, size_t len);

    // Type-specific data
    void *impl_data;
} Interface;
```

### TCP Client Interface

Connects to a remote Reticulum node over TCP.

```c
typedef struct {
    int socket_fd;
    char *host;
    uint16_t port;
    Deframer deframer;
} TCPClientInterface;

Interface* tcp_client_create(const char *host, uint16_t port) {
    TCPClientInterface *impl = malloc(sizeof(TCPClientInterface));
    impl->host = strdup(host);
    impl->port = port;
    deframer_init(&impl->deframer);

    // Connect
    impl->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    inet_pton(AF_INET, host, &addr.sin_addr);
    connect(impl->socket_fd, (struct sockaddr*)&addr, sizeof(addr));

    Interface *iface = malloc(sizeof(Interface));
    iface->name = "TCPClient";
    iface->enabled = true;
    iface->online = true;
    iface->send = tcp_client_send;
    iface->impl_data = impl;

    return iface;
}

bool tcp_client_send(Interface *iface, const uint8_t *packet, size_t len) {
    TCPClientInterface *impl = iface->impl_data;

    uint8_t framed[2048];
    size_t framed_len = hdlc_frame(packet, len, framed, sizeof(framed));

    ssize_t sent = send(impl->socket_fd, framed, framed_len, 0);
    if (sent > 0) {
        iface->tx_bytes += sent;
        return true;
    }
    return false;
}

void tcp_client_receive(Interface *iface) {
    TCPClientInterface *impl = iface->impl_data;

    uint8_t recv_buf[1024];
    ssize_t n = recv(impl->socket_fd, recv_buf, sizeof(recv_buf), MSG_DONTWAIT);

    if (n > 0) {
        iface->rx_bytes += n;
        deframer_process(&impl->deframer, recv_buf, n,
                         on_frame_received, iface);
    }
}
```

### TCP Server Interface

Listens for incoming connections from other Reticulum nodes.

```c
typedef struct {
    int listen_fd;
    int *client_fds;
    size_t client_count;
    uint16_t port;
} TCPServerInterface;

// Accepts multiple clients, broadcasts to all
```

### UDP Interface

Connectionless interface, useful for local networks.

```c
typedef struct {
    int socket_fd;
    uint16_t port;
    struct sockaddr_in broadcast_addr;
} UDPInterface;

// Note: UDP doesn't need HDLC framing since datagrams
// preserve message boundaries. Reticulum may still use
// HDLC for consistency across interface types.
```

### Serial/UART Interface

For direct connections to radio modems or other devices.

```c
typedef struct {
    int serial_fd;
    char *device;      // e.g., "/dev/ttyUSB0"
    int baudrate;
    Deframer deframer;
} SerialInterface;

Interface* serial_create(const char *device, int baudrate) {
    SerialInterface *impl = malloc(sizeof(SerialInterface));
    impl->device = strdup(device);
    impl->baudrate = baudrate;
    deframer_init(&impl->deframer);

    impl->serial_fd = open(device, O_RDWR | O_NOCTTY);

    struct termios tty;
    tcgetattr(impl->serial_fd, &tty);
    cfsetospeed(&tty, baudrate_to_const(baudrate));
    cfsetispeed(&tty, baudrate_to_const(baudrate));
    tty.c_cflag |= (CLOCAL | CREAD);
    tty.c_cflag &= ~PARENB;
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;
    tcsetattr(impl->serial_fd, TCSANOW, &tty);

    // ... create Interface struct
}
```

### LoRa Interface

For long-range radio communication using LoRa modulation.

```c
// LoRa interfaces typically use RNode firmware
// Communication is via serial to the RNode device

typedef struct {
    int serial_fd;
    uint32_t frequency;
    uint8_t bandwidth;
    uint8_t spreading_factor;
    uint8_t coding_rate;
} LoRaInterface;
```

## 6.6 Interface Authentication (IFAC)

IFAC protects local network segments by adding an authentication code and masking the packet contents.

### How IFAC Works

When IFAC is enabled:

1. A shared secret (passphrase) is configured for the interface
2. An IFAC identity is derived from the secret via HKDF (64 bytes)
3. Outgoing packets are signed and masked
4. Incoming packets are verified and unmasked
5. Unauthorized packets are dropped

### IFAC Key Derivation

```c
// Derive IFAC identity from passphrase
void derive_ifac_identity(const char *passphrase,
                          uint8_t ifac_key[64]) {
    // Use HKDF with fixed salt
    static const uint8_t IFAC_SALT[] = {
        0xad, 0xf5, 0x4d, 0x88, 0x2c, 0x9a, 0x9b, 0x80,
        0x77, 0x1e, 0xb4, 0x99, 0x5d, 0x70, 0x2d, 0x4a,
        0x3e, 0x73, 0x33, 0x91, 0xb2, 0xa0, 0xf5, 0x3f,
        0x41, 0x6d, 0x9f, 0x90, 0x7e, 0x55, 0xcf, 0xf8
    };
    hkdf_sha256(IFAC_SALT, 32,
                (uint8_t*)passphrase, strlen(passphrase),
                NULL, 0,  // no info
                ifac_key, 64);
}
```

### IFAC Tag Computation

The IFAC tag is the **last N bytes of an Ed25519 signature**, not an HMAC:

```c
void compute_ifac_tag(const uint8_t *ifac_signing_key,
                      const uint8_t *packet, size_t packet_len,
                      uint8_t *tag, size_t ifac_size) {
    // Sign the packet with the IFAC identity
    uint8_t signature[64];
    crypto_sign_detached(signature, NULL,
                         packet, packet_len,
                         ifac_signing_key);
    // Take the LAST ifac_size bytes of the signature
    memcpy(tag, signature + (64 - ifac_size), ifac_size);
}
```

### IFAC Masking

IFAC also masks the packet using an HKDF-derived key, providing confidentiality on the local segment:

```c
void ifac_mask_packet(const uint8_t *ifac_tag, size_t ifac_size,
                      uint8_t *packet, size_t packet_len) {
    // Derive mask from IFAC tag
    uint8_t mask[512];  // enough for max packet
    hkdf_sha256(ifac_tag, ifac_size,
                NULL, 0,   // no salt
                NULL, 0,   // no info
                mask, packet_len);
    // XOR packet with mask
    for (size_t i = 0; i < packet_len; i++) {
        packet[i] ^= mask[i];
    }
}
```

### Packet with IFAC

```
+------+------+-----------+------+-----------+------+
| 0x7E |Header| IFAC Tag  | Hops | Rest of   | 0x7E |
|      | 0x8x | 16 bytes  |      | (masked)  |      |
+------+------+-----------+------+-----------+------+
```

The header byte has bit 7 set (0x80) to indicate IFAC presence. Default IFAC size is 16 bytes.

## 6.7 Interface Selection

When sending a packet, the transport layer must choose which interface(s) to use.

### Outgoing Interface Selection

```c
typedef enum {
    MODE_FULL          = 0x01,  // Full node, send on all interfaces
    MODE_POINT_TO_POINT= 0x02,  // Direct peer connection
    MODE_ACCESS_POINT  = 0x03,  // Access point mode
    MODE_ROAMING       = 0x04,  // Mobile client
    MODE_BOUNDARY      = 0x05,  // Network boundary
    MODE_GATEWAY       = 0x06,  // Gateway between networks
} InterfaceMode;

void transport_send(Transport *t, Packet *pkt) {
    switch (t->interface_mode) {
    case IFACE_MODE_FULL:
        // Broadcast to all enabled interfaces
        for (size_t i = 0; i < t->interface_count; i++) {
            if (t->interfaces[i]->enabled && t->interfaces[i]->online) {
                t->interfaces[i]->send(t->interfaces[i],
                                       pkt->raw, pkt->raw_len);
            }
        }
        break;

    case IFACE_MODE_ACCESS_POINT:
        // Send only on designated interface
        t->access_point_interface->send(t->access_point_interface,
                                        pkt->raw, pkt->raw_len);
        break;

    case IFACE_MODE_ROAMING:
        // Choose best interface based on path table
        Interface *best = find_best_interface(t, pkt->destination);
        best->send(best, pkt->raw, pkt->raw_len);
        break;
    }
}
```

### Incoming Packet Handling

```c
void on_packet_received(Interface *iface, const uint8_t *data, size_t len) {
    // 1. Parse packet
    Packet pkt;
    if (!parse_packet(data, len, &pkt)) {
        return;  // Invalid packet
    }

    // 2. Check IFAC if required
    if (iface->ifac_enabled) {
        if (!verify_ifac(&pkt, iface->ifac_key)) {
            return;  // Auth failed
        }
    }

    // 3. Check if we should forward
    if (pkt.hops < MAX_HOPS && should_forward(&pkt)) {
        pkt.hops++;
        forward_packet(&pkt, iface);  // Don't send back on same interface
    }

    // 4. Check if addressed to us
    Destination *dest = lookup_destination(pkt.destination);
    if (dest) {
        deliver_to_destination(dest, &pkt);
    }
}
```

## 6.8 Flow Control

Some interfaces need flow control to prevent buffer overflow.

### Transmit Queue

```c
typedef struct {
    uint8_t *packets[256];
    size_t packet_lens[256];
    size_t head;
    size_t tail;
} TxQueue;

void queue_packet(TxQueue *q, const uint8_t *packet, size_t len) {
    size_t next = (q->head + 1) % 256;
    if (next == q->tail) {
        // Queue full - drop oldest
        free(q->packets[q->tail]);
        q->tail = (q->tail + 1) % 256;
    }
    q->packets[q->head] = malloc(len);
    memcpy(q->packets[q->head], packet, len);
    q->packet_lens[q->head] = len;
    q->head = next;
}
```

### Rate Limiting

For bandwidth-constrained links:

```c
typedef struct {
    uint64_t bytes_per_second;
    uint64_t last_send_time;
    uint64_t tokens;
} RateLimiter;

bool rate_limiter_allow(RateLimiter *rl, size_t bytes) {
    uint64_t now = get_time_ms();
    uint64_t elapsed = now - rl->last_send_time;

    // Add tokens based on time elapsed
    rl->tokens += (elapsed * rl->bytes_per_second) / 1000;
    if (rl->tokens > rl->bytes_per_second) {
        rl->tokens = rl->bytes_per_second;  // Cap at 1 second buffer
    }
    rl->last_send_time = now;

    if (rl->tokens >= bytes) {
        rl->tokens -= bytes;
        return true;
    }
    return false;  // Would exceed rate limit
}
```

## 6.9 Summary

| Component | Purpose |
|-----------|---------|
| HDLC Framing | Packet delimiting on byte streams |
| 0x7E | Frame delimiter (FLAG) |
| 0x7D | Escape character |
| Byte stuffing | Encode special bytes in data |
| No CRC | Rely on cryptographic integrity (Fernet HMAC) |

| Interface Type | Use Case |
|----------------|----------|
| TCP Client | Connect to remote node |
| TCP Server | Accept incoming connections |
| UDP | Local network broadcast |
| Serial | Radio modems, direct links |
| LoRa | Long-range radio |

| IFAC | Interface Authentication Code |
|------|------------------------------|
| Enabled | Bit 7 of header set |
| Tag | 16-byte Ed25519 signature (last N bytes) |
| Masking | Packet XORed with HKDF-derived mask |
| Purpose | Protect and obscure local network traffic |

[The next chapter covers **link establishment** - creating encrypted bidirectional channels.](07-link-establishment.md)
