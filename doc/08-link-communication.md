# Chapter 8: Link Communication

Once a link is established, both sides can exchange encrypted data. This chapter covers data transmission, keep-alive, and link lifecycle management.

## 8.1 Data Packets on Links

### Packet Structure

Data packets on links use the LINK destination type:

```
+------+------+----------+---------+---------------------+
|Header| Hops | Link ID  | Context | Encrypted Payload   |
| 0x0C | 1B   | 16B      | varies  | Fernet token        |
+------+------+----------+---------+---------------------+

Header 0x0C = BROADCAST + Header1 + LINK + DATA
```

### Sending Data

```c
bool link_send(Link *link, const uint8_t *data, size_t len,
               uint8_t context, Transport *transport) {
    if (link->state != LINK_ACTIVE) {
        return false;  // Link not ready
    }

    // 1. Encrypt with link key (Fernet)
    uint8_t ciphertext[PACKET_MTU];
    size_t cipher_len = fernet_encrypt(link->link_key, data, len,
                                       ciphertext, sizeof(ciphertext));
    if (cipher_len == 0) {
        return false;  // Encryption failed
    }

    // 2. Build packet
    Packet pkt = {
        .destination_type = DEST_LINK,
        .packet_type = PACKET_DATA,
        .hops = 0,
    };
    memcpy(pkt.destination, link->id, 16);
    pkt.context = context;
    pkt.payload = ciphertext;
    pkt.payload_len = cipher_len;

    // 3. Send
    bool sent = transport_send(transport, &pkt);
    if (sent) {
        link->last_activity = get_time_ms();
    }

    return sent;
}

// Convenience for default context
bool link_send_data(Link *link, const uint8_t *data, size_t len,
                    Transport *transport) {
    return link_send(link, data, len, CONTEXT_NONE, transport);
}
```

### Receiving Data

```c
bool link_receive(Link *link, const Packet *pkt,
                  uint8_t *plaintext, size_t *plaintext_len) {
    if (link->state != LINK_ACTIVE) {
        return false;
    }

    // Decrypt Fernet token
    bool success = fernet_decrypt(link->link_key,
                                  pkt->payload, pkt->payload_len,
                                  plaintext, plaintext_len);
    if (success) {
        link->last_activity = get_time_ms();
    }

    return success;
}
```

### Handling Incoming Link Packets

```c
void handle_link_packet(Transport *transport, Packet *pkt) {
    // Find link by ID
    Link *link = find_link(pkt->destination);
    if (!link) {
        return;  // Unknown link
    }

    if (pkt->packet_type == PACKET_DATA) {
        switch (pkt->context) {
        case CONTEXT_NONE:
            // Regular data
            uint8_t plaintext[PACKET_MTU];
            size_t plain_len;
            if (link_receive(link, pkt, plaintext, &plain_len)) {
                if (link->on_data) {
                    link->on_data(link, plaintext, plain_len);
                }
            }
            break;

        case CONTEXT_KEEPALIVE:
            handle_keepalive(link, pkt, transport);
            break;

        case CONTEXT_LINK_RTT:
            handle_rtt_packet(link, pkt);
            break;

        case CONTEXT_RESOURCE:
        case CONTEXT_RESOURCE_ADV:
            // Resource transfer handling (see Chapter 10)
            handle_resource_packet(link, pkt);
            break;

        default:
            // Unknown context - forward to callback
            if (link->on_data) {
                link->on_data(link, pkt->payload, pkt->payload_len);
            }
        }
    }
}
```

## 8.2 Maximum Transfer Unit (MTU)

### Link MTU

The maximum data size per packet depends on:
- Interface MTU (typically ~500 bytes)
- Packet overhead (header, destination, context)
- Encryption overhead (Fernet: 1 + 16 + padding + 32)

```c
#define PACKET_MTU 500
#define LINK_HEADER_SIZE (1 + 1 + 16 + 1)  // header + hops + dest + context
#define FERNET_OVERHEAD (1 + 16 + 32)       // version + IV + HMAC

size_t link_mtu(void) {
    // Available for plaintext
    size_t available = PACKET_MTU - LINK_HEADER_SIZE - FERNET_OVERHEAD;
    // Account for padding (worst case: 16 bytes)
    return available - 16;
}

// Typically ~430 bytes per packet
```

### Signalling MTU

During link establishment, the responder can advertise a custom MTU in the signalling bytes:

```c
void decode_signalling(const uint8_t signalling[3], uint16_t *mtu) {
    // Signalling format: [mtu_high, mtu_low, flags]
    *mtu = (signalling[0] << 8) | signalling[1];
    // flags byte for future use
}

void encode_signalling(uint16_t mtu, uint8_t signalling[3]) {
    signalling[0] = (mtu >> 8) & 0xFF;
    signalling[1] = mtu & 0xFF;
    signalling[2] = 0x00;  // flags
}
```

## 8.3 Keep-Alive Mechanism

Links can go stale if there's no activity. Keep-alive packets maintain the connection.

### Keep-Alive Protocol

```
Initiator                              Responder
    |                                      |
    |---- [KEEPALIVE request 0xFF] ------->|
    |                                      |
    |<--- [KEEPALIVE response 0xFE] -------|
    |                                      |
```

### Keep-Alive Packet Structure

```
+------+------+----------+---------+------+
|Header| Hops | Link ID  | Context | Data |
| 0x0C | 1B   | 16B      | 0xFA    | 1B   |
+------+------+----------+---------+------+

Context 0xFA = CONTEXT_KEEPALIVE
Data:   0xFF = Request
        0xFE = Response
```

### Implementation

```c
#define KEEPALIVE_INTERVAL_MS 120000  // 2 minutes
#define STALE_TIMEOUT_MS      300000  // 5 minutes

void link_send_keepalive(Link *link, Transport *transport) {
    uint8_t data = 0xFF;  // Request

    Packet pkt = {
        .destination_type = DEST_LINK,
        .packet_type = PACKET_DATA,
        .hops = 0,
    };
    memcpy(pkt.destination, link->id, 16);
    pkt.context = CONTEXT_KEEPALIVE;
    pkt.payload = &data;
    pkt.payload_len = 1;

    transport_send(transport, &pkt);
}

void handle_keepalive(Link *link, Packet *pkt, Transport *transport) {
    if (pkt->payload_len < 1) return;

    uint8_t type = pkt->payload[0];

    if (type == 0xFF) {
        // Request - send response
        uint8_t response = 0xFE;
        Packet resp_pkt = {
            .destination_type = DEST_LINK,
            .packet_type = PACKET_DATA,
            .hops = 0,
        };
        memcpy(resp_pkt.destination, link->id, 16);
        resp_pkt.context = CONTEXT_KEEPALIVE;
        resp_pkt.payload = &response;
        resp_pkt.payload_len = 1;

        transport_send(transport, &resp_pkt);
        link->last_activity = get_time_ms();

    } else if (type == 0xFE) {
        // Response - link is alive
        link->last_activity = get_time_ms();
    }
}
```

### Periodic Check

```c
void link_periodic_check(Link *link, Transport *transport) {
    if (link->state != LINK_ACTIVE) return;

    uint64_t now = get_time_ms();
    uint64_t idle = now - link->last_activity;

    if (idle > STALE_TIMEOUT_MS) {
        // Link is stale - close it
        link->state = LINK_STALE;
        link_close(link, transport);
        return;
    }

    if (idle > KEEPALIVE_INTERVAL_MS) {
        // Send keepalive
        link_send_keepalive(link, transport);
    }
}
```

## 8.4 RTT Measurement

Round-trip time (RTT) helps with timeout tuning and performance monitoring.

### Initial RTT

The initial RTT is measured during link establishment:

```c
// In process_link_proof():
link->rtt_ms = get_time_ms() - link->request_time;
```

### RTT Packet

After link establishment, the responder can send an RTT packet. The RTT value is encoded using [MessagePack](appendix-b-background.md#option-3-messagepack-what-reticulum-uses), a compact binary serialization format.

```c
void link_send_rtt(Link *link, Transport *transport) {
    // Pack RTT as msgpack float (see Appendix B for MessagePack details)
    uint8_t plaintext[8];
    float rtt_seconds = link->rtt_ms / 1000.0f;
    size_t len = msgpack_write_float(plaintext, rtt_seconds);

    // Encrypt and send
    uint8_t ciphertext[64];
    size_t cipher_len = fernet_encrypt(link->link_key, plaintext, len,
                                       ciphertext, sizeof(ciphertext));

    Packet pkt = {
        .destination_type = DEST_LINK,
        .packet_type = PACKET_DATA,
        .hops = 0,
    };
    memcpy(pkt.destination, link->id, 16);
    pkt.context = CONTEXT_LINK_RTT;
    pkt.payload = ciphertext;
    pkt.payload_len = cipher_len;

    transport_send(transport, &pkt);
}
```

### Processing RTT

```c
void handle_rtt_packet(Link *link, Packet *pkt) {
    // Decrypt
    uint8_t plaintext[64];
    size_t plain_len;
    if (!fernet_decrypt(link->link_key, pkt->payload, pkt->payload_len,
                        plaintext, &plain_len)) {
        return;
    }

    // Parse msgpack float
    float rtt_seconds;
    if (msgpack_read_float(plaintext, plain_len, &rtt_seconds)) {
        // Use the peer's measured RTT
        link->peer_rtt_ms = (uint64_t)(rtt_seconds * 1000);
    }
}
```

## 8.5 Link Identification

Links can optionally identify themselves with additional metadata.

### Identification Packet

```c
void link_send_identification(Link *link, const uint8_t *identity_data,
                              size_t identity_len, Transport *transport) {
    // Encrypt identity data
    uint8_t ciphertext[PACKET_MTU];
    size_t cipher_len = fernet_encrypt(link->link_key,
                                       identity_data, identity_len,
                                       ciphertext, sizeof(ciphertext));

    Packet pkt = {
        .destination_type = DEST_LINK,
        .packet_type = PACKET_DATA,
        .hops = 0,
    };
    memcpy(pkt.destination, link->id, 16);
    pkt.context = CONTEXT_LINK_IDENTIFY;  // 0xFB
    pkt.payload = ciphertext;
    pkt.payload_len = cipher_len;

    transport_send(transport, &pkt);
}
```

## 8.6 Closing Links

### Graceful Close

Send a close packet before terminating:

```c
void link_close(Link *link, Transport *transport) {
    if (link->state == LINK_CLOSED) return;

    // Send close notification
    Packet pkt = {
        .destination_type = DEST_LINK,
        .packet_type = PACKET_DATA,
        .hops = 0,
    };
    memcpy(pkt.destination, link->id, 16);
    pkt.context = CONTEXT_LINK_CLOSE;  // 0xFC
    pkt.payload = NULL;
    pkt.payload_len = 0;

    transport_send(transport, &pkt);

    // Update state
    link->state = LINK_CLOSED;

    // Notify callback
    if (link->on_closed) {
        link->on_closed(link);
    }

    // Clear sensitive data
    sodium_memzero(link->link_key, sizeof(link->link_key));
    sodium_memzero(link->local_x25519_priv, 32);
}
```

### Handling Close

```c
void handle_link_close(Link *link) {
    if (link->state == LINK_CLOSED) return;

    link->state = LINK_CLOSED;

    if (link->on_closed) {
        link->on_closed(link);
    }

    sodium_memzero(link->link_key, sizeof(link->link_key));
}
```

### Implicit Close

Links close implicitly when:
- Stale timeout exceeded
- Too many failed decryptions
- Transport layer failure

## 8.7 Contexts Summary

| Context | Value | Direction | Purpose |
|---------|-------|-----------|---------|
| NONE | 0x00 | Both | Regular data |
| RESOURCE | 0x01 | Both | Resource transfer data |
| RESOURCE_ADV | 0x02 | Sender | Resource advertisement |
| RESOURCE_REQ | 0x03 | Receiver | Resource request |
| RESOURCE_HMU | 0x04 | Sender | Resource hash map update |
| RESOURCE_PRF | 0x05 | Receiver | Resource proof |
| RESOURCE_ICL | 0x06 | Sender | Initiator cancel |
| RESOURCE_RCL | 0x07 | Receiver | Receiver cancel |
| KEEPALIVE | 0xFA | Both | Keep-alive ping/pong |
| LINK_IDENTIFY | 0xFB | Both | Identity metadata |
| LINK_CLOSE | 0xFC | Both | Close notification |
| LINK_PROOF | 0xFD | Both | Link packet proof |
| LINK_RTT | 0xFE | Responder | RTT measurement |
| LINK_REQUEST_PROOF | 0xFF | Responder | Link establishment proof |

## 8.8 Complete Link Lifecycle

```c
// 1. CREATE
Link *link = link_create();

// 2. INITIATE (client side)
link->on_established = my_established_callback;
link->on_data = my_data_callback;
link->on_closed = my_closed_callback;
link_initiate(link, transport, dest_hash, dest_ed25519_pub);

// ... or ACCEPT (server side)
link = handle_link_request(destination, incoming_pkt);
link->on_data = my_data_callback;
link->on_closed = my_closed_callback;
send_link_proof(link, transport);

// 3. USE
while (link->state == LINK_ACTIVE) {
    // Send data
    link_send_data(link, message, message_len, transport);

    // Periodic maintenance
    link_periodic_check(link, transport);

    // Process incoming packets
    poll_interfaces(transport);
}

// 4. CLOSE
link_close(link, transport);

// 5. CLEANUP
link_destroy(link);
```

## 8.9 Error Handling

### Decryption Failures

```c
#define MAX_DECRYPT_FAILURES 5

void handle_decrypt_failure(Link *link) {
    link->decrypt_failures++;

    if (link->decrypt_failures > MAX_DECRYPT_FAILURES) {
        // Too many failures - close link
        log_warn("Link %s: too many decryption failures, closing",
                 bytes_to_hex(link->id, 16));
        link->state = LINK_CLOSED;
    }
}
```

### Unexpected Packets

```c
void handle_unexpected_link_packet(Link *link, Packet *pkt) {
    // Log but don't close - might be delayed/reordered packet
    log_debug("Link %s: unexpected packet type %d context %d",
              bytes_to_hex(link->id, 16),
              pkt->packet_type, pkt->context);
}
```

## 8.10 Threading Considerations

If using multiple threads:

```c
typedef struct Link {
    // ... other fields ...
    pthread_mutex_t lock;
} Link;

bool link_send_threadsafe(Link *link, const uint8_t *data, size_t len,
                          Transport *transport) {
    pthread_mutex_lock(&link->lock);
    bool result = link_send_data(link, data, len, transport);
    pthread_mutex_unlock(&link->lock);
    return result;
}
```

Or use lock-free queues for message passing:

```c
typedef struct {
    uint8_t data[PACKET_MTU];
    size_t len;
} LinkMessage;

typedef struct Link {
    // ... other fields ...
    mpsc_queue_t *outgoing_queue;
    mpsc_queue_t *incoming_queue;
} Link;
```

## 8.11 Summary

| Operation | Context | Encrypted | Purpose |
|-----------|---------|-----------|---------|
| Send data | NONE | Yes | Application data |
| Keep-alive request | KEEPALIVE | No | Ping |
| Keep-alive response | KEEPALIVE | No | Pong |
| RTT measurement | (data pkt) | Yes | Latency info |
| Identify | LINK_IDENTIFY | Yes | Metadata exchange |
| Close | LINK_CLOSE | No | Graceful shutdown |

| Timeout | Default | Purpose |
|---------|---------|---------|
| Keep-alive interval | 2 minutes | Send ping if idle |
| Stale timeout | 5 minutes | Close if no response |
| Proof timeout | 15 seconds | Initial handshake |

Link communication provides:
- **Confidentiality**: All data encrypted with link key
- **Integrity**: Fernet HMAC detects tampering
- **Bidirectional**: Both sides can send without re-handshaking
- **Efficiency**: Key exchange once, symmetric crypto thereafter
- **Health monitoring**: Keep-alive detects dead links

The remaining chapters cover advanced topics: announces/routing, resource transfers, and the transport layer.
