# Chapter 4: Packet Structure

Packets are the fundamental data unit in Reticulum. This chapter details the exact byte-level structure of packets.

## 4.1 Packet Overview

A Reticulum packet consists of:

```
+--------+------+-------------+----------+---------+---------+
| Header | Hops | Destination | Transport| Context | Payload |
| 1 byte | 1 byte | 16 bytes  | 0/16 B   | 1 byte  | varies  |
+--------+------+-------------+----------+---------+---------+
```

Minimum packet size: 19 bytes (header + hops + dest + context)
Maximum packet size: ~500 bytes (interface-dependent)

## 4.2 The Header Byte

The first byte encodes multiple fields using bit flags:

```
Bit:  7     6      5 4       3 2        1 0
    +-----+------+-------+---------+----------+
    |IFAC |Header|Propag.|DestType |PacketType|
    +-----+------+-------+---------+----------+
```

### Bit 7: IFAC Flag

```
0 = No interface authentication
1 = Interface Authentication Code present (after header)
```

When set, the packet includes authentication data specific to the interface. Used to protect local networks.

### Bit 6: Header Type

```
0 = Header Type 1 (without transport address)
1 = Header Type 2 (with transport address)
```

**Note**: The naming is historical - "Type 1" has bit=0, "Type 2" has bit=1. In code, check `header_type == 1` for Type 2.

Header Type 2 includes an additional 16-byte transport address after the destination, used for source routing.

### Bits 5-4: Propagation Type

```
00 = BROADCAST - Send to all reachable nodes
01 = TRANSPORT - Routed through specific path
10 = (reserved)
11 = (reserved)
```

### Bits 3-2: Destination Type

```
00 = SINGLE - Single destination (encrypted)
01 = GROUP  - Group destination (shared secret)
10 = PLAIN  - Plain destination (unencrypted)
11 = LINK   - Established link
```

### Bits 1-0: Packet Type

```
00 = DATA        - Regular data packet
01 = ANNOUNCE    - Identity announcement
10 = LINKREQUEST - Request to establish link
11 = PROOF       - Cryptographic proof
```

### Header Byte Examples

```
0x00 = BROADCAST + Header1 + SINGLE + DATA
       = Standard encrypted data packet

0x40 = BROADCAST + Header2 + SINGLE + DATA
       = Data packet with transport address

0x01 = BROADCAST + Header1 + SINGLE + ANNOUNCE
       = Identity announcement

0x02 = BROADCAST + Header1 + SINGLE + LINKREQUEST
       = Link establishment request

0x0C = BROADCAST + Header1 + LINK + DATA
       = Data on established link
```

### Parsing the Header

```c
typedef struct {
    bool     ifac;            // Bit 7
    bool     header_type;     // Bit 6 (0=type1, 1=type2)
    uint8_t  propagation;     // Bits 5-4
    uint8_t  destination_type;// Bits 3-2
    uint8_t  packet_type;     // Bits 1-0
} PacketHeader;

void parse_header(uint8_t byte, PacketHeader *h) {
    h->ifac             = (byte >> 7) & 0x01;
    h->header_type      = (byte >> 6) & 0x01;
    h->propagation      = (byte >> 4) & 0x03;
    h->destination_type = (byte >> 2) & 0x03;
    h->packet_type      = byte & 0x03;
}

uint8_t build_header(PacketHeader *h) {
    return (h->ifac << 7) |
           (h->header_type << 6) |
           (h->propagation << 4) |
           (h->destination_type << 2) |
           h->packet_type;
}
```

## 4.3 Hops Field

The second byte is the **hops counter**:

```
+-------+
| Hops  |
| 1 byte|
+-------+

Value: Number of times this packet has been forwarded
Range: 0-255
```

Each forwarding node increments this value. Packets with too many hops are discarded to prevent routing loops.

```c
#define MAX_HOPS 128

bool should_forward(uint8_t hops) {
    return hops < MAX_HOPS;
}
```

## 4.4 Destination Address

The destination is a 16-byte truncated hash:

```
+-----------------------+
| Destination Hash      |
| 16 bytes              |
+-----------------------+
```

This addresses either:
- A destination (SINGLE, GROUP, PLAIN types)
- An established link (LINK type)

```c
void get_destination(const uint8_t *packet, uint8_t dest[16]) {
    memcpy(dest, &packet[2], 16);
}
```

## 4.5 Transport Address (Header Type 2)

When header bit 6 is set, an additional transport address follows:

```
+------------------+-----------------------+
| Destination Hash | Transport Hash        |
| 16 bytes         | 16 bytes              |
+------------------+-----------------------+
```

The transport address identifies the next hop or routing path. This enables:
- Source routing
- Path-specific forwarding
- Transport nodes

```c
void get_transport(const uint8_t *packet, uint8_t transport[16]) {
    // Only valid if header_type == 1
    memcpy(transport, &packet[18], 16);
}
```

## 4.6 Context Byte

The context byte indicates the payload type:

```
+---------+
| Context |
| 1 byte  |
+---------+
```

### Context Values

```c
#define CONTEXT_NONE            0x00  // Regular data
#define CONTEXT_RESOURCE        0x01  // Resource transfer
#define CONTEXT_RESOURCE_ADV    0x02  // Resource advertisement
#define CONTEXT_RESOURCE_REQ    0x03  // Resource request
#define CONTEXT_RESOURCE_HMU    0x04  // Resource hash map update
#define CONTEXT_RESOURCE_PRF    0x05  // Resource proof
#define CONTEXT_RESOURCE_ICL    0x06  // Resource initiator cancel
#define CONTEXT_RESOURCE_RCL    0x07  // Resource receiver cancel
#define CONTEXT_CACHE_REQUEST   0x08  // Request cached data
#define CONTEXT_REQUEST         0x09  // Request
#define CONTEXT_RESPONSE        0x0A  // Response
#define CONTEXT_PATH_RESPONSE   0x0B  // Path response
#define CONTEXT_COMMAND         0x0C  // Command
#define CONTEXT_COMMAND_STATUS  0x0D  // Command status
#define CONTEXT_CHANNEL         0x0E  // Channel data
#define CONTEXT_KEEPALIVE       0xFA  // Link keep-alive
#define CONTEXT_LINK_IDENTIFY   0xFB  // Link peer identification proof
#define CONTEXT_LINK_CLOSE      0xFC  // Link close message
#define CONTEXT_LINK_PROOF      0xFD  // Link packet proof
#define CONTEXT_LINK_RTT        0xFE  // Link request RTT measurement
#define CONTEXT_LINK_REQUEST_PROOF 0xFF  // Link request proof (during establishment)
```

### Context Byte Position

```c
size_t get_context_offset(PacketHeader *h) {
    if (h->header_type == 0) {
        return 18;  // header(1) + hops(1) + dest(16)
    } else {
        return 34;  // header(1) + hops(1) + dest(16) + transport(16)
    }
}

uint8_t get_context(const uint8_t *packet, PacketHeader *h) {
    return packet[get_context_offset(h)];
}
```

## 4.7 Payload

The payload follows the context byte:

```
+------------------+
| Payload          |
| variable length  |
+------------------+
```

Payload content depends on packet type and context:
- **DATA packets**: Encrypted or plain application data
- **ANNOUNCE packets**: Identity information
- **LINKREQUEST packets**: Initiator's public keys
- **PROOF packets**: Cryptographic proof data

### Maximum Packet and Data Sizes

Reticulum defines several size limits:

| Term | Default | Description |
|------|---------|-------------|
| **MTU** | 500 bytes | Maximum total packet size on wire |
| **MDU** | 464 bytes | Maximum data unit (payload space) for general packets |
| **Link MDU** | 431 bytes | Maximum plaintext per link data packet |

**Why Link MDU is smaller**: Link data is encrypted, adding 48+ bytes of Fernet overhead. The Link MDU accounts for this and ensures the encrypted packet fits in the MTU.

```
MTU (500) = Header (up to 35) + IFAC (1+) + Payload
MDU (464) = MTU - max_header - min_ifac = 500 - 35 - 1

Link MDU (431) = floor((MTU - header - ifac - token_overhead) / 16) * 16 - 1
               = floor((500 - 19 - 1 - 48) / 16) * 16 - 1 = 431
```

**Interface variations**:
- LoRa interfaces may have smaller MTU (e.g., 255 bytes)
- TCP interfaces can negotiate larger MTU
- Link MTU discovery can automatically upgrade link capacity

## 4.8 Packet Type Details

### DATA Packet

Most common packet type. Carries application data.

```
Header Type 1 (no transport):
+------+------+------+---------+-----------+
|Header| Hops | Dest | Context | Payload   |
| 0x00 | 1B   | 16B  | 1B      | up to 481B|
+------+------+------+---------+-----------+

Header Type 2 (with transport):
+------+------+------+-----------+---------+-----------+
|Header| Hops | Dest | Transport | Context | Payload   |
| 0x40 | 1B   | 16B  | 16B       | 1B      | up to 465B|
+------+------+------+-----------+---------+-----------+
```

For SINGLE destinations, payload is encrypted. For PLAIN destinations, it's cleartext.

### ANNOUNCE Packet

Broadcasts identity information to the network.

```
+------+------+------+---------+-------------------------+
|Header| Hops | Dest | Context | Announce Data           |
| 0x01 | 1B   | 16B  | 1B      | identity + app + sig    |
+------+------+------+---------+-------------------------+

Announce Data:
+----------+----------+---------+--------+-----------+
| X25519   | Ed25519  | Name    | Random | Signature |
| 32 bytes | 32 bytes | varies  | 5 bytes| 64 bytes  |
+----------+----------+---------+--------+-----------+
```

The signature covers: destination_hash + x25519 + ed25519 + name + random

### LINKREQUEST Packet

Initiates link establishment.

```
+------+------+------+---------+------------------+
|Header| Hops | Dest | Context | Link Request Data|
| 0x02 | 1B   | 16B  | 1B      | public keys      |
+------+------+------+---------+------------------+

Link Request Data:
+------------------+-------------------+
| Initiator X25519 | Initiator Ed25519 |
| 32 bytes         | 32 bytes          |
+------------------+-------------------+
```

Total: 64 bytes of public key data.

### PROOF Packet

Responds to link requests or proves packet delivery.

```
+------+------+------+---------+------------+
|Header| Hops | Dest | Context | Proof Data |
| 0x03 | 1B   | 16B  | 1B      | varies     |
+------+------+------+---------+------------+
```

For Link Request Proof (context = 0xFF):
```
Proof Data:
+-----------+-----------------+------------+
| Signature | Responder X25519| Signalling |
| 64 bytes  | 32 bytes        | 3 bytes    |
+-----------+-----------------+------------+
```

Total: 99 bytes.

## 4.9 Complete Packet Examples

### Example 1: Simple Data Packet

```
Sending "Hello" to destination 0xa1b2...

Hex: 00 00 a1b2c3d4e5f6789012345678abcdef01 00 [encrypted payload]

Breakdown:
  00        Header: BROADCAST + Header1 + SINGLE + DATA
  00        Hops: 0 (fresh packet)
  a1b2...   Destination hash (16 bytes)
  00        Context: NONE
  [...]     Encrypted payload (Fernet token)
```

### Example 2: Link Request Packet

```
Requesting link to destination 0xa1b2...

Hex: 02 00 a1b2c3d4e5f6789012345678abcdef01 00
     [32 bytes X25519 pub][32 bytes Ed25519 pub]

Breakdown:
  02        Header: BROADCAST + Header1 + SINGLE + LINKREQUEST
  00        Hops: 0
  a1b2...   Destination hash (16 bytes)
  00        Context: NONE
  [64B]     Initiator's public keys
```

### Example 3: Link Proof Packet

```
Proving link establishment to link 0xfedc...

Hex: 0F 00 fedcba9876543210fedcba9876543210 FF
     [64 bytes signature][32 bytes X25519 pub][3 bytes signalling]

Breakdown:
  0F        Header: BROADCAST + Header1 + LINK + PROOF
  00        Hops: 0
  fedc...   Link ID (16 bytes)
  FF        Context: LINK_PROOF
  [64B]     Ed25519 signature
  [32B]     Responder's X25519 public key
  [3B]      Signalling bytes (MTU info)
```

### Example 4: Data on Established Link

```
Sending encrypted data on link 0xfedc...

Hex: 0C 00 fedcba9876543210fedcba9876543210 00 [encrypted payload]

Breakdown:
  0C        Header: BROADCAST + Header1 + LINK + DATA
  00        Hops: 0
  fedc...   Link ID (16 bytes)
  00        Context: NONE
  [...]     Encrypted payload (Fernet token with link key)
```

## 4.10 Packet Parsing in C

Complete packet parser:

```c
typedef struct {
    // Header fields
    bool     ifac;
    bool     header_type;
    uint8_t  propagation;
    uint8_t  destination_type;
    uint8_t  packet_type;

    // Addresses
    uint8_t  hops;
    uint8_t  destination[16];
    uint8_t  transport[16];      // Only if header_type == 1
    bool     has_transport;

    // Context and payload
    uint8_t  context;
    uint8_t  *payload;
    size_t   payload_len;
} Packet;

bool parse_packet(const uint8_t *data, size_t len, Packet *pkt) {
    if (len < 19) return false;  // Minimum packet size

    // Parse header
    uint8_t header = data[0];
    pkt->ifac             = (header >> 7) & 0x01;
    pkt->header_type      = (header >> 6) & 0x01;
    pkt->propagation      = (header >> 4) & 0x03;
    pkt->destination_type = (header >> 2) & 0x03;
    pkt->packet_type      = header & 0x03;

    // Hops
    pkt->hops = data[1];

    // Destination
    memcpy(pkt->destination, &data[2], 16);

    // Transport (if header type 2)
    size_t offset = 18;
    if (pkt->header_type) {
        if (len < 35) return false;  // Need transport address
        memcpy(pkt->transport, &data[18], 16);
        pkt->has_transport = true;
        offset = 34;
    } else {
        pkt->has_transport = false;
    }

    // Context
    pkt->context = data[offset];
    offset++;

    // Payload
    pkt->payload = (uint8_t*)&data[offset];
    pkt->payload_len = len - offset;

    return true;
}

size_t build_packet(const Packet *pkt, uint8_t *out, size_t max_len) {
    size_t offset = 0;

    // Header
    out[offset++] = (pkt->ifac << 7) |
                    (pkt->header_type << 6) |
                    (pkt->propagation << 4) |
                    (pkt->destination_type << 2) |
                    pkt->packet_type;

    // Hops
    out[offset++] = pkt->hops;

    // Destination
    memcpy(&out[offset], pkt->destination, 16);
    offset += 16;

    // Transport (if header type 2)
    if (pkt->header_type) {
        memcpy(&out[offset], pkt->transport, 16);
        offset += 16;
    }

    // Context
    out[offset++] = pkt->context;

    // Payload
    if (offset + pkt->payload_len > max_len) {
        return 0;  // Buffer too small
    }
    memcpy(&out[offset], pkt->payload, pkt->payload_len);
    offset += pkt->payload_len;

    return offset;
}
```

## 4.11 Summary

| Field | Size | Description |
|-------|------|-------------|
| Header | 1 byte | Flags and packet type |
| Hops | 1 byte | Forward count |
| Destination | 16 bytes | Target address hash |
| Transport | 0 or 16 bytes | Routing address (header type 2 only) |
| Context | 1 byte | Payload type indicator |
| Payload | Variable | Packet data |

| Packet Type | Value | Purpose |
|-------------|-------|---------|
| DATA | 0x00 | Application data |
| ANNOUNCE | 0x01 | Identity broadcast |
| LINKREQUEST | 0x02 | Link establishment |
| PROOF | 0x03 | Cryptographic proof |

| Destination Type | Value | Encryption |
|------------------|-------|------------|
| SINGLE | 0x00 | Encrypted to identity |
| GROUP | 0x01 | Shared group key |
| PLAIN | 0x02 | Unencrypted |
| LINK | 0x03 | Link-derived key |

The next chapter explores **destinations** - the addressable endpoints that receive packets.
