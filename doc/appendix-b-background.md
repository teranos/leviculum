# Appendix B: Background Knowledge

This appendix covers foundational concepts from cryptography, networking, and computer science that underlie Reticulum's design. Understanding these concepts helps explain *why* the protocol works the way it does.

## B.1 Cryptographic Key Sizes and Security Levels

### What "128-bit Security" Means

Security level describes how much work an attacker needs to break the system:

```
128-bit security = Attacker needs ~2^128 operations to break

How big is 2^128?
  2^128 ≈ 3.4 × 10^38

For comparison:
  - Atoms in the observable universe: ~10^80
  - Fastest supercomputer: ~10^18 operations/second
  - Operations per year: ~3 × 10^25
  - Years to try 2^128: ~10^13 years (10 trillion years)
  - Age of universe: ~1.4 × 10^10 years

Conclusion: 128-bit security is computationally infeasible to break.
```

### Key Size vs Security Level

Different algorithms provide different security levels per bit of key:

| Algorithm | Key Size | Security Level | Notes |
|-----------|----------|----------------|-------|
| AES-128 | 128 bits | 128 bits | Symmetric cipher |
| AES-256 | 256 bits | 256 bits | Symmetric cipher |
| X25519 | 256 bits | ~128 bits | Elliptic curve (smaller keys) |
| Ed25519 | 256 bits | ~128 bits | Elliptic curve signatures |
| RSA-2048 | 2048 bits | ~112 bits | Older, needs bigger keys |
| RSA-3072 | 3072 bits | ~128 bits | Equivalent to X25519 |

**Why elliptic curves use smaller keys**:
- RSA security based on factoring large numbers
- ECC security based on elliptic curve discrete log
- Discrete log is harder → same security with smaller keys
- Smaller keys = less bandwidth, faster computation

### Reticulum's Security Targets

```
Component              Key/Hash Size    Security Level
─────────────────────────────────────────────────────
SHA-256 (full)         256 bits        128 bits (collision)
SHA-256 (truncated)    128 bits        64 bits (collision)
X25519                 256 bits        ~128 bits
Ed25519                256 bits        ~128 bits
AES-256-CBC            256 bits        256 bits
HMAC-SHA256            256 bits        256 bits
```

## B.2 The Birthday Paradox and Hash Collisions

### The Birthday Problem

```
Question: In a room of N people, what's the probability
          that two people share a birthday?

Intuition says: Need ~365 people for 100% chance
Reality: Only 23 people gives >50% chance!

Why? You're not looking for YOUR birthday twin.
     You're looking for ANY two people matching.

With 23 people: 23 × 22 / 2 = 253 pairs to check
Each pair has 1/365 chance of matching
253 × (1/365) ≈ 69% expected matches
```

### Birthday Bound for Hash Functions

```
For a hash function with N-bit output:

Possible hash values: 2^N
Expected collisions after: ~√(2^N) = 2^(N/2) hashes

SHA-256 (256-bit output):
  Collision expected after: 2^128 hashes
  This is computationally infeasible

Truncated to 128 bits:
  Collision expected after: 2^64 hashes
  Still very large, but not infeasible

Truncated to 64 bits:
  Collision expected after: 2^32 ≈ 4 billion hashes
  Feasible on modern hardware!
```

### Why Reticulum Uses 128-bit Truncated Hashes

```
Destination addresses use SHA-256 truncated to 128 bits (16 bytes)

Birthday bound: 2^64 operations to find collision

Is 2^64 safe?

  2^64 ≈ 1.8 × 10^19 (18 quintillion)

  At 1 billion hashes/second:
    Time to birthday attack: ~585 years

  At 1 trillion hashes/second (massive hardware):
    Time to birthday attack: ~213 days
    Cost: Millions of dollars in hardware

Conclusion:
  - For addressing: 128-bit is sufficient
  - For critical signatures: Use full 256-bit hashes
  - Trade-off: 16 bytes vs 32 bytes per address (50% savings)
```

### Collision vs Preimage Resistance

```
Collision resistance:
  Find ANY two inputs that hash to same output
  Birthday bound: 2^(N/2)

Preimage resistance:
  Given a hash H, find ANY input that produces H
  Full security: 2^N

Second preimage resistance:
  Given input X, find different input Y with same hash
  Full security: 2^N

For addresses:
  - Attacker wants collision (two destinations, same address)
  - Birthday bound applies: 2^64 for 128-bit hashes

For integrity:
  - Attacker wants to find different data with same HMAC
  - Preimage bound applies: 2^256 for HMAC-SHA256
```

## B.3 Mesh Networking Fundamentals

### Traditional Hierarchical Networks

```
Internet topology (simplified):

         [Core Routers]
        /      |       \
   [Regional] [Regional] [Regional]
      |          |          |
   [ISP]      [ISP]       [ISP]
   / | \      / | \       / | \
[Users]    [Users]      [Users]

Properties:
  - Tree-like structure
  - Central points of control
  - Single path between nodes (mostly)
  - Routing tables describe ENTIRE network
  - Failure of core affects many users
```

### Mesh Network Topology

```
Mesh topology:

    [A]----[B]----[C]
     |  \   |   /  |
     |   \  |  /   |
    [D]----[E]----[F]
     |   /  |  \   |
     |  /   |   \  |
    [G]----[H]----[I]

Properties:
  - No hierarchy
  - Multiple paths between nodes
  - No central point of failure
  - Each node only knows local neighbors
  - Routing discovered dynamically
```

### Flooding Algorithm

```
Basic flooding (what Reticulum uses for broadcasts):

When node X receives packet P:
  1. Have I seen P before? (check packet hash)
     - Yes → Drop it (prevents loops)
     - No → Continue

  2. Add P's hash to "seen" list

  3. Is P addressed to me?
     - Yes → Process locally
     - Also continue to step 4 (might still forward)

  4. Is hop count < maximum?
     - No → Drop (prevents infinite propagation)
     - Yes → Forward to ALL neighbors except sender

Result: Packet reaches every node in connected network
```

### Why Flooding Works

```
Advantages:
  - Simple to implement
  - No routing tables needed
  - Works with dynamic topology
  - Handles network partitions gracefully
  - Eventually consistent

Disadvantages:
  - Bandwidth inefficient (every node sees every packet)
  - Doesn't scale to huge networks
  - Requires deduplication state

Reticulum's approach:
  - Flooding for announces (discovery)
  - Directed routing for data (after path known)
  - Hop limits prevent infinite propagation
  - Packet hash deduplication prevents loops
```

### Path Discovery via Announces

```
How node A learns to reach node G:

1. G sends ANNOUNCE packet
2. Announce floods through network:

   G → H → E → B → A  (3 hops)
   G → H → E → D → A  (3 hops)
   G → I → F → C → B → A  (4 hops)

3. A receives announce from multiple paths
4. A records: "To reach G, use path via B (3 hops)"
5. A ignores longer paths (4 hops via C)

6. Later: A wants to send to G
7. A looks up path table: "G via B"
8. A sends packet to B with transport header
9. B forwards toward G based on its path table
```

## B.4 Byte Order and Endianness

### What is Endianness?

```
Multi-byte values can be stored two ways:

Value: 0x12345678 (4 bytes)

Big-endian (network byte order):
  Address:  0    1    2    3
  Content: [12] [34] [56] [78]
  Most significant byte FIRST

Little-endian (Intel/AMD CPUs):
  Address:  0    1    2    3
  Content: [78] [56] [34] [12]
  Least significant byte FIRST
```

### Why This Matters for Protocols

```
If Alice (big-endian) sends 0x1234 to Bob (little-endian):

Alice sends: [0x12] [0x34]

Without agreement:
  Bob reads: 0x3412  (WRONG!)

With network byte order convention:
  Everyone uses big-endian on wire
  Bob converts after receiving: ntohl(received) → correct value
```

### Reticulum Uses Big-Endian

```
All multi-byte fields in Reticulum are big-endian:

Timestamp in random hash (5 bytes):
  uint64_t time = 1704067200;  // 2024-01-01 00:00:00 UTC

  Big-endian encoding:
    bytes[0] = (time >> 32) & 0xFF;  // 0x00
    bytes[1] = (time >> 24) & 0xFF;  // 0x00
    bytes[2] = (time >> 16) & 0xFF;  // 0x00
    bytes[3] = (time >> 8) & 0xFF;   // 0x65
    bytes[4] = time & 0xFF;          // 0x80

  Result: [0x00, 0x00, 0x00, 0x65, 0x80]
```

### C Code for Byte Order Conversion

```c
#include <stdint.h>

// Write 16-bit value as big-endian
void write_be16(uint8_t *buf, uint16_t val) {
    buf[0] = (val >> 8) & 0xFF;
    buf[1] = val & 0xFF;
}

// Read 16-bit value from big-endian
uint16_t read_be16(const uint8_t *buf) {
    return ((uint16_t)buf[0] << 8) | buf[1];
}

// Write 32-bit value as big-endian
void write_be32(uint8_t *buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
}

// Read 32-bit value from big-endian
uint32_t read_be32(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) |
           buf[3];
}

// Or use standard library (if available):
#include <arpa/inet.h>
uint32_t network = htonl(host);   // Host to network (big-endian)
uint32_t host = ntohl(network);   // Network to host
```

## B.5 Why Layered Protocols

### The OSI Model Concept

```
Layer 7: Application    - What the user sees
Layer 6: Presentation   - Data formatting
Layer 5: Session        - Connection management
Layer 4: Transport      - Reliable delivery
Layer 3: Network        - Routing
Layer 2: Data Link      - Framing
Layer 1: Physical       - Bits on wire
```

### Reticulum's Layers

```
┌─────────────────────────┐
│ Application             │  Your code
├─────────────────────────┤
│ Resource                │  Large data transfers
├─────────────────────────┤
│ Link                    │  Encrypted channels
├─────────────────────────┤
│ Destination             │  Addressing
├─────────────────────────┤
│ Packet                  │  Data units
├─────────────────────────┤
│ Transport               │  Routing
├─────────────────────────┤
│ Interface               │  Abstraction
├─────────────────────────┤
│ Framing (HDLC)          │  Packet boundaries
├─────────────────────────┤
│ Physical                │  TCP, Serial, LoRa...
└─────────────────────────┘
```

### Why Layering Matters

```
Separation of concerns:

Without layers:
  - Change physical medium → Rewrite everything
  - Fix encryption bug → Might break routing
  - Add new feature → Must understand entire system

With layers:
  - Change TCP to LoRa → Only Interface layer changes
  - Fix encryption → Only Link layer changes
  - Add compression → Only Resource layer changes

Each layer:
  - Has well-defined interface to adjacent layers
  - Hides internal details
  - Can be tested independently
  - Can be replaced without affecting others
```

### Example: Sending Data Through Layers

```
Application: send("Hello")
    ↓
Link: encrypt("Hello") → [ciphertext]
    ↓
Packet: add_header([ciphertext]) → [header][ciphertext]
    ↓
Transport: route([packet]) → select interface
    ↓
Framing: hdlc_frame([packet]) → [0x7E][data][0x7E]
    ↓
Physical: tcp_send([framed])
    ↓
═══════════════════════════════════════ Network ═══
    ↓
Physical: tcp_recv() → [framed]
    ↓
Framing: hdlc_deframe([framed]) → [packet]
    ↓
Transport: deliver([packet]) → find destination
    ↓
Packet: parse([packet]) → [header][ciphertext]
    ↓
Link: decrypt([ciphertext]) → "Hello"
    ↓
Application: receive("Hello")
```

## B.6 Framing and the Synchronization Problem

### The Problem

```
Scenario: Continuous byte stream (serial port, TCP socket)

Sender sends packets:
  Packet 1: [A][B][C]
  Packet 2: [D][E]
  Packet 3: [F][G][H][I]

Receiver sees:
  [A][B][C][D][E][F][G][H][I]

Question: Where does Packet 1 end and Packet 2 begin?
```

### Solution 1: Length Prefix

```
Each packet starts with its length:

  [3][A][B][C][2][D][E][4][F][G][H][I]
   ↑           ↑        ↑
  len=3       len=2    len=4

Advantages:
  - Simple
  - Efficient (minimal overhead)

Disadvantages:
  - If you lose sync, hard to recover
  - Single corrupted length byte breaks everything
```

### Solution 2: Delimiter-Based (HDLC)

```
Special byte marks boundaries:

  [0x7E][A][B][C][0x7E][D][E][0x7E][F][G][H][I][0x7E]
    ↑            ↑          ↑                 ↑
   start        end/       end/              end
               start      start

Problem: What if data contains 0x7E?

Solution: Escape sequences (byte stuffing)
  Data 0x7E → Send 0x7D 0x5E
  Data 0x7D → Send 0x7D 0x5D

Advantages:
  - Self-synchronizing (scan for 0x7E to find boundaries)
  - Can recover from corruption

Disadvantages:
  - Variable overhead (depends on data content)
  - Slightly more complex parsing
```

### Why Reticulum Uses HDLC

```
1. Self-synchronizing
   - Radio links may have dropouts
   - Can resync by finding next 0x7E

2. Works on any byte stream
   - Serial ports
   - TCP sockets
   - Radio modems

3. Simple state machine
   - Easy to implement on microcontrollers

4. Proven design
   - Used since 1970s
   - Well-understood behavior
```

## B.7 Serialization Formats

### Why Serialization?

```
Problem: How to transmit structured data?

Announce contains:
  - Public key (64 bytes)
  - Name hash (10 bytes)
  - Random hash (10 bytes)
  - Optional: ratchet (32 bytes)
  - Signature (64 bytes)
  - Optional: app data (variable)

Need to encode:
  - Field boundaries
  - Optional presence
  - Variable lengths
```

### Option 1: Fixed Format

```
Every field at known offset:

Offset 0:  public_key[64]
Offset 64: name_hash[10]
Offset 74: random_hash[10]
Offset 84: signature[64]
Offset 148: app_data[...]

Advantages:
  - Fast (direct memory access)
  - Compact (no metadata)

Disadvantages:
  - Can't have optional fields
  - Hard to extend (breaks compatibility)
```

### Option 2: JSON

```json
{
  "public_key": "base64...",
  "name_hash": "base64...",
  "random_hash": "base64...",
  "signature": "base64...",
  "app_data": {...}
}

Advantages:
  - Human readable
  - Self-describing
  - Optional fields natural

Disadvantages:
  - Verbose (field names in every message)
  - Base64 increases size by 33%
  - Parsing overhead
```

### Option 3: MessagePack (What Reticulum Uses)

```
Binary format with type markers:

Map with 5 entries:
  0x85                    // Map of 5 items
  0xa1 0x74               // Key "t" (1-char string)
  0xcd 0x12 0x34          // Value 0x1234 (uint16)
  0xa1 0x68               // Key "h"
  0xc4 0x20 [32 bytes]    // Value (32-byte bin)
  ...

Advantages:
  - Compact (minimal overhead)
  - Self-describing (has types)
  - Optional fields supported
  - Fast parsing

Disadvantages:
  - Not human readable
  - Need library to parse
```

### Why MessagePack for Reticulum

```
Resource advertisements use msgpack because:
  - Variable number of fields
  - Optional fields (request_id, metadata)
  - Need type information (distinguish int from bytes)
  - Bandwidth critical (smaller than JSON)

Packet headers use fixed format because:
  - Always same fields
  - Known sizes
  - Maximum efficiency
  - Simpler parsing
```

## B.8 State Machines in Protocols

### What is a State Machine?

```
A state machine has:
  - States (conditions the system can be in)
  - Transitions (how to move between states)
  - Events (what triggers transitions)
  - Actions (what happens during transitions)
```

### Link State Machine

```
States:
  PENDING    - Request sent, waiting for proof
  HANDSHAKE  - Processing key exchange
  ACTIVE     - Link operational
  STALE      - No recent activity
  CLOSED     - Link terminated

Transitions:

  [PENDING] --proof_received--> [HANDSHAKE]
  [PENDING] --timeout--> [CLOSED]

  [HANDSHAKE] --key_derived--> [ACTIVE]
  [HANDSHAKE] --error--> [CLOSED]

  [ACTIVE] --data_received--> [ACTIVE] (reset timer)
  [ACTIVE] --keepalive_timeout--> [STALE]
  [ACTIVE] --close_received--> [CLOSED]

  [STALE] --keepalive_response--> [ACTIVE]
  [STALE] --stale_timeout--> [CLOSED]
```

### Why State Machines Matter

```
Without explicit states:

  if (proof_received && !key_derived && ...) {
    // What state are we in??
  }

With explicit states:

  switch (link->state) {
    case LINK_PENDING:
      if (proof_received) {
        process_proof();
        link->state = LINK_HANDSHAKE;
      }
      break;
    case LINK_HANDSHAKE:
      // ...
  }

Benefits:
  - Clear what's valid in each state
  - Easy to add logging ("state changed to X")
  - Easier to debug ("stuck in state Y")
  - Documents expected behavior
```

## B.9 Flow Control Concepts

### The Problem

```
Fast sender, slow receiver:

Sender (1 Mbps) ────────> Receiver (100 Kbps)
                              ↓
                         [Buffer fills]
                              ↓
                         [Packets dropped!]
```

### Window-Based Flow Control

```
Sender has "window" of how many packets to send before waiting:

Window = 4:
  Send packet 1
  Send packet 2
  Send packet 3
  Send packet 4
  WAIT for acknowledgment

  Receive ACK for 1,2
  Window slides: can send 5,6

  Send packet 5
  Send packet 6
  WAIT...
```

### Reticulum's Resource Flow Control

```
Adaptive window:
  - Start small (window = 4)
  - Increase on success
  - Decrease on timeout

Rate detection:
  - Measure response time
  - Fast link (>50 Kbps): allow large window (75)
  - Slow link (<2 Kbps): cap window (4)

This prevents:
  - Buffer overflow on slow links
  - Unnecessary waiting on fast links
```

### AIMD (Additive Increase, Multiplicative Decrease)

```
TCP's approach (similar to Reticulum):

On success:
  window = window + 1  (additive increase)

On timeout:
  window = window / 2  (multiplicative decrease)

Why multiplicative decrease?
  - Timeout likely means congestion
  - Need to back off quickly
  - Additive decrease too slow to relieve congestion

Why additive increase?
  - Probe available bandwidth gradually
  - Avoid causing congestion
```

## B.10 Time and Clocks in Distributed Systems

### The Clock Problem

```
Node A's clock: 10:00:00
Node B's clock: 10:05:00  (5 minutes ahead)

A sends announce with timestamp 10:00:00
B receives it, thinks it's 5 minutes old
B might reject as "stale"!
```

### How Reticulum Handles Time

```
Path expiration:
  - Uses LOCAL clock to timestamp when path was learned
  - Expiration = learned_time + TTL
  - No synchronization needed!

Announce timestamps:
  - Embedded in random hash for ordering
  - Used to compare "which is newer" not "how old"
  - Works even with unsynchronized clocks:

    Announce A has timestamp T1
    Announce B has timestamp T2
    If T2 > T1, B is "newer" regardless of clock offset
```

### Reticulum's Clock Skew Tolerance

Reticulum has **no explicit clock synchronization requirement**. This is achieved through careful design:

| Operation | Clock Dependency | Tolerance |
|-----------|-----------------|-----------|
| Path expiry | Local clock only | Unlimited skew |
| Announce ordering | Relative comparison | Works with any skew |
| Link timeout | Local elapsed time | Unlimited skew |
| Ratchet expiry | Local clock only | Unlimited skew |

**Potential issues with extreme skew**:
- A node with clock set **far in the future** will have its announces appear "more recent", potentially winning path selection unfairly
- A node with clock set **far in the past** may have its announces ignored as "older"
- Path TTLs (7 days default) use local time, so won't be affected

**Practical guidance**: While Reticulum tolerates clock differences, keeping clocks roughly accurate (within hours) is good practice. NTP synchronization is not required but recommended.

### Best Practices

```
1. Use relative time where possible
   - "Expires in 7 days" not "Expires on Jan 15"

2. For ordering, compare within same source
   - Node X's timestamps can be compared to each other
   - Don't compare Node X's timestamp to Node Y's

3. For absolute deadlines, allow margin
   - LINK_TIMEOUT = 120 seconds
   - Check: elapsed > 120 + margin
```

## B.11 Summary: Key Takeaways

### Cryptographic Foundations

| Concept | Key Point |
|---------|-----------|
| 128-bit security | ~2^128 operations to break = infeasible |
| Birthday bound | Collision after ~2^(N/2) for N-bit hash |
| Forward secrecy | Ephemeral keys protect past communications |
| Encrypt-then-MAC | Verify integrity before decryption |

### Networking Foundations

| Concept | Key Point |
|---------|-----------|
| Mesh flooding | Send to all neighbors, deduplicate |
| Path discovery | Learn routes from received announces |
| Big-endian | Most significant byte first on wire |
| HDLC framing | 0x7E delimiters, escape 0x7D |

### Protocol Design

| Concept | Key Point |
|---------|-----------|
| State machines | Explicit states make behavior clear |
| Layering | Isolate concerns, enable replacement |
| Flow control | Adapt to link speed |
| Serialization | MessagePack balances size and flexibility |

### Common Pitfalls

| Mistake | Consequence |
|---------|-------------|
| Wrong byte order | Interoperability fails |
| Timing attack | Secret data leaked |
| Skip HMAC check | Accept tampered packets |
| Reuse ephemeral keys | Lose forward secrecy |
| Ignore state machine | Race conditions, hangs |
