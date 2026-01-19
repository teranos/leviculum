# Chapter 1: Introduction to Reticulum

## 1.1 What is Reticulum?

Reticulum is a cryptography-based networking stack designed for building resilient, private, and medium-agnostic communication networks. Unlike traditional networking protocols that assume reliable infrastructure, abundant bandwidth, and trusted intermediaries, Reticulum is built for a different world:

- **Medium-agnostic**: Works over any data carrier - TCP/IP, UDP, LoRa radio, serial lines, even audio modems
- **Bandwidth-efficient**: Designed for links as slow as 500 bits per second
- **Self-configuring**: No central coordination, addresses, or registries needed
- **Privacy-first**: End-to-end encryption is the default, not an option
- **Resilient**: Works in mesh topologies, tolerates network partitions

Reticulum does not replace the Internet. Instead, it provides a networking layer that can run *over* the Internet, *alongside* it, or *completely without* it. A Reticulum network can span radio links, serial cables, and TCP connections simultaneously.

## 1.2 The Problem with Traditional Networks

To understand why Reticulum exists, consider how traditional networks work:

### IP Addressing Requires Coordination

Every device on an IP network needs a unique address. This creates dependencies:
- DHCP servers assign addresses locally
- NAT routers share public addresses
- DNS servers map names to addresses
- Regional registries allocate address blocks

Each of these is a point of control, failure, or surveillance.

### Client-Server Dominates

Most Internet services follow the client-server model:
- Clients initiate connections to servers
- Servers have well-known addresses
- Data flows through central points
- Servers can be blocked, seized, or monitored

Even "peer-to-peer" systems often depend on central trackers, DHT bootstraps, or STUN servers.

### Encryption is Bolted On

Transport Layer Security (TLS) was added to HTTP decades after the web was invented. This pattern - plaintext first, encryption later - means:
- Encryption is optional and often misconfigured
- Metadata (who talks to whom, when, how much) remains visible
- Legacy systems resist encryption adoption

### Identity is External

On the Internet, your identity is:
- Your IP address (assigned by your ISP)
- Your domain name (rented from a registrar)
- Your certificate (issued by a certificate authority)
- Your username (stored on someone else's server)

None of these are truly *yours*. They can be revoked, reassigned, or compromised by third parties.

## 1.3 The Reticulum Philosophy

Reticulum takes a fundamentally different approach, guided by principles documented in the "Zen of Reticulum":

### Uncentralizability

> "No mechanism in Reticulum should ever require, result in, or even allow centralised points of authority or control."

The protocol has no:
- Central servers or coordinators
- Address registries or allocation authorities
- Certificate authorities or trust anchors
- Required Internet connectivity

### Cryptographic Identity

> "Trust issued from cryptographic origins, over authority from institutions."

In Reticulum:
- **Your identity is a key pair** - specifically, an X25519 key (for encryption) and an Ed25519 key (for signing)
- **Your address is derived from your keys** - a hash of your public keys becomes your network address
- **You control your identity** - no one can revoke it, and you can use it anywhere

### Encryption as Gravity

> "Encryption is gravity. It must be the overarching influence that ensures everything stays together, and without which everything falls apart."

Encryption is not a feature in Reticulum - it's the foundation:
- All communication is encrypted by default
- The only way to *disable* encryption is to explicitly request it
- Even "plaintext" destinations encrypt the transport layer

### Scarcity Consciousness

> "Reticulum must be scarcity-conscious, and designed for simple, cheap, low-power and salvaged devices."

The protocol is designed for:
- Low bandwidth (500 bps minimum)
- Limited memory (microcontrollers)
- Intermittent connectivity
- Heterogeneous links

### Medium Agnosticism

Reticulum treats all data carriers the same:
- A TCP socket is just a byte stream
- A serial port is just a byte stream
- A LoRa radio is just a byte stream (with packet boundaries)

The same protocol runs unchanged over fiber optics or 1200 baud radio.

## 1.4 Comparison with TCP/IP

For programmers familiar with TCP/IP, here's how Reticulum maps to familiar concepts:

| TCP/IP Concept | Reticulum Equivalent |
|----------------|---------------------|
| IP Address | Destination Hash (16 bytes) |
| MAC Address | Interface-specific, not protocol-visible |
| DNS Name | Application Name (hashed into address) |
| TCP Connection | Link |
| UDP Datagram | Packet |
| TLS Certificate | Identity (Ed25519 public key) |
| Port Number | Aspect (hashed into address) |

### Key Differences

**Addresses are hashes, not assignments**: A Reticulum address is the truncated hash of a public key. You generate it yourself - no registration needed.

**No connection state in the network**: Routers don't track connections. Each packet is independently routable.

**Encryption is mandatory**: You cannot send a packet to a "single" destination without encrypting it.

**Identity is portable**: Your key pair works anywhere. Move to a new network, use a new interface - your identity follows.

## 1.5 Network Topology

Reticulum networks form a mesh topology:

```
    [Node A]----[Node B]----[Node C]
        |           |           |
        |       [Node D]        |
        |           |           |
    [Node E]----[Node F]----[Node G]
```

- Any node can talk to any other node
- Multiple paths may exist between nodes
- Nodes forward packets for others
- No hierarchy or designated routers

### Announces and Discovery

How does Node A find Node G? Through **announces**:

1. Node G broadcasts an announce packet with its identity
2. The announce propagates through the mesh
3. Each forwarding node records the path back to G
4. Node A receives the announce and learns how to reach G

This is similar to how routing protocols like OSPF or BGP work, but:
- No routing tables to configure
- No AS numbers to register
- Works across heterogeneous links
- Includes cryptographic verification

### Links

For bidirectional communication, nodes establish **links**:

1. Node A sends a link request to Node G
2. Node G responds with a cryptographic proof
3. Both derive shared encryption keys
4. A bidirectional encrypted channel is established

Links are similar to TCP connections but:
- Encrypted by default
- Can span multiple hops
- Include forward secrecy

## 1.6 The Protocol Stack

Reticulum is a complete networking stack:

```
+------------------------+
|     Application        |  Your code
+------------------------+
|     Destination        |  Addressing and identity
+------------------------+
|     Link               |  Encrypted channels
+------------------------+
|     Packet             |  Data units
+------------------------+
|     Interface          |  Physical transport
+------------------------+
|     Physical Medium    |  TCP, UDP, Serial, Radio...
+------------------------+
```

### Interface Layer

The bottom layer handles byte streams. Reticulum uses HDLC-like framing:
- `0x7E` marks frame boundaries
- Byte stuffing escapes special characters
- No CRC (Reticulum relies on cryptographic integrity)

### Packet Layer

Packets are the basic data unit:
- 2-byte header (flags, hops)
- 16-byte destination address
- Optional transport address
- 1-byte context
- Payload (up to ~500 bytes)

### Link Layer

Links provide reliable encrypted channels:
- Bidirectional communication
- Derived symmetric keys
- Keep-alive and timeout handling
- Round-trip time measurement

### Destination Layer

Destinations represent addressable endpoints:
- Derived from identity public keys
- Include application name and aspect
- Support callbacks for incoming packets

### Application Layer

Your code interacts with destinations and links:
- Register a destination to receive packets
- Establish links for bidirectional channels
- Send and receive encrypted data

## 1.7 Getting Started

The rest of this textbook will build up your understanding layer by layer:

1. **Chapter 2**: Learn the cryptographic primitives (hashing, encryption, signatures)
2. **Chapter 3**: Understand identity and addressing
3. **Chapter 4**: Study packet structure
4. **Chapter 5**: Explore destination types
5. **Chapter 6**: See how framing works
6. **Chapter 7-8**: Dive deep into link establishment
7. **Chapter 9-11**: Advanced topics (routing, resources, transport)
8. **Chapter 12-13**: Implementation guidance

By the end, you'll understand Reticulum well enough to implement it from scratch.

## 1.8 Summary

- Reticulum is a cryptography-first networking stack
- Addresses are derived from cryptographic keys
- Encryption is default, not optional
- Works over any byte-stream medium
- Self-configuring mesh topology
- No central authorities or registries

The next chapter introduces the cryptographic building blocks that make this all possible.
