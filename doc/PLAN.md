# Reticulum Textbook Implementation Plan

## Overview

Create a comprehensive textbook about the Reticulum protocol stack for experienced C programmers without domain-specific knowledge in mesh networking, cryptography, or protocol design.

**Target Location**: `/home/lew/coding/leviculum/doc/`
**Source of Truth**: Python implementation at `/home/lew/coding/Reticulum`
**Target Audience**: Experienced C programmers, no domain knowledge assumed

---

## Textbook Structure

### Part I: Foundations

#### Chapter 1: Introduction to Reticulum
- What is Reticulum and why does it exist
- The problem of centralized infrastructure
- Design philosophy from "Zen of Reticulum"
- Key properties: medium-agnostic, uncensorable, self-configuring
- Comparison with traditional networking (TCP/IP stack)

#### Chapter 2: Cryptographic Primitives
- **2.1 Hash Functions**
  - What is a hash function
  - SHA-256 and its properties
  - Truncated hashes (128-bit address hashes)
  - Hash-based addressing

- **2.2 Symmetric Encryption**
  - Block ciphers (AES)
  - Modes of operation (CBC)
  - Padding (PKCS7)
  - The Fernet token format

- **2.3 Asymmetric Cryptography**
  - Public/private key pairs
  - Elliptic Curve Cryptography basics
  - X25519: Key exchange (ECDH)
  - Ed25519: Digital signatures

- **2.4 Key Derivation**
  - HKDF (HMAC-based Key Derivation Function)
  - Deriving symmetric keys from shared secrets
  - Salt and context in key derivation

#### Chapter 3: Identity and Addressing
- **3.1 The Identity Concept**
  - Cryptographic identity vs network identity
  - Identity = X25519 public key + Ed25519 public key
  - Self-sovereign identity (you control your keys)

- **3.2 Address Hashing**
  - Full hash vs truncated hash
  - Address hash computation
  - Collision probability and security margins

- **3.3 Identity Operations**
  - Creating identities
  - Signing and verification
  - Encryption to an identity
  - Key exchange with an identity

### Part II: Protocol Architecture

#### Chapter 4: Packet Structure
- **4.1 Packet Header**
  - Header flags byte (IFAC, header type, propagation, destination type, packet type)
  - Hops counter
  - Address fields
  - Context byte

- **4.2 Packet Types**
  - DATA packets
  - ANNOUNCE packets
  - LINKREQUEST packets
  - PROOF packets

- **4.3 Destination Types**
  - SINGLE (unicast)
  - GROUP (multicast)
  - PLAIN (broadcast)
  - LINK (established link)

#### Chapter 5: Destinations
- **5.1 Destination Concept**
  - What is a destination
  - Destination hash computation
  - Application names and aspects

- **5.2 Destination Types**
  - Single destinations (point-to-point)
  - Group destinations (shared secret)
  - Plain destinations (unencrypted)

- **5.3 Callbacks and Handlers**
  - Packet callbacks
  - Link establishment callbacks
  - Proof strategies

#### Chapter 6: Transport Layer Framing
- **6.1 HDLC Framing**
  - Frame delimiters (0x7E)
  - Byte stuffing and escape sequences
  - Why no CRC in Reticulum's HDLC

- **6.2 Interface Types**
  - TCP Client/Server interfaces
  - UDP interfaces
  - Serial/UART interfaces
  - LoRa and other radio interfaces

- **6.3 Interface Authentication (IFAC)**
  - Interface authentication codes
  - Shared secrets per interface
  - Protecting local networks

### Part III: Link Layer

#### Chapter 7: Link Establishment
- **7.1 The Link Concept**
  - Why links exist (bidirectional encrypted channels)
  - Link states: PENDING → HANDSHAKE → ACTIVE → STALE → CLOSED
  - Link identification

- **7.2 Link Request**
  - Building a LINKREQUEST packet
  - Ephemeral key generation
  - Link ID computation

- **7.3 Link Proof**
  - Proof packet structure (signature + public key + signalling)
  - Signed data format (83 bytes)
  - Signature verification

- **7.4 Key Derivation for Links**
  - ECDH shared secret
  - HKDF key derivation
  - Symmetric encryption setup

#### Chapter 8: Link Communication
- **8.1 Data Packets on Links**
  - Encryption with derived key
  - Packet contexts (NONE, RESOURCE, etc.)

- **8.2 Keep-Alive Mechanism**
  - Keep-alive packets (0xFF request, 0xFE response)
  - Timeout handling
  - Stale link detection

- **8.3 RTT Measurement**
  - Round-trip time packets
  - RTT computation and use

### Part IV: Advanced Topics

#### Chapter 9: Announces and Path Discovery
- **9.1 Announce Packets**
  - Announce structure
  - Propagation rules
  - Announce rate limiting

- **9.2 Path Table**
  - Storing discovered paths
  - Path selection
  - Path expiry

#### Chapter 10: Resource Transfers
- **10.1 Resource Concept**
  - Large data transfer over links
  - Segmentation and reassembly
  - Progress tracking

- **10.2 Resource Protocol**
  - Resource advertisements
  - Request/response flow
  - Compression (LZMA)

#### Chapter 11: Transport Layer
- **11.1 Transport Instance**
  - Global transport coordination
  - Interface management
  - Packet routing

- **11.2 Mesh Routing Basics**
  - Hop-by-hop forwarding
  - Announce propagation
  - Convergence

### Part V: Implementation Guide

#### Chapter 12: Building a Reticulum Implementation
- **12.1 Minimum Viable Implementation**
  - Required components
  - Optional components
  - Testing against Python RNS

- **12.2 Memory and Resource Constraints**
  - Embedded system considerations
  - No-std implementations
  - Buffer management

#### Chapter 13: Interoperability Testing
- **13.1 Test Vectors**
  - Known good packet examples
  - Cryptographic test vectors
  - Link establishment test cases

---

## Implementation Stages

### Stage 1: Foundation Chapters (Chapters 1-3)
**Goal**: Philosophy and cryptographic foundations
**Files**:
- `01-introduction.md`
- `02-cryptography.md`
- `03-identity.md`
**Status**: Complete

### Stage 2: Protocol Chapters (Chapters 4-6)
**Goal**: Core protocol structure
**Files**:
- `04-packets.md`
- `05-destinations.md`
- `06-framing.md`
**Status**: Complete

### Stage 3: Link Chapters (Chapters 7-8)
**Goal**: Link establishment and communication
**Files**:
- `07-link-establishment.md`
- `08-link-communication.md`
**Status**: Complete

### Stage 4: Advanced Chapters (Chapters 9-11)
**Goal**: Routing and resource transfer
**Files**:
- `09-announces.md`
- `10-resources.md`
- `11-transport.md`
**Status**: Complete

### Stage 5: Implementation Guide (Chapters 12-13)
**Goal**: Practical implementation guidance
**Files**:
- `12-implementation.md`
- `13-testing.md`
**Status**: Complete

---

## Didactic Approach

1. **Bottom-up learning**: Start with cryptographic primitives before using them
2. **Concrete examples**: Include hex dumps, code snippets, diagrams
3. **C programmer perspective**: Use familiar concepts (structs, byte arrays, pointers)
4. **Incremental complexity**: Each chapter builds on previous ones
5. **Cross-references**: Link related concepts between chapters
6. **Test vectors**: Provide concrete data for verification

## Research Notes

### Key Files in Python Implementation
- `RNS/Identity.py` - Identity and cryptography
- `RNS/Packet.py` - Packet structure
- `RNS/Destination.py` - Destination types
- `RNS/Link.py` - Link establishment
- `RNS/Resource.py` - Resource transfer
- `RNS/Transport.py` - Routing and transport
- `RNS/Interfaces/` - Various interface implementations

### Philosophy (from Zen of Reticulum)
- Uncentralizability is paramount
- Sovereignty and consent are uncompromisable
- Cryptographic trust over institutional authority
- Portability of identity
- Encryption is "gravity" - always present unless explicitly removed
- Scarcity-conscious design
- Medium-agnostic operation
