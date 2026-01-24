# Reticulum Protocol Textbook

A comprehensive guide to the Reticulum networking stack for programmers.

## Target Audience

This textbook is written for experienced programmers (particularly C programmers) who want to understand and implement Reticulum. No prior knowledge of cryptography, mesh networking, or protocol design is assumed.

## Source of Truth

This documentation is based on the Python reference implementation at:
https://github.com/markqvist/Reticulum

## Table of Contents

### Part I: Foundations

1. **[Introduction to Reticulum](01-introduction.md)** - Philosophy, design goals, and comparison with traditional networking
2. **[Cryptographic Primitives](02-cryptography.md)** - SHA-256, AES, Fernet, X25519, Ed25519, HKDF
3. **[Identity and Addressing](03-identity.md)** - Key pairs, address hashing, identity operations

### Part II: Protocol Architecture

4. **[Packet Structure](04-packets.md)** - Header format, packet types, payload encoding
5. **[Destinations](05-destinations.md)** - SINGLE, GROUP, PLAIN types, announces, callbacks
6. **[Transport Layer Framing](06-framing.md)** - HDLC framing, interface types, IFAC authentication

### Part III: Link Layer

7. **[Link Establishment](07-link-establishment.md)** - LINKREQUEST, PROOF, key derivation
8. **[Link Communication](08-link-communication.md)** - Data packets, keep-alive, RTT, link lifecycle

### Part IV: Advanced Topics

9. **[Announces and Path Discovery](09-announces.md)** - Broadcast announcements, path tables, routing
10. **[Resource Transfers](10-resources.md)** - Large data transfer, segmentation, flow control
11. **[Transport Layer](11-transport.md)** - Packet routing, table management, interface coordination

### Part V: Implementation Guide

12. **[Building a Reticulum Implementation](12-implementation.md)** - Architecture, components, platform considerations
13. **[Interoperability Testing](13-testing.md)** - Test vectors, integration testing, debugging

### Appendices

- **[Appendix A: Security Concepts](appendix-a-security.md)** - Attack types, cryptographic properties, forward secrecy, ratchets, timing attacks
- **[Appendix B: Background Knowledge](appendix-b-background.md)** - Cryptographic foundations, mesh networking, byte order, state machines

## Reading Order

For a complete understanding, read the chapters in order. Each chapter builds on concepts from previous chapters.

If you're implementing Reticulum:
1. Start with Chapters 1-3 for foundational knowledge
2. Read Chapter 4-6 to understand the wire format
3. Study Chapters 7-8 in detail for link implementation
4. Refer back to Chapter 2 for crypto implementation details
5. Consult the appendices when you encounter unfamiliar concepts

## Quick Reference

### Sizes

| Component | Size |
|-----------|------|
| SHA-256 hash | 32 bytes |
| Truncated hash (address) | 16 bytes |
| Name hash | 10 bytes |
| X25519 key (public/private) | 32 bytes |
| Ed25519 public key | 32 bytes |
| Ed25519 signature | 64 bytes |
| Fernet overhead | 48 bytes + padding (no version byte) |
| Link request payload | 64 or 67 bytes (with MTU signalling) |
| Link proof payload | 96 or 99 bytes (with signalling) |
| Signed data in proof | 80 or 83 bytes (with signalling) |

### Packet Header Bits

```
Bit 7: IFAC flag
Bit 6: Header type (0=type1, 1=type2 with transport)
Bit 5: Context flag (used with ratchets)
Bit 4: Transport type (0=broadcast, 1=transport)
Bits 3-2: Destination type (00=SINGLE, 01=GROUP, 10=PLAIN, 11=LINK)
Bits 1-0: Packet type (00=DATA, 01=ANNOUNCE, 10=LINKREQUEST, 11=PROOF)
```

### Key Context Values

| Context | Value | Use |
|---------|-------|-----|
| NONE | 0x00 | Regular data |
| KEEPALIVE | 0xFA | Link keep-alive |
| LINK_IDENTIFY | 0xFB | Link peer identification |
| LINK_CLOSE | 0xFC | Close link |
| LINK_PROOF | 0xFD | Link packet proof |
| LINK_RTT | 0xFE | RTT measurement |
| LINK_REQUEST_PROOF | 0xFF | Link establishment proof |

## License

This documentation is provided for educational purposes alongside the leviculum implementation.

## See Also

- [Reticulum Network Stack](https://reticulum.network/)
- [Python Reference Implementation](https://github.com/markqvist/Reticulum)
- [Zen of Reticulum](https://github.com/markqvist/Reticulum/blob/master/Zen%20of%20Reticulum.md)
