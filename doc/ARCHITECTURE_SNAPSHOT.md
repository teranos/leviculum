# reticulum-core — Architecture Snapshot (post Phase 5c)

2026-02-16. Honest X-ray, not marketing.

---

## Module Map

| Module | Owns | Depends on | Depended on by |
|--------|------|-----------|---------------|
| `crypto/` | Ed25519, X25519, AES-CBC, HKDF, HMAC, Fernet tokens | nothing | identity, destination, announce, ifac, transport, link |
| `framing/` | HDLC, KISS encoding | nothing | (std crate only) |
| `constants` | All protocol magic numbers | nothing | everything |
| `traits` | Clock, Storage, Interface traits | constants | transport, node, ratchet |
| `identity` | Keypair (X25519+Ed25519), encrypt/decrypt/sign/verify | crypto, constants | destination, announce, ifac, receipt, link, transport, node |
| `destination` | Destination struct (hash, identity, ratchets, proof strategy) | crypto, identity, announce, packet, ratchet, constants | transport, node |
| `packet` | Packet struct, header parsing, wire format | constants, destination | announce, transport, node/link_management |
| `announce` | Announce construction/validation, emission timing | crypto, identity, destination, packet, constants | transport, node |
| `receipt` | PacketReceipt, ReceiptStatus | crypto, identity, destination, constants | transport |
| `ifac` | Interface authentication codes | crypto, identity, constants | (used via transport config) |
| `ratchet` | Ratchet key rotation, KnownRatchets cache | crypto, destination, traits, constants | destination |
| `link/` | Link struct (19 fields: keys, phase, RTT, keepalive, channel) | crypto, identity, destination, packet, channel, constants | node/link_management |
| `link/channel/` | Channel (window, pacing, SRTT), Envelope, buffer types | constants | link, node/link_management |
| `transport` | Routing engine: 12 BTreeMaps (paths, announces, link relay, receipts, packet cache, rate limits) | crypto, identity, destination, packet, announce, receipt, link, traits, constants | node |
| `node/` | NodeCore: links, destinations, receipt maps. Coordinates all subsystems | transport, link, destination, identity, announce, packet, traits, constants | (top-level API) |
| `resource` | Empty stub (doc comments only, 32 lines) | nothing | nothing |

---

## State Duplication

| What | Location A | Location B | Overlap | Sync mechanism |
|------|-----------|-----------|---------|----------------|
| **H1** Destinations | `NodeCore.destinations: BTreeMap<DestinationHash, Destination>` (14 fields) | `Transport.destinations: BTreeMap<[u8;10], DestinationEntry>` (3 fields: accepts_links, proof_strategy, identity) | 3 fields duplicated | Manual: `register_destination()` writes both, no unregister path |
| **H4** Channel receipt keys | `NodeCore.channel_receipt_keys: BTreeMap<(LinkId,u16), [u8;10]>` | `NodeCore.channel_hash_to_seq: BTreeMap<[u8;32], (LinkId,u16)>` | Same mapping, two directions | Manual insert/remove in send_on_link, handle_data_proof, check_channel_timeouts |
| **New?** Identity table | `Transport.identity_table: BTreeMap<[u8;10], Identity>` | `NodeCore.destinations[hash].identity` | Identities for locally registered destinations appear in both | Transport learns identities from announces; NodeCore stores them on Destination. For remote peers only Transport has it. For local destinations both have it. |

No other duplication found. `Transport.link_table` (relay routing for OTHER nodes' links) vs `NodeCore.links` (OWN link state machines) are genuinely disjoint.

---

## Abstraction Boundary Issues

**Transport knows too much about Link internals.** `transport.rs` imports `Link` directly (for `handle_link_request`), uses `link::build_proof_packet`, `link::parse_proof`. These are wire-format concerns that arguably belong in transport, but the import direction (Layer 3 → Layer 2) is correct per the dependency rules.

**`handle_link_data` is a 241-line god method** (`node/link_management.rs:498-738`). It dispatches RTT packets, keepalives, channel data, channel proofs, link close, and proof requests — all in one match. Every new link-layer feature will grow this method.

**`pub(crate)` fields on `DataReceipt`**: `full_hash`, `link_id`, `sent_at_ms` — all three are pub(crate) because NodeCore reaches into the struct directly. Should be methods.

**`PathEntry` fields are `pub`** in a `pub(crate)` struct — visible to node/ which reads them to make routing decisions. Not wrong (node needs routing info), but Transport's routing tables are directly walked by NodeCore rather than queried through an API.

---

## Multi-Transport Assumptions

Single transport is **hardcoded**:

```rust
pub struct NodeCore<R, C, S> {
    transport: Transport<C, S>,  // singular, not Vec or BTreeMap
    ...
}
```

| Assumption | Where | What breaks |
|-----------|-------|------------|
| Single `transport` field | `node/mod.rs:164` | Can't route packets through different transport instances |
| `InterfaceId(usize)` is globally unique | `transport.rs:63-68` | Two transports could both have interface 0 |
| `Link.attached_interface: Option<usize>` | `link/mod.rs:347` | Raw usize, not scoped to a transport instance |
| `handle_packet(iface, data)` unwraps to `transport.process_incoming(iface.0, data)` | `node/mod.rs:462` | Only one transport to route into |

**Verdict:** Adding multi-transport requires either (a) a transport registry with scoped interface IDs, or (b) a single Transport that internally manages multiple interface groups. Current design doesn't prevent (b) — `InterfaceId` is already opaque to the driver, and Transport already handles multiple interfaces. The real Reticulum concept of "shared instance" (multiple programs sharing one transport) is a different problem entirely.

---

## Resource Transfer Readiness

`resource.rs` is an empty stub (32 lines of doc comments).

| What's needed | Where it would live | Current state |
|--------------|-------------------|---------------|
| Resource state machine (Queued→Advertised→Transferring→Complete) | `resource.rs` | Empty |
| Part segmentation + reassembly | `resource.rs` | Missing |
| Sliding window with retransmit | `link/channel/` has this for envelopes | Would need adaptation or new impl |
| Hash verification of reassembled data | `crypto/` has sha256 | Available |
| Advertisement/acceptance handshake | Needs new system message types on Channel | Channel supports custom `Message` trait impls |
| Integration with NodeCore | `node/link_management.rs` | `handle_link_data` would need new dispatch arm |
| Flow control backpressure to driver | Needs `NodeEvent` variants | Missing |

**Buffer system** (`link/channel/buffer.rs`) provides `RawChannelWriter`/`RawChannelReader` for streaming over channels, but resources use a different wire protocol (part-based, not stream-based). Buffer is more relevant to `Channel.send_bytes()` style streaming than to resource transfers.

**Biggest gap:** No resource advertisement protocol, no part tracking, no proof-of-completion. This is a full feature, not a small addition.

---

## unwrap()/expect() in Non-Test Code

**Zero.** All instances are inside `#[cfg(test)]` modules or doc examples. Production code is clean.

---

## Largest Methods

| Lines | File | Method | Concern |
|-------|------|--------|---------|
| **241** | `node/link_management.rs` | `handle_link_data` | God method: dispatches 6+ link-layer message types in one match |
| **191** | `transport.rs` | `handle_announce` | Announce validation + propagation logic |
| **164** | `transport.rs` | `handle_proof` | Proof routing + receipt matching |
| **117** | `node/mod.rs` | `handle_transport_event` | Event dispatch from transport to node |
| **116** | `transport.rs` | `handle_data` | Data packet routing + proof generation |
| **100** | `node/link_management.rs` | `check_channel_timeouts` | Channel retransmit + link teardown |
| **99** | `transport.rs` | `handle_link_request` | Link relay setup |
| **96** | `transport.rs` | `handle_path_request` | Path discovery |

`handle_link_data` at 241 lines is the clear design smell. It should be split into per-message-type handlers. `handle_announce` at 191 is borderline — complex validation is inherently long, but some extraction is possible.

---

## Summary

| Metric | Value |
|--------|-------|
| Open issues | 12 (3 Phase 6, 9 Phase 7) |
| State duplications | 2 confirmed (H1, H4), 1 minor (identity_table) |
| unwrap/expect in prod | 0 |
| Methods > 100 lines | 6 |
| Methods > 200 lines | 1 (`handle_link_data`, 241) |
| BTreeMaps on Transport | 12 |
| BTreeMaps on NodeCore | 5 |
| Multi-transport ready | No — single `transport` field, unscoped InterfaceId |
| Resource transfer ready | No — empty stub, full protocol needed |
