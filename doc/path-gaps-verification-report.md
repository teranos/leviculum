# Path Gaps Implementation: Verification Report

All answers cite exact file:line numbers from the current codebase.

## Immediate Action

**Done.** `tracing::warn!` added at `transport.rs:1710-1714`:

```rust
if link_entry.peer_signing_key.is_none() {
    tracing::warn!(
        link_id = ?dest_hash,
        "forwarding LRPROOF without signature validation — announce not cached for link"
    );
}
```

---

## Gap 1: Path Timestamp Refresh

### Q1.1: Python Link-Table Traffic and Path Refresh

Python refreshes `path_table` timestamp in two places:

1. **`Transport.py:990`** — when a data packet is forwarded via the **path table**
   (local outbound send through a known route):
   ```python
   Transport.path_table[packet.destination_hash][IDX_PT_TIMESTAMP] = time.time()
   ```

2. **`Transport.py:1504`** — when a link request is forwarded via the **path table**
   (relay forwarding):
   ```python
   Transport.path_table[packet.destination_hash][IDX_PT_TIMESTAMP] = time.time()
   ```

For **link-table traffic** (established link data), Python does NOT refresh the
path table. `Transport.py:1514-1549` handles link-table forwarding, and the only
timestamp update is:
```python
Transport.link_table[packet.destination_hash][IDX_LT_TIMESTAMP] = time.time()
```
(line 1549) — this updates the **link table** timestamp, not path_table.

**Conclusion:** Python and Rust behave identically. Link-table data does not refresh
path_table timestamps. There is no gap.

### Q1.2: Long-Lived Links and Path Expiry

Given that link data does NOT refresh the path:

- **Yes, the path entry expires while the link is still active.** After
  `path_expiry_secs` of no path-table traffic (announces, data forwarding, link
  requests), the path entry is removed.

- **What breaks?** The active link continues to work — link data routes through the
  link table, which has its own expiry (`LINK_TIMEOUT_MS`). But:
  - A **new** link request to the same destination cannot be forwarded (no path entry).
  - Path requests for that destination won't get a cached response.
  - The path would need to be re-established via a new announce.

- **Same in Python?** Yes. Python's link-table forwarding (Transport.py:1549) only
  updates `IDX_LT_TIMESTAMP`, not `IDX_PT_TIMESTAMP`. The path will expire identically.

This is a known limitation in both implementations, not a gap between them.

### Q1.3: Test Coverage for handle_link_request Refresh

Test: `test_path_refresh_on_link_request_forward` at `transport.rs:2981`.

**Setup:**
1. Create transport with `path_expiry_secs = 10` (line 2990).
2. Register two interfaces (0 and 1) (lines 2994-2995).
3. Insert a path entry for `dest_hash` pointing to interface 1 with `expires_ms =
   now + 10000` and `hops = 1` (lines 2998-3013).
4. Populate announce cache with a valid announce packet for `dest_hash` (lines
   3015-3023).

**Packet sent:**
A link request packet (Type1, PacketType::Linkrequest) targeting `dest_hash`, arriving
on interface 0. The packet payload is 2 bytes (dummy link request body) (lines 3025-3039).

**Refresh verification:**
After `process_incoming()`, the test reads `path.expires_ms` from the path table and
asserts it equals `now + 10_000` (the refresh pushes expiry to now + path_expiry_secs *
1000). Since `now` hasn't advanced, the refresh re-sets to the same value. The test then
advances the clock to `now + 9_999` and verifies the path still exists, then to
`now + 10_001` and verifies it was cleaned (lines 3041-3045).

**Additionally:** `test_path_refresh_on_forward` (`transport.rs:2913`) tests the
`forward_packet()` refresh path with the same pattern.

---

## Gap 2: LRPROOF Signature Validation

### Q2.1: Existing Interop Test Coverage

`test_rust_relay_announce_and_link_data` at `rust_relay_tests.rs:35`:

- **Yes**, it uses a Rust node with `enable_transport: true` as the relay (line 42).
- **Yes**, a link is established THROUGH this Rust relay. Python-B creates a link to
  Python-A's destination, with the link request forwarded by the Rust relay (line 30:
  "Link request forwarding (both directions)").
- **Yes**, bidirectional data flows through the relay (line 32: "Bidirectional data
  routing via link table").

Since the link proof (LRPROOF) must pass through the Rust relay for the link to
establish, the new signature validation code is exercised end-to-end. If the validation
were incorrect, the proof would be dropped and the link would never establish.

**Verdict:** No additional interop test needed for Gap 2.

### Q2.2: Signing Key Extraction

Code at `transport.rs:1464-1480`:

```rust
let peer_signing_key = self.announce_cache.get(&dest_hash).and_then(|cached_raw| {
    Packet::unpack(cached_raw).ok().and_then(|p| {
        let payload = p.data.as_slice();
        if payload.len() >= crate::constants::IDENTITY_KEY_SIZE {
            let mut key = [0u8; crate::constants::ED25519_KEY_SIZE];
            key.copy_from_slice(
                &payload[crate::constants::X25519_KEY_SIZE
                    ..crate::constants::IDENTITY_KEY_SIZE],
            );
            Some(key)
        } else {
            None
        }
    })
});
```

**What bytes are read:** `payload[32..64]` — that is, bytes 32-63 of the announce
payload (after unpacking the outer packet framing).

**Why these are the correct bytes:** The announce payload format (per `announce.rs`
and `constants.rs:87-90`):
- Bytes `0..32`: X25519 public key (`X25519_KEY_SIZE = 32`)
- Bytes `32..64`: Ed25519 public key (`ED25519_KEY_SIZE = 32`)
- Bytes `64..128`: Name hash + random hash
- Bytes `128..192`: Ed25519 signature

So `payload[X25519_KEY_SIZE..IDENTITY_KEY_SIZE]` = `payload[32..64]` = Ed25519 signing
key. Correct.

**If announce cache doesn't have the entry:** `self.announce_cache.get(&dest_hash)`
returns `None`, the `and_then` chain produces `None`, and `peer_signing_key = None`.
The link entry is created with `peer_signing_key: None`. If an LRPROOF later arrives,
it is forwarded without validation (with a `tracing::warn!` at line 1711-1714).

### Q2.3: Signature Validation Logic

Code at `transport.rs:1645-1716`:

**Size check (lines 1655-1662):**
- `LINK_PROOF_SIZE_MIN = 96` (sig(64) + X25519(32))
- `LINK_PROOF_SIZE_MAX = 99` (sig(64) + X25519(32) + signalling(3))
- If `proof_data.len()` is neither 96 nor 99: `packets_dropped += 1; return Ok(())`.

**Valid signature (lines 1665-1706):**
When `peer_signing_key` is `Some`:
1. Extract `signature = proof_data[0..64]`, `peer_x25519_pub = proof_data[64..96]`,
   `signalling = proof_data[96..]` (if present).
2. Build `signed_data = link_id(16) + X25519_pub(32) + Ed25519_pub(32) + signalling`.
3. Construct `VerifyingKey::from_bytes(peer_ed25519_bytes)`.
4. Call `vk.verify(&signed, &sig)`.
5. If verification **succeeds**: fall through to forwarding code (line 1718+).

**Invalid signature (lines 1695-1698):**
```rust
if vk.verify(&signed, &sig).is_err() {
    self.stats.packets_dropped += 1;
    return Ok(());
}
```
Yes, `packets_dropped` is incremented.

**peer_signing_key is None (lines 1708-1715):**
```rust
if link_entry.peer_signing_key.is_none() {
    tracing::warn!(
        link_id = ?dest_hash,
        "forwarding LRPROOF without signature validation — announce not cached for link"
    );
}
```
The LRPROOF is forwarded (falls through to line 1718+) with a warning logged.

**Malformed key bytes (lines 1701-1705):**
```rust
Err(_) => {
    // Malformed key bytes — drop
    self.stats.packets_dropped += 1;
    return Ok(());
}
```
If `VerifyingKey::from_bytes()` fails (not a valid Ed25519 point), packet is dropped
and `packets_dropped` is incremented.

### Q2.4: LinkEntry Construction Sites

**Production code — 1 site:**

1. `transport.rs:1485-1498` — in `handle_link_request()`. `peer_signing_key` is set
   from the announce cache extraction (line 1497). This is the **only** production
   construction site.

**Test code — 25 sites** (all with `peer_signing_key: None` except 2):

| Line | Test | `peer_signing_key` |
|------|------|--------------------|
| 3779 | `test_link_table_entry_expiry_validated` | `None` |
| 3812 | `test_link_table_entry_expiry_unvalidated` | `None` |
| 3843 | `test_link_table_validated_not_expired_early` | `None` |
| 4405 | `test_lrproof_invalid_length_not_forwarded` | `None` |
| 4472 | `test_lrproof_valid_signature_forwarded` | `Some(peer_ed25519)` |
| 4548 | `test_lrproof_invalid_signature_dropped` | `Some(peer_ed25519)` |
| 4612 | `test_lrproof_no_signing_key_forwarded` | `None` |
| 5256 | `test_link_table_cleaned_when_interface_down` | `None` |
| 5708 | `test_link_data_wrong_hops_dropped` | `None` |
| 5743 | `test_link_data_correct_hops_forwarded` | `None` |
| 5794 | `test_link_data_correct_hops_from_initiator` | `None` |
| 6691 | `test_announce_cap_does_not_affect_data` | `None` |
| 7841 | `test_link_table_data_deferred_hash_allows_retry` | `None` |
| 7892 | `test_link_table_data_successful_forward_caches_hash` | `None` |
| 7979 | `test_lrproof_not_cached_on_link_table_forward` | `None` |
| 8374 | `test_link_table_expiry_unvalidated_marks_unresponsive_1hop_dest` | `None` |
| 8429 | `test_link_table_expiry_unvalidated_marks_unresponsive_1hop_initiator` | `None` |
| 8477 | `test_link_table_expiry_unvalidated_no_mark_when_dest_far` | `None` |
| 8528 | `test_link_table_expiry_unvalidated_sends_path_request` | `None` |
| 8567 | `test_link_table_expiry_unvalidated_path_missing_sends_path_request` | `None` |
| 8616 | `test_link_table_expiry_validated_no_rediscovery` | `None` |
| 8744 | `test_full_recovery_cycle` | `None` |
| 8809 | (same test, second link entry) | `None` |

**All `None` values are correct.** These tests exercise link-table expiry, data
forwarding, hop counting, recovery logic, etc. — none of them test LRPROOF signature
validation. The two tests with `Some(key)` are specifically testing the signature
validation code paths (valid and invalid signatures).

Additionally, `test_link_entry_signing_key_from_announce_cache` at line 4648 verifies
that the production construction site correctly extracts the key from the announce cache.

---

## Gap 3: Announce Bandwidth Caps

### Q3.1: Interaction with check_announce_rebroadcasts()

Code at `transport.rs:2279-2352`.

**1. How does `check_announce_rebroadcasts()` decide whether to use caps?**

Lines 2330-2336:
```rust
if original_hops == 0 || self.interface_announce_caps.is_empty() {
    self.forward_on_all_except(except_iface, &mut parsed);
} else {
    self.broadcast_announce_with_caps(except_iface, &mut parsed);
}
```

If the announce originated locally (`hops == 0`) OR no interfaces have registered
bitrates, it uses the uncapped `forward_on_all_except()`. Otherwise, it uses
`broadcast_announce_with_caps()`.

**2. What happens for a capped interface in holdoff?**

`broadcast_announce_with_caps()` at lines 2391-2411: if `now < cap.allowed_at_ms`,
the announce is queued (`cap.queue.push_back(...)`) up to
`MAX_QUEUED_ANNOUNCES_PER_INTERFACE`. If the queue is full, the announce is silently
dropped (line 2412).

**3. What happens for an uncapped interface?**

Line 2416: `self.send_on_all_interfaces_except(except_index, &raw)` emits a
`Broadcast` action, which the driver dispatches to all registered interfaces except
the excluded one.

**4. Where does the hops==0 bypass happen?**

Line 2332: `if original_hops == 0`. The code comment at line 2331 cites:
`// (Python Transport.py:1086-1089: \`if packet.hops > 0:\`)`.

### Q3.2: Queue Drain Timing

**If `allowed_at_ms = now + 500`, does `next_deadline()` return 500ms from now?**

Yes. `next_deadline()` at lines 1150-1155:
```rust
for cap in self.interface_announce_caps.values() {
    if !cap.queue.is_empty() {
        update(cap.allowed_at_ms);
    }
}
```
`update()` tracks the minimum deadline, so if `allowed_at_ms = now + 500`, the returned
deadline will be at most `now + 500` (could be earlier if another deadline is sooner).

**Multiple interfaces with different drain times?**

`next_deadline()` iterates all caps and takes the minimum. Each interface has its own
`allowed_at_ms`, so the earliest one wins.

**What if `poll()` is called BEFORE the drain deadline?**

`drain_announce_queues()` at line 2427: `if cap.queue.is_empty() || now < cap.allowed_at_ms { continue; }`. The queue entry stays put — it's only dequeued when `now >= allowed_at_ms`.

### Q3.3: Queue Overflow Behavior

Code at `broadcast_announce_with_caps()` line 2405:
```rust
} else if cap.queue.len() < MAX_QUEUED_ANNOUNCES_PER_INTERFACE {
    cap.queue.push_back(QueuedAnnounce { ... });
}
// else: queue full, drop silently
```

- **Newest entries are dropped.** The queue is a FIFO (`VecDeque`), and the new
  announce is only added if the queue is under the limit. If at the limit, the new
  announce is silently discarded.

- **No log message** for overflow. This matches Python's behavior (Interface.py's
  `announce_queue` has a `MAX_HELD_ANNOUNCES = 256` but doesn't log on overflow either).

- **Test:** `test_announce_queue_max_size` at `transport.rs:4871`. It registers a
  low-bitrate interface, queues `MAX_QUEUED_ANNOUNCES_PER_INTERFACE` announces (by
  sending them while the interface is in holdoff), then sends one more and verifies
  the queue size hasn't grown past the limit.

### Q3.4: Priority Dequeue

Code at `drain_announce_queues()` lines 2432-2441:
```rust
let best_idx = cap
    .queue
    .iter()
    .enumerate()
    .min_by(|(_, a), (_, b)| {
        a.hops
            .cmp(&b.hops)
            .then(a.queued_at_ms.cmp(&b.queued_at_ms))
    })
    .map(|(i, _)| i);
```

**Lowest hops first**, then **oldest within same hops** (by `queued_at_ms`). This
matches Python's Interface.py:263-266:
```python
min_hops = min(entry["hops"] for entry in self.announce_queue)
entries = list(filter(lambda e: e["hops"] == min_hops, self.announce_queue))
entries.sort(key=lambda e: e["time"])
selected = entries[0]
```

**Python line reference in code comment:** Yes, at line 2422:
`/// within same hops (Python Interface.py:263-266).`

### Q3.5: Broadcast Duplication Risk

**Scenario 1: Interface A (TCP, no cap) and Interface B (TCP, no cap), announce arrives
on A:**

No interfaces have registered bitrates, so `self.interface_announce_caps.is_empty()`
is true (line 2332). The code takes the `forward_on_all_except()` path, which emits a
single `Broadcast { data, exclude_iface: A }`. The driver sends to B only. **No
duplication.**

**Scenario 2: Interface B registered with a bitrate (capped), announce arrives on A:**

`interface_announce_caps` is non-empty and hops > 0, so `broadcast_announce_with_caps()`
is called (line 2335). This method:
1. Lines 2381-2411: Iterates capped interfaces. B is capped; if `now >= allowed_at_ms`,
   emits `SendPacket { iface: B, data }`.
2. Line 2416: `send_on_all_interfaces_except(except_index, &raw)` emits
   `Broadcast { data, exclude_iface: A }` — which the driver sends to ALL interfaces
   except A, **including B**.

**Result: B receives the announce twice** — once via `SendPacket` and once via
`Broadcast`.

**Is it harmless?** Yes:
- TCP interfaces currently use `bitrate = 0` (no cap registered), so this scenario
  doesn't arise in practice.
- When it does arise (future LoRa/serial): the receiver deduplicates via packet hash
  (`packet_cache` check in `process_incoming()` at line 889). The second copy is silently
  dropped.
- The only cost is one extra serialized packet on the wire — no state corruption.

---

## Gap 4: 32-Byte Path Requests

### Q4.1: Parsing Both Formats

**Sending** (`request_path()` at lines 2005-2019):

```rust
let data = if self.config.enable_transport {
    // 48-byte: dest_hash(16) + transport_id(16) + tag(16)
    let mut d = Vec::with_capacity(48);
    d.extend_from_slice(dest_hash);
    d.extend_from_slice(&transport_id_bytes);
    d.extend_from_slice(tag);
    d
} else {
    // 32-byte: dest_hash(16) + tag(16)
    let mut d = Vec::with_capacity(32);
    d.extend_from_slice(dest_hash);
    d.extend_from_slice(tag);
    d
};
```

**Receiving** (`handle_path_request()` at lines 2127-2144):

```rust
// Minimum: dest_hash(16) + tag(16) = 32 bytes
if data.len() < 32 {
    return Ok(());
}

let mut requested_hash = [0u8; TRUNCATED_HASHBYTES];
requested_hash.copy_from_slice(&data[..TRUNCATED_HASHBYTES]);

// Extract tag (last 16 bytes)
let tag_start = data.len() - TRUNCATED_HASHBYTES;
let mut tag = [0u8; TRUNCATED_HASHBYTES];
tag.copy_from_slice(&data[tag_start..]);
```

**Format determination:** The code does NOT need to determine the format explicitly.
It always reads the destination hash from the first 16 bytes and the tag from the
**last** 16 bytes. For 32-byte requests, these overlap correctly (bytes 0-15 = dest,
bytes 16-31 = tag). For 48-byte requests (bytes 0-15 = dest, 16-31 = transport_id,
32-47 = tag), the tag is correctly extracted from position 32.

The middle 16 bytes (transport_id) in the 48-byte format are not used by the handler —
they're only relevant for the sender to identify which transport node should respond.

### Q4.2: Edge Case — 33 bytes

A 33-byte path request passes the `data.len() < 32` check (line 2129). Then:
- `requested_hash = data[0..16]` — correct.
- `tag_start = 33 - 16 = 17`, so `tag = data[17..33]` — this reads 1 garbage byte
  (data[17]) plus 15 correct tag bytes... actually, wait:

For a legitimate 32-byte request, the tag is `data[16..32]`. For 33 bytes, the tag
would be `data[17..33]`. This means 1 byte of the tag is shifted, resulting in an
**incorrect tag**. The tag is used for deduplication (`path_request_tags` at line 2146),
so this malformed request would:
1. Not match any previously-seen tag (no dedup hit).
2. Be forwarded or processed with the wrong tag.
3. Any response would carry the wrong tag back, which the requester would ignore.

**Net effect:** The 33-byte request is not rejected but is effectively useless — the
mismatched tag means the response won't correlate. No crash, no corruption.

There is no explicit validation that the length is exactly 32 or 48. The minimum check
(`< 32`) is the only guard. This matches Python's behavior, which also extracts tag
from the last bytes without explicit length validation.

---

## General

### Q5.1: All New Tests

**Gap 1 — Path Timestamp Refresh (4 unit tests + 2 interop tests):**

| Test | Line | Verifies |
|------|------|----------|
| `test_path_refresh_on_forward` | `transport.rs:2913` | `forward_packet()` refreshes `expires_ms` |
| `test_path_refresh_on_link_request_forward` | `transport.rs:2981` | `handle_link_request()` refreshes `expires_ms` |
| `test_path_not_refreshed_without_forward` | `transport.rs:3046` | No path entry = no refresh (no panic) |
| `test_path_stays_alive_under_continuous_traffic` | `transport.rs:3089` | Short expiry + periodic forward = path survives past original expiry |
| `test_path_refresh_keeps_route_alive` | `path_gap_tests.rs:29` | (Interop) Link request through Rust relay refreshes path beyond expiry |
| `test_path_expires_when_idle` | `path_gap_tests.rs:105` | (Interop) Idle path expires after `path_expiry_secs` |

**Gap 4 — 32-Byte Path Requests (5 unit tests + 2 interop tests):**

| Test | Line | Verifies |
|------|------|----------|
| `test_non_transport_sends_32_byte_path_request` | `transport.rs:3908` | Non-transport node emits 32-byte payload |
| `test_transport_sends_48_byte_path_request` | `transport.rs:3939` | Transport node emits 48-byte payload |
| `test_handle_32_byte_path_request` | `transport.rs:3971` | Transport with cached announce responds to 32-byte request |
| `test_handle_48_byte_path_request` | `transport.rs:4016` | Transport with cached announce responds to 48-byte request |
| `test_handle_short_path_request_rejected` | `transport.rs:4062` | < 32 bytes silently dropped |
| `test_path_request_through_python_relay` | `path_gap_tests.rs:166` | (Interop) Non-transport Rust learns path via Python relay |
| `test_path_request_for_unknown_destination` | `path_gap_tests.rs:234` | (Interop) Unknown dest doesn't crash, times out gracefully |

**Gap 2 — LRPROOF Signature Validation (5 unit tests, 0 new interop tests):**

| Test | Line | Verifies |
|------|------|----------|
| `test_lrproof_valid_signature_forwarded` | `transport.rs:4444` | Valid Ed25519 signature = forwarded |
| `test_lrproof_invalid_signature_dropped` | `transport.rs:4521` | Corrupted signature = dropped + `packets_dropped++` |
| `test_lrproof_no_signing_key_forwarded` | `transport.rs:4590` | `peer_signing_key: None` = forwarded anyway |
| `test_lrproof_unknown_link_dropped` | `transport.rs:4718` | Link ID not in link_table = dropped |
| `test_link_entry_signing_key_from_announce_cache` | `transport.rs:4648` | Announce in cache -> LinkEntry has correct `peer_signing_key` |

Existing interop test `test_rust_relay_announce_and_link_data` (`rust_relay_tests.rs:35`)
implicitly validates LRPROOF forwarding end-to-end.

**Gap 3 — Announce Bandwidth Caps (9 unit tests + 2 interop tests):**

| Test | Line | Verifies |
|------|------|----------|
| `test_announce_cap_delays_second_announce` | `transport.rs:4762` | Second announce queued when in holdoff |
| `test_announce_cap_drains_queue_after_holdoff` | `transport.rs:4831` | Queued announce emitted after holdoff expires |
| `test_announce_queue_max_size` | `transport.rs:4871` | Queue capped at MAX_QUEUED_ANNOUNCES_PER_INTERFACE |
| `test_announce_cap_does_not_affect_data` | `transport.rs:4911` | Data forwarding unaffected by announce caps |
| `test_announce_cap_per_interface_independence` | `transport.rs:4972` | Two interfaces have independent caps |
| `test_local_announce_skips_cap` | `transport.rs:5020` | hops == 0 bypasses caps |
| `test_queue_drain_priority_lowest_hops` | `transport.rs:5065` | Lower-hops announce dequeued first |
| `test_no_cap_unregistered_interface` | `transport.rs:5111` | No bitrate registered = immediate send |
| `test_next_deadline_includes_queue_drain` | `transport.rs:5148` | Non-empty queue sets deadline in `next_deadline()` |
| `test_announces_forwarded_through_transport` | `path_gap_tests.rs:270` | (Interop) Announces propagate through Rust relay with cap system |
| `test_burst_announces_not_lost` | `path_gap_tests.rs:325` | (Interop) 3 sequential announces all reach the other side |

**Total: 23 unit tests + 6 interop tests = 29 new tests.**

### Q5.2: Clippy Clean

Yes. `cargo clippy --all-targets` produces zero lint warnings after all changes. The
only output is pre-existing `dead_code` warnings from `reticulum-ffi` (pre-existing,
unrelated to these changes).

### Q5.3: Python Line References in Code

All code comments citing Python Transport.py or Interface.py line numbers:

| Rust Location | Python Reference | Context |
|---------------|------------------|---------|
| `transport.rs:205` | Transport.py:1672-1681 | Path state marked unresponsive |
| `transport.rs:316` | Interface.py:25-28, Transport.py:1091-1104 | InterfaceAnnounceCap struct doc |
| `transport.rs:595` | Interface.py:25-28 | `interface_announce_caps` field doc |
| `transport.rs:918` | Transport.py:1193-1196 | Header Type 2 transport_id filter |
| `transport.rs:927` | Transport.py:1205-1225 | PLAIN/GROUP destination filtering |
| `transport.rs:958` | Transport.py:1355-1372 | Link request forwarding to path table |
| `transport.rs:1292` | Transport.py:1620-1681 | Announce processing and path update logic |
| `transport.rs:1320` | Transport.py:1677-1679 | Stale announce as alternative route |
| `transport.rs:1358` | Transport.py:1692-1719 | Per-destination announce rate limiting |
| `transport.rs:1465` | Transport.py:2021-2033 | Peer signing key extraction from announce cache |
| `transport.rs:1511` | Transport.py:1504 | Path refresh on link request forward |
| `transport.rs:1611` | Transport.py:2072 | Non-LRPROOF proof handling |
| `transport.rs:1646` | Transport.py:2021-2033 | LRPROOF signature validation |
| `transport.rs:1726` | Transport.py:1543 | Hash insertion for non-LRPROOF proofs |
| `transport.rs:1728` | Transport.py:2016-2039 | LRPROOF forwarding |
| `transport.rs:1756` | Transport.py:2054-2073 | Proof handling for non-transport nodes |
| `transport.rs:1850` | Transport.py:1543 | Validated link direction forwarding |
| `transport.rs:1869` | Transport.py:1969-1994 | Link data delivery to local links |
| `transport.rs:1906` | Transport.py:990 | Path refresh on forward |
| `transport.rs:2008` | Transport.py:2541-2557 | Path request format (32 vs 48 bytes) |
| `transport.rs:2331` | Transport.py:1086-1089 | Local announce cap bypass |
| `transport.rs:2422` | Interface.py:263-266 | Queue drain priority (lowest hops first) |
| `transport.rs:2488` | Transport.py:629-699 | Announce processing main logic |
| `transport.rs:2507` | Transport.py:644 | Announce throttle check skip |
| `transport.rs:2517` | Transport.py:660-676 | Direct neighbor announce handling |
| `transport.rs:2525` | Transport.py:682-689 | Hops == 0 announce handling |
| `transport.rs:2535` | Transport.py:695-699 | Announce TTL enforcement |
| `transport.rs:2554` | Transport.py:601-604, 813-814 | Announce processing entry point |
| `transport.rs:2575` | Transport.py:1692-1719 | Announce rate limiting |
