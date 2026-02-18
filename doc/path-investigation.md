# Investigation: Path System and Transport Node Forwarding

## Part 1: Python Reference Implementation

All references are to `vendor/Reticulum/RNS/Transport.py` unless otherwise noted.

### 1.1 Path Table / Routing Table

**Where stored:** `Transport.path_table` — a Python `dict` keyed by `destination_hash`
(16-byte truncated hash). Declared at line 107.

**Path entry fields** (list with 7 elements, index constants at lines 3274–3280):

| Index | Constant | Type | Description |
|-------|----------|------|-------------|
| 0 | `IDX_PT_TIMESTAMP` | float (seconds) | When the path was recorded |
| 1 | `IDX_PT_NEXT_HOP` | bytes (16) | Next-hop transport identity hash, or destination_hash if direct |
| 2 | `IDX_PT_HOPS` | int | Hops to destination (already incremented +1 on receipt) |
| 3 | `IDX_PT_EXPIRES` | float (seconds) | Absolute expiration time |
| 4 | `IDX_PT_RANDBLOBS` | list of bytes | Random blobs from announces (replay detection) |
| 5 | `IDX_PT_RVCD_IF` | Interface object | Interface the announce arrived on |
| 6 | `IDX_PT_PACKET` | bytes | Packet hash of the cached announce |

Path entry constructed at line 1868.

**Path states** (lines 83–85, stored in separate `Transport.path_states` dict at line 115):

| State | Value | Transition |
|-------|-------|------------|
| `STATE_UNKNOWN` | 0x00 | Set when a new/updated announce is accepted (lines 1628, 1656, 1667) |
| `STATE_UNRESPONSIVE` | 0x01 | Set when a link attempt fails for a 1-hop destination (lines 676, 689) |
| `STATE_RESPONSIVE` | 0x02 | Defined but **never called** internally |

When a path is `UNRESPONSIVE`, same-emission announces with worse hops are accepted,
allowing path recovery via alternative routes (line 1677).

Cleanup: stale path state entries (destination no longer in path_table) are removed
every 5 seconds in `jobs()` (lines 601–604, 813–819).

### 1.2 Packet Forwarding

**Entry point:** `Transport.inbound()` at line 1241.

**Hop increment:** `packet.hops += 1` at line 1319 — on receipt, before any processing.
This is the ONLY place hops are incremented (exception: shared instance adjustments at
lines 1345/1348 which decrement back by 1).

**Forwarding code path** (for a packet where `transport_id == Transport.identity.hash`):

1. Check if we are the designated next hop (line 1428)
2. Look up destination in `path_table` (line 1429)
3. Get `next_hop` and `remaining_hops` from path entry (lines 1430–1431)
4. Based on `remaining_hops`:
   - `> 1`: Keep HEADER_2, replace `transport_id` with `next_hop` (lines 1435–1438)
   - `== 1`: Strip to HEADER_1 / BROADCAST (lines 1441–1444)
   - `== 0`: Update hop count in place, transmit as-is (lines 1447–1449)
5. Outbound interface from `path_table[dest][IDX_PT_RVCD_IF]` (line 1451)
6. Create link table entry for LINKREQUEST (lines 1483–1493) or reverse entry for
   other packets (lines 1496–1501)
7. Transmit (line 1503)
8. Refresh path timestamp (line 1504) — keeps active paths alive

**Max hops:** `PATHFINDER_M = 128` (line 62). Checked at line 1608.

**No path found:** Packet dropped silently (line 1510). No REJECT mechanism (TODO at
lines 1507–1509).

**Different rules per packet type:**

| Packet Type | Routing Mechanism | Notes |
|-------------|------------------|-------|
| Data | Path table (lines 1427–1504) | Reverse entry created |
| LinkRequest | Path table (same path) | Link table entry created, MTU clamping (lines 1458–1480) |
| Link traffic | Link table (lines 1514–1548) | Bidirectional, hop-validated |
| Announce | Separate announce system (section 1.6) | Not through path table forwarding |
| Proof | Reverse table or link table (section 1.7) | Not through path table forwarding |
| LRPROOF | Link table (lines 2016–2048) | Signature validated before forwarding |

### 1.3 Reverse Paths

**Yes, reverse paths are created.** Stored in `Transport.reverse_table` (line 108),
keyed by `packet.getTruncatedHash()`.

**Entry fields** (lines 3283–3285):

| Index | Constant | Description |
|-------|----------|-------------|
| 0 | `IDX_RT_RCVD_IF` | Interface the original packet was received on |
| 1 | `IDX_RT_OUTB_IF` | Interface the packet was forwarded to |
| 2 | `IDX_RT_TIMESTAMP` | Creation time |

**When created:** At forwarding time, for all non-LINKREQUEST packets forwarded via
the path table (lines 1495–1501). Link requests create link table entries instead.

**TTL:** 8 minutes (`REVERSE_TIMEOUT = 8*60`, line 88). Cleaned in `jobs()` every 5
seconds (lines 607–615).

**Differences from announce-derived paths:**
- Keyed by per-packet hash (not destination hash) — one-shot, per-packet
- Only stores interface pair + timestamp — no hop count, no next-hop identity
- Short-lived (8 min vs 1 week)
- Purpose: proof routing only

**Used for:** Proof routing (section 1.7). NOT used for link establishment (link
requests use the link table).

### 1.4 Path Requests and Responses

**Requesting a path:** `Transport.request_path()` at line 2541.

**Packet format:** DATA packet to PLAIN destination `rnstransport.path.request`
(created at line 210).

Payload:
- Transport node: `dest_hash(16) + transport_id(16) + tag(16)` = 48 bytes
- Non-transport node: `dest_hash(16) + tag(16)` = 32 bytes

Sent as HEADER_1 / BROADCAST (line 2561).

**Who responds** (priority order, in `Transport.path_request()` at line 2696):

1. **The destination itself** (line 2719): sends an announce with `path_response=True`
2. **Transport nodes with cached announce** (line 2723): retransmit cached announce as
   PATH_RESPONSE, after `PATH_REQUEST_GRACE = 0.4s` grace (line 79) + additional
   `PATH_REQUEST_RG = 1.5s` for roaming interfaces (line 80)
3. **Transport nodes on discoverable interfaces** without the path (line 2792): forward
   the path request onward, wait up to `PATH_REQUEST_TIMEOUT = 15s`
4. **Shared instances** forward to local clients (lines 2808–2813)

**Path response format:** An ANNOUNCE packet with `context=PATH_RESPONSE` (0x0B), using
HEADER_2 with the responding transport node's identity as transport_id.

**Loop prevention:**
1. Tag-based dedup via `discovery_pr_tags` (line 2673). Tags = `dest_hash + tag_bytes`.
2. Tag list capped at `max_pr_tags = 32000` (line 120), trimmed at lines 596–597.
3. Next-hop self-check: if the known path's next hop IS the requestor, suppress response
   (line 2738).

**Rate limiting:**
- Minimum interval: `PATH_REQUEST_MI = 20s` (line 81)
- Announce cap enforcement on recursive path requests (lines 2563–2585)
- Per-destination timestamp tracking: `path_requests[dest_hash] = time.time()` (line 2588)

### 1.5 Path Expiry and Cleanup

**TTLs** (set on creation, vary by interface mode, lines 1730–1735):

| Interface Mode | Constant | Duration |
|----------------|----------|----------|
| Access Point | `AP_PATH_TIME` (line 71) | 1 day |
| Roaming | `ROAMING_PATH_TIME` (line 72) | 6 hours |
| All others | `PATHFINDER_E` (line 70) | 1 week |

Not configurable at runtime.

**Cleanup:** Timer-based in `jobs()`, every `tables_cull_interval = 5.0s` (line 158).
Path culling at lines 701–721. Also removes paths whose interface is no longer active.

**On expiry:** Path entry removed (lines 786–788). No event emitted. Corresponding
`path_states` entry cleaned on next cull cycle. Debug log message only.

**Force-expire:** `Transport.expire_path()` at line 2483 sets timestamp=0, so it
expires on next cull.

**Path timestamp refresh:** `path_table[dest][IDX_PT_TIMESTAMP]` is refreshed on every
forward (lines 990, 1504), keeping actively-used paths alive indefinitely.

**Reverse path TTL:** Fixed 8 minutes, regardless of interface mode.

### 1.6 Announce Forwarding by Transport Nodes

**Yes, transport nodes re-broadcast announces.** Two-step process:

**Step 1 — Schedule (on receipt):** When announce passes validation, it's inserted into
`announce_table` (lines 1754–1764) with `retransmit_timeout = now + rand() * PATHFINDER_RW`
(`PATHFINDER_RW = 0.5s`, line 69) introducing 0–500ms random delay.

**Step 2 — Execute (in jobs() loop):** At lines 519–577:
- Rebuild as HEADER_2 with this transport node's identity hash as `transport_id`
- Hop count preserved from receipt (already incremented by +1)
- Context preserved from original
- Forward on all interfaces except arrival

**Loop prevention mechanisms:**

1. Packet hash dedup via `packet_hashlist` (lines 1227–1238)
2. Random blob replay detection: per-destination random blob list (lines 1611–1670)
3. Emission timestamp comparison: reject announces with older/same emission (line 1627)
4. Hop count comparison: reject announces with more hops than existing path (line 1620)
5. Local rebroadcast counting: when our rebroadcast is echoed back, increment counter.
   At `LOCAL_REBROADCASTS_MAX = 2`, stop (lines 1586–1590)
6. Next-node detection: cancel retransmit if next node in chain already forwarded (lines
   1592–1597)

**Rate limiting:**

1. Per-destination announce rate tracking via `announce_rate_table` (lines 1692–1719):
   rate violations → temporary block for `rate_penalty` seconds
2. Per-interface bandwidth caps: `announce_cap` (default 2%). After transmit, calculates
   wait time = `tx_time / announce_cap`. Excess announces queued (max 16384).
3. Ingress limiting for unknown destinations (lines 1567–1571)

PATH_RESPONSE announces bypass per-destination rate limiting (line 1692).

### 1.7 Proof Routing

**Regular proofs → reverse table** (lines 2091–2100):
- Look up `packet.destination_hash` in `reverse_table`
- Entry is popped (consumed) on use — one-shot
- Proof must arrive on the outbound interface; forwarded to the receiving interface
- Only hop count byte updated; rest forwarded as-is

**LRPROOF → link table** (lines 2016–2048):
- Look up by link_id in `link_table`
- Proof must arrive from `NH_IF` direction, forwarded to `RCVD_IF`
- **Signature validated** before forwarding (line 2033: `peer_identity.validate()`)
- Link marked validated on success (line 2038)

**Reverse path gone:** Proof cannot be routed. Falls through to local receipt
validation (lines 2102–2115). No retry mechanism.

---

## Part 2: Rust Implementation Status

All references are to `reticulum-core/src/transport.rs` unless otherwise noted.

### 2.1 Path Table

**Status: IMPLEMENTED**

**Storage:** `path_table: BTreeMap<[u8; 16], PathEntry>` at line 517.

**PathEntry struct** (lines 217–228):

| Field | Type | Description |
|-------|------|-------------|
| `hops` | `u8` | Hops to destination (0 = direct neighbor; NOT incremented on receipt) |
| `expires_ms` | `u64` | Absolute expiration time (ms) |
| `interface_index` | `usize` | Interface the announce arrived on |
| `random_blobs` | `Vec<[u8; 10]>` | Random blobs for replay detection (capped at 64) |
| `next_hop` | `Option<[u8; 16]>` | Next-hop transport identity hash, None if direct |

Helper methods (lines 230–241): `is_direct()` (hops == 0), `needs_relay()` (hops > 0
&& next_hop.is_some()).

**Path states** (lines 206–213, stored in `path_states: BTreeMap` at line 521):

| State | Description |
|-------|-------------|
| `Unknown` | Default state |
| `Unresponsive` | Communication attempt failed |
| `Responsive` | Communication succeeded (defined but not used internally) |

State management: `mark_path_unresponsive()`, `mark_path_responsive()`,
`mark_path_unknown_state()`, `path_is_unresponsive()` at lines 703–744.

**Comparison to Python:**

| Aspect | Python | Rust | Match? |
|--------|--------|------|--------|
| Data structure | dict of lists | BTreeMap of structs | Equivalent |
| Fields | 7 (including packet_hash) | 5 (no packet_hash) | Rust uses separate announce_cache |
| Path states | 3 states, path_states dict | 3 states, path_states BTreeMap | Match |
| Hops semantics | +1 on receipt | +1 on forward | Off-by-one (documented, handled) |

### 2.2 Packet Forwarding

**Status: IMPLEMENTED**

**Core functions:**

- `forward_packet()` (line 1753): Path-table forwarding for data packets
- `forward_on_interface()` (line 1797): Single-interface forwarding with hop increment
- `forward_on_all_except()` (line 1813): Broadcast forwarding (announce rebroadcast)

**Full code path (data packet arriving at transport node):**

1. `process_incoming()` (line 870) → parse, dedup check (lines 908–917)
2. Route to `handle_data()` (line 944) via `packet.flags.packet_type` match
3. `handle_data()` (line 1647) → check path request hash (1657), local destination (1662)
4. Transport mode check (line 1681): `self.config.enable_transport`
5. Try link table first (lines 1683–1721) for link-addressed packets
6. Fall through to `forward_packet()` (line 1728) for path-table routing
7. `forward_packet()` → look up path (1760), create reverse entry (1766), adjust
   header type (1775–1785), call `forward_on_interface()` (1787)
8. `forward_on_interface()` → increment hops (1802), check TTL (1803), pack and send

**Hop count:** Incremented on forward in `forward_on_interface()` (line 1802) via
`packet.hops.saturating_add(1)`. Max: `PATHFINDER_MAX_HOPS = 128` (constants.rs:110).

**`enable_transport` respected:** Yes, gated at all forwarding paths:
- Link request forwarding: line 1399
- Proof routing: line 1546
- Data forwarding: line 1681
- Announce rebroadcast: lines 1322, 2089
- Path request forwarding: line 1994

**Link request forwarding** (lines 1378–1473):
- Creates link table entry (lines 1406–1421)
- Creates reverse table entry (lines 1425–1432)
- Adjusts header type based on `needs_relay()` (lines 1435–1463)
- Calls `forward_on_interface()` (line 1465)

### 2.3 Reverse Paths

**Status: IMPLEMENTED**

**Storage:** `reverse_table: BTreeMap<[u8; 16], ReverseEntry>` at line 530.

**ReverseEntry struct** (lines 267–274):

| Field | Type | Description |
|-------|------|-------------|
| `timestamp_ms` | `u64` | When created |
| `receiving_interface_index` | `usize` | Where the original packet came FROM |
| `outbound_interface_index` | `usize` | Where we forwarded it TO |

**Created at forwarding time** in three locations:
1. `handle_link_request()` line 1425 — for link requests
2. `handle_data()` link-table routing line 1703 — for link traffic
3. `forward_packet()` line 1766 — for path-table data packets

Design documented at lines 934–936.

**Cleanup:** `clean_reverse_table()` at line 2058, TTL = `REVERSE_TABLE_EXPIRY_MS =
480_000` (8 minutes, constants.rs:170). Also: consumed on proof routing (line 1603),
cleaned on interface down (line 1175).

### 2.4 Path Requests and Responses

**Status: IMPLEMENTED**

**Sending:** `request_path()` at line 1848.
- Rate-limited to one per destination per `PATH_REQUEST_MIN_INTERVAL_MS = 20_000`
  (constants.rs:137)
- Payload: `dest_hash(16) + transport_id(16) + tag(16)` = 48 bytes
- Sent as HEADER_1 / BROADCAST

**Handling:** `handle_path_request()` at line 1929.
1. Parse and validate minimum 32 bytes (line 1938)
2. Tag-based dedup via `path_request_tags: VecDeque` (line 1955, capped at 32,000)
3. Local destination → emit `PathRequestReceived` event + schedule re-announce from
   cache with `block_rebroadcasts: true` (lines 1966–1990)
4. Transport node with cached announce → schedule rebroadcast from `announce_cache`
   with `PATH_REQUEST_GRACE_MS` + jitter (lines 1994–2014)
5. Transport node, unknown destination → forward path request on all interfaces except
   arrival (lines 2017–2020)

**Path response:** Rebroadcast fired in `check_announce_rebroadcasts()` with
`PacketContext::PathResponse` (line 2136). Path responses are exempt from further
rebroadcast (`should_rebroadcast` check at line 1322) and from announce rate limiting
(line 1315).

### 2.5 Path Expiry

**Status: IMPLEMENTED**

**Expiry function:** `expire_paths()` at line 2028, called from `poll()` at line 1035.

**Duration:** `PATHFINDER_EXPIRY_SECS = 60 * 60 * 24 * 7` (7 days, constants.rs:112).
Set on creation at line 1305: `expires_ms: now + (self.config.path_expiry_secs * 1000)`.

**On expiry:** Path removed, `TransportEvent::PathLost` emitted (lines 2036–2041).

**Additional cleanup:**
- `expire_path()` force-expire at line 750 (used by link timeout recovery)
- `handle_interface_down()` removes all paths for downed interface (node/mod.rs:497–510)
- `clean_path_states()` at line 2245 removes orphan path state entries
- `clean_announce_rate_table()` at line 2258 removes orphan rate entries

**Reverse table:** Cleaned every `poll()` cycle, 8-minute TTL (line 2058).

### 2.6 Announce Forwarding

**Status: IMPLEMENTED**

**Step 1 — Schedule (on receipt):** In `handle_announce()` at lines 1322–1343.
`retransmit_at_ms` set with `calculate_retransmit_delay()` + jitter. Gated on
`enable_transport` and `!is_path_response`.

**Step 2 — Execute (in poll()):** `check_announce_rebroadcasts()` at lines 2088–2155.
- Gated on `enable_transport` (line 2089)
- Rebuild as HEADER_2 with our transport_id (lines 2128–2132)
- `PathResponse` context for `block_rebroadcasts` entries (line 2136)
- Forward on all interfaces except arrival (line 2139)
- Retries: `PATHFINDER_RETRIES = 1` (constants.rs:111), removed when exceeded (line 2099)
- Local rebroadcast limit: `LOCAL_REBROADCASTS_MAX = 2` (line 2100)
- Next retransmit at `PATHFINDER_G_MS = 5000` + jitter (line 2151)

**Loop prevention:**
1. Packet dedup cache (lines 914–917)
2. Per-destination announce rate limiting via `announce_rate_table` (lines 2267–2308)
3. `ANNOUNCE_RATE_LIMIT_MS` minimum interval (constants.rs)
4. Random blob replay detection (capped at 64 per destination, constants.rs:164)
5. Local rebroadcast counting and next-node detection (lines 1224–1238)
6. Hop limit: `PATHFINDER_MAX_HOPS = 128`
7. Retry limit: `PATHFINDER_RETRIES = 1`

### 2.7 Proof Routing

**Status: IMPLEMENTED**

**Link table routing** (lines 1546–1600):
- Look up `dest_hash` (= link_id) in `link_table`
- Direction determined by matching `interface_index` against stored interface indices
- Hop count validated against `remaining_hops` or `hops`
- LRPROOF: data size validated (96 or 99 bytes, lines 1572–1579)
- Link marked validated on first proof (lines 1583–1588)
- Non-LRPROOF proofs cached in packet_cache (line 1594)
- Forward via `forward_on_interface()` (line 1599)

**Reverse table routing** (lines 1602–1614):
- Look up `dest_hash` in `reverse_table`
- Entry consumed (`.remove()`) on use (line 1603)
- Must arrive on outbound interface, forwarded to receiving interface
- Forward via `forward_on_interface()` (line 1609)

Multi-hop proof routing works: both link table and reverse table chains are created at
each hop during forwarding.

---

## Part 3: Gap Analysis

| Feature | Python Behavior | Rust Status | Gap |
|---------|----------------|-------------|-----|
| Path storage | dict of 7-element lists, keyed by dest_hash | BTreeMap of PathEntry structs, 5 fields | **Minor**: Rust uses separate `announce_cache` instead of `IDX_PT_PACKET` in path entry. Functionally equivalent. |
| Packet forwarding | Via path table for data/LR; hop++ on receipt (inbound:1319) | Via path table for data/LR; hop++ on forward (forward_on_interface:1802) | **None**: Different counting convention (documented, off-by-one handled via `is_direct()`/`needs_relay()`) |
| Reverse paths | Created at forwarding time, keyed by packet hash, 8-min TTL, consumed on proof delivery | Identical design: 3 creation sites, 8-min TTL, consumed on use | **None** |
| Path requests | 32/48 byte payload, tag dedup (32k), 20s rate limit, recursive forwarding, grace periods | Implemented: 48 byte payload, tag dedup (32k), 20s rate limit, forwarding, grace+jitter | **Minor**: Rust always sends 48-byte format (includes transport_id even if not transport node). Non-transport nodes in Python send 32 bytes. |
| Path responses | Cached announce re-sent as ANNOUNCE with PATH_RESPONSE context, exempt from rebroadcast and rate limits | Implemented: announce_cache rebroadcast with PathResponse context, exempt from rebroadcast and rate limits | **None** |
| Path expiry | Mode-dependent: 6h/1d/7d; timer-based in jobs() every 5s; timestamp refresh on forward keeps active paths alive | Fixed 7d; timer-based in poll(); **no timestamp refresh on forward** | **Moderate** (see below) |
| Announce forwarding | Scheduled rebroadcast via announce_table; HEADER_2 with transport_id; 6 loop prevention mechanisms; per-interface bandwidth caps | Implemented: scheduled rebroadcast, HEADER_2, loop prevention | **Minor**: No per-interface announce bandwidth caps (announce_cap). Has per-destination rate limiting but not per-interface bandwidth shaping. |
| Proof routing | Via reverse table (regular) or link table (LRPROOF). LRPROOF signature validated before forwarding. | Via reverse table (regular) or link table (LRPROOF). LRPROOF size validated but **not** signature validated. | **Moderate** (see below) |
| Path state tracking | 3 states (UNKNOWN, UNRESPONSIVE, RESPONSIVE); UNRESPONSIVE allows path recovery | 3 states, same semantics; UNRESPONSIVE allows path recovery | **None** |
| Path timestamp refresh | Refreshed on every forward (line 1504, 990), keeping active paths alive | **Not implemented** | **Moderate** |
| Interface modes | AP (1d), ROAMING (6h), other (7d) path TTLs | Not implemented — fixed 7d TTL | **Low priority**: Interface modes not yet in Rust |
| LRPROOF signature validation | Validated before forwarding (line 2033) | Only size validated, not signature | **Moderate** |
| Per-interface announce bandwidth caps | announce_cap (default 2%), queue (16384) | Not implemented | **Low priority** |
| MTU clamping on link request forwarding | Clamps path MTU based on outbound interface HW_MTU (lines 1458–1480) | Not implemented | **Low priority**: Link MTU signalling not yet in Rust |
| Shared instance / local client | Shared instance forwarding, local client detection | Not implemented (by design — no shared instance concept in Rust) | **Not applicable** |
| Tunnel support | Tunnel table, tunnel synthesis (line 2120+) | Not implemented | **Deferred** |

### Detailed Gap Notes

#### 1. Path timestamp refresh on forward (Moderate)

**Python:** `path_table[dest][IDX_PT_TIMESTAMP] = time.time()` on every forward (lines
990, 1504). This keeps actively-used paths alive indefinitely — they only expire if
unused for the TTL duration.

**Rust:** No equivalent. Paths expire based solely on their creation time. An
actively-used path will expire after 7 days even if packets are still flowing through it.

- **Difficulty:** Trivial — add `self.path_table.get_mut(...).map(|p| p.expires_ms = now + ...)` in `forward_packet()` and link-table data routing.
- **Dependencies:** None
- **Priority:** Must-have for production transport nodes (long-lived routes would break)

#### 2. LRPROOF signature validation before forwarding (Moderate)

**Python:** Before forwarding an LRPROOF, validates the peer identity's signature (line
2033: `peer_identity.validate()`). This prevents forwarding invalid proofs.

**Rust:** Only validates proof data size (96 or 99 bytes, lines 1572–1579). Does NOT
validate the cryptographic signature. An invalid LRPROOF could be forwarded wastefully.

- **Difficulty:** Moderate — requires recalling the peer identity (from the announce/destination stored in `link_entry.destination_hash`) and performing Ed25519 verification before forwarding.
- **Dependencies:** Identity recall from announce cache or identity store
- **Priority:** Nice-to-have (invalid proofs would be rejected by the initiator anyway; this is a bandwidth optimization, not a correctness issue)

#### 3. Per-interface announce bandwidth caps (Low)

**Python:** Each interface has an `announce_cap` (default 2%). After transmitting an
announce, a wait time is calculated: `tx_time / announce_cap`. Excess announces are
queued (max 16384).

**Rust:** Has per-destination announce rate limiting but no per-interface bandwidth
shaping. On busy networks with many destinations, a single interface could be flooded
with announces.

- **Difficulty:** Moderate — requires per-interface state tracking (last announce time, queue)
- **Dependencies:** Interface mode support (caps vary by mode)
- **Priority:** Nice-to-have for busy multi-hop networks

#### 4. Interface mode-dependent path TTLs (Low)

**Python:** Access Point paths expire after 1 day, Roaming after 6 hours, others after
1 week.

**Rust:** Fixed 7-day TTL for all paths.

- **Difficulty:** Trivial once interface modes are implemented
- **Dependencies:** Interface mode system (ROADMAP item)
- **Priority:** Can wait — blocked on interface mode support

#### 5. Path request format difference (Trivial)

**Python:** Non-transport nodes send 32-byte path requests (no transport_id). Transport
nodes send 48 bytes.

**Rust:** Always sends 48 bytes (always includes transport_id).

- **Difficulty:** Trivial
- **Dependencies:** None
- **Priority:** Can wait — Python accepts both formats; extra bytes are harmless

#### 6. MTU clamping on link request forwarding (Low)

**Python:** When forwarding a link request, clamps the path MTU based on the outbound
interface's HW_MTU (lines 1458–1480).

**Rust:** Link MTU signalling not yet implemented.

- **Difficulty:** Moderate
- **Dependencies:** Link MTU signalling system
- **Priority:** Can wait — blocked on link MTU feature
