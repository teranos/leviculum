# Ratchet Specification

Reference analysis of Python Reticulum's ratchet implementation.
All line numbers reference `vendor/Reticulum/`.

## 1. Concept & Purpose

### Problem

Without ratchets, all packets sent to a `SINGLE` destination are encrypted using
the destination's **static** X25519 public key (derived from the identity). If an
attacker records ciphertext and later compromises the identity's private key, they
can decrypt all historical traffic. There is no forward secrecy for link-less
(`Packet`) communication.

Links already have forward secrecy: each link establishment performs a fresh
ephemeral X25519 key exchange. But many RNS applications send packets directly to
destinations without establishing links (e.g., LXMF delivery).

### Solution

Ratchets add forward secrecy to link-less packet communication. A destination
periodically generates a new X25519 keypair (the "ratchet key") and includes its
public half in announces. Senders use the latest ratchet public key instead of the
destination's static public key for ECDH key exchange when encrypting packets. The
destination retains a window of recent ratchet private keys for decryption.

### Threat model

- **Passive adversary recording ciphertext**: Cannot decrypt past traffic even if
  they later compromise the identity key, because the ephemeral ratchet key used
  for encryption has been rotated and the old private key is no longer retained.
- **Ratchet key compromise**: Only compromises packets encrypted with that specific
  ratchet key, not packets encrypted with earlier or later ratchet keys.
- **Identity key compromise without ratchet keys**: Cannot decrypt packets that were
  encrypted with ratchet keys (if `enforce_ratchets` is enabled on the destination).

### What ratchets do NOT provide

- Ratchets do not authenticate senders. Authentication is still based on the
  identity signature in announces.
- Ratchets do not provide forward secrecy for the announce itself (the announce
  payload is not encrypted).
- Ratchets do not protect link establishment (links have their own ephemeral
  key exchange).

## 2. Announce Ratchets — Wire Format

### Announce payload layout

The presence of a ratchet is signalled by the **context flag** in the packet
header flags byte.

**Flags byte** (Packet.py:168-172):
```
bit 7   bit 6   bit 5         bit 4           bit 3-2          bit 1-0
unused  hdr_typ context_flag  transport_type  destination_type  packet_type
```

`context_flag = 1` (FLAG_SET) → announce contains a ratchet.
`context_flag = 0` (FLAG_UNSET) → announce does not contain a ratchet.

### Payload structure

Constants (Identity.py:59-83):
- `KEYSIZE = 512` bits → 64 bytes (32 bytes X25519 pub + 32 bytes Ed25519 pub)
- `RATCHETSIZE = 256` bits → 32 bytes
- `NAME_HASH_LENGTH = 80` bits → 10 bytes
- `SIGLENGTH = 512` bits → 64 bytes (Ed25519 signature)
- `random_hash`: 10 bytes (5 random + 5 timestamp)

**Without ratchet** (context_flag = 0):

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 64 | public_key (X25519 pub ‖ Ed25519 pub) |
| 64 | 10 | name_hash |
| 74 | 10 | random_hash |
| 84 | 64 | signature |
| 148 | variable | app_data (optional) |

Minimum size: 148 bytes.

**With ratchet** (context_flag = 1):

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 64 | public_key (X25519 pub ‖ Ed25519 pub) |
| 64 | 10 | name_hash |
| 74 | 10 | random_hash |
| 84 | 32 | **ratchet** (X25519 public key) |
| 116 | 64 | signature |
| 180 | variable | app_data (optional) |

Minimum size: 180 bytes. Ratchets add exactly **32 bytes** to every announce.

Reference: Identity.py:391-423 (`validate_announce`).

### Signed data

The signature covers (Identity.py:425, Destination.py:297-299):
```
signed_data = destination_hash + public_key + name_hash + random_hash + ratchet + app_data
```

When no ratchet: `ratchet = b""` (empty bytes), so it's effectively absent from
signed_data.

### Ratchet field contents

The ratchet field contains the **X25519 public key** derived from the current
ratchet private key (Identity.py:287-288):
```python
def _ratchet_public_bytes(ratchet):
    return X25519PrivateKey.from_private_bytes(ratchet).public_key().public_bytes()
```

This is a raw 32-byte Curve25519 public key. Not a hash, not an ID.

### Ratchet ID

The ratchet ID (used for tracking which ratchet was used) is a truncated hash
of the ratchet public key (Identity.py:283-284):
```python
def _get_ratchet_id(ratchet_pub_bytes):
    return Identity.full_hash(ratchet_pub_bytes)[:Identity.NAME_HASH_LENGTH//8]
```

This is `SHA-256(ratchet_public_key)[:10]` — a 10-byte (80-bit) identifier.
The ratchet ID is never transmitted on the wire; it is computed locally for
logging and tracking purposes.

## 3. Announce Ratchets — State Machine

### Enabling ratchets (sender side)

A destination enables ratchets by calling (Destination.py:477-500):
```python
destination.enable_ratchets(ratchets_path)
```

This:
1. Sets `latest_ratchet_time = 0` (forces immediate rotation on next announce)
2. Calls `_reload_ratchets(ratchets_path)` which either:
   - Loads existing ratchet list from file (signed with identity key, verified)
   - Or creates empty list `[]` and persists it

### Ratchet rotation

Rotation happens in `rotate_ratchets()` (Destination.py:227-241), called at the
start of every `announce()` (Destination.py:284-287):

```python
def rotate_ratchets(self):
    if self.ratchets != None:
        now = time.time()
        if now > self.latest_ratchet_time + self.ratchet_interval:
            new_ratchet = RNS.Identity._generate_ratchet()
            self.ratchets.insert(0, new_ratchet)   # Prepend (newest first)
            self.latest_ratchet_time = now
            self._clean_ratchets()                  # Trim to RATCHET_COUNT
            self._persist_ratchets()                # Write to disk
```

Key parameters:
- `RATCHET_INTERVAL = 30 * 60` — 30 minutes minimum between rotations
  (Destination.py:90-93)
- `RATCHET_COUNT = 512` — maximum retained ratchets (Destination.py:85-88)
- Configurable via `set_ratchet_interval()` and `set_retained_ratchets()`

A ratchet is an X25519 private key (32 bytes), generated by
`_generate_ratchet()` (Identity.py:291-294):
```python
def _generate_ratchet():
    ratchet_prv = X25519PrivateKey.generate()
    return ratchet_prv.private_bytes()
```

### Sender state

The destination (sender) maintains:
- `self.ratchets`: `list[bytes]` — ordered list of ratchet private keys, newest
  first. Maximum `RATCHET_COUNT` entries.
- `self.ratchets_path`: filesystem path for persistence
- `self.latest_ratchet_time`: timestamp of last rotation
- `self.ratchet_interval`: minimum seconds between rotations (default 1800)
- `self.retained_ratchets`: max ratchets to keep (default 512)
- `self.latest_ratchet_id`: 10-byte hash of the ratchet public key last used
  for encryption

On announce (Destination.py:280-302):
1. `rotate_ratchets()` — generates new key if interval elapsed
2. `ratchet = _ratchet_public_bytes(self.ratchets[0])` — get public key of newest
3. `_remember_ratchet(self.hash, ratchet)` — also store in receiver-side cache
   (so the sender can receive packets encrypted with its own ratchet)
4. Include ratchet public key in announce payload and set `context_flag = FLAG_SET`

### Receiver state

Receivers maintain a class-level dict (Identity.py:94):
```python
Identity.known_ratchets = {}   # {destination_hash: ratchet_public_bytes}
```

This maps each destination hash to the **most recently seen ratchet public key**
(32 bytes). Only the latest ratchet per destination is kept in memory.

### Validation rules on announce receipt

During `validate_announce()` (Identity.py:391-493):

1. Parse the announce payload, detecting ratchet presence via `context_flag`
2. Verify the Ed25519 signature over `signed_data` (which includes ratchet bytes)
3. Verify `destination_hash == hash(name_hash + identity_hash)`
4. Check for public key collision with known destinations
5. Store identity in `known_destinations`
6. **If ratchet is present** (line 477-478):
   ```python
   if ratchet:
       Identity._remember_ratchet(destination_hash, ratchet)
   ```

There is **no validation of the ratchet itself** beyond:
- It is covered by the signature (so it came from the destination's identity)
- It must be exactly 32 bytes (RATCHETSIZE//8) when loaded from disk
  (Identity.py:374)

There is **no ratchet continuity check**: a receiver does not verify that a new
ratchet follows from a previous one. Any valid signed announce with a ratchet
replaces the stored ratchet. This is by design — ratchets are independent keys,
not a chain.

### First-time ratchet (bootstrap)

When a receiver first sees a ratchet for a destination:
- `_remember_ratchet()` stores it in `known_ratchets` and persists to disk
- From that point, `get_ratchet(destination_hash)` returns this key
- When encrypting packets to this destination, the ratchet key is used instead
  of the static identity key

No special handling. The first ratchet is simply stored.

### Ratchet rotation (receiver perspective)

When a receiver sees a new (different) ratchet for a known destination:
- `_remember_ratchet()` checks if the new ratchet differs from the stored one
  (Identity.py:299-300)
- If different, replaces the in-memory entry and persists to disk
- The old ratchet is discarded (receiver side only keeps the latest)

## 4. Announce Ratchets — Storage

### Sender-side storage (ratchet key file)

File path: user-specified via `enable_ratchets(path)`.
Format: msgpack-encoded dict with signature verification (Destination.py:210-225):

```python
{
    "signature": bytes,     # Ed25519 signature over packed_ratchets
    "ratchets": bytes       # msgpack-encoded list of private key bytes
}
```

The inner `ratchets` field when unpacked is `list[bytes]` — each entry is a
32-byte X25519 private key, ordered newest-first.

Written atomically: write to `.tmp`, then `os.replace()` (Destination.py:213-220).

Loaded at startup via `_reload_ratchets()` (Destination.py:437-476):
1. Read file, unpack outer dict
2. Verify signature with destination's identity key
3. Unpack inner ratchets list
4. On failure: retry once after 500ms (I/O conflict handling)
5. On second failure: set `ratchets = None` and raise error

### Receiver-side storage (per-destination ratchet files)

Directory: `{storagepath}/ratchets/`
Filename: hex-encoded destination hash (e.g., `a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4`)

Format: msgpack-encoded dict (Identity.py:310-322):
```python
{
    "ratchet": bytes,      # 32-byte X25519 public key
    "received": float      # time.time() when received
}
```

Written atomically: write to `.out` file, then `os.replace()`.
Written in a daemon thread to avoid blocking (Identity.py:325).
Protected by `ratchet_persist_lock` (Identity.py:96, 309).

**Not persisted for shared instance clients** (Identity.py:307):
```python
if not RNS.Transport.owner.is_connected_to_shared_instance:
    # persist to disk
```

Loaded on demand in `get_ratchet()` (Identity.py:364-388):
1. Check in-memory `known_ratchets` dict first
2. If not found, try to load from file
3. Validate: not expired and correct size (32 bytes)
4. Cache in `known_ratchets` dict

### Cleanup

`_clean_ratchets()` (Identity.py:333-362):
- Called once at startup by `Reticulum.__start_jobs()` (Reticulum.py:354)
- Iterates all files in `{storagepath}/ratchets/`
- Removes files where `time.time() > received + RATCHET_EXPIRY`
- `RATCHET_EXPIRY = 60*60*24*30` — 30 days (Identity.py:69-74)
- Also removes corrupted files that can't be unpacked

**Note**: This cleanup is NOT periodic. It only runs once at startup. Ratchets
that arrive during runtime and expire are only cleaned on next startup.

## 5. Link Ratchets

Link.py does **not** use announce ratchets for link establishment. Links have
their own independent forward secrecy mechanism:

1. **Link initiator** generates ephemeral X25519 keypair + ephemeral Ed25519
   keypair (Link.py:281-286)
2. **Link responder** generates ephemeral X25519 keypair, reuses destination's
   Ed25519 signing key (Link.py:278-279)
3. ECDH exchange uses only these ephemeral keys (Link.py:356)
4. Derived key via HKDF (Link.py:362-366)

The only ratchet-related code in Link.py is setting `packet.ratchet_id` to
`self.link_id` when a data packet is received over a link (Link.py:994). This
is purely for the application's tracking purposes — it tells the application
"this packet was received with forward secrecy via link X" rather than "this
packet used ratchet key X".

**Summary**: Links do not use ratchets. Links have their own per-link ephemeral
key exchange that provides forward secrecy independently.

## 6. Encryption & Decryption with Ratchets

### Encrypting a packet to a ratcheted destination

When a `Packet` is packed for a `SINGLE` destination (Packet.py:215):
```python
self.ciphertext = self.destination.encrypt(self.data)
```

`Destination.encrypt()` (Destination.py:596-610):
```python
selected_ratchet = RNS.Identity.get_ratchet(self.hash)
if selected_ratchet:
    self.latest_ratchet_id = RNS.Identity._get_ratchet_id(selected_ratchet)
return self.identity.encrypt(plaintext, ratchet=selected_ratchet)
```

`Identity.encrypt()` (Identity.py:668-700):
```python
if ratchet != None:
    target_public_key = X25519PublicKey.from_public_bytes(ratchet)
else:
    target_public_key = self.pub

shared_key = ephemeral_key.exchange(target_public_key)
derived_key = hkdf(shared_key, salt=identity_hash, ...)
ciphertext = Token(derived_key).encrypt(plaintext)
return ephemeral_pub_bytes + ciphertext
```

Key point: when a ratchet is available, the ECDH exchange uses the ratchet
public key instead of the identity's static X25519 public key. The HKDF salt
is still the identity hash (not the ratchet key). The encrypted packet format
on the wire is identical — the receiver must try ratchet keys to determine
which was used.

### Decrypting a packet at a ratcheted destination

`Destination.decrypt()` (Destination.py:622-654):
1. If ratchets are enabled (`self.ratchets` is not None):
   - Try decrypting with each retained ratchet private key (newest first)
   - If `enforce_ratchets` and all ratchet decryptions fail → return None (drop)
   - If not enforcing and ratchet decryption fails → fall back to static identity key
2. If decryption fails, reload ratchets from file and retry (handles concurrent
   writes from other processes)

`Identity.decrypt()` (Identity.py:713-769):
```python
if ratchets:
    for ratchet in ratchets:
        ratchet_prv = X25519PrivateKey.from_private_bytes(ratchet)
        shared_key = ratchet_prv.exchange(peer_pub)
        plaintext = self.__decrypt(shared_key, ciphertext)
        if plaintext: break

if enforce_ratchets and plaintext == None:
    return None  # Drop packet

if plaintext == None:
    # Fall back to static identity key
    shared_key = self.prv.exchange(peer_pub)
    plaintext = self.__decrypt(shared_key, ciphertext)
```

### Ratchet enforcement

`enforce_ratchets()` (Destination.py:502-513):
- Requires ratchets to already be enabled
- Sets `__enforce_ratchets = True`
- When enforced, packets that cannot be decrypted with any retained ratchet key
  are dropped entirely — no fallback to static identity key

## 7. Python Code References

### Identity.py
| Line | Function/Constant |
|------|-------------------|
| 64 | `RATCHETSIZE = 256` (bits) |
| 69-74 | `RATCHET_EXPIRY = 2592000` (30 days, seconds) |
| 94 | `known_ratchets = {}` class variable |
| 96 | `ratchet_persist_lock` |
| 269-280 | `current_ratchet_id()` — get ratchet ID for a destination |
| 283-284 | `_get_ratchet_id()` — SHA256(pub_bytes)[:10] |
| 287-288 | `_ratchet_public_bytes()` — derive public key from private |
| 291-294 | `_generate_ratchet()` — generate X25519 private key |
| 297-330 | `_remember_ratchet()` — store + persist ratchet |
| 333-362 | `_clean_ratchets()` — remove expired ratchet files |
| 364-388 | `get_ratchet()` — load ratchet for destination |
| 391-493 | `validate_announce()` — parse + validate announce, store ratchet |
| 405-412 | Ratchet-bearing announce payload parsing |
| 477-478 | `_remember_ratchet` called after successful validation |
| 668-700 | `encrypt()` — ECDH with ratchet or static key |
| 713-769 | `decrypt()` — try ratchets, then static key |

### Destination.py
| Line | Function/Constant |
|------|-------------------|
| 85-88 | `RATCHET_COUNT = 512` |
| 90-93 | `RATCHET_INTERVAL = 1800` (30 min, seconds) |
| 161-167 | Instance fields: `ratchets`, `ratchets_path`, `ratchet_interval`, etc. |
| 205-208 | `_clean_ratchets()` — trim list to RATCHET_COUNT |
| 210-225 | `_persist_ratchets()` — atomic write with signature |
| 227-241 | `rotate_ratchets()` — generate new key if interval elapsed |
| 243-324 | `announce()` — calls rotate_ratchets, includes ratchet in payload |
| 284-287 | Ratchet inclusion in announce: rotate, get public bytes, remember |
| 314-317 | Set context_flag based on ratchet presence |
| 437-476 | `_reload_ratchets()` — load from file with signature verification |
| 477-500 | `enable_ratchets()` — enable and load |
| 502-513 | `enforce_ratchets()` — reject non-ratcheted packets |
| 515-528 | `set_retained_ratchets()` |
| 530-542 | `set_ratchet_interval()` |
| 596-610 | `encrypt()` — get_ratchet + encrypt with ratchet key |
| 622-654 | `decrypt()` — try ratchets, reload on failure, enforce |

### Packet.py
| Line | Function/Constant |
|------|-------------------|
| 95-96 | `FLAG_SET = 0x01`, `FLAG_UNSET = 0x00` |
| 133 | `self.context_flag` stored on packet |
| 160 | `self.ratchet_id = None` |
| 170-172 | context_flag encoded in flags byte at bit 5 |
| 216-217 | `ratchet_id` set after encryption |
| 247 | context_flag extracted during unpack |

### Link.py
| Line | Function/Constant |
|------|-------------------|
| 994 | `packet.ratchet_id = self.link_id` — sets ratchet_id to link_id for tracking |

### Transport.py
| Line | Function/Constant |
|------|-------------------|
| 553 | `context_flag = packet.context_flag` — preserved during rebroadcast |
| 1811,1829,1861 | `context_flag = packet.context_flag` — preserved for local clients |

### Reticulum.py
| Line | Function/Constant |
|------|-------------------|
| 354 | `Identity._clean_ratchets()` — called once at startup |

## 8. RNS Utility & Example Ratchet Support

| Utility/Example | Ratchet support | Notes |
|----------------|-----------------|-------|
| `rnsd` | Passive | Forwards announces with ratchets (preserves context_flag). No config option to enable ratchets on daemon destinations. |
| `rnstatus` | No | Status display only; no ratchet-related output. |
| `rnpath` | No | Path discovery only; no ratchet interaction. |
| `rnprobe` | No | Creates ephemeral destination for probing; no ratchet support. |
| `rncp` | No | Uses links for file transfer; links have own forward secrecy. |
| `rnx` | No | Uses links for remote execution; links have own forward secrecy. |
| `rnid` | No | Identity management only; no ratchet operations. |
| `rnir` | No | Interface rate configuration; no ratchet interaction. |
| `rnodeconf` | No | RNode hardware configuration; no ratchet interaction. |
| `rnpkg` | No | Package management; no ratchet interaction. |
| `Examples/Ratchets.py` | **Yes** | Complete client/server example demonstrating ratchet setup. Server calls `enable_ratchets()` and announces. Client sends encrypted packets using ratchet key automatically via `Identity.get_ratchet()`. Can be used to test ratchet functionality between two nodes. |
| `Examples/Echo.py` | No | Similar to Ratchets.py but without ratchet enablement. |
| `Examples/Link.py` | No | Uses links (own forward secrecy, not ratchets). |
| `Examples/Announce.py` | No | Basic announce, no ratchet enablement. |
| `Examples/Broadcast.py` | No | GROUP destination, ratchets N/A. |
| `Examples/Buffer.py` | No | Uses links. |
| `Examples/Channel.py` | No | Uses links. |
| `Examples/Filetransfer.py` | No | Uses links/resources. |
| `Examples/Identify.py` | No | Uses links. |
| `Examples/Minimal.py` | No | Minimal setup, no ratchets. |
| `Examples/Request.py` | No | Uses links. |
| `Examples/Resource.py` | No | Uses links/resources. |
| `Examples/Speedtest.py` | No | Uses links. |

**No RNS utility supports enabling ratchets.** Only the `Examples/Ratchets.py`
example demonstrates the feature. LXMF (external, not in RNS) is noted as
supporting ratchets from version 0.5.0.

## 9. Clarifications

### 9.1 Rebroadcast: ratchet bytes are relayed unmodified

**Confirmed.** The ratchet bytes in an announce are never transformed or stripped
during relay. The full chain:

1. **Announce table stores the original packet object** (Transport.py:1760):
   `Transport.announce_table[dest_hash][5] = packet`. This is the parsed `Packet`
   object with its `.data` field containing the raw announce payload (public_key +
   name_hash + random_hash + ratchet + signature + app_data).

2. **Rebroadcast uses `packet.data` verbatim** (Transport.py:538):
   `announce_data = packet.data`. This is passed directly as the payload of the
   new `Packet()`, no parsing or modification.

3. **`context_flag` is copied** (Transport.py:553):
   `context_flag = packet.context_flag`. The flag that indicates ratchet presence
   is preserved in the rebroadcast packet's header.

4. **Packet cache stores raw bytes** (Transport.py:2345):
   `umsgpack.packb([packet.raw, interface_reference])`. The raw wire bytes
   (header + payload) are cached to disk as-is.

5. **Path response retrieves from cache** (Transport.py:2724):
   `Transport.get_cached_packet(packet_hash, packet_type="announce")`. This
   reconstructs a `Packet` from the cached raw bytes, then `.unpack()` extracts
   `.data` — the original unmodified payload.

6. **Local client forwarding** also uses `packet.data` and `packet.context_flag`
   verbatim (Transport.py:1796-1833).

Transport.py contains **zero ratchet-aware code**. It treats the announce payload
as an opaque blob. The ratchet bytes survive because they are part of `packet.data`
which is never parsed or modified by transport — only by `Identity.validate_announce()`
at the receiving endpoint.

### 9.2 Sender self-remember: why the sender stores its own ratchet

In `Destination.announce()` (Destination.py:284-287):
```python
if self.ratchets != None:
    self.rotate_ratchets()
    ratchet = RNS.Identity._ratchet_public_bytes(self.ratchets[0])
    RNS.Identity._remember_ratchet(self.hash, ratchet)
```

The sender calls `_remember_ratchet(self.hash, ratchet_pub)` to store its own
ratchet's **public key** in the receiver-side `Identity.known_ratchets` dict.

**Why this is needed:**

`Destination.encrypt()` (Destination.py:607) calls:
```python
selected_ratchet = RNS.Identity.get_ratchet(self.hash)
```

This call uses `self.hash` — the destination's own hash. It is called on **OUT**
(outgoing) destinations. When a remote peer creates an `OUT` destination pointing
at a ratcheted destination and sends a packet, the encryption path calls
`get_ratchet(destination_hash)` to look up the ratchet public key. But this same
code path also runs when the destination owner itself creates a loopback/test
packet, or when a **shared instance daemon** encrypts a packet on behalf of a
local client.

More importantly, in multi-process Python Reticulum (shared instance mode):
- The daemon (rnsd) receives announces and stores ratchets via `validate_announce()`
- A local client program creates an OUT destination and calls `encrypt()`
- The client calls `get_ratchet(dest_hash)` which checks `known_ratchets` dict
  (populated from the announce) and falls back to loading from disk

But for the **sender's own destination** running in the same process:
- The sender has the IN destination with `self.ratchets` (private key list)
- When it calls `_remember_ratchet(self.hash, ratchet_pub)`, it populates
  `known_ratchets[self.hash]` with the public key
- This ensures that if any code in the same process creates an OUT destination
  to the same hash and encrypts to it, `get_ratchet()` returns the correct
  public key

**What breaks if omitted:** If the sender doesn't self-remember, then
`get_ratchet(own_hash)` returns `None` (no ratchet file exists because the
sender is not a "receiver" of its own announce). Any packet encrypted to the
sender's own destination (by code in the same process) would use the static
identity key instead of the ratchet key. The sender's `Destination.decrypt()`
would then try all ratchet private keys first (all fail — wrong key was used),
then fall back to the static key (succeeds). This wastes 512 ECDH+HMAC
attempts. With `enforce_ratchets`, the packet would be **silently dropped**
because the static-key fallback is disabled.

### 9.3 Decryption strategy: pure brute-force, no hints

**The decryption is pure brute-force.** There is no optimization and no hint
in the packet about which ratchet was used.

The packet wire format for encrypted data is (Identity.py:696):
```
ephemeral_pub_bytes (32 bytes) + Token_ciphertext (iv + aes_ciphertext + hmac)
```

There is no ratchet ID, ratchet index, or any other indicator in the encrypted
packet. The receiver has no way to know which ratchet key was used without
trying each one.

**The brute-force loop** (Identity.py:730-743):
```python
for ratchet in ratchets:       # Up to 512 entries
    try:
        ratchet_prv = X25519PrivateKey.from_private_bytes(ratchet)
        ratchet_id = Identity._get_ratchet_id(ratchet_prv.public_key().public_bytes())
        shared_key = ratchet_prv.exchange(peer_pub)
        plaintext = self.__decrypt(shared_key, ciphertext)
        break                  # Success — stop trying
    except Exception as e:
        pass                   # HMAC mismatch — try next ratchet
```

For each candidate ratchet, this performs:
1. X25519 scalar multiplication (derive public key from private — for ratchet_id)
2. X25519 ECDH exchange (ratchet private × ephemeral public)
3. HKDF key derivation
4. HMAC-SHA256 verification of the Token
5. If HMAC passes: AES-CBC decryption + PKCS7 unpadding

**The HMAC check is the early-exit mechanism.** `Token.decrypt()` (Token.py:100-102)
calls `verify_hmac()` first, which is a constant-time HMAC comparison. If the
wrong ratchet was used, the derived key is wrong, the HMAC won't match, and
`verify_hmac()` returns `False`, causing a `ValueError` to be raised — caught
by the `except` in the loop. AES decryption is never attempted for the wrong key.

**Worst-case cost per packet:** 512 × (X25519 scalar_mult + X25519 ECDH + HKDF +
HMAC-SHA256). This occurs when the packet was encrypted with the static identity
key (not a ratchet) and `enforce_ratchets` is off — all ratchets fail, then the
static key succeeds.

**Typical cost:** 1 × (everything above). Since senders use `get_ratchet()` which
returns the latest ratchet, and the receiver's list is newest-first, the first
entry in the loop is almost always the correct one.

**Mitigations that Python does NOT implement but could:**
- Include a truncated ratchet ID in the encrypted packet header (trades 2-4 bytes
  of overhead for O(1) lookup instead of O(n) trial decryption)
- Use a hash table indexed by ratchet ID for O(1) lookup
- Python does none of this — the design prioritizes simplicity and minimal
  wire overhead

## 10. Rust Implementation Status (leviculum)

### What is implemented

| Feature | Status | Location |
|---------|--------|----------|
| Ratchet key generation | Done | `ratchet.rs`: `Ratchet::generate()` |
| Ratchet rotation | Done | `destination.rs`: `rotate_ratchet_if_needed()` |
| Ratchet in announce payload | Done | `destination.rs`: `announce()` sets `context_flag` |
| Sender-side persistence | Done | `destination.rs`: `serialize_ratchets_signed()` / `load_ratchets_signed()` |
| Receiver-side persistence | Done | `storage.rs`: `remember_known_ratchet()` write-through |
| Ratchet expiry (cleanup) | Done | `storage.rs`: `expire_known_ratchets()` deletes files |
| Python format compatibility | Done | Verified with Python-generated test vectors |
| Encryption with ratchet key | Done | `destination.rs`: `encrypt()` uses `get_ratchet()` |
| Decryption with ratchet keys | Done | `destination.rs`: `decrypt()` tries all ratchets |

### What is NOT yet implemented

| Feature | Notes |
|---------|-------|
| Ratchet validation on announce receipt | `validate_announce()` parses ratchet bytes but does not call `_remember_ratchet()` in transport (ROADMAP 3.3) |
| `enforce_ratchets` | Destination field exists but no enforcement in decrypt path |
| Interop test: ratcheted announce exchange | Pending transport-level ratchet integration |

### Sender-side persistence format

The sender stores ratchet private keys in `{storagepath}/ratchetkeys/{hex_dest_hash}`.
Format is hand-rolled msgpack (no_std compatible, no library):

```
fixmap(2)                           # 0x82
  fixstr(9) "signature"             # 0xa9 + bytes
  bin8(64)  <Ed25519 signature>     # 0xc4 0x40 + 64 bytes
  fixstr(8) "ratchets"              # 0xa8 + bytes
  bin16(N)  <inner msgpack>         # 0xc5 + BE u16 + N bytes
    fixarray(K) or array16(K)       # inner: array of K entries
      bin8(32) <X25519 privkey>     # each entry: 0xc4 0x20 + 32 bytes
```

The signature covers the inner bytes (the msgpack-encoded array of private keys).
On load, the signature is verified with the destination's Ed25519 identity key
before any keys are used.

### Receiver-side persistence format

Each known ratchet is stored in `{storagepath}/ratchets/{hex_dest_hash}`.
Format uses `rmpv` (reticulum-std only):

```
map(2)
  str "ratchet"   → bin(32)    # X25519 public key
  str "received"  → f64        # wall-clock seconds (time.time() equivalent)
```

The `received` timestamp uses wall-clock seconds for Python compatibility.
Conversion to/from core's monotonic milliseconds uses `mono_offset_ms`.

## 11. Summary of Key Constants

| Constant | Value | Unit | Location |
|----------|-------|------|----------|
| `RATCHETSIZE` | 256 | bits (32 bytes) | Identity.py:64 |
| `RATCHET_EXPIRY` | 2,592,000 | seconds (30 days) | Identity.py:69 |
| `RATCHET_COUNT` | 512 | keys | Destination.py:85 |
| `RATCHET_INTERVAL` | 1,800 | seconds (30 min) | Destination.py:90 |
| `FLAG_SET` | 0x01 | — | Packet.py:95 |
| `FLAG_UNSET` | 0x00 | — | Packet.py:96 |
| `NAME_HASH_LENGTH` | 80 | bits (10 bytes) | Identity.py:82 |
