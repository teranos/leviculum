# leviculum – Project Context

## Zweck dieses Chats


1. **Architekturentscheidungen diskutiert und trifft** – Design-Fragen, Tradeoffs, Protokoll-Verständnis
3. **Das große Ganze im Blick behält** – der Agent hat nur sein aktuelles Context Window, hier lebt die Gesamtarchitektur

### Warum das nötig ist


### Sprach-Konventionen

- **Diskussion hier:** Deutsch oder Englisch, wie's gerade passt
- **Agent-Instruktionen:** Englisch
- **Code, Commits, Doku:** Englisch

---

## Was ist leviculum?

Eine Rust-Implementierung des Reticulum Mesh-Networking-Protokolls. Ziel: eine universelle Library mit stabiler C-API/ABI, die überall läuft – vom nRF52840-Mikrocontroller bis zum Server.

Mark Qvists Python-Implementierung ist die **Protokoll-Referenz**. leviculum soll die **Deployment-Referenz** werden: native Performance, kein Python-Interpreter, echtes Embedded. Sovereign Tech Fund Förderantrag für 1 Jahr Vollzeit läuft.

---

## Design-Prinzipien

1. **Sans-I/O Core** – `reticulum-core` ist eine reine State Machine. Kein I/O, alles über `Action` Return Values.
2. **Alle Protokoll-Logik im Core** – Transport, Routing, Announces, Links, Channels, Action Dispatch.
3. **no_std + alloc im Core** – Läuft auf ESP32, nRF52840, RP2040, Linux, macOS.
4. **Dünne Platform-Driver** – Nur I/O, Framing und Event Loop in `reticulum-std` und Embedded-Crates.
5. **Python-Referenz gilt** – Im Zweifel ist Marks Implementierung korrekt, bis das Gegenteil bewiesen ist.

---

## Architecture Rules (Agent-Leitplanken)

Diese Regeln sind die häufigsten Bruchstellen wenn der Agent freihändig arbeitet. Beim Review immer dagegen prüfen.

### Ownership & State

- **Ein Owner pro Datum.** Wenn Daten woanders leben, Accessor-Methode statt Duplikat.
- **Keine versteckte State-Duplikation.** Neuer BTreeMap/Vec in einem Struct braucht Begründung: Welche Daten, warum existieren sie nicht schon woanders?
- **Cleanup-Invariante:** Jede Insertion braucht einen dokumentierten Removal-Pfad.
- **Kein `pub(crate)` auf Struct-Feldern** – nur Accessor-Methoden.
- **`let _ =` auf Result ist verboten** in Production Code. Log or propagate.

### Storage Trait Owns All Collections

**Jeder langlebige `BTreeMap`/`BTreeSet` in Transport und NodeCore MUSS hinter dem `Storage` Trait leben** (definiert in `traits.rs`). Das macht leviculum portabel über Embedded-Flash, In-Memory und File-Backed Persistence — Storage entscheidet Kapazität, Eviction und Haltbarkeit.

Regeln:

1. **Keine nackten Collection-Felder auf Transport oder NodeCore** für Daten die einen einzelnen Funktionsaufruf überleben. Stattdessen typisierte Methoden am Storage Trait.
2. **Storage-Methoden sind typisiert, nicht generisch.** Jede Collection bekommt eigene `get_*/set_*/expire_*/has_*`-Methoden mit konkreten Key/Value-Typen. Kein `load(category, key) -> Vec<u8>`.
3. **Getter geben Owned Values zurück** (`Option<T>`, nicht `Option<&T>`) für Daten die eine Disk-Backed Storage deserialisieren müsste.
4. **Expiry ist Storage-Verantwortung.** Jede Collection hat ihre eigene Expiry-Methode am Trait. Transport ruft diese in `clean_path_states()` auf.
5. **Cleanup-Checkliste** bei neuen Storage-Collections: `expire_*` wenn TTL, in `clear_all()`, in `diagnostic_dump()`, Delegation in `reticulum-std/src/storage.rs`.

### Layer-Trennung: Destination kennt kein Storage

Destination serialisiert und signiert (Byte-Produktion). Storage schreibt und liest (Datei-I/O). NodeCore verkabelt (reicht Bytes durch). Keine Schicht überschreitet ihre Zuständigkeit:

```
Schreiben:  Destination.serialize_ratchets_signed() → Vec<u8> → NodeCore → Storage.store()
Lesen:      Storage.load() → Vec<u8> → NodeCore → Destination.load_ratchets_signed()
```

### Structural Change Checklist

Nach jeder Änderung die ein Feld, eine Collection oder einen neuen Struct hinzufügt:
1. Existieren diese Daten bereits woanders im Codebase?
2. Wer ist der Owner? Kann ich den Owner abfragen?
3. Falls Duplikat: Welcher Sync-Mechanismus stellt Konsistenz sicher?
4. Welcher Code-Pfad entfernt diese Daten wenn sie nicht mehr gebraucht werden?

### No Silent Stubs

- `unimplemented!("description — see ROADMAP #X")` wenn der Code-Pfad noch nicht erreicht werden soll
- Safe Default nur wenn er **korrekt** ist, nicht nur non-crashing
- Niemals Dummy-Werte die subtil falsche Ergebnisse produzieren
- Jeder TODO/FIXME muss ein ROADMAP-Item referenzieren

### Explicit Prohibitions

| # | Regel | Scope |
|---|-------|-------|
| 1 | Kein `use std::` in Production Code | reticulum-core |
| 2 | Keine Heap-allocierten Error Payloads (Error Types müssen `Copy` sein) | reticulum-core |
| 3 | Kein `HashMap` — nur `BTreeMap` (deterministische Ordnung) | reticulum-core |
| 4 | Kein globaler State, keine Singletons | alle Crates |
| 5 | Kein `unwrap()`/`expect()` in Non-Test Code | alle Crates |
| 6 | Kein `#[allow(dead_code)]` ohne Kommentar + ROADMAP/Issue-Referenz | alle Crates |
| 7 | Keine zirkulären Modul-Dependencies | alle Crates |
| 8 | Keine Protokoll-Logik in `reticulum-std` — nur Platform Glue | reticulum-std |
| 9 | Kein duplizierter State — wenn Daten auf einem anderen Struct existieren, Accessor nutzen | alle Crates |

---

## Python-Porting-Gotchas

Kritische Unterschiede beim Übersetzen von Python Reticulum nach Rust. Der Agent vergisst diese regelmäßig.

### Time Units & Clock Domains

Python: `time.time()` → **float, Sekunden, Wall-Clock (Unix Epoch)**.
Rust: `clock.now_ms()` → **u64, Millisekunden, Monoton (startet bei 0)**.

→ Python-Timeout-Konstanten immer ×1000 beim Portieren.
→ Auf Disk speichern: Wall-Clock (Python-kompatibel). Im RAM: Monoton. Konversion beim Load/Store über `mono_offset_ms` (Wall-Clock bei Prozess-Start). Nach Restart werden Timestamps aus früheren Sessions zu `saturating_sub → 0`, was "lange her" bedeutet — korrekt für Expiry.

### Shared Instance

Python hat `is_connected_to_shared_instance` für lokales Multi-Programm Transport Sharing. Rust hat LocalInterface als IPC-Mechanismus, aber kein identisches Konzept. Code der darauf prüft braucht Fall-für-Fall-Analyse — nicht blind portieren.

### Interface Modes

Python hat `MODE_ACCESS_POINT`, `MODE_ROAMING`, `MODE_BOUNDARY`. In Rust noch nicht implementiert. Code der auf Interface Mode brancht muss deferred oder adaptiert werden.

### Generelle Porting-Regel

Bei jeder Schwellwert-Übernahme aus Python fragen: "Setzt Pythons Wert ein vorheriges Inkrement, eine Unit-Konversion oder einen State voraus, der in Rust nicht existiert?" Keine Magic Numbers blind kopieren.

---

## API-Konventionen

### Naming Patterns

| Pattern | Bedeutung |
|---------|-----------|
| `handle_*()` | Sans-I/O Entry Point, gibt `TickOutput` zurück |
| `process_*()` | Internes Verarbeiten eines Pakets/Events |
| `drain_*()` | Pending Events/Actions konsumieren und zurückgeben |
| `poll()` | Zeitbasierte State Transitions (intern) |
| `next_deadline()` | Nächsten Timeout abfragen |
| `build_*()` | Komplexe Paket-Erstellung |
| `from_*()` | Konversion aus Bytes/anderen Typen |

### Parameter-Reihenfolge

Wenn eine Funktion `rng` und `now_ms` nimmt: **`rng` kommt immer vor `now_ms`**.

```rust
pub fn announce<R: CryptoRngCore>(&mut self, app_data: Option<&[u8]>, rng: &mut R, now_ms: u64)
```

### Error Handling

- Module definieren eigene Error Enums (`LinkError`, `PacketError`, etc.)
- Error Types: `Debug, Clone, Copy, PartialEq, Eq` + `core::fmt::Display`
- Kein `std::error::Error` im Core (verletzt no_std)
- `thiserror` nur in `reticulum-std`

### Visibility

- Default: `pub(crate)`. Nur `pub` wenn externe Consumer es brauchen.
- `pub(super)` für Sharing zwischen Submodulen.
- Jedes `pub` Item in `lib.rs` muss die externe API bedienen.

---

## Crate-Struktur

```
leviculum/
├── reticulum-core/          # no_std + alloc — ALLE Protokoll-Logik (sans-I/O)
│   ├── constants.rs         # Protokoll-Konstanten
│   ├── traits.rs            # Platform Traits: Clock, Storage (~44 Methoden), Interface; NoStorage
│   ├── storage_types.rs     # Datentypen für Storage und Transport
│   ├── memory_storage.rs    # MemoryStorage (BTreeMap, konfigurierbare Caps)
│   ├── crypto/              # Kryptographische Primitives
│   ├── framing/             # HDLC Framing, KISS Encoding
│   ├── identity.rs          # Identity (X25519 + Ed25519 Keypairs)
│   ├── destination.rs       # Endpoints, Ratchet Sign/Verify (hand-rolled msgpack, kein rmpv)
│   ├── packet.rs            # Paket-Encoding/Decoding
│   ├── announce.rs          # Announce-Erstellung/Validierung
│   ├── ratchet.rs           # Forward-Secrecy Ratchet Keys
│   ├── ifac.rs              # Interface Authentication Codes
│   ├── receipt.rs           # Delivery Receipts und Proofs
│   ├── link/                # Link State Machine + Channels
│   │   ├── mod.rs           # Link Establishment, Encryption, Teardown
│   │   └── channel/         # Reliable Ordered Messaging über Links
│   ├── transport.rs         # Sans-I/O Routing Engine + dispatch_actions()
│   ├── resource.rs          # Segmented Data Transfer (Stub)
│   └── node/                # High-Level Unified API
│       ├── mod.rs           # NodeCore: bindet alles zusammen
│       ├── send.rs          # Outbound Message Routing
│       ├── link_management.rs # Link Lifecycle
│       └── event.rs         # NodeEvent Enum
│
├── reticulum-std/           # std — Platform Driver für Desktop/Server
│   ├── interfaces/          # Konkrete Interface-Implementierungen
│   │   ├── mod.rs           # InterfaceHandle, InterfaceRegistry (Round-Robin)
│   │   ├── tcp.rs           # TCP Client + Server mit HDLC Framing
│   │   ├── udp.rs           # UDP Point-to-Point/Broadcast
│   │   ├── local.rs         # Unix Abstract Socket IPC (Shared Instance)
│   │   └── auto_interface/  # Zero-Config IPv6 Multicast LAN Discovery
│   ├── driver/              # Sans-I/O Driver (Event Loop)
│   │   ├── mod.rs           # ReticulumNode: owns Interfaces, drives NodeCore
│   │   ├── builder.rs       # ReticulumNodeBuilder
│   │   ├── sender.rs        # PacketSender (fire-and-forget)
│   │   └── stream.rs        # LinkHandle (async Send Handle)
│   ├── rpc/                 # RPC Server für Python CLI Tools (rnstatus, rnpath, rnprobe)
│   ├── storage.rs           # FileStorage: MemoryStorage + Disk Persistence (rmpv msgpack)
│   ├── config.rs / ini_config.rs  # Config Parsing (Python-kompatibel)
│   └── known_destinations.rs / packet_hashlist.rs  # msgpack Persistence
│
├── reticulum-integ/         # Docker-basiertes Integration Test Framework
├── reticulum-nrf/           # Embedded Driver für nRF52840 (Heltec T114, SX1262 LoRa)
├── reticulum-ffi/           # C-API Bindings
└── reticulum-cli/           # CLI Tools (lrns, lrnsd)
    └── selftest.rs          # 8 Modi: all, link, packet, ratchet-basic/enforced/rotation, bulk-transfer
```

### Cross-Crate Dependency Rules

- `reticulum-std` importiert `reticulum-core` — niemals umgekehrt
- `reticulum-ffi` importiert `reticulum-core` direkt (korrekt für C Bindings)
- `reticulum-cli` importiert `reticulum-std`
- `rmpv` (msgpack) nur in `reticulum-std` — Core nutzt hand-rolled msgpack wo nötig (no_std)

---

## Sans-I/O Architektur

Der Core macht nie I/O. Er ist eine reine State Machine:

```
                     ┌─────────────────────────────────┐
                     │         reticulum-core           │
  handle_packet() ──►│  NodeCore<R, C, S>               │──► TickOutput {
  (iface_id, data)   │    ├── Transport (Routing)       │      actions: Vec<Action>,
                     │    ├── Links + Channels           │      events: Vec<NodeEvent>,
  handle_timeout() ─►│    └── Destinations              │    }
                     │                                  │
  next_deadline() ──►│  Returns: Option<u64>            │
                     └─────────────────────────────────┘
```

**Actions:** `SendPacket { iface, data }` oder `Broadcast { data, exclude }`

`dispatch_actions()` lebt im Core (nicht im Driver) – Broadcast-Exclusion und Interface-Selection sind Protokoll-Logik.

### Event Loop (reticulum-std, 6 Branches)

1. Paket von Interface empfangen → `handle_packet()` → dispatch
2. Externe Aktion (connect, send, announce) → dispatch
3. Timer feuert → `handle_timeout()` → dispatch
4. Shutdown Signal → break
5. Neues Interface registriert (TCP accept, Local connect) → `handle_interface_up()`
6. Periodischer Storage Flush (Crash Protection, 3600s)

### Post-Dispatch (nach jedem Core-Call)

1. `dispatch_actions()` → Pakete an Interfaces routen
2. Errors reagieren: `BufferFull` loggen, `Disconnected` → `handle_interface_down()`
3. Events an Application forwarden
4. Timer updaten aus `next_deadline_ms`

---

## Interface Design

### Send/Receive Asymmetrie

`Interface` Trait deckt nur die **Send-Seite** ab:

```rust
pub trait Interface {
    fn id(&self) -> InterfaceId;
    fn name(&self) -> &str;
    fn mtu(&self) -> usize;
    fn is_online(&self) -> bool;
    fn try_send(&mut self, data: &[u8]) -> Result<(), InterfaceError>;
}
```

Receive ist absichtlich nicht im Trait – async und driver-spezifisch. `try_send()` ist fire-and-forget (Reticulum = best-effort, kein Backpressure).

### Konkrete Interfaces

| Interface | Transport | HW_MTU | Framing |
|-----------|-----------|--------|---------|
| TCP | TCP Stream | 262144 | HDLC |
| UDP | UDP Datagram | 1064 | None |
| LocalInterface | Unix Abstract Socket | 262144 | HDLC |
| AutoInterface | IPv6 Multicast + Unicast UDP | 1196 | None |

### Zero-Delay Core, Interface-Side Jitter

Core verarbeitet Pakete sofort. Collision Avoidance ist Sache des Interface:
- TCP/UDP: sofort senden
- LoRa/Serial (zukünftig): Send-Queue mit konfigurierbarem Jitter

Das ist ein bewusster Unterschied zu Python, wo Jitter im Core steckt.

---

## Layer-Architektur

```
Layer 4 (Entry):    node/
Layer 3 (Infra):    transport
Layer 2 (Conn):     link/ ── link/channel/
Layer 1 (Addr):     identity, destination, announce, ratchet, receipt, packet, ifac
Layer 0 (Prims):    crypto/, framing/, constants, traits
```

Import-Regeln: Jeder Layer darf nur gleiche oder tiefere Layer importieren. Keine Aufwärts-Importe.

---

## Platform Traits

| Trait | Zweck | std impl | Embedded impl |
|-------|-------|----------|---------------|
| `Clock` | Monotone Timestamps | `SystemClock` | Hardware Timer |
| `Storage` | Type-Safe Collection Storage (~44 Methoden) | `FileStorage` | `MemoryStorage` / `NoStorage` |
| `CryptoRngCore` | Zufallszahlen | `OsRng` | Hardware RNG |

### Storage: Drei Implementierungen

| Type | Crate | Backing | Use Case |
|------|-------|---------|----------|
| `NoStorage` | core | Zero-Sized No-Op | Stubs, FFI, Smoke Tests |
| `MemoryStorage` | core | BTreeMap, konfigurierbare Caps | Embedded, Core Tests |
| `FileStorage` | std | Wraps MemoryStorage + Disk | Desktop/Server |

### FileStorage Persistence-Strategie

Zwei Modelle koexistieren:

| Modell | Collections | Wann auf Disk |
|--------|-------------|---------------|
| Flush-on-Shutdown | `known_destinations`, `packet_hashlist` | Periodisch (3600s) + Shutdown |
| Write-Through | `ratchets/`, `ratchetkeys/` | Sofort bei jedem Store |

Write-Through für Ratchets weil: Krypto-Keys die bei Crash verloren gehen bedeuten dass Peers verschlüsselte Pakete senden die niemand mehr entschlüsseln kann.

### FileStorage Dateiformate (Python-kompatibel)

| Verzeichnis | Inhalt | Format | Python-Referenz |
|-------------|--------|--------|-----------------|
| `ratchets/{hex}` | Receiver-side Ratchet Cache | msgpack `{"ratchet": bytes(32), "received": float(secs)}` | `Identity._persist_ratchet()` |
| `ratchetkeys/{hex}` | Sender-side Private Keys | msgpack `{"signature": Ed25519(inner), "ratchets": msgpack([key1, ...])}` | `Destination._persist_ratchets()` |
| `known_destinations/` | Identity Cache | msgpack (Python-kompatibel) | `Identity._remember()` |
| `packet_hashlist` | Dedup Cache | msgpack Array | `Transport._save_packet_hashlist()` |

`ratchetkeys` wird von Destination im Core signiert/verifiziert (hand-rolled msgpack, kein rmpv). FileStorage behandelt den Inhalt als opake Bytes.

---

## Protokoll-Grundlagen

### Routing-Modell

- **Announces** werden geflutet (Discovery)
- **Path Requests** werden geflutet wenn Pfad unbekannt
- **Datenpakete** laufen über etablierte Pfade (kein Flooding)
- **Announce Racing:** Schnellster Announce gewinnt → Distance-Vector ohne Metrik-Austausch
- **Route Timeout:** ~555s (3× Announce-Interval + 15s)

### Paket-Header

- HEADER_1: Announces und Path Requests (geflutet)
- HEADER_2: Datenpakete (über Pfade geroutet, Promotion bei Multi-Hop Forwarding)

### Krypto

Ed25519, X25519, AES-256, HKDF. Im no_std-Kern: Pure-Rust (RustCrypto). Auf nRF52840: CryptoCell als Option.

### Ratchet Forward Secrecy

Destinations können Ratchets aktivieren: kurzlebige X25519-Schlüsselpaare die periodisch rotiert werden. Public Keys werden im Announce transportiert. Sender verschlüsseln damit (zusätzlich zur Identity-Key-Verschlüsselung). Empfänger können `enforce_ratchets` setzen um nicht-ratcheted Pakete abzulehnen.

Architektur-Entscheidung: Destination signiert/verifiziert Ratchet-Keys (hat Identity). Storage speichert/lädt opake Bytes (hat Filesystem). NodeCore verbindet beides (Orchestrator). Detaillierte Spezifikation: `doc/RATCHET_SPEC.md` (667 Zeilen, komplette Python-Analyse).

---

## Definition of Done

Ein Feature ist NICHT fertig bis:

1. **Unit Tests** bestehen (Komponente funktioniert isoliert)
2. **Interop-Test** beweist dass ein echtes Paket den neuen Code end-to-end durchläuft: wire → transport → node → application (oder umgekehrt), durch mindestens einen Python `rnsd` Relay
3. Falls kein Interop-Test existiert: Status ist "⚠️ Partial — unit-tested, not integration-tested"
4. Für Routing/Announce/Path-Features: **Integration-Test** in `reticulum-integ/` der das Szenario in einer Multi-Node-Topologie testet

**Eine Komponente die nur Unit Tests hat aber keinen Interop-Test für ihren Paket-Pfad ist UNVERIFIED, nicht complete.**

### Packet Trace Verification

Bevor ein Transport-Layer Feature als complete markiert wird: einen konkreten Paket-Trace durch den vollen Code-Pfad zeigen, von Wire bis Application (oder umgekehrt). File:Line für jeden Schritt. Wenn der Trace eine Funktion trifft die nur aus Unit Tests aufgerufen wird und nie aus der `handle_packet → process_incoming → handler` Chain, ist das Feature nicht integriert.

### Drei Test-Levels

| Level | Command | Was es testet | Aktuelle Zahl |
|-------|---------|---------------|---------------|
| Unit Tests | `cargo test -p reticulum-core --lib` | Protokoll-Logik isoliert, sans-I/O | ~763 |
| Unit Tests (std) | `cargo test -p reticulum-std --lib` | FileStorage, Persistence, Driver | ~172 |
| Interop Tests | `cargo test -p reticulum-std --test rnsd_interop` | Rust ↔ Python auf localhost | ~10 |
| Integration Tests | `cargo test -p reticulum-integ -- --nocapture` | Docker Multi-Node Szenarien | ~57 |

---

## Test-Infrastruktur

### Integration Test Framework (reticulum-integ)

Docker-basiert, TOML-definierte Szenarien, gemischte Rust/Python-Topologien.

**Step Types:** `wait_for_path`, `rnprobe`, `rnpath`, `rnstatus`, `sleep`, `restart`, `exec`, `block_link`, `restore_link`

Unterstützt negative Assertions (`expect_result = "no_path"` / `"fail"`). PID-basierte Container-Namen für parallele Ausführung.

### selftest (`lrns selftest`)

Akzeptiert zwei Daemon-Adressen (`lrns selftest <addr_a> <addr_b>`), erstellt zwei ephemere In-Process-Nodes die sich jeweils mit einem Daemon verbinden. Wenn `addr_a == addr_b`: beide zum selben Relay. Wenn verschieden: beliebige Topologie dazwischen (Multi-Hop, Mixed-Implementation).

Modi: `all`, `link`, `packet`, `ratchet-basic`, `ratchet-enforced`, `ratchet-rotation`, `bulk-transfer`. Mit `--corrupt-every N` für Byte-Level-Korruption.

### schneckenschreck (Cross-Machine Testing)

Manche Bugs (z.B. AutoInterface Wire Format, Source Port Mismatch) lassen sich nur testen wenn Rust und Python auf **separaten Maschinen** im selben LAN laufen. Same-Machine Testing kann diese Code-Pfade nicht erreichen weil Pythons socketserver kein SO_REUSEPORT auf dem AutoInterface Data Port hat.

**schneckenschreck** ist eine Debian KVM/QEMU VM (x86_64) im lokalen LAN:
- Erreichbar via `ssh schneckenschreck` mit passwordless sudo
- hamster nutzt `br0`, schneckenschreck nutzt `enp1s0`
- IPv6 Link-Local Multicast funktioniert zwischen beiden
- Cross-Machine AutoInterface Test: `fish scripts/test-auto-crossmachine.fish`

---

## Logging-Konventionen

`tracing` Crate, `no_std`-kompatibel (default-features = false im Core).

| Level | CLI | Was |
|-------|-----|-----|
| `error!` | immer | Persistente Fehler |
| `warn!` | immer | Recoverable Errors |
| `info!` | default | Startup, Shutdown, Lifecycle |
| `debug!` | `-v` | Routing-Entscheidungen, Path Updates, Link Lifecycle |
| `trace!` | `-vv` | Jedes Paket, Drop Reasons, Queue Ops |

**Stil:** Satz-artig mit inline Kontext, nicht Key-Value-Dumps. HexShort (16 hex chars) für Hashes in debug, volle HexFmt nur in warn/error.

---

## Aktueller Stand (Februar 2026)

**Version: 0.5.19+ (Unreleased), auf Codeberg: `codeberg.org/Lew_Palm/leviculum`**

Progression: 0.1.0 (Jan 2025, Protokoll-Foundation) → 0.2.0 (Core API) → 0.3.0–0.4.x (Transport, Interop) → 0.5.x (Full Node, Interfaces, Channel Congestion)

### Abgeschlossene Subsysteme

**Krypto & Identity:** Ed25519, X25519, AES-CBC, HKDF, Fernet, HMAC. Identity-Management.

**Ratchet Forward Secrecy (KOMPLETT):**
- Krypto: Ratchet-Generierung, Rotation, Multi-Key Decryption (bis 512 retained Keys)
- Transport: handle_announce() speichert Ratchets, Sender Self-Remember, Periodic Cleanup (30 Tage)
- Encryption: send_single_packet() nutzt Ratchet-Key, enforce_ratchets blockiert Fallback
- Persistence: Python-kompatibles msgpack für beide Collections (receiver + sender-side), signiert mit Ed25519
- Storage Trait Migration: KnownRatchets, local_client_dest_map, local_client_known_dests alle über Storage Trait
- Tests: 10 Interop-Tests (enforce_ratchets, bidirektional, durch Relay), Docker-Tests (direct, chain, mixed, bulk, corruption)
- Spezifikation: `doc/RATCHET_SPEC.md` (667 Zeilen)

**Paket-Layer:** Alle Pakettypen (Header 1/2), Encoding/Decoding, Announce Creation/Validation, Proof System (PROVE_NONE/APP/ALL).

**Link-Layer:** Vollständige Link State Machine (Initiator + Responder), Keepalive, Stale Detection, Graceful Close (LINKCLOSE), MTU-Negotiation (bis 262KB über TCP). Channel-System mit Window-basierter Flow Control und automatischer Retransmission.

**Channel Congestion Control (v0.5.14–0.5.19):** AIMD Sender-Side Pacing, Smoothed RTT (RFC 6298) mit Karn's Algorithm, Live Timeout Computation, Half-Sequence-Space Duplicate Detection, `CHANNEL_MAX_TRIES=8` mit Exponential Backoff.

**Transport/Routing:** Sans-I/O Routing Engine, Path Discovery, Announce Propagation mit Racing, Packet Forwarding, Deferred Hashing für Shared-Medium Retry. Per-Interface Announce Bandwidth Caps (Priority Queue, Lowest Hops First). Path Timestamp Refresh bei Forward. LRPROOF Ed25519 Validation.

**Flooding/Broadcasting:** Alle Divergenzen zur Python-Referenz gefixt (#4 Echo Prevention, Issue A Hop Count, Issue B random_blobs Cap, #12 HEADER_2 Forwarding, #14 Filtering, #15 PLAIN/GROUP Restriction, #9/#10 Deferred Hashing).

**Interfaces:** TCP Client (mit Auto-Reconnect) + Server, UDP (Point-to-Point/Broadcast), LocalInterface (Unix Socket IPC für Shared Instance), AutoInterface (IPv6 Multicast LAN Discovery, Linux). HDLC Framing, Dynamic Interface Registration.

**Shared Instance:** Local Client Routing Gates, Registration Delay (250ms Batch), Reconnect Re-Announce, Destination Expiry (6h TTL), Cached Announce Forwarding zu Local Clients.

**RPC-Kompatibilität:** Python `multiprocessing.connection` Wire Protocol, HMAC Auth (MD5 legacy + SHA256), Pickle Ser/De. `rnstatus`, `rnpath`, `rnprobe` funktionieren gegen den Rust-Daemon.

**CLI:** `lrnsd` (Daemon mit SIGTERM/SIGINT/SIGUSR1, `-v`/`-q`, RUST_LOG), `lrns connect` (interaktiv), `lrns selftest` (8 Modi inkl. Ratchet-Tests und Byte-Korruption).

**Storage:** Type-Safe Storage Trait (~44 Methoden), MemoryStorage (no_std), FileStorage (Python-kompatibles msgpack), Write-Through für Ratchets, Dirty-Flag Tracking, SIGUSR1 Diagnostic Dump.

### Aktueller Meilenstein: Pfad-Implementierung

1. `path_is_unresponsive` – Erkennung toter Pfade (noch nicht expired)
2. Path State Tracking – Monitoring ob Pfade antworten
3. Bidirektionale Kommunikation über etablierte Pfade

### Roadmap danach

- Python `PATHFINDER_RW_MS` analysieren bevor LoRa-Interface designt wird
- LoRa Shared-Medium Jitter → Interface-Layer, nicht Core
- lrcp (Buffer/Stream — benötigt Link-Layer, Phase C10)
- C-Bindings via `cbindgen` (reticulum-ffi)
- Debian-Paketierung (`apt install leviculum-dev`)
- Consumer-grade LXMF-Client (Sekundärziel)
- Resource Transfer (segmented data, aktuell nur Stub)

---

## Wiederkehrende Bug-Patterns (Review-Checkliste)

Aus dem Changelog destilliert – das sind die Fallen, in die der Agent immer wieder tappt:

**1. State-Duplikation / Split Ownership**
Connection und LinkManager hatten jeweils einen eigenen Channel → Sends gingen an den einen, Timeouts checkten den anderen → Retransmissions feuerten nie (v0.5.15). Immer prüfen: Gibt es genau EINEN Owner für diesen State?

**2. Silent Drops**
Pakete/Events die durch `_ => {}` Match-Arms oder fehlende Handler still verschwinden. `MessageReceived` wurde im Driver ignoriert (v0.5.6), Link-addressed Data auf Non-Transport Nodes gedroppt (v0.5.5), WindowFull still geschluckt (v0.5.14). Jeder Drop braucht ein Log.

**3. Python-Inkompatibilität durch subtile Semantik-Unterschiede**
Hops-Increment (bei Empfang, nicht bei Forward), Header1→Header2 Promotion für Multi-Hop, 32-byte vs 48-byte Path Requests, Transport ID in Type2 Paketen. Immer gegen Python-Referenz tracen.

**4. Timer/Deadline-Bugs**
Event Loop schläft auf stale Deadlines weil next_poll nicht nach handle_packet() aktualisiert wird. Timer Floor (250ms Clamp) verhindert sub-millisecond Wakeups. Pacing nutzt Handshake-RTT statt SRTT. Deadlines immer nach jedem Core-Call neu berechnen.

**5. Startup-Races**
Rust startet in Millisekunden, Python in Sekunden. Re-Announce bei TCP-Peer-Connect nötig, sonst verpasst Python die Announces. Ingress Control auf TCP kontraproduktiv (E24).

**6. Borrow-Konflikte bei Storage + Transport**
Wenn Transport Storage borgt und gleichzeitig andere Felder mutiert werden müssen: owned Values extrahieren (`.copied()`, Capture in lokale Variable) bevor der Storage-Borrow beginnt. Typisches Pattern in send_single_packet() und announce_destination().

---

## Bekannte offene Issues

### v1.0-Blocker (Sicherheit)

**B3 – IFAC (Interface Access Codes):** Modul fertig (`ifac.rs`), aber `verify_ifac()` wird im Empfangspfad nicht aufgerufen. Ohne IFAC kann jeder auf jedes Interface zugreifen. Muss vor 1.0 rein.

Resource Transfer ist v1.1 (aktuell nur Stub in `resource.rs`).

### Design-Schulden (architekturrelevant)

**E10 – Interface-spezifischer Send-Side Jitter (Prio M)**
LoRa/Serial Interfaces brauchen Jitter für Collision Avoidance. Core bleibt instant, Interface verzögert. Blockiert von LoRa-Interface-Implementierung.

**E24 – Ingress Control per Interface (Prio M)**
Pythons `ingress_control` rate-limitiert Announces auf neuen Interfaces. Sinnvoll für LoRa, kontraproduktiv für TCP. Lösung: per-Interface Default – TCP/UDP off, LoRa/Serial on.

**E13 – Storage Trait gibt Referenzen zurück (Prio L)**
Blockiert reine Disk-Backed Implementierungen. Fix: `Option<T>` statt `Option<&T>`. Teilweise bereits behoben (Ratchet-Methods geben Owned zurück), Rest offen.

**E14 – FileStorage/MemoryStorage Kopplung (Prio L)**
BTreeMap in MemoryStorage verhindert Insertion-Order Eviction (LRU).

### Feature-Lücken

- E18/E19: UDP `device` Parameter und Multiple Forward Addresses
- E20: AutoInterface auf macOS/Windows
- E21: NIC Hot-Plug Detection
- E22: Multiple AutoInterface-Instanzen mit verschiedenen Group IDs
- E25: Integration Tests für Shared Instance Blocks B/C

### Kleinigkeiten

- E12: Flush-Interval konfigurierbar machen
- E15: Git History mit No-Op FileStorage Commits (Doku)
- E16: FileStorage Full-Rewrite bei Flush (SD-Karten-Wear)
- E23: `carrier_changed` Flag ist Dead Code

---

## Testing-Philosophie

- Jeder Fix braucht Tests. TDD wo sinnvoll — Test schreiben BEVOR der Fix kommt.
- Interop-Tests gegen Python-Referenz verifizieren Protokoll-Kompatibilität.
- Agent-Workflow: Erst Bestandsaufnahme (was existiert, was testen die Tests), dann Lücken identifizieren, dann priorisiert fixen.
- Interop-Tests umgehen aktuell `ingress_control` via Config (siehe E24).
- **Bugs nicht in Tests zementieren:** Wenn ein Test einen Schwellwert asserted, prüfen ob der Wert korrekt ist — nicht nur ob der Code ihn produziert.
- **Versioning:** SemVer im Workspace-Root `Cargo.toml`. MINOR bei Phase-Abschluss oder Breaking Changes, PATCH bei Bugfixes. Keine Effort-Estimates in Docs.
