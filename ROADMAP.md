# Leviculum Roadmap

**Projektziel:** Vollständige Rust-Implementierung des Reticulum Network Stack
**Zeitrahmen:** 9 Monate (1 Entwickler Vollzeit)
**Referenz:** Python-Implementierung (Reticulum, ~40.700 LOC)

| Version | Zeitraum | Fokus |
|---------|----------|-------|
| **1.0** | Monat 1-6 | Core-Protokoll, Basis-Interfaces, Datenübertragung |
| **1.1** | Monat 7-9 | Hardware-Interfaces, C-API, Debian-Paket, Android |

---

# Version 1.0 — Core-Implementierung

---

## Versionen

| Version | Phase | Status |
|---------|-------|--------|
| 0.1.0 | Phase 1: Protokoll-Fundament | ✅ |
| **0.2.0** | Phase 2: Core API & Full Node | 🔶 Aktuell (~80%) |
| 0.3.0 | Phase 3: Datenübertragung & Release-Vorbereitung | ⬜ |
| **1.0.0** | Erstes stabiles Release | ⬜ |
| 1.1.0 | Phase 5-7: Hardware, C-API, Android | ⬜ |

---

## Aktueller Stand

Das Projekt hat Phase 1 vollständig abgeschlossen und Phase 2 ist zu ~85% fertig — neben TCP Server (Meilenstein 2.4) fehlen IFAC/Ratchet-Integration und API-Vervollständigung. Kritische Bugs C8 (Link-Daten verworfen), C9 (Channel-ACKs) und D12 (close_connection) sind in v0.5.5 behoben. Meilensteine 2.1 (Destination API), 2.2 (Link-Responder), 2.3 (High-Level Link API inkl. Keepalive) und 2.5 (Transport Layer) sind abgeschlossen. Meilenstein 3.2 (Channel-System inkl. Buffer-System) ist ebenfalls fertig — StreamDataMessage für binäre Streams und RawChannelReader/Writer für gepufferte I/O sind implementiert. **High-Level Node API** (`NodeCore` in reticulum-core, `ReticulumNode` in reticulum-std) bietet eine einheitliche async-kompatible Schnittstelle mit Smart Routing, Connection-Abstraktion und symmetrischer Channel-API. Vollständige Interoperabilität mit Python rnsd ist nachgewiesen. **CLI-Tool `lrns`** existiert mit Subcommands: `status`, `path`, `identity`, `probe`, `interfaces` (nur `identity` ist voll implementiert, die anderen sind Gerüste mit "Not implemented yet").

**Sans-I/O-Architektur abgeschlossen:** `reticulum-core` ist jetzt ein reiner Zustandsautomat ohne jegliche direkte I/O-Operationen. `NodeCore` nimmt eingehende Pakete via `handle_packet()` entgegen und gibt `Action`-Werte (`SendPacket`, `Broadcast`) zurück, die der Treiber ausführt. Der Treiber in `reticulum-std` besitzt die Interfaces, liest Pakete, speist sie in den Core, und dispatcht die resultierenden Actions. `TransportRunner` wurde entfernt; `ReticulumNode` ist der einheitliche Treiber. Diese Architektur ermöglicht den Einsatz auf Embedded-Plattformen ohne `std`.

**Async Event Loop (v0.3.2):** Die Event-Loop in `reticulum-std` nutzt jetzt `tokio::select!` statt 50ms-Polling. Der Treiber wacht sofort auf bei Socket-Lesbarkeit, ausgehenden Daten oder Timer-Ablauf — ohne Latenz-Overhead und mit minimalem CPU-Verbrauch im Leerlauf.

**Channel-Bridge-Architektur (v0.4.0):** Interfaces laufen jetzt als eigenständige Tokio-Tasks und kommunizieren über `mpsc`-Channels mit der Event-Loop. `reticulum-net` (neues `no_std`-Crate) definiert die gemeinsamen Datentypen (`IncomingPacket`, `OutgoingPacket`, `InterfaceInfo`), die sowohl auf std- als auch Embedded-Plattformen funktionieren. `reticulum-nrf` ist ein Embassy-basiertes Firmware-Crate für den Heltec Mesh Node T114 (nRF52840 + SX1262) mit vollständigen Pin-Mappings, USB Composite CDC-ACM (Debug-Log + Reticulum-Transport als zwei serielle Ports), `info!`/`warn!`-Logging-Makros, FICR-basierter USB-Seriennummer, udev-Regeln für stabile Gerätesymlinks, und einem automatisierten Flash-und-Verify-Testharnisch (`tools/flash-and-read.sh`).

**Sofortige Action-Rückgabe (v0.5.0, vormals Deferred-Dispatch v0.3.1):** Alle Applikationsmethoden (`connect()`, `accept_connection()`, `send_on_connection()`, `close_connection()`, `send_single_packet()`, `announce_destination()`) geben `TickOutput` direkt zurück — Actions werden sofort geflusht statt erst beim nächsten `handle_timeout()`. Der Treiber dispatcht die zurückgegebenen Actions genauso wie bei `handle_packet()`/`handle_timeout()`. `Link.attached_interface` (analog zu Python) steuert das Routing für Link-gebundenen Verkehr.

**Architektur-Migration abgeschlossen:** `NodeCore` besitzt RNG intern als generischen Parameter (`NodeCore<R, C, S>`). Alle Runtime-Methoden (`handle_packet()`, `connect()`, etc.) benötigen keinen `Context`-Parameter mehr. Die `Context`-Trait-Abstraktion wurde vollständig entfernt — Funktionen nehmen direkt `rng: &mut R` und `now_ms: u64` als Parameter. Alle `#[cfg(feature = "alloc")]` wurden entfernt — `alloc` ist immer verfügbar. Das `std` Feature aktiviert nur noch optimierte Crypto-Implementierungen.

**Ratchet & IFAC:** Kryptographische Module implementiert und unit-getestet. IFAC ist noch nicht in den Paketempfangspfad eingebunden. Ratchet-Validierung ist bei Announces und Link-Establishment noch nicht aktiv.

**Transport Layer vollständig (3.676 LOC):** Announce-Rebroadcast, PATH_REQUEST/PATH_RESPONSE, Reverse-Path-Routing, Link-Tabellenverwaltung, Hop-Count-Validation, Header-Stripping am letzten Hop, Announce-Replay-Schutz, LRPROOF-Validierung, Auto-Re-Announce auf PATH_REQUEST. **Path Recovery** (v0.4.2/v0.4.3): Pfad-Zustandsverfolgung (`PathState`), automatische Markierung als unresponsive bei abgelaufenen unvalidierten Links, Akzeptanz von Same-Emission-Announces über Alternativrouten, direkte `request_path()`-Aufrufe aus dem Core für Pfad-Neuentdeckung. **Announce Rate Limiting** (v0.4.4): Per-Destination-Violation/Grace/Penalty-Eskalationsmechanismus analog zu Python Transport.py:1692-1719, blockiert nur Rebroadcast (nicht Pfad-Updates), konfigurierbar und standardmäßig deaktiviert. **Hop-Threshold-Korrektur** (v0.5.2): 4 Off-by-One-Bugs in Forwarding-Schwellwerten behoben (Python inkrementiert `hops` bei Empfang, Rust nicht — aus Python kopierte Schwellwerte waren um 1 daneben). `PathEntry::is_direct()` und `PathEntry::needs_relay()` kapseln die Semantik-Differenz und verhindern Wiederholung. **Rust Transport Relay** funktioniert vollständig: Announce-Rebroadcast, Link-Routing und Datenweiterleitung zwischen zwei Python-Daemons getestet. **Gemischte Relay-Ketten** (Rust + Python Relays in Serie) funktionieren inklusive Link-Establishment und bidirektionaler Datenübertragung über die volle Kette.

**Code-Qualität:** LinkManager intern auf einheitliche Paket-Queue (`PendingPacket` Enum) umgestellt, Timeout-Konstanten zentralisiert, `LinkId` und `DestinationHash` als Newtype-Structs für vollständige Typ-Sicherheit (keine `Deref` mehr, kein `as_bytes_mut()`). Proof-Strategy und Signing-Key von LinkManager's Destination-Map auf den `Link` selbst verschoben — reduziert duplizierte State zwischen Transport, LinkManager und NodeCore. ~860 Tests bestehen (582 Core-Unit + 20 Std-Lib + 175 Interop + 26 Doctests + 18 Proptest + 31 Test-Vektoren + 7 Core-Integration + 3 Std-Integration).

| Komponente | Status | LOC |
|------------|--------|-----|
| Kryptographie (AES, SHA, HMAC, HKDF, Token) | ✅ Fertig | 1.030 |
| Identity-Management (Schlüsselpaare, Signaturen, Encrypt/Decrypt) | ✅ Fertig | 1.194 |
| Packet-Strukturen (alle Typen, Header 1/2) | ✅ Fertig | 411 |
| Announce (Erstellung, Validierung, Signaturprüfung) | ✅ Fertig | 681 |
| Destination (Hashing, Typen, Ratchets) | ✅ Fertig | 921 |
| Ratchet (Forward Secrecy) | ⚠️ Krypto fertig, Validierung nicht eingebunden | 419 |
| IFAC (Interface Access Codes) | ⚠️ Modul fertig, nicht in Empfangspfad eingebunden | 378 |
| Link-State-Machine (Handshake, Proof, RTT, Data) | ✅ Initiator + Responder | 1.800 |
| Transport Layer (Routing, Pfade, Announces, Relay) | ✅ Fertig | 3.676 |
| HDLC-Framing (no_std + alloc) | ✅ Fertig | 577 |
| Interface-Traits + TCP-Client (Channel-basiert) | ✅ Fertig | 623 |
| reticulum-net (Shared Interface-Datentypen, no_std) | ✅ Fertig | 48 |
| Sans-I/O Driver (async select!, kein Polling) | ✅ Fertig | 224 |
| Reticulum-Instanz + Config + Storage | ✅ Fertig | 597 |
| FFI/C-API | ✅ Grundfunktionen | 361 |
| Tests (Rust + C) | | ~19.700 |
| **Gesamt** | | **~25.000** |

**Crate-Aufteilung:**
| Crate | src LOC | test LOC | Beschreibung |
|-------|---------|----------|-------------|
| reticulum-core | 22.087 | 1.527 | Protokoll-Logik (no_std) |
| reticulum-net | 48 | — | Shared Interface-Datentypen (no_std) |
| reticulum-std | 2.182 | 10.418 | Plattform-Glue (tokio, TCP) |
| reticulum-nrf | ~400 | — | Embedded-Firmware (Embassy, nRF52840, USB CDC-ACM) |
| reticulum-ffi | 361 | 404 | C-API |

**Test-Abdeckung:** ~860 Tests (582 Core-Unit + 18 Proptest + 31 Test-Vektoren + 26 Doctests + 20 Std-Lib + 7 Core-Integration + 3 Std-Integration + 175 Interop gegen rnsd)

**Architektur:** Siehe [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) — no_std/embedded-freundlich, sans-I/O Core (reine Zustandsmaschine), I/O via Action-Rückgabewerte an den Treiber.

---

## Phase 1: Protokoll-Fundament (Monat 1-2)

### Ziel
Vollständige Interoperabilität auf Paket-Ebene mit der Python-Referenzimplementierung.

### Meilenstein 1.1: Krypto-Validierung (Woche 1-2) ✅
- [x] Vollständige Test-Vektoren aus Python generieren (826 LOC)
- [x] Identity-Verschlüsselung mit ephemeren Schlüsseln
- [x] Ratchet-Schlüsselverwaltung für Forward Secrecy
- [x] Cross-Implementation-Tests: Rust verschlüsselt ↔ Python entschlüsselt
- [x] Property-Based Testing mit proptest (307 LOC)

**Deliverable:** ✅ Kryptographie vollständig kompatibel mit Python Reticulum

### Meilenstein 1.2: Paket-Serialisierung (Woche 3-4) ✅
- [x] Packet pack/unpack für alle Pakettypen (DATA, ANNOUNCE, LINKREQUEST, PROOF)
- [x] Alle Kontexttypen (RESOURCE, RESOURCE_ADV, CACHE_REQUEST, etc.)
- [x] Header-Formate (HEADER_1, HEADER_2 für Transport)
- [x] Paket-Hash-Berechnung

**Deliverable:** ✅ Rust kann Pakete von Python parsen und umgekehrt

### Meilenstein 1.3: Identity & Destination (Woche 5-6) ✅
- [x] Identity-Serialisierung (Speichern/Laden)
- [x] Destination-Hash-Berechnung
- [x] Destination-Typen (SINGLE, GROUP, PLAIN, LINK)
- [x] Announce-Pakete erstellen und validieren
- [x] Proof-Strategien (PROVE_NONE, PROVE_APP, PROVE_ALL)

**Deliverable:** ✅ Announcements funktionieren bidirektional

### Meilenstein 1.4: Link-Establishment (Woche 7-8)
- [x] 3-Paket-Handshake implementieren (Initiator-Seite):
  - Link Request (ephemere X25519-Pubkey)
  - Link Proof Verifikation (signierte Challenge)
  - RTT-Paket (finalisiert Link auf Gegenseite)
- [x] ECDH-Schlüsselaustausch für Link-Keys
- [x] Link-Verschlüsselung/Entschlüsselung (AES-256-CBC + Fernet-kompatibel)
- [x] Link-State-Machine (Initiator): Pending → Handshake → Active
- [x] Bidirektionale verschlüsselte Datenkommunikation mit Python rnsd
- [x] Link-Responder-Seite (eingehende Links akzeptieren)
- [x] Keepalive-Mechanismus
- [x] Link-Teardown (ordnungsgemäßes Schließen)

**Deliverable:** ✅ Rust kann Link zu Python rnsd aufbauen und verschlüsselt kommunizieren

---

## Phase 2: Core API & Full Node (Monat 3-4)

### Ziel
Vollständige API für Destinations und Links. Leviculum kann sowohl Client als auch Server sein.

### Meilenstein 2.1: Destination API (Woche 9) ✅

- [x] `generate_random_hash()` in announce.rs (5 random + 5 timestamp bytes)
- [x] `Destination::announce()` → erstellt signiertes Announce-Paket
- [x] `Destination::announce_with_app_data(data)` → mit Application Data
- [x] Hash-Berechnungsmethoden öffentlich machen (für Debugging/Tests)
- [x] `ReceivedAnnounce` und Test-`ParsedAnnounce` unifizieren

```rust
// Implementierte API:
let dest = Destination::new(identity, Direction::In, DestinationType::Single, "app", &["echo"]);
let announce_packet = dest.announce(Some(b"app-data"), &mut rng, now_ms)?;
transport.send_announce(announce_packet)?;
```

**Deliverable:** ✅ Announces können über die Library erstellt werden

### Meilenstein 2.2: Link-Responder (Woche 10-11) ✅

- [x] `Destination::set_link_established_callback(fn)` (via LinkManager Events)
- [x] Link-Request-Verarbeitung in Transport (`handle_link_request()`)
- [x] Proof-Generierung (signierte Challenge)
- [x] Link-Aktivierung nach RTT-Empfang
- [x] Incoming Link → Event an Destination (via `drain_events()`)

```rust
// Implementierte API (via LinkManager):
link_manager.register_destination(dest_hash, &identity);
// Bei eingehendem Link-Request:
let events = link_manager.drain_events();
// LinkEvent::LinkEstablished { link_id, ... }
```

**Deliverable:** ✅ Leviculum kann eingehende Links akzeptieren

### Meilenstein 2.3: High-Level Link API (Woche 12) ✅

- [x] `LinkManager::initiate()` / `initiate_with_path()` für Link-Aufbau
- [x] Automatisches Warten auf Announce (mit Timeout via `poll()`)
- [x] Automatisches Proof-Handling und RTT
- [x] Link-State-Callbacks via Events (`drain_events()`)
- [x] Keepalive-Mechanismus (Initiator 0xFF, Responder Echo 0xFE, RTT-basiertes Intervall)
- [x] Link-Stale-Erkennung und automatisches Schließen nach Timeout
- [x] Link-Teardown (ordnungsgemäßes Schließen via `close()` mit LINKCLOSE-Paket)

**Einschränkungen behoben (v0.5.5):** C8 (Link-adressierte Pakete verworfen) und D12 (close_connection nicht exponiert) sind behoben — LINKCLOSE, Keepalive-Echos und Channel-ACKs erreichen jetzt LinkManager korrekt.

```rust
// Implementierte API (via LinkManager):
let link_id = link_manager.initiate(dest_hash, &identity)?;
link_manager.send(link_id, b"Hello")?;
let events = link_manager.drain_events();
// LinkEvent::DataReceived { link_id, data }
link_manager.close(link_id)?;
```

**Deliverable:** ✅ High-Level Link-API vollständig (inkl. Keepalive und Stale-Erkennung)

### Bugfix: Keepalive-Echo von Python funktioniert nicht ✅

- [x] Python-Daemon echoed keine Keepalive-Pakete von Rust-Initiator
- [x] Ursache: Keepalive-Pakete werden in Python NICHT verschlüsselt, Rust hat sie aber verschlüsselt
- [x] Test `test_rust_initiator_sends_keepalive_python_echoes` besteht
- [x] `#[ignore]` Attribut entfernt

### Meilenstein 2.4: TCP Server & Daemon-Grundlage (Woche 13-14) ⬜

- [ ] TCP Server Interface (accept incoming connections)
- [ ] `lrnsd` Grundgerüst (Config laden, Interfaces starten, Event-Loop)
- [ ] Graceful Shutdown
- [ ] Logging-Integration (tracing)

**Deliverable:** Minimaler funktionierender Daemon

### Meilenstein 2.5: Transport Layer Vervollständigung (Woche 15-16) ✅

3.676 LOC — vollständige Transport-Implementierung:

- [x] Pfad-Tabellenverwaltung (BTreeMap in core Transport)
- [x] Announce-Verarbeitung und Rebroadcast
- [x] PATH_REQUEST/PATH_RESPONSE Handling
- [x] Paket-Weiterleitung (forward_packet)
- [x] Duplikaterkennung (packet_cache mit Expiry)
- [x] Reverse-Path-Tracking (proof routing via reverse table, hop validation, announce replay protection)
- [x] Rate Limiting (Announce-Rate-Limiting)
- [x] Link-Tabellenverwaltung
- [x] Announce-Tabellenverwaltung
- [x] Destination-Pfadtabellen
- [x] Transport Relay (Announce-Rebroadcast, Link-Routing, Datenweiterleitung)
- [x] LRPROOF-Validierung
- [x] Auto-Re-Announce auf PATH_REQUEST

**Multi-Hop Link von Non-Transport Nodes** (v0.5.3): `connect()` nutzt jetzt `PathEntry::needs_relay()` für korrekte HEADER_2-Formatierung mit transport_id, und LRPROOF-Pakete werden an lokale Pending-Links zugestellt (Python Transport.py:2054-2073). Interop-Test bestätigt: Link-Aufbau, Timeout-Recovery (expire_path + request_path), und Wiederherstellung.

Kleinere Lücken (nicht blockierend für v1.0): Announce-Expiry-Timer, mehrere Pfade pro Destination, MTU-Signaling für Link-MDU-Verhandlung, TCP-Reconnection bei Verbindungsabbruch (A2), LRPROOF/Receipt-Disambiguierung ohne Receipt-Tabelle (E16).

**Deliverable:** ✅ Vollständiges Routing für direkte und Multi-Hop-Verbindungen

### Bekannte Bugs und Lücken (Gap-Analyse Feb 2026)

Die folgende Liste wurde durch eine systematische 5-Runden-Lückenanalyse (Startup → Announce → Link → Data → Lifecycle) identifiziert.

#### Bugs

| ID | Schwere | Beschreibung | Betroffene Datei |
|----|---------|-------------|------------------|
| C8 | ✅ Behoben (v0.5.5) | `Transport::handle_data()` verwirft Link-adressierte Data-Pakete auf Non-Transport-Nodes still — behoben durch Link-adressierte Paket-Zustellung + Proof-Routing-Erweiterung. | `transport.rs` |
| C9 | ✅ Behoben (v0.5.5) | `Channel::mark_delivered()` wird in Produktion nie aufgerufen — behoben durch vollständige Proof-Delivery-Chain (Receiver-Proof-Generierung, Sender-Receipt-Registrierung, mark_delivered-Aufruf). | `link/manager.rs`, `node/mod.rs` |
| D11 | 🟡 Mittel | `handle_interface_down()` räumt Transport-Tabellen auf, aber nicht LinkManager. Links auf toten Interfaces bleiben ~12 Min als Zombies bestehen. | `node/mod.rs:701-737` |
| D13 | 🟠 Niedrig | Geschlossene Links werden nie aus `LinkManager::links` entfernt — `close()` setzt Status aber löscht nicht aus BTreeMap. Speicherleck bei langlebigen Nodes. | `link/manager.rs:421-441` |

#### Fehlende Integrationen

| ID | Beschreibung | Status |
|----|-------------|--------|
| B3 | IFAC-Modul existiert, ist aber nicht in den Paketempfangspfad eingebunden | ⚠️ Modul fertig |
| B4 | Ratchet-Krypto funktioniert, aber Validierung bei Announces/Links nicht aktiv | ⚠️ Krypto fertig |
| C10 | Buffer/Stream-System (1091 LOC) existiert, ist aber nicht in ConnectionStream integriert | ⚠️ Code fertig |
| D12 | `NodeCore::close_connection()` funktioniert, aber nicht über `ReticulumNode` exponiert | ✅ Behoben (v0.5.5) |

#### Fehlende Features

| ID | Beschreibung |
|----|-------------|
| A2 | Keine TCP-Reconnection-Logik — Interface geht bei Verbindungsabbruch permanent verloren |
| E15 | Kein `wait_established()` API auf ConnectionStream — Anwendungen können nicht auf Link-Handshake warten |
| E16 | LRPROOF und Receipt sind beide 96 Bytes — Disambiguierung nur über Receipt-Tabellen-Lookup, kein Typ-Feld |

---

## Phase 3: Datenübertragung & Release-Vorbereitung (Monat 5-6)

### Ziel
Zuverlässiger Dateitransfer zwischen Rust und Python. Release-Qualität erreichen.

### Meilenstein 3.1: Resource Transfer (Woche 17-19)
- [ ] Resource-Segmentierung
- [ ] Advertisement-Protokoll
- [ ] Sliding-Window-Management (2-75 Pakete)
- [ ] Bandbreitenanpassung
- [ ] Kompression (bz2)
- [ ] Hashmap-Berechnung
- [ ] Fortschritts-Callbacks
- [ ] Request/Response-Pattern (benötigt für Resource Advertisement)

**Deliverable:** Dateitransfer zwischen Rust und Python

### Meilenstein 3.2: Channels & Buffer (Woche 20) ⚠️
- [x] Channel-Abstraktion für zuverlässige Streams
- [x] Message Envelopes
- [x] StreamDataMessage (0xff00) für binäre Stream-Übertragung
- [x] Buffer-System (RawChannelReader, RawChannelWriter, BufferedChannelWriter)
- [x] BZ2-Kompression für Stream-Daten

**Deliverable:** ⚠️ Channel-Envelope funktioniert inkl. mark_delivered() (v0.5.5), aber Buffer/Stream-Layer nicht in ConnectionStream integriert

---

## Phase 3b: Release-Vorbereitung

### Ziel
Production-ready: QA, zusätzliche Interfaces, Dokumentation.

### `lrns` CLI
- [ ] `lrns status` - Status-Anzeige
- [ ] `lrns path` - Pfad-Lookup
- [ ] `lrns probe` - Konnektivitätstest
- [x] `lrns identity` - Identity-Management
- [ ] `lrns interfaces` - Interface-Übersicht
- [ ] `lrns cp` - Dateitransfer (benötigt Resource Transfer aus Phase 3)
- [ ] `lrnsd` - Daemon (aufbauend auf Meilenstein 2.4)

### Zusätzliche Interfaces
- [ ] UDP Interface
- [ ] LocalInterface (IPC)
- [ ] Serial Interface
- [ ] Async interface connect path — `spawn_tcp_interface()` connects synchronously (blocking on tokio thread), which is fine at startup but blocks the event loop for runtime hot-plug. Prerequisite for USB and BLE interface support. The channel-based `InterfaceRegistry` already supports dynamic `register()`, only the connect step needs an async variant.

### Qualitätssicherung
- [x] Integration-Tests gegen rnsd-Daemon (175 Tests)
- [ ] Performance-Optimierung
- [ ] Speicher-Profiling mit Valgrind
- [ ] Fuzzing der Paket-Parser
- [ ] Dokumentation vervollständigen
- [x] CI/CD-Pipeline mit no_std-Checks
- [x] `LinkId` Newtype (Typ-Sicherheit statt `[u8; 16]` Alias)
- [x] `DestinationHash` Newtype (analog zu `LinkId`, verhindert Verwechslung von Link-IDs und Destination-Hashes)
- [x] `LinkId::Deref` entfernen (nach `DestinationHash`-Migration, für vollständige Typ-Sicherheit)
- [x] Magic Numbers in `link/manager.rs` durch benannte Konstanten ersetzen (`MTU`, `MODE_AES256_CBC`)

**Deliverable:** Version 1.0 Release

---

## Deferred (Version 1.1+)

Diese Features sind nice-to-have, aber nicht MVP-kritisch:

- [ ] Interface Access Control (IFAC) — ⚠️ Modul implementiert, nicht in Empfangspfad eingebunden
- [ ] Ratchet-Schlüsselverwaltung für Forward Secrecy — ⚠️ Krypto implementiert, Validierung nicht eingebunden
- [ ] AutoInterface (lokale Netzwerk-Autodiscovery)
- [ ] KISS Interface (TNC-Protokoll)
- [ ] Pipe Interface
- [ ] Erreichbarkeitstracking
- [ ] Roaming-Modus
- [x] ~~Proof-Strategien (PROVE_NONE, PROVE_APP, PROVE_ALL)~~ ✅ Implementiert (Transport + Link-Level)

---

## Test-Strategie

### Unit Tests
- Jedes Modul mit Abdeckung > 80%
- Alle Edge Cases und Fehlerbedingungen
- Property-Based Testing mit proptest

### Interoperabilitäts-Tests
| Test-Kategorie | Methode | Status |
|----------------|---------|--------|
| Kryptographie | Test-Vektoren aus Python | ✅ |
| Paket-Format | Roundtrip-Tests | ✅ |
| HDLC-Framing | Byte-genaue Verifikation | ✅ |
| Announce-Validierung | Signaturprüfung gegen rnsd | ✅ |
| Announce-Propagation | Multi-Client-Test gegen rnsd | ✅ |
| Link-Establishment | Live-Tests gegen rnsd | ✅ |
| Transport-Integration | TCP + Transport + Events | ✅ |
| Transport Relay | Announce-Rebroadcast, Link-Routing | ✅ |
| Multi-Hop | Multi-Hop-Topologie und Routing | ✅ |
| Channel/Buffer | Stream + gepuffertes I/O | ✅ |
| Eingehende Link-Daten | Empfangspfad für Link-Data-Pakete | ✅ (C8 behoben v0.5.5) |
| Resource Transfer | Dateitransfer-Verifikation | - |

### Integration-Tests
```
Testumgebung:
┌─────────────┐      ┌─────────────┐
│   Python    │ TCP  │    Rust     │
│    rnsd     │◄────►│  leviculum│
└─────────────┘      └─────────────┘
```

Automatisierte Test-Suite (175 Interop-Tests in 24 Modulen gegen rnsd):
- ✅ TCP-Verbindung zu rnsd
- ✅ Pakete empfangen und senden
- ✅ Announce-Erstellung und -Validierung
- ✅ Announce-Signaturprüfung (inkl. ungültige Signaturen)
- ✅ Announce-Propagation zwischen Clients
- ✅ Identity/Destination-Hash-Berechnung
- ✅ Link-Establishment (mit Python-Destination)
- ✅ Bidirektionale verschlüsselte Datenpakete
- ✅ Transport + TcpClientInterface End-to-End
- ✅ Ratchet-Verschlüsselung und -Rotation
- ✅ Multi-Hop-Topologie und Routing
- ✅ Link-Manager mit Responder-Modus
- ✅ Edge-Cases und Stress-Tests
- ✅ Transport Relay (Rust-Node leitet Announces, Links und Daten zwischen zwei Python-Daemons)
- ✅ Gemischte Relay-Ketten (Rust + Python Relays, Link-Establishment über volle Kette)
- ✅ Relay-Failover und Pfad-Recovery (Diamond-Topologie mit Relay-Austausch)
- ✅ Path Recovery via Link-Timeout (LRPROOF-Drop, expire_path + request_path)
- ✅ Link Keepalive und Close
- ✅ Proof-Strategien
- ✅ Flood/Loop-Prevention (Triangle, Diamond, redundante Pfade)
- Resource Transfer
- Error Recovery

---

## Aufwandsschätzung

| Phase | Geschätzte LOC | Komplexität |
|-------|---------------|-------------|
| Phase 1: Protokoll-Fundament | ~3.000 ✅ | Mittel |
| Phase 2: Core API & Full Node | ~2.500 🔶 (~80%) | Hoch |
| Phase 3: Datenübertragung & Release | ~4.500 | Mittel |
| **Gesamt neu** | **~10.000** | |
| **Gesamt (inkl. bestehend)** | **~25.000** | |

---

## Risiken und Mitigationsstrategien (Version 1.0)

| Risiko | Wahrscheinlichkeit | Mitigation |
|--------|-------------------|------------|
| Transport Layer komplexer als erwartet | ✅ Gelöst | 3.676 LOC, vollständig implementiert |
| Interop-Probleme mit Python | Mittel | Frühe und kontinuierliche Tests (175 Interop-Tests) |
| Performance-Probleme bei async | Niedrig | Profiling ab Phase 2 |
| no_std-Kompatibilitätsprobleme | ✅ Gelöst | Context-Trait entfernt, direkte RNG/time-Parameter |
| Resource Transfer Komplexität | Mittel | Sliding-Window, Hashmap, Compression — frühzeitig planen |

---

## Meilenstein-Übersicht

```
Monat 1    Monat 2    Monat 3       Monat 4       Monat 5         Monat 6
   │          │          │             │             │               │
   ▼          ▼          ▼             ▼             ▼               ▼
┌──────────────────┐┌─────────────────────────┐┌────────────────────────────────┐
│ Phase 1          ││ Phase 2                 ││ Phase 3                        │
│ Protokoll-       ││ Core API & Full Node    ││ Datenübertragung &             │
│ Fundament ✅     ││ (~80%) 🔶              ││ Release-Vorbereitung           │
└──────────────────┘└─────────────────────────┘└────────────────────────────────┘
        │                      │                           │
        ▼                      ▼                           ▼
   Link zu Python      Transport Relay ✅           Resource Transfer
   funktioniert ✅     High-Level Link API ✅       TCP Server → lrnsd
                       lrns CLI (teilw.)             Version 1.0 Release
```

### Kritischer Pfad bis v1.0

```
┌─────────────────────┐
│ C8 handle_data-Bug  │ ✅ Behoben (v0.5.5)
│     fix             │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 2.4 TCP Server      │ ⬜ Offen — letzter Phase-2-Meilenstein
│     lrnsd Basis     │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 3.1 Resource        │ ⬜ Offen — Dateitransfer + Request/Response
│     Transfer        │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 3b Release QA       │ ⬜ Offen — Fuzzing, Valgrind, Docs
│    Version 1.0      │
└─────────────────────┘
```

---

## Definition of Done für Version 1.0

**Must-Have (MVP):**
- [x] `Destination::announce()` API funktioniert
- [x] Link-Responder: eingehende Links akzeptieren
- [x] High-Level Link API: `LinkManager` mit `initiate()`, `send()`, `close()`
- [x] Transport Layer: Routing, Announce-Relay, Multi-Hop
- [x] Channel-System: Streams und gepuffertes I/O
- [ ] Resource Transfer: Dateien übertragen
- [ ] TCP Server Interface
- [ ] `lrnsd` Daemon läuft standalone
- [x] Integration-Tests gegen Python rnsd bestehen (175 Interop-Tests)
- [x] no_std-Kompatibilität für reticulum-core
- [ ] Forward Secrecy via Ratchets — ⚠️ Krypto fertig, Validierung nicht eingebunden
- [ ] Interface Access Codes (IFAC) — ⚠️ Modul fertig, nicht in Empfangspfad eingebunden

**Should-Have:**
- [ ] `lrns` CLI: status, path, ~~identity~~, probe, interfaces (nur `identity` fertig)
- [ ] `lrns cp` - Dateitransfer (benötigt Resource Transfer)
- [ ] UDP Interface
- [ ] Unit-Test-Abdeckung > 80%
- [ ] Dokumentation vollständig
- [ ] Keine bekannten Speicherlecks (Valgrind-geprüft)

**Nice-to-Have (→ Version 1.1):**
- [ ] LocalInterface, Serial, KISS, AutoInterface
- [ ] Roaming
- [ ] Performance-Optimierung

---
---

# Version 1.1 — Plattform-Integration

**Zeitraum:** Monat 7-9
**Ziel:** Hardware-Interfaces, produktionsreife C-API, Debian-Paket, Android-Integration

---

## Phase 5: Hardware-Interfaces (Monat 7)

### Ziel
Unterstützung für LoRa-Hardware und anonyme Netzwerke.

### Meilenstein 5.1: RNode/LoRa Interface (Woche 27-29)

Das RNode-Interface ermöglicht Kommunikation über LoRa-Funk mit RNode-Hardware.

- [ ] KISS-Protokoll-Implementierung für RNode
  - Frame-Encoding/Decoding
  - Escape-Sequenzen (FEND, FESC, TFEND, TFESC)
- [ ] LoRa-Parameter-Konfiguration
  - Frequenz, Bandbreite, Spreading Factor
  - TX-Power, Coding Rate
- [ ] Hardware-Erkennung und -Initialisierung
  - Plattform-Erkennung (ESP32, nRF52, AVR)
  - Firmware-Version-Abfrage
- [ ] Radio-State-Management
  - On/Off/ASK States
  - Airtime-Limiting (ST_ALOCK, LT_ALOCK)
- [ ] Statistik-Abfragen (RSSI, SNR, Temperatur, Batterie)
- [ ] Multi-Interface-Unterstützung (RNodeMultiInterface)
  - Mehrere Frequenzen/Kanäle gleichzeitig

**Komplexität:** Hoch (~1.500 LOC)
**Deliverable:** LoRa-Kommunikation mit RNode-Hardware funktioniert

### Meilenstein 5.2: I2P Interface (Woche 30-31)

Integration mit dem I2P-Anonymitätsnetzwerk über das SAM-Protokoll.

- [ ] SAM v3-Protokoll-Client
  - Session-Management
  - Stream-Verbindungen
- [ ] I2P-Destination-Handling
  - Base64-Adressen
  - Destination-Generierung
- [ ] Tunnel-Management
  - Inbound/Outbound-Tunnel
  - Tunnel-Länge-Konfiguration
- [ ] Verbindungs-Timeouts und Retry-Logik
- [ ] Integration mit I2P-Router (i2pd oder Java I2P)

**Komplexität:** Mittel (~600 LOC)
**Deliverable:** Anonyme Kommunikation über I2P möglich

### Meilenstein 5.3: AX.25 KISS Interface (Woche 31-32)

Amateurfunk-Integration über AX.25-Protokoll.

- [ ] AX.25-Frame-Format
  - Adressfelder (Source, Destination, Digipeater)
  - Control- und PID-Felder
- [ ] KISS-TNC-Integration
  - Aufbauend auf bestehendem KISS-Interface
- [ ] Callsign-Handling
- [ ] SSID-Unterstützung

**Komplexität:** Niedrig (~250 LOC)
**Deliverable:** Kommunikation über Amateurfunk-TNCs

---

## Phase 6: C-API & Linux-Distribution (Monat 8)

### Ziel
Produktionsreife C-Bibliothek für Linux-Entwickler mit Debian-Paketierung.

### Meilenstein 6.1: C-API Vervollständigung (Woche 33-34)

Erweiterung von `leviculum-ffi` zur vollständigen C-API.

**Bestehende API (erweitern):**
```c
// Bereits implementiert
lrns_init(), lrns_version()
lrns_identity_new(), lrns_identity_free()
lrns_identity_sign(), lrns_identity_verify()
```

**Neue API-Bereiche:**

- [ ] **Reticulum-Instanz**
  ```c
  LrnsReticulum* lrns_reticulum_new(const char* config_path);
  int lrns_reticulum_start(LrnsReticulum* rns);
  int lrns_reticulum_stop(LrnsReticulum* rns);
  void lrns_reticulum_free(LrnsReticulum* rns);
  ```

- [ ] **Destination-Management**
  ```c
  LrnsDestination* lrns_destination_new(LrnsIdentity* id,
                                         LrnsDestType type,
                                         const char* app_name,
                                         const char** aspects);
  int lrns_destination_announce(LrnsDestination* dest);
  int lrns_destination_set_proof_strategy(LrnsDestination* dest, int strategy);
  ```

- [ ] **Link-Establishment**
  ```c
  LrnsLink* lrns_link_new(LrnsDestination* dest);
  int lrns_link_establish(LrnsLink* link, LrnsLinkCallback callback);
  int lrns_link_send(LrnsLink* link, const uint8_t* data, size_t len);
  int lrns_link_close(LrnsLink* link);
  ```

- [ ] **Packet-Handling**
  ```c
  int lrns_packet_send(LrnsDestination* dest,
                       const uint8_t* data, size_t len);
  int lrns_destination_set_packet_callback(LrnsDestination* dest,
                                           LrnsPacketCallback callback);
  ```

- [ ] **Resource Transfer**
  ```c
  LrnsResource* lrns_resource_new(LrnsLink* link,
                                   const uint8_t* data, size_t len);
  int lrns_resource_start(LrnsResource* res, LrnsResourceCallback callback);
  float lrns_resource_progress(LrnsResource* res);
  ```

- [ ] **Path Discovery**
  ```c
  int lrns_request_path(LrnsReticulum* rns, const uint8_t* dest_hash);
  int lrns_has_path(LrnsReticulum* rns, const uint8_t* dest_hash);
  ```

**Deliverable:** Vollständige C-API für alle Kernfunktionen

### Meilenstein 6.2: Entwickler-Infrastruktur (Woche 35)

- [ ] **pkg-config Integration**
  ```
  # leviculum.pc
  prefix=/usr
  libdir=${prefix}/lib
  includedir=${prefix}/include

  Name: leviculum
  Description: Rust implementation of the Reticulum network stack
  Version: 1.1.0
  Libs: -L${libdir} -lreticulum
  Cflags: -I${includedir}/leviculum
  ```

- [ ] **Header-Generierung mit cbindgen**
  - Automatische `leviculum.h` Generierung
  - Dokumentationskommentare in Header

- [ ] **Man-Pages**
  - `lrns_identity(3)` - Identity-Funktionen
  - `lrns_link(3)` - Link-Funktionen
  - `lrns_reticulum(3)` - Hauptinstanz

- [ ] **Beispiel-C-Programm**
  ```c
  // examples/c/announce.c
  #include <leviculum.h>

  int main() {
      lrns_init();
      LrnsReticulum* rns = lrns_reticulum_new("/etc/leviculum");
      LrnsIdentity* id = lrns_identity_new();
      // ... vollständiges Beispiel
  }
  ```

- [ ] **CMake Find-Modul**
  ```cmake
  # FindLeviculum.cmake
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(LEVICULUM REQUIRED leviculum)
  ```

**Deliverable:** Nahtlose Integration in C/C++-Build-Systeme

### Meilenstein 6.3: Debian-Paketierung (Woche 36)

- [ ] **Paket-Struktur**
  ```
  debian/
  ├── control          # Paket-Metadaten
  ├── rules            # Build-Regeln
  ├── changelog        # Versionshistorie
  ├── copyright        # Lizenzinformationen
  ├── leviculum0.install
  ├── leviculum-dev.install
  └── leviculum-tools.install
  ```

- [ ] **Paket: leviculum0** (Runtime)
  - `/usr/lib/x86_64-linux-gnu/leviculum.so.1.1.0`
  - `/usr/lib/x86_64-linux-gnu/leviculum.so.1` (Symlink)
  - Shared-Library mit SONAME

- [ ] **Paket: leviculum-dev** (Development)
  - `/usr/include/leviculum/leviculum.h`
  - `/usr/lib/x86_64-linux-gnu/leviculum.a` (Statische Lib)
  - `/usr/lib/x86_64-linux-gnu/pkgconfig/leviculum.pc`
  - Man-Pages

- [ ] **Paket: leviculum-tools** (CLI)
  - `/usr/bin/lrns` (Subcommands: status, path, identity, probe, interfaces, cp)
  - `/usr/bin/lrnsd`
  - Systemd-Unit-File für lrnsd

- [ ] **Lintian-Konformität**
  - Keine Lintian-Fehler oder -Warnungen
  - Debian-Policy-konform

- [ ] **Einreichung bei Debian**
  - ITP (Intent to Package) Bug erstellen
  - Sponsor für Upload finden
  - Mentors-Upload vorbereiten

**Deliverable:** Installation via `apt install leviculum-dev leviculum-tools`

---

## Phase 7: Android-Integration (Monat 9)

### Ziel
Minimale Hürden für Android-Entwickler durch native Kotlin-API und AAR-Paket.

### Meilenstein 7.1: JNI-Grundlagen (Woche 37)

- [ ] **JNI-Binding-Schicht**
  ```rust
  // leviculum-android/src/lib.rs
  #[no_mangle]
  pub extern "system" fn Java_net_leviculum_Identity_nativeNew(
      env: JNIEnv,
      _class: JClass,
  ) -> jlong {
      let identity = Identity::new();
      Box::into_raw(Box::new(identity)) as jlong
  }
  ```

- [ ] **Cargo-Konfiguration für Android**
  ```toml
  # .cargo/config.toml
  [target.aarch64-linux-android]
  linker = "aarch64-linux-android21-clang"

  [target.armv7-linux-androideabi]
  linker = "armv7a-linux-androideabi21-clang"
  ```

- [ ] **Cross-Compilation Setup**
  - NDK-Integration
  - Target-Architekturen: arm64-v8a, armeabi-v7a, x86_64

**Deliverable:** Native Libraries für alle Android-Architekturen

### Meilenstein 7.2: UniFFI-Integration (Woche 38)

[UniFFI](https://mozilla.github.io/uniffi-rs/) generiert automatisch Kotlin-Bindings aus Rust.

- [ ] **UniFFI-Definition**
  ```
  // leviculum.udl
  namespace leviculum {
    string version();
  };

  interface Identity {
    constructor();
    [Throws=ReticulumError]
    constructor(sequence<u8> private_key);

    sequence<u8> hash();
    sequence<u8> public_key();

    [Throws=ReticulumError]
    sequence<u8> sign(sequence<u8> message);

    [Throws=ReticulumError]
    boolean verify(sequence<u8> message, sequence<u8> signature);
  };

  interface Destination {
    constructor(Identity identity, DestinationType dtype,
                string app_name, sequence<string> aspects);
    [Throws=ReticulumError]
    void announce();
  };

  interface Link {
    constructor(Destination destination);
    [Throws=ReticulumError]
    void establish();
    [Throws=ReticulumError]
    void send(sequence<u8> data);
    void close();
  };

  [Error]
  enum ReticulumError {
    "Crypto",
    "Network",
    "InvalidState",
    "Timeout",
  };

  enum DestinationType {
    "Single",
    "Group",
    "Plain",
    "Link",
  };
  ```

- [ ] **Generierte Kotlin-API**
  ```kotlin
  // Automatisch generiert - saubere Kotlin-API
  val identity = Identity()
  val destination = Destination(
      identity,
      DestinationType.SINGLE,
      "myapp",
      listOf("service")
  )
  destination.announce()

  val link = Link(destination)
  link.establish()
  link.send("Hello".toByteArray())
  ```

**Deliverable:** Idiomatische Kotlin-API ohne manuelle JNI-Arbeit

### Meilenstein 7.3: AAR-Paket & Gradle (Woche 39-40)

- [ ] **AAR-Struktur**
  ```
  leviculum.aar
  ├── AndroidManifest.xml
  ├── classes.jar          # Kotlin-Bindings
  ├── jni/
  │   ├── arm64-v8a/
  │   │   └── libuniffi_leviculum.so
  │   ├── armeabi-v7a/
  │   │   └── libuniffi_leviculum.so
  │   └── x86_64/
  │       └── libuniffi_leviculum.so
  └── R.txt
  ```

- [ ] **Gradle-Plugin / Maven-Publikation**
  ```kotlin
  // build.gradle.kts (Nutzer-App)
  dependencies {
      implementation("net.leviculum:leviculum-android:1.1.0")
  }
  ```

- [ ] **Maven Central Publikation**
  - GPG-Signierung
  - Sonatype OSSRH Account
  - POM-Metadaten

- [ ] **Beispiel-Android-App**
  ```kotlin
  class MainActivity : AppCompatActivity() {
      override fun onCreate(savedInstanceState: Bundle?) {
          super.onCreate(savedInstanceState)

          // Leviculum initialisieren
          val configPath = filesDir.resolve("reticulum").absolutePath
          val reticulum = Reticulum(configPath)

          // Identity erstellen
          val identity = Identity()
          Log.d("Reticulum", "Identity hash: ${identity.hash().toHex()}")

          // Destination und Announce
          val dest = Destination(identity, DestinationType.SINGLE,
                                 "example", listOf("echo"))
          dest.announce()
      }
  }
  ```

- [ ] **ProGuard-Regeln**
  ```
  # proguard-rules.pro (automatisch im AAR)
  -keep class net.leviculum.** { *; }
  -keepclassmembers class net.leviculum.** { *; }
  ```

**Deliverable:** `implementation("net.leviculum:leviculum-android:1.1.0")` funktioniert

### Meilenstein 7.4: Dokumentation & Release (Woche 40)

- [ ] **Android-Dokumentation**
  - Getting Started Guide
  - API-Referenz (KDoc)
  - Beispiel-Projekte auf GitHub

- [ ] **C-API-Dokumentation**
  - Tutorial für C-Entwickler
  - API-Referenz (Doxygen-kompatibel)

- [ ] **Release-Vorbereitung**
  - Changelog
  - Migration Guide von 1.0 zu 1.1
  - Ankündigung

**Deliverable:** Version 1.1 Release

---

## Aufwandsschätzung Version 1.1

| Phase | Geschätzte LOC | Komplexität |
|-------|---------------|-------------|
| Phase 5: Hardware-Interfaces | ~2.350 | Hoch |
| Phase 6: C-API & Debian | ~1.500 | Mittel |
| Phase 7: Android-Integration | ~1.000 | Mittel |
| **Gesamt Version 1.1** | **~4.850** | |

---

## Technologie-Stack Version 1.1

### Hardware-Interfaces
- `serialport` Crate für Serial/RNode
- `tokio-serial` für async Serial I/O

### C-API
- `cbindgen` für Header-Generierung
- Statische + dynamische Library

### Android
- **UniFFI** (Mozilla) - Automatische Kotlin-Bindings
- **cargo-ndk** - Android-Cross-Compilation
- **gradle-cargo-plugin** - Build-Integration

---

## Risiken und Mitigationsstrategien (Version 1.1)

| Risiko | Wahrscheinlichkeit | Mitigation |
|--------|-------------------|------------|
| RNode-Hardware nicht verfügbar | Niedrig | Emulator/Mock für Tests |
| I2P-Router-Kompatibilität | Mittel | Tests mit i2pd und Java I2P |
| Debian-Sponsorship dauert lange | Mittel | Parallel eigenes APT-Repo |
| UniFFI-Limitierungen | Niedrig | Fallback auf manuelle JNI |
| Android-NDK-Änderungen | Niedrig | CI mit mehreren NDK-Versionen |

---

## Meilenstein-Übersicht (Gesamt)

```
Monat 1-2      Monat 3-4      Monat 5-6                  Monat 7        Monat 8        Monat 9
    │              │             │                          │              │              │
    ▼              ▼             ▼                          ▼              ▼              ▼
┌────────────┐┌────────────┐┌───────────────────────┐  ┌────────────┐┌────────────┐┌────────────┐
│  Phase 1   ││  Phase 2   ││ Phase 3               │  │  Phase 5   ││  Phase 6   ││  Phase 7   │
│  Protokoll ││  Netzwerk  ││ Datenübertragung &    │  │  Hardware  ││  C-API &   ││  Android   │
│   ✅       ││  (~80%) 🔶 ││ Release-Vorbereitung  │  │  Interfaces││  Debian    ││            │
└────────────┘└────────────┘└───────────────────────┘  └────────────┘└────────────┘└────────────┘
      │              │                  │                    │              │              │
      ▼              ▼                  ▼                    ▼              ▼              ▼
   Link zu       Transport         Resource Transfer     RNode/LoRa     Debian-       Version 1.1
   Python ✅     Relay ✅          Version 1.0 Release   I2P, AX.25     Paket         Release

├─────────────────────────────────────────────────┤  ├────────────────────────────────────────┤
                    VERSION 1.0                                      VERSION 1.1
```

---

## Definition of Done für Version 1.1

- [ ] RNode/LoRa Interface funktioniert mit echter Hardware
- [ ] I2P Interface verbindet über SAM-Protokoll
- [ ] AX.25 KISS Interface für Amateurfunk
- [ ] Vollständige C-API für alle Kernfunktionen
- [ ] pkg-config und CMake-Integration
- [ ] Man-Pages für C-API
- [ ] Debian-Pakete (leviculum0, -dev, -tools) lintian-konform
- [ ] ITP bei Debian eingereicht
- [ ] Android AAR auf Maven Central
- [ ] Kotlin-API via UniFFI
- [ ] Beispiel-Android-App
- [ ] Dokumentation für C und Android

---

## Nicht im Scope von 1.1

Für spätere Versionen:

- `rnodeconf` - RNode-Konfigurationstool (~4.500 LOC)
- `rnx` - Remote Command Execution
- iOS/Swift-Integration
- WebAssembly-Build
- Tunneling
- Remote Management

---

*Stand: 11. Februar 2026*
*Projekt: leviculum*
*Lizenz: MIT*
