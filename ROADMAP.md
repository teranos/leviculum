# Leviculum Roadmap

**Projektziel:** Vollständige Rust-Implementierung des Reticulum Network Stack
**Zeitrahmen:** 9 Monate (1 Entwickler Vollzeit)
**Referenz:** Python-Implementierung (Reticulum, ~40.700 LOC)

| Version | Zeitraum | Fokus |
|---------|----------|-------|
| **1.0** | Monat 1-6 | Core-Protokoll, Basis-Interfaces, CLI-Tools |
| **1.1** | Monat 7-9 | Hardware-Interfaces, C-API, Debian-Paket, Android |

---

# Version 1.0 — Core-Implementierung

---

## Versionen

| Version | Phase | Status |
|---------|-------|--------|
| 0.1.0 | Phase 1: Protokoll-Fundament | ✅ |
| **0.2.0** | Phase 2: Core API & Full Node | 🔶 Aktuell |
| 0.3.0 | Phase 3: Datenübertragung | ⬜ |
| 0.4.0 | Phase 4: CLI-Tools & Polish | ⬜ |
| **1.0.0** | Erstes stabiles Release | ⬜ |
| 1.1.0 | Phase 5-7: Hardware, C-API, Android | ⬜ |

---

## Aktueller Stand

Das Projekt hat Phase 1 vollständig abgeschlossen und Phase 2 ist zu ~90% fertig. Meilensteine 2.1 (Destination API), 2.2 (Link-Responder) und 2.3 (High-Level Link API inkl. Keepalive) sind abgeschlossen. Meilenstein 3.2 (Channel-System inkl. Buffer-System) ist ebenfalls fertig — StreamDataMessage für binäre Streams und RawChannelReader/Writer für gepufferte I/O sind implementiert. **Neu: High-Level Node API** (`NodeCore` in reticulum-core, `ReticulumNode` in reticulum-std) bietet eine einheitliche async-kompatible Schnittstelle mit Smart Routing, Connection-Abstraktion und symmetrischer Channel-API. Die Architektur wurde grundlegend umgebaut: alle Protokolllogik lebt in `reticulum-core` (no_std + alloc), plattformspezifische I/O in `reticulum-std` via Traits. Vollständige Interoperabilität mit Python rnsd ist nachgewiesen.

**Architektur-Migration abgeschlossen:** Die `Context`-Trait-Abstraktion für RNG, Clock und Storage ist vollständig. Alle `#[cfg(feature = "alloc")]` wurden entfernt — `alloc` ist immer verfügbar. Das `std` Feature aktiviert nur noch optimierte Crypto-Implementierungen.

**Ratchet & IFAC implementiert:** Forward Secrecy via Ratchets und Interface Access Codes sind vollständig implementiert und gegen Python Reticulum getestet.

**Code-Qualität:** LinkManager intern auf einheitliche Paket-Queue (`PendingPacket` Enum) umgestellt, Timeout-Konstanten zentralisiert, `LinkId` und `DestinationHash` als Newtype-Structs für vollständige Typ-Sicherheit (keine `Deref` mehr, kein `as_bytes_mut()`). 671 Tests bestehen (421 Core + 20 Std-Lib + 230 Interop).

| Komponente | Status | LOC |
|------------|--------|-----|
| Kryptographie (AES, SHA, HMAC, HKDF, Token) | ✅ Fertig | 1.030 |
| Identity-Management (Schlüsselpaare, Signaturen, Encrypt/Decrypt) | ✅ Fertig | 1.194 |
| Packet-Strukturen (alle Typen, Header 1/2) | ✅ Fertig | 411 |
| Announce (Erstellung, Validierung, Signaturprüfung) | ✅ Fertig | 681 |
| Destination (Hashing, Typen, Ratchets) | ✅ Fertig | 921 |
| Ratchet (Forward Secrecy) | ✅ Fertig | 419 |
| IFAC (Interface Access Codes) | ✅ Fertig | 378 |
| Link-State-Machine (Handshake, Proof, RTT, Data) | ✅ Initiator + Responder | 1.800 |
| Transport Layer (Routing, Pfade, Announces, Dedup) | ✅ Kern fertig | 1.227 |
| HDLC-Framing (no_std + alloc) | ✅ Fertig | 577 |
| Interface-Traits + TCP-Client | ✅ Fertig | 623 |
| Async Runtime (tokio-Wrapper) | ✅ Fertig | 224 |
| Reticulum-Instanz + Config + Storage | ✅ Fertig | 597 |
| FFI/C-API | ✅ Grundfunktionen | 361 |
| Tests (Rust + C) | | 11.737 |
| **Gesamt** | | **~24.300** |

**Crate-Aufteilung:**
| Crate | src LOC | test LOC |
|-------|---------|----------|
| reticulum-core | 11.442 | 1.319 |
| reticulum-std | 1.146 | 10.418 |
| reticulum-ffi | 361 | 404 |

**Test-Abdeckung:** 671 Tests (440 Core-Unit + 18 Proptest + 38 Test-Vektoren + 14 Doctests + 20 Std-Lib + 1 FFI + 140 Interop gegen rnsd)

**Architektur:** Siehe [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) — no_std/embedded-freundlich, Protocol in Core, I/O via Traits.

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
let announce_packet = dest.announce(Some(b"app-data"), &mut ctx)?;
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

### Meilenstein 2.5: Transport Layer Vervollständigung (Woche 15-16) 🔶

Bestehende Infrastruktur fertigstellen:

- [x] Pfad-Tabellenverwaltung (BTreeMap in core Transport)
- [x] Announce-Verarbeitung und Rebroadcast
- [ ] PATH_REQUEST/PATH_RESPONSE Handling
- [x] Paket-Weiterleitung (forward_packet)
- [x] Duplikaterkennung (packet_cache mit Expiry)
- [ ] Reverse-Path-Tracking (Datenstrukturen vorhanden, Logik unvollständig)
- [x] Rate Limiting (Announce-Rate-Limiting)
- [x] Link-Tabellenverwaltung
- [x] Announce-Tabellenverwaltung
- [x] Destination-Pfadtabellen

**Deliverable:** Vollständiges Routing für direkte und Multi-Hop-Verbindungen

---

## Phase 3: Datenübertragung (Monat 5)

### Ziel
Zuverlässiger Dateitransfer zwischen Rust und Python.

### Meilenstein 3.1: Resource Transfer (Woche 17-19)
- [ ] Resource-Segmentierung
- [ ] Advertisement-Protokoll
- [ ] Sliding-Window-Management (2-75 Pakete)
- [ ] Bandbreitenanpassung
- [ ] Kompression (bz2)
- [ ] Hashmap-Berechnung
- [ ] Fortschritts-Callbacks

**Deliverable:** Dateitransfer zwischen Rust und Python

### Meilenstein 3.2: Channels & Buffer (Woche 20) ✅
- [x] Channel-Abstraktion für zuverlässige Streams
- [x] Message Envelopes
- [x] StreamDataMessage (0xff00) für binäre Stream-Übertragung
- [x] Buffer-System (RawChannelReader, RawChannelWriter, BufferedChannelWriter)
- [x] BZ2-Kompression für Stream-Daten
- [ ] Request/Response-Pattern

**Deliverable:** ✅ Channel-System für zuverlässige Nachrichtenübertragung implementiert

---

## Phase 4: CLI-Tools & Polish (Monat 6)

### Ziel
Production-ready mit vollständigem Tooling.

### Meilenstein 4.1: CLI-Tools (Woche 21-23)
- [ ] `lrnsd` - Daemon (aufbauend auf 2.4)
- [ ] `lrnstatus` - Status-Anzeige
- [ ] `lrnpath` - Pfad-Lookup
- [ ] `lrnprobe` - Konnektivitätstest
- [ ] `lrncp` - Dateitransfer (benötigt Resource Transfer)
- [ ] `lrnid` - Identity-Management

**Deliverable:** Grundlegende CLI-Tools für den Betrieb

### Meilenstein 4.2: Zusätzliche Interfaces (Woche 24)
- [ ] UDP Interface
- [ ] LocalInterface (IPC)
- [ ] Serial Interface

**Deliverable:** Wichtigste Interface-Typen verfügbar

### Meilenstein 4.3: Qualitätssicherung (Woche 25-26)
- [x] Integration-Tests gegen rnsd-Daemon (140 Tests)
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

- [x] ~~Interface Access Control (IFAC)~~ ✅ Implementiert in 0.2.1
- [x] ~~Ratchet-Schlüsselverwaltung für Forward Secrecy~~ ✅ Implementiert
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
| Resource Transfer | Dateitransfer-Verifikation | - |

### Integration-Tests
```
Testumgebung:
┌─────────────┐      ┌─────────────┐
│   Python    │ TCP  │    Rust     │
│    rnsd     │◄────►│  leviculum│
└─────────────┘      └─────────────┘
```

Automatisierte Test-Suite (140 Interop-Tests gegen rnsd):
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
- Resource Transfer
- Error Recovery

---

## Aufwandsschätzung

| Phase | Geschätzte LOC | Komplexität |
|-------|---------------|-------------|
| Phase 1: Protokoll-Fundament | ~3.000 ✅ | Mittel |
| Phase 2: Core API & Full Node | ~2.500 | Hoch |
| Phase 3: Datenübertragung | ~2.000 | Mittel |
| Phase 4: CLI-Tools & Polish | ~2.500 | Mittel |
| **Gesamt neu** | **~10.000** | |
| **Gesamt (inkl. bestehend ~12.600)** | **~22.600** | |

---

## Risiken und Mitigationsstrategien (Version 1.0)

| Risiko | Wahrscheinlichkeit | Mitigation |
|--------|-------------------|------------|
| Transport Layer komplexer als erwartet | Mittel | 2 Wochen Puffer eingeplant |
| Interop-Probleme mit Python | Mittel | Frühe und kontinuierliche Tests |
| Performance-Probleme bei async | Niedrig | Profiling ab Phase 2 |
| no_std-Kompatibilitätsprobleme | ✅ Gelöst | Context-Trait-Abstraktion vollständig |

---

## Meilenstein-Übersicht

```
Monat 1    Monat 2    Monat 3       Monat 4       Monat 5    Monat 6
   │          │          │             │             │          │
   ▼          ▼          ▼             ▼             ▼          ▼
┌──────────────────┐┌─────────────────────────┐┌─────────┐┌──────────────────┐
│ Phase 1          ││ Phase 2                 ││ Phase 3 ││ Phase 4          │
│ Protokoll-       ││ Core API & Full Node    ││ Daten-  ││ CLI-Tools &      │
│ Fundament ✅     ││                         ││ transfer││ Polish           │
└──────────────────┘└─────────────────────────┘└─────────┘└──────────────────┘
        │                      │                    │              │
        ▼                      ▼                    ▼              ▼
   Link zu Python      Destination.announce()  Resource      Version 1.0
   funktioniert ✅     Link-Responder          Transfer      Release
                       High-Level Link API
                       lrnsd Daemon
```

### Prioritäten Phase 2 (kritischer Pfad)

```
┌─────────────────────┐
│ 2.1 Destination API │ ✅ FERTIG
│     announce()      │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 2.2 Link-Responder  │ ✅ FERTIG
│     accept links    │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 2.3 High-Level Link │ ✅ FERTIG (inkl. Keepalive + Stale + Close)
│     LinkManager API │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 2.4 TCP Server      │ ⬜ Offen - Daemon kann Verbindungen annehmen.
│     lrnsd Basis     │
└─────────────────────┘
```

---

## Definition of Done für Version 1.0

**Must-Have (MVP):**
- [x] `Destination::announce()` API funktioniert
- [x] Link-Responder: eingehende Links akzeptieren
- [x] High-Level Link API: `LinkManager` mit `initiate()`, `send()`, `close()`
- [ ] Resource Transfer: Dateien übertragen
- [ ] `lrnsd` Daemon läuft standalone
- [ ] TCP Client + Server Interfaces
- [x] Integration-Tests gegen Python rnsd bestehen (140 Interop-Tests)
- [x] no_std-Kompatibilität für reticulum-core (Context-Trait)
- [x] Forward Secrecy via Ratchets
- [x] Interface Access Codes (IFAC)

**Should-Have:**
- [ ] CLI-Tools: lrnstatus, lrnpath, lrnprobe, lrncp, lrnid
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
  - `/usr/bin/lrnsd`
  - `/usr/bin/lrnstatus`
  - `/usr/bin/lrnpath`
  - `/usr/bin/lrnprobe`
  - `/usr/bin/lrncp`
  - `/usr/bin/lrnid`
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
Monat 1-2      Monat 3-4      Monat 5      Monat 6        Monat 7        Monat 8        Monat 9
    │              │             │            │              │              │              │
    ▼              ▼             ▼            ▼              ▼              ▼              ▼
┌────────────┐┌────────────┐┌────────┐┌────────────┐  ┌────────────┐┌────────────┐┌────────────┐
│  Phase 1   ││  Phase 2   ││Phase 3 ││  Phase 4   │  │  Phase 5   ││  Phase 6   ││  Phase 7   │
│  Protokoll ││  Netzwerk  ││Features││  Tools     │  │  Hardware  ││  C-API &   ││  Android   │
│            ││            ││        ││  & QA      │  │  Interfaces││  Debian    ││            │
└────────────┘└────────────┘└────────┘└────────────┘  └────────────┘└────────────┘└────────────┘
      │              │            │           │              │              │              │
      ▼              ▼            ▼           ▼              ▼              ▼              ▼
   Link zu       Multi-Hop    Datei-    Version 1.0     RNode/LoRa     Debian-       Version 1.1
   Python        Routing      transfer   Release        I2P, AX.25     Paket         Release

├──────────────────────────────────────────────────┤  ├────────────────────────────────────────┤
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

*Stand: 3. Februar 2026*
*Projekt: leviculum*
*Lizenz: MIT*
