# Leviculum Roadmap

**Projektziel:** Vollständige Rust-Implementierung des Reticulum Network Stack
**Referenz:** Python-Implementierung (`vendor/Reticulum/`)

| Version | Fokus |
|---------|-------|
| **1.0** | Core-Protokoll, Sicherheit (IFAC + Ratchet), Basis-Interfaces, Daemon |
| **1.1** | Resource Transfer, Hardware-Interfaces, C-API, Paketierung |

---

# Version 1.0 — Core-Implementierung

---

## Versionen

| Version | Phase | Status |
|---------|-------|--------|
| 0.1.0 | Phase 1: Protokoll-Fundament | ✅ |
| 0.2.0 | Phase 2: Core API & Full Node | ✅ |
| **0.5.19** | Aktuelle Version (Refactoring Phasen 0–7 abgeschlossen) | 🔶 Aktuell |
| 0.6.0 | Phase 3: Sicherheit, Persistenz & Release-Vorbereitung | ⬜ |
| **1.0.0** | Erstes stabiles Release | ⬜ |

---

## Aktueller Stand

**Aktuelle Version: 0.5.19.** Phase 1 (Protokoll-Fundament) und Phase 2 (Core API & Full Node) sind vollständig abgeschlossen, inklusive eines 7-phasigen Code-Refactorings (63 Issues in `doc/BATTLEPLAN.md`). Storage-Trait-Refactoring abgeschlossen: alle 11 Transport/NodeCore-Sammlungen auf typsicheren Storage-Trait migriert, FileStorage umschließt MemoryStorage mit Python-kompatibler Persistenz. UDP-Interface implementiert (Socket, I/O-Task, Config-Parsing, Interop-Tests). AutoInterface mit 7 Integrationstests und Cross-Machine-Interop-Test abgedeckt: In-Process-Tests für Discovery, Announce, Link+Daten, MTU, Peer-Timeout, 3-Node-Mesh, Gruppen-Isolation; Cross-Machine-Test (`scripts/test-auto-crossmachine.fish`) validiert Rust↔Python über echtes LAN (hamster↔schneckenschreck VM). Zwei-Tier Peer-Lookup (exact match, dann IP-only Fallback) für Python-Interop. `lrnsd` respektiert jetzt `RUST_LOG`-Umgebungsvariable. Offene Issues: E10 (Interface-spezifischer Jitter für Shared-Medium-Interfaces).

**Kernfunktionalität:** `NodeCore` (reticulum-core) und `ReticulumNode` (reticulum-std) bieten eine einheitliche async-kompatible API für Destinations, Links, Channels, Single-Packet-Verschlüsselung und Proof-Delivery. Vollständige Interoperabilität mit Python rnsd ist durch umfangreiche Interop-Tests nachgewiesen.

**CLI-Tool `lrns`** mit Subcommands: `status`, `path`, `identity`, `probe`, `interfaces`, `connect`, `selftest`. Davon voll implementiert: `identity`, `connect`, `selftest` (Zwei-Adress-Modus für Multi-Daemon-Topologien). Die anderen sind Gerüste.

**Daemon `lrnsd`** läuft als Drop-in-Ersatz für `rnsd` mit TCP-Server/Client-Support, TCP-Reconnection, Config-Loading und sauberem Shutdown.

**Sans-I/O-Architektur:** `reticulum-core` ist ein reiner Zustandsautomat — keine I/O, kein Jitter, keine künstlichen Verzögerungen. Der Core verarbeitet und leitet Pakete sofort weiter. Kollisionsvermeidung und Send-Timing liegen in der Verantwortung der Interface-Implementierung (siehe `doc/ARCHITECTURE.md`, Abschnitt "Zero-delay core"). `reticulum-nrf` ist ein Embassy-basiertes Firmware-Crate für den Heltec Mesh Node T114 (nRF52840 + SX1262).

**Transport Layer vollständig:** Announce-Rebroadcast (sofort, ohne Jitter), PATH_REQUEST/PATH_RESPONSE, Reverse-Path-Routing, Link-Tabellenverwaltung, Hop-Count-Validation, LRPROOF-Validierung, Path Recovery, Announce Rate Limiting, Per-Interface Announce-Bandbreitenbegrenzung. Multi-Hop-Relay funktioniert vollständig, inklusive gemischter Rust+Python-Ketten.

**Single-Packet-Verschlüsselung:** `send_single_packet()` verschlüsselt automatisch mit der Remote-Identity aus `known_identities`. Proof-Delivery-Chain vollständig (PROVE_ALL, PROVE_APP, PROVE_NONE).

| Komponente | Status |
|------------|--------|
| Kryptographie (AES, SHA, HMAC, HKDF, Token) | ✅ Fertig |
| Identity-Management (Schlüsselpaare, Signaturen, Encrypt/Decrypt) | ✅ Fertig |
| Packet-Strukturen (alle Typen, Header 1/2) | ✅ Fertig |
| Announce (Erstellung, Validierung, Signaturprüfung) | ✅ Fertig |
| Destination (Hashing, Typen, Ratchets, Encrypt/Decrypt) | ✅ Fertig |
| Receipt (Delivery-Tracking, Proof-Validierung) | ✅ Fertig |
| Ratchet (Forward Secrecy) | ⚠️ Krypto fertig, Validierung nicht eingebunden |
| IFAC (Interface Access Codes) | ⚠️ Modul fertig, nicht in Empfangspfad eingebunden |
| Link-State-Machine (Handshake, Proof, RTT, Data) | ✅ Initiator + Responder |
| Channel/Buffer (Reliable Messaging, Streams) | ✅ Fertig |
| Node (High-Level API, Builder, Events, LinkManagement) | ✅ Fertig |
| Transport Layer (Routing, Pfade, Announces, Relay) | ✅ Fertig |
| HDLC-Framing (no_std + alloc) | ✅ Fertig |
| Storage-Trait (typsicher, ~44 Methoden, 3 Implementierungen) | ✅ Fertig |
| reticulum-std (Driver, TCP, Storage) | ✅ Fertig |
| reticulum-ffi (C-API) | ✅ Grundfunktionen |
| reticulum-cli (lrns, lrnsd) | 🔶 Teilweise |

**Architektur:** Siehe [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) — no_std/embedded-freundlich, sans-I/O Core (reine Zustandsmaschine), I/O via Action-Rückgabewerte an den Treiber.

---

## Phase 1: Protokoll-Fundament ✅

### Ziel
Vollständige Interoperabilität auf Paket-Ebene mit der Python-Referenzimplementierung.

### Meilenstein 1.1: Krypto-Validierung ✅
- [x] Vollständige Test-Vektoren aus Python generieren
- [x] Identity-Verschlüsselung mit ephemeren Schlüsseln
- [x] Ratchet-Schlüsselverwaltung für Forward Secrecy
- [x] Cross-Implementation-Tests: Rust verschlüsselt ↔ Python entschlüsselt
- [x] Property-Based Testing mit proptest

### Meilenstein 1.2: Paket-Serialisierung ✅
- [x] Packet pack/unpack für alle Pakettypen (DATA, ANNOUNCE, LINKREQUEST, PROOF)
- [x] Alle Kontexttypen (RESOURCE, RESOURCE_ADV, CACHE_REQUEST, etc.)
- [x] Header-Formate (HEADER_1, HEADER_2 für Transport)
- [x] Paket-Hash-Berechnung

### Meilenstein 1.3: Identity & Destination ✅
- [x] Identity-Serialisierung (Speichern/Laden)
- [x] Destination-Hash-Berechnung
- [x] Destination-Typen (SINGLE, GROUP, PLAIN, LINK)
- [x] Announce-Pakete erstellen und validieren
- [x] Proof-Strategien (PROVE_NONE, PROVE_APP, PROVE_ALL)

### Meilenstein 1.4: Link-Establishment ✅
- [x] 3-Paket-Handshake (Initiator + Responder)
- [x] ECDH-Schlüsselaustausch für Link-Keys
- [x] Link-Verschlüsselung/Entschlüsselung (AES-256-CBC + Fernet-kompatibel)
- [x] Link-State-Machine: Pending → Handshake → Active
- [x] Bidirektionale verschlüsselte Datenkommunikation mit Python rnsd
- [x] Keepalive-Mechanismus und Link-Teardown

---

## Phase 2: Core API & Full Node ✅

### Ziel
Vollständige API für Destinations und Links. Leviculum kann sowohl Client als auch Server sein.

### Meilenstein 2.1: Destination API ✅
- [x] `Destination::announce()` → erstellt signiertes Announce-Paket
- [x] `generate_random_hash()` (5 random + 5 timestamp bytes)
- [x] Hash-Berechnungsmethoden öffentlich

### Meilenstein 2.2: Link-Responder ✅
- [x] Link-Request-Verarbeitung in Transport
- [x] Proof-Generierung (signierte Challenge)
- [x] Incoming Link → Event an Destination

### Meilenstein 2.3: High-Level Link API ✅
- [x] `initiate()` / `send()` / `close()` API
- [x] Keepalive (Initiator 0xFF, Responder Echo 0xFE, RTT-basiert)
- [x] Link-Stale-Erkennung und automatisches Schließen

### Meilenstein 2.4: TCP Server & Daemon ✅
- [x] TCP Server Interface (`spawn_tcp_server()`)
- [x] TCP Client Reconnection (`spawn_tcp_client_with_reconnect()`)
- [x] `lrnsd` Daemon (Config-Loading, Interfaces, Graceful Shutdown, Log-Levels)
- [x] Transport-Tracing (`tracing::trace!` in Hot-Path-Funktionen)

### Meilenstein 2.5: Transport Layer ✅
- [x] Announce-Rebroadcast (sofort, ohne Jitter — Core ist zero-delay)
- [x] PATH_REQUEST/PATH_RESPONSE Handling
- [x] Paket-Weiterleitung mit Duplikaterkennung
- [x] Reverse-Path-Tracking (Proof-Routing)
- [x] Rate Limiting und Per-Interface Announce-Bandbreitenbegrenzung
- [x] LRPROOF-Validierung (Ed25519-Signaturprüfung)
- [x] 32-Byte Path Requests für Non-Transport-Nodes
- [x] Multi-Hop Link von Non-Transport Nodes

Kleinere Lücken (nicht blockierend für v1.0): Announce-Expiry-Timer, mehrere Pfade pro Destination. MTU-Signaling für Link-MDU-Verhandlung ist implementiert (Link-Requests enthalten immer 3 Signaling-Bytes; Responder echot die MTU zurück; `Link::mdu()` berechnet den verschlüsselten MDU aus der verhandelten MTU; Responder-seitiges Clamping auf Interface-HW_MTU). Announce-Bandbreitenbegrenzung ist implementiert, aber für TCP-Interfaces inaktiv (bitrate=0); wird für zukünftige LoRa/Serial-Interfaces aktiviert (siehe E10 in `doc/OPEN_ISSUES_TRACKER.md`).

### Bekannte Bugs und Lücken

#### Bugs (alle behoben)

| ID | Beschreibung | Status |
|----|-------------|--------|
| C8 | Link-adressierte Data-Pakete auf Non-Transport-Nodes verworfen | ✅ Behoben (v0.5.5) |
| C9 | `Channel::mark_delivered()` nie aufgerufen in Produktion | ✅ Behoben (v0.5.5) |
| D11 | `handle_interface_down()` räumt jetzt Pfade, Links und Reverse-Tabelle auf | ✅ Behoben |
| D13 | `close_link()` entfernt Links korrekt aus der BTreeMap | ✅ Behoben |

#### Fehlende Integrationen (v1.0-Blocker)

| ID | Beschreibung | Status |
|----|-------------|--------|
| B3 | IFAC-Modul existiert, nicht in Paketempfangspfad eingebunden | ⚠️ Modul fertig |
| B4 | Ratchet-Krypto funktioniert, Validierung bei Announces/Links nicht aktiv | ⚠️ Krypto fertig |
| C10 | Buffer/Stream-System existiert, nicht in LinkHandle integriert | ⚠️ Code fertig |

#### Fehlende Features

| ID | Beschreibung | Status |
|----|-------------|--------|
| A2 | TCP-Client-Reconnection | ✅ Behoben |
| E9 | Persistente Speicherung für known_identities und path_table | ✅ Behoben |
| E10 | Interface-spezifischer Send-Side-Jitter für Shared-Medium-Interfaces | ⬜ Offen (v1.1, für LoRa/Serial) |

---

## Phase 3: Sicherheit, Persistenz & Release-Vorbereitung

### Ziel
Sicherheitsfeatures verdrahten, Daemon-Zustand persistieren, Release-Qualität erreichen.

### Meilenstein 3.1: Persistente Speicherung (E9) ✅
- [x] `known_identities` über Storage-Trait persistieren (laden bei Start, speichern bei flush)
- [x] `packet_hashlist` über Storage-Trait persistieren (laden bei Start, speichern bei flush)
- [x] Alle 11 Transport/NodeCore-Sammlungen auf typsicheren Storage-Trait migriert
- [x] FileStorage umschließt MemoryStorage + Python-kompatible Persistenz
- [ ] Interop-Test: Rust-Node neustarten, zuvor bekannte Destinations ohne Re-Announce erreichbar

### Meilenstein 3.2: IFAC-Integration (B3)
- [ ] IFAC in den Paketempfangspfad einbinden (Validierung eingehender Pakete)
- [ ] IFAC in den Sendevorgang einbinden (Tags an ausgehende Pakete)
- [ ] Config-Option für IFAC pro Interface
- [ ] Interop-Test: IFAC-gesicherte Kommunikation zwischen Rust und Python

### Meilenstein 3.3: Ratchet-Validierung (B4)
- [ ] Ratchet-Validierung bei Announce-Empfang aktivieren
- [ ] Ratchet-Austausch bei Link-Establishment aktivieren
- [ ] Forward-Secrecy-Rotation im laufenden Betrieb
- [ ] Interop-Test: Ratchet-geschützte Announces zwischen Rust und Python

### Meilenstein 3.4: UDP Interface ✅
- [x] UDP-Interface implementieren (reticulum-std)
- [x] Config-Option für UDP-Interfaces in `lrnsd`
- [x] Interop-Test: Rust ↔ Python über UDP

### Meilenstein 3.5: Buffer/Stream-Integration (C10)
- [ ] Buffer/Stream-Layer in LinkHandle integrieren
- [ ] Kompression (BZ2) über Links nutzbar
- [ ] Interop-Test: Stream-Daten zwischen Rust und Python

### `lrns` CLI
- [ ] `lrns status` — Status-Anzeige
- [ ] `lrns path` — Pfad-Lookup
- [ ] `lrns probe` — Konnektivitätstest
- [x] `lrns identity` — Identity-Management ✅
- [x] `lrns connect` — Interaktive Session ✅
- [x] `lrns selftest` — Zwei-Adress-Modus für Multi-Daemon-Topologien ✅
- [ ] `lrns interfaces` — Interface-Übersicht
- [x] `lrnsd` — Daemon ✅

### Qualitätssicherung
- [x] Interop-Tests gegen rnsd-Daemon ✅
- [ ] Fuzzing der Paket-Parser
- [ ] Dokumentation vervollständigen
- [x] CI/CD-Pipeline mit no_std-Checks ✅
- [x] Logging-Qualität: 156 tracing-Aufrufe, alle unhappy paths geloggt ✅

### Kritischer Pfad bis v1.0

```
┌─────────────────────┐
│ 3.1 Persistenz (E9) │ ✅ — Storage-Trait-Refactoring abgeschlossen
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 3.2 IFAC (B3)       │ ⬜ — Interface-Authentifizierung
│ 3.3 Ratchet (B4)    │ ⬜ — Forward Secrecy
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ 3.4 UDP Interface    │ ✅ — Implementiert mit Interop-Tests
│ 3.5 Buffer (C10)     │ ⬜ — Stream-API vervollständigen
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│ Release QA           │ ⬜ — Fuzzing, Docs, CLI-Subcommands
│ Version 1.0          │
└─────────────────────┘
```

### Definition of Done für Version 1.0

**Must-Have:**
- [x] `Destination::announce()` API funktioniert
- [x] Link-Responder: eingehende Links akzeptieren
- [x] High-Level Link API: `initiate()`, `send()`, `close()`
- [x] Transport Layer: Routing, Announce-Relay, Multi-Hop
- [x] Channel-System: Reliable Messaging
- [x] TCP Server + Client Interface (mit Reconnection)
- [x] `lrnsd` Daemon läuft standalone
- [x] Interop-Tests gegen Python rnsd bestehen
- [x] no_std-Kompatibilität für reticulum-core
- [ ] Forward Secrecy via Ratchets (B4)
- [ ] Interface Access Codes / IFAC (B3)
- [x] Persistente Speicherung (E9)
- [x] UDP Interface

**Should-Have:**
- [ ] `lrns` CLI: status, path, probe, interfaces
- [ ] Buffer/Stream-Integration in LinkHandle (C10)
- [ ] Fuzzing der Paket-Parser
- [ ] Dokumentation vollständig

---

## Test-Strategie

### Unit Tests
- Jedes Modul mit hoher Abdeckung
- Alle Edge Cases und Fehlerbedingungen
- Property-Based Testing mit proptest

### Interoperabilitäts-Tests

| Test-Kategorie | Status |
|----------------|--------|
| Kryptographie (Test-Vektoren aus Python) | ✅ |
| Paket-Format (Roundtrip-Tests) | ✅ |
| HDLC-Framing (Byte-genaue Verifikation) | ✅ |
| Announce-Validierung (Signaturprüfung gegen rnsd) | ✅ |
| Announce-Propagation (Multi-Client) | ✅ |
| Link-Establishment (Live-Tests gegen rnsd) | ✅ |
| Transport-Integration (TCP + Transport + Events) | ✅ |
| Transport Relay (Announce-Rebroadcast, Link-Routing) | ✅ |
| Multi-Hop (Multi-Hop-Topologie und Routing) | ✅ |
| Channel/Buffer (Stream + gepuffertes I/O) | ✅ |
| Full Link Lifecycle (Bidirektionale Daten, ACKs, Close durch Relay) | ✅ |
| Responder Node (Rust als Connection-Responder) | ✅ |
| Flood/Loop-Prevention (Triangle, Diamond, redundante Pfade) | ✅ |
| UDP Interop (Announce, Link, Daten, MTU-Verhandlung, Python-Baseline) | ✅ |
| MTU Negotiation (TCP, UDP, Relay-Clamping, Boundary, Bidirektional) | ✅ |
| AutoInterface (Discovery, Announce, Link, Daten, MTU, Peer-Timeout, Mesh, Isolation) | ✅ |
| AutoInterface Cross-Machine (Rust@schneckenschreck ↔ Python@hamster, 4 Phasen + RUST_LOG + Datenempfang) | ✅ |
| Shared Instance (LocalInterface Unix Socket IPC, HDLC-Framing, Announce Rx+Tx) | ✅ |
| Resource Transfer | ⬜ (v1.1) |

### Testumgebung
```
┌─────────────┐      ┌─────────────┐
│   Python    │ TCP  │    Rust     │
│    rnsd     │◄────►│  leviculum│
└─────────────┘      └─────────────┘
```

---

# Version 1.1 — Datenübertragung & Plattform-Integration

---

## Resource Transfer
- Resource-Segmentierung und Advertisement-Protokoll
- Sliding-Window-Management
- Bandbreitenanpassung und Kompression (bz2)
- Hashmap-Berechnung und Fortschritts-Callbacks
- Request/Response-Pattern
- `lrns cp` — Dateitransfer über CLI
- Interop-Tests: Dateitransfer zwischen Rust und Python

## IPC (Shared Instance)
- ✅ LocalInterface: Unix-Domain-Socket-basierte IPC-Kommunikation zwischen `lrnsd` und Client-Programmen (wie Python's `LocalClientInterface` / `LocalServerInterface`) — Abstract Unix Socket (`\0rns/{instance_name}`), HDLC-Framing, `spawn_local_server()`, Config-Integration (`share_instance`/`instance_name`), 2 Python-Interop-Tests
- ✅ Routing-Gates für Local-Client-Bedingungen: `handle_link_request()`, `handle_proof()`, `handle_data()` routen Pakete für/von Local-Client-Interfaces auch ohne `enable_transport`, matching Python Transport.py:1378-1404. 5 Unit-Tests mit `enable_transport=false`
- [ ] Mehrere Programme teilen sich eine Reticulum-Instanz über den laufenden Daemon (End-to-End-Validierung)
- [ ] `is_connected_to_shared_instance`-Semantik (Python-Äquivalent) für lokale Transport-Entscheidungen

## Hardware-Interfaces
- RNode/LoRa Interface (KISS-Protokoll, LoRa-Parameter, Radio-State, Airtime-Limiting)
- Interface-spezifischer Send-Side-Jitter für Shared-Medium-Interfaces (E10)
- Serial Interface
- KISS Interface (TNC-Protokoll)
- ✅ AutoInterface (lokale Netzwerk-Autodiscovery) — IPv6-Multicast-Discovery, dynamisches Peer-Management, ephemere Data-Ports für Same-Machine-Testing, SocketAddrV6-basierte Peer-Identität, 7 Integrationstests, Linux

## C-API & Paketierung
- `leviculum-ffi` erweitern (Reticulum-Instanz, Destinations, Links, Packets, Resources, Path Discovery)
- pkg-config Integration und Header-Generierung (cbindgen)
- Debian-Pakete (leviculum0, -dev, -tools) mit systemd-Unit für lrnsd

## Android-Integration
- UniFFI-basierte Kotlin-Bindings
- AAR-Paket mit Cross-Compilation (arm64-v8a, armeabi-v7a, x86_64)
- Maven Central Publikation

## Weitere Features (v1.1+)
- I2P Interface (SAM v3-Protokoll)
- AX.25 KISS Interface (Amateurfunk)
- Roaming-Modus und Erreichbarkeitstracking
- Pipe Interface
- Performance-Optimierung und Speicher-Profiling

## Nicht im Scope
- `rnodeconf` — RNode-Konfigurationstool
- `rnx` — Remote Command Execution
- iOS/Swift-Integration
- WebAssembly-Build
- Tunneling und Remote Management

---

*Stand: 23. Februar 2026*
*Projekt: leviculum*
*Lizenz: MIT*
