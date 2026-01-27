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

## Aktueller Stand

Das Projekt hat eine solide Grundlage mit funktionierenden kryptographischen Primitiven, validierter Interoperabilität mit Python Reticulum, und einer sauberen Architektur:

| Komponente | Status | LOC |
|------------|--------|-----|
| Kryptographie (AES, SHA, HMAC, HKDF, Token) | ✅ Fertig | ~1.500 |
| Identity-Management (Schlüsselpaare, Signaturen, Encrypt/Decrypt) | ✅ Fertig | ~800 |
| Packet-Strukturen (alle Typen, Header 1/2) | ✅ Fertig | ~600 |
| Link-State-Machine (Handshake, Proof, RTT, Data) | ✅ Initiator-Seite fertig | ~900 |
| Destination | 🔶 Teilweise | ~200 |
| Announce (Erstellung, Validierung) | 🔶 In Tests | ~300 |
| Transport Layer | 🔶 Design fertig | - |
| Interfaces (HDLC, Traits) | 🔶 Traits + HDLC | ~500 |
| FFI/C-API | ✅ Grundfunktionen | ~400 |
| CLI-Tools | 🔶 Struktur | ~200 |
| **Gesamt** | | **~5.400** |

**Test-Abdeckung:** 210 Unit-Tests + 13 C-Tests (alle bestehend), Integration-Tests gegen rnsd

**Architektur:** Siehe [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) für die neue no_std/embedded-freundliche Architektur.

---

## Phase 1: Protokoll-Fundament (Monat 1-2)

### Ziel
Vollständige Interoperabilität auf Paket-Ebene mit der Python-Referenzimplementierung.

### Meilenstein 1.1: Krypto-Validierung (Woche 1-2)
- [ ] Vollständige Test-Vektoren aus Python generieren
- [ ] Identity-Verschlüsselung mit ephemeren Schlüsseln
- [ ] Ratchet-Schlüsselverwaltung für Forward Secrecy
- [ ] Cross-Implementation-Tests: Rust verschlüsselt ↔ Python entschlüsselt

**Deliverable:** 100% kompatible Kryptographie mit Python Reticulum

### Meilenstein 1.2: Paket-Serialisierung (Woche 3-4)
- [ ] Packet pack/unpack für alle Pakettypen (DATA, ANNOUNCE, LINKREQUEST, PROOF)
- [ ] Alle Kontexttypen (RESOURCE, RESOURCE_ADV, CACHE_REQUEST, etc.)
- [ ] Header-Formate (HEADER_1, HEADER_2 für Transport)
- [ ] Paket-Hash-Berechnung

**Deliverable:** Rust kann Pakete von Python parsen und umgekehrt

### Meilenstein 1.3: Identity & Destination (Woche 5-6)
- [ ] Identity-Serialisierung (Speichern/Laden)
- [ ] Destination-Hash-Berechnung
- [ ] Destination-Typen (SINGLE, GROUP, PLAIN, LINK)
- [ ] Announce-Pakete erstellen und validieren
- [ ] Proof-Strategien (PROVE_NONE, PROVE_APP, PROVE_ALL)

**Deliverable:** Announcements funktionieren bidirektional

### Meilenstein 1.4: Link-Establishment (Woche 7-8)
- [x] 3-Paket-Handshake implementieren (Initiator-Seite):
  - Link Request (ephemere X25519-Pubkey)
  - Link Proof Verifikation (signierte Challenge)
  - RTT-Paket (finalisiert Link auf Gegenseite)
- [x] ECDH-Schlüsselaustausch für Link-Keys
- [x] Link-Verschlüsselung/Entschlüsselung (AES-256-CBC + Fernet-kompatibel)
- [x] Link-State-Machine (Initiator): Pending → Handshake → Active
- [x] Bidirektionale verschlüsselte Datenkommunikation mit Python rnsd
- [ ] Link-Responder-Seite (eingehende Links akzeptieren)
- [ ] Keepalive-Mechanismus
- [ ] Link-Teardown (ordnungsgemäßes Schließen)

**Deliverable:** ✅ Rust kann Link zu Python rnsd aufbauen und verschlüsselt kommunizieren

---

## Phase 2: Netzwerk-Infrastruktur (Monat 3-4)

### Ziel
Funktionale Netzwerkkommunikation über verschiedene Interfaces.

### Meilenstein 2.1: Basis-Interfaces (Woche 9-10)
- [ ] Interface-Trait vollständig implementiert
- [ ] TCP Client/Server Interface
- [ ] UDP Interface
- [ ] LocalInterface (IPC)
- [ ] Interface Access Control (IFAC)

**Deliverable:** Verbindung zu Python rnsd über TCP möglich

### Meilenstein 2.2: Transport Layer - Kern (Woche 11-13)
- [ ] Pfad-Tabellenverwaltung
- [ ] Announce-Verarbeitung und Rebroadcast
- [ ] PATH_REQUEST/PATH_RESPONSE Handling
- [ ] Paket-Weiterleitung
- [ ] Duplikaterkennung
- [ ] Reverse-Path-Tracking
- [ ] Rate Limiting

**Deliverable:** Pakete werden korrekt durch das Netzwerk geroutet

### Meilenstein 2.3: Transport Layer - Erweitert (Woche 14-16)
- [ ] Link-Tabellenverwaltung
- [ ] Announce-Tabellenverwaltung
- [ ] Destination-Pfadtabellen
- [ ] Interface-Aktivitätskoordination
- [ ] Erreichbarkeitstracking
- [ ] Roaming-Modus

**Deliverable:** Vollständiger Transport Layer, Multi-Hop-Routing funktioniert

---

## Phase 3: Erweiterte Features (Monat 5)

### Ziel
Vollständige Feature-Parität für Datenübertragung.

### Meilenstein 3.1: Resource Transfer (Woche 17-18)
- [ ] Resource-Segmentierung
- [ ] Advertisement-Protokoll
- [ ] Sliding-Window-Management (2-75 Pakete)
- [ ] Bandbreitenanpassung
- [ ] Kompression (bz2)
- [ ] Hashmap-Berechnung
- [ ] Fortschritts-Callbacks

**Deliverable:** Dateitransfer zwischen Rust und Python

### Meilenstein 3.2: Channels & Buffer (Woche 19-20)
- [ ] Channel-Abstraktion für zuverlässige Streams
- [ ] Message Envelopes
- [ ] Stream Data Messages
- [ ] BufferedReader/BufferedWriter
- [ ] Request/Response-Pattern

**Deliverable:** Vollständige Kommunikationsmuster verfügbar

---

## Phase 4: Interfaces & Tools (Monat 6)

### Ziel
Production-ready mit vollständigem Tooling.

### Meilenstein 4.1: Erweiterte Interfaces (Woche 21-22)
- [ ] Serial Interface
- [ ] KISS Interface (TNC-Protokoll)
- [ ] AutoInterface (lokale Netzwerk-Autodiscovery)
- [ ] Pipe Interface

**Deliverable:** Wichtigste Interface-Typen verfügbar

### Meilenstein 4.2: CLI-Tools (Woche 23-24)
- [ ] `lrnsd` - Daemon
- [ ] `lrnstatus` - Status-Anzeige
- [ ] `lrnpath` - Pfad-Lookup
- [ ] `lrnprobe` - Konnektivitätstest
- [ ] `lrncp` - Dateitransfer
- [ ] `lrnid` - Identity-Management

**Deliverable:** Grundlegende CLI-Tools für den Betrieb

### Meilenstein 4.3: Qualitätssicherung (Woche 25-26)
- [ ] Integration-Tests gegen rnsd-Daemon
- [ ] Performance-Optimierung
- [ ] Speicher-Profiling mit Valgrind
- [ ] Fuzzing der Paket-Parser
- [ ] Dokumentation vervollständigen
- [ ] CI/CD-Pipeline mit no_std-Checks

**Deliverable:** Version 1.0 Release

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
| Link-Establishment | Live-Tests gegen rnsd | ✅ |
| Announce-Propagation | Multi-Node-Setup | 🔶 |
| Resource Transfer | Dateitransfer-Verifikation | - |

### Integration-Tests
```
Testumgebung:
┌─────────────┐      ┌─────────────┐
│   Python    │ TCP  │    Rust     │
│    rnsd     │◄────►│  leviculum│
└─────────────┘      └─────────────┘
```

Automatisierte Test-Suite:
- ✅ Link-Establishment (mit Python-Destination getestet)
- ✅ Bidirektionale verschlüsselte Datenpakete
- Announce-Validierung
- Resource Transfer
- Error Recovery

---

## Aufwandsschätzung

| Phase | Geschätzte LOC | Komplexität |
|-------|---------------|-------------|
| Phase 1: Protokoll-Fundament | ~3.000 | Mittel |
| Phase 2: Netzwerk-Infrastruktur | ~4.500 | Hoch |
| Phase 3: Erweiterte Features | ~2.500 | Mittel |
| Phase 4: Interfaces & Tools | ~3.000 | Mittel |
| **Gesamt neu** | **~13.000** | |
| **Gesamt (inkl. bestehend)** | **~18.000** | |

---

## Risiken und Mitigationsstrategien (Version 1.0)

| Risiko | Wahrscheinlichkeit | Mitigation |
|--------|-------------------|------------|
| Transport Layer komplexer als erwartet | Mittel | 2 Wochen Puffer eingeplant |
| Interop-Probleme mit Python | Mittel | Frühe und kontinuierliche Tests |
| Performance-Probleme bei async | Niedrig | Profiling ab Phase 2 |
| no_std-Kompatibilitätsprobleme | Niedrig | CI-Checks, regelmäßige Builds |

---

## Meilenstein-Übersicht

```
Monat 1    Monat 2    Monat 3    Monat 4    Monat 5    Monat 6
   │          │          │          │          │          │
   ▼          ▼          ▼          ▼          ▼          ▼
┌──────────────────┐┌──────────────────┐┌─────────┐┌──────────────────┐
│ Phase 1          ││ Phase 2          ││ Phase 3 ││ Phase 4          │
│ Protokoll-       ││ Netzwerk-        ││ Features││ Tools & QA       │
│ Fundament        ││ Infrastruktur    ││         ││                  │
└──────────────────┘└──────────────────┘└─────────┘└──────────────────┘
        │                    │               │              │
        ▼                    ▼               ▼              ▼
   Link zu Python      Multi-Hop        Dateitransfer   Version 1.0
   funktioniert        Routing          funktioniert    Release
```

---

## Definition of Done für Version 1.0

- [ ] Alle Core-Features der Python-Referenz implementiert
- [ ] TCP, UDP, Local, Serial, KISS, Auto Interfaces
- [ ] Grundlegende CLI-Tools (daemon, status, path, probe, cp, id)
- [ ] Unit-Test-Abdeckung > 80%
- [ ] Integration-Tests gegen Python rnsd bestehen
- [ ] Dokumentation vollständig
- [ ] no_std-Kompatibilität für reticulum-core gewährleistet
- [ ] Keine bekannten Speicherlecks (Valgrind-geprüft)
- [ ] Performance vergleichbar mit Python-Implementierung

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

*Stand: 25. Januar 2026*
*Projekt: leviculum*
*Lizenz: MIT*
