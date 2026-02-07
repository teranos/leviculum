# leviculum – Device-Roadmap

Stand: 2026-02-07

## Architektur-Überblick

Der Aufwand pro Device skaliert an drei Achsen:

1. **MCU-Plattform** (HAL-Crate, Toolchain, Async-Runtime) — teuerste Achse
2. **LoRa-Chip** (RadioKind-Implementierung in lora-phy oder eigener Treiber) — mittlerer Aufwand
3. **Board-Variante** (Pin-Mapping, Display, GPS, PMIC) — billigste Achse, ~50-100 Zeilen Config

Jede neue MCU-Plattform ist ein eigenes Platform-Crate. Jeder neue LoRa-Chip braucht einen Treiber. Jedes neue Board innerhalb einer bestehenden MCU+Chip-Kombi ist nur ein Config-Struct.

### Relevante Rust-Crates

| Komponente | Crate | Status |
|---|---|---|
| ESP32/S3/C3/C6 HAL | `esp-hal` (1.0.0-beta) | Production-ready, Espressif-backed |
| nRF52840 HAL | `embassy-nrf` | Stable, released on crates.io |
| RP2040/RP2350 HAL | `embassy-rp` | Stable |
| STM32 HAL | `embassy-stm32` | Stable, 1400+ Chips |
| SX1261/62/68 Treiber | `lora-phy` (lora-rs) | Vorhanden, async |
| SX1276/77/78/79 Treiber | `lora-phy` (lora-rs) | Vorhanden, async |
| LR1110/1120/1121 Treiber | — | **Existiert nicht in Rust** |
| SX1280/81 Treiber | — | **Existiert nicht in lora-phy** |
| OLED SSD1306 | `ssd1306` | Stable |
| E-Ink diverse | `epd-waveshare`, `ssd1680` | Stable |
| TFT ST7789/ILI9341 | `mipidsi`, `st7789` | Stable |
| GPS NMEA | `nmea0183` / custom | Verfügbar |
| Linux SPI/GPIO | `linux-embedded-hal` | Stable |

---

## Phase 1 — Kernplattformen (ESP32-S3 + SX1262, nRF52840 + SX1262)

Deckt ~70% aller aktiv genutzten LoRa-Mesh-Devices ab. Alles hier teilt sich den gleichen LoRa-Treiber (`lora-phy` SX126x) und braucht nur zwei Platform-Crates.

### 1.1 ESP32-S3 + SX1262

Toolchain: `espup` (Xtensa, nicht upstream LLVM). HAL: `esp-hal` mit `esp-wifi` für WiFi/BLE.

| Device | LoRa | Display | GPS | Konnektivität | PMIC | Besonderheiten | Unterstützt von |
|---|---|---|---|---|---|---|---|
| **Heltec LoRa32 V3** | SX1262 | SSD1306 OLED 0.96" (I2C) | — | WiFi, BLE | Integriert (USB-Laden) | Billigstes Device (~20€), Community-Favorit | MT, MC, RN |
| **Heltec LoRa32 V4** | SX1262 | SSD1306 OLED 0.96" (I2C) | Optional (ext. Modul) | WiFi, BLE | Integriert + Solar-Input | **Externer PA bis +28 dBm**, GPIO 7/2/46 müssen HIGH | MT, MC |
| **LilyGO T-Beam Supreme** | SX1262 | SH1106 OLED 1.3" (I2C) | L76K (UART) | WiFi, BLE | AXP2101 | GPS + 18650 Halter, vollausgestattetes Board | MT, MC, RN |
| **LilyGO T3S3** | SX1262 | SSD1306 OLED 0.96" (I2C) | — | WiFi, BLE | — | Kompaktes Dev-Board | MT, MC, RN |
| **LilyGO T-Deck / T-Deck Plus** | SX1262 | ST7789 TFT 2.8" (SPI) + Trackball | L76K (UART) | WiFi, BLE | — | **Standalone mit Keyboard**, beliebtestes MeshCore-Device | MT, MC, RN |
| **B&Q Station G2** | SX1262 | SSD1306 OLED 1.3" (I2C) | Optional (ext.) | WiFi, BLE | Ext. 9-19V DC | **PA + LNA**, High-Power für Amateurfunk, Grove/Qwiic | MT, MC |
| **Heltec Wireless Paper** | SX1262 | E-Ink 2.13" (SPI, SSD1680) | — | WiFi, BLE | — | E-Paper statt OLED | MT |
| **Heltec Vision Master E213** | SX1262 | E-Ink 2.13" (SPI) | — | WiFi, BLE | — | E-Paper Dev-Board | MT |
| **Heltec Vision Master E290** | SX1262 | E-Ink 2.9" (SPI) | — | WiFi, BLE | — | Größeres E-Paper | MT |
| **SenseCAP Indicator** | SX1262 | ILI9341 TFT 4" Touch (SPI) | — | WiFi, BLE | — | **Dual-MCU: ESP32-S3 + RP2040**, Touchscreen | MT |
| **RAK WisBlock (RAK3312 Core)** | SX1262 | Variabel (je nach Base Board) | Optional (RAK12500) | WiFi, BLE | — | Modulares System, ESP32-S3 Core-Modul | MT |
| **Elecrow ThinkNode M2** | SX1262 | TFT (SPI) | GPS (UART) | WiFi, BLE | — | Outdoor-Handheld | MT |
| **Elecrow ThinkNode M5** | SX1262 | TFT 1.54" (SPI) | GPS (UART) | WiFi, BLE | Custom Board-Klasse | Neues Standalone-Device | MT, MC |
| **LilyGO T-LoRa Pager** | SX1262 | TFT (SPI) + Keyboard | — | WiFi, BLE | — | Pager-Formfaktor mit Keyboard | MT |
| **Seeed Xiao ESP32-S3 + WIO SX1262** | SX1262 | — | — | WiFi, BLE | — | Tiny-Formfaktor | MC |

### 1.2 nRF52840 + SX1262

Toolchain: Standard-Rust (`thumbv7em-none-eabihf`). HAL: `embassy-nrf`. Ultra-Low-Power.

| Device | LoRa | Display | GPS | Konnektivität | PMIC | Besonderheiten | Unterstützt von |
|---|---|---|---|---|---|---|---|
| **LilyGO T-Echo** | SX1262 | E-Ink 1.54" (SPI, GDE0154) | L76K (UART) | BLE 5.0, NFC | — | All-in-one mit Gehäuse, 850mAh, 3 Antennen | MT, MC, RN |
| **LilyGO T-Echo Lite** | SX1262 | E-Ink (SPI) | — | BLE | — | Abgespeckte T-Echo Variante | MT |
| **RAK WisBlock (RAK4631 Core)** | SX1262 | Variabel | Optional (RAK12500) | BLE | — | Modulares System, nRF52840 Core, Base Boards 19003/19007/19026 | MT, MC, RN |
| **RAK WisMesh Pocket V2** | SX1262 | OLED 1.3" (I2C) | GPS | BLE | — | Turnkey-Handheld mit Gehäuse, ~$99 | MT |
| **RAK WisMesh Pocket Mini** | SX1262 | OLED (I2C) | GPS | BLE | — | Kompaktere Pocket-Variante | MT |
| **RAK WisMesh Tag** | SX1262 | — | GPS | BLE | — | Kreditkarten-Tracker, IP66 | MT |
| **Heltec T114** | SX1262 | TFT 1.14" (SPI, ST7789) | Optional (ext. GNSS-Modul) | BLE | — | 23µA Deep Sleep, Solar-Input | MT, MC, RN |
| **Seeed T1000-E** | SX1262 | — | GPS | BLE | — | Kreditkarten-Tracker, IP65, wasserdicht, 700mAh | MT, MC |
| **Canary One** | SX1262 | OLED (I2C) | GPS | BLE | — | Standalone-Handheld, SOS-Funktion | MT |
| **R1 Neo** | SX1262 | OLED (I2C) | GPS | BLE | — | Custom nRF52840 Design | MT |
| **Seeed Xiao nRF52** | SX1262 (ext.) | — | — | BLE | — | Tiny-Formfaktor | MC |
| **OpenCom XL** | SX1262 **+ SX1280** | — | — | BLE | — | **Dual-Transceiver: Sub-GHz + 2.4 GHz** | RN |

**Legende:** MT = Meshtastic, MC = MeshCore, RN = Reticulum/RNode

---

## Phase 2 — Low Hanging Fruits (existierende Treiber, minimaler Mehraufwand)

### 2.1 SX1276/78 Support (lora-phy hat den Treiber)

Ältere Gen-1 Chips. `lora-phy` unterstützt SX1276/77/78/79 nativ. Aufwand: Feature-Flag umschalten, ggf. anderes SPI-Timing.

| Device | MCU | LoRa | Display | GPS | Besonderheiten | Unterstützt von |
|---|---|---|---|---|---|---|
| **Heltec LoRa32 V2** | ESP32 (classic) | SX1276 | SSD1306 OLED 0.96" (I2C) | — | Älteres Board, noch weit verbreitet | MT, MC, RN |
| **LilyGO T-Beam (alt, V0.7/V1.x)** | ESP32 (classic) | SX1276 | — | NEO-6M (UART) | GPS + 18650, Gen-1-Klassiker | MT, MC, RN |
| **LilyGO T-Beam SX1278** | ESP32 (classic) | SX1278 | — | GPS (UART) | 433MHz Variante | MT, MC |
| **LilyGO LoRa32 V2.1** | ESP32 (classic) | SX1276 | SSD1306 OLED (I2C) | — | SD-Karten-Slot | MT, RN |
| **LilyGO LoRa32 V2.0** | ESP32 (classic) | SX1276 | SSD1306 OLED (I2C) | — | Älteres Board | RN |
| **LilyGO LoRa32 V1.0** | ESP32 (classic) | SX1276 | SSD1306 OLED (I2C) | — | Ältestes TTGO Board | RN |
| **Unsigned RNode V2.x** | ESP32 (classic) | SX1276 | — | — | Dedicated Reticulum-Transceiver | RN |

**Hinweis:** ESP32 (classic) braucht dieselbe Xtensa-Toolchain wie ESP32-S3, ist aber ein anderer Chip. In `esp-hal` über Feature-Flag `esp32` statt `esp32s3` selektiert. Der Großteil des Codes bleibt identisch.

### 2.2 ESP32-C3 (RISC-V — Standard-Rust-Toolchain!)

Target: `riscv32imc-unknown-none-elf`. **Kein `espup` nötig**, compiliert mit Standard-Rust. HAL: `esp-hal` mit Feature `esp32c3`.

| Device | LoRa | Display | GPS | Besonderheiten | Unterstützt von |
|---|---|---|---|---|---|
| **Seeed Xiao ESP32-C3 + ext. SX1262** | SX1262 | — | — | Tiny RISC-V, billig | MC |
| **Heltec WiFi LoRa32 C3** | SX1262 | OLED (I2C) | — | RISC-V, low-power | MT |

### 2.3 ESP32-C6 (RISC-V + WiFi 6 + Zigbee/Thread)

Target: `riscv32imac-unknown-none-elf`. Standard-Rust-Toolchain. HAL: `esp-hal` mit Feature `esp32c6`.

| Device | LoRa | Display | GPS | Besonderheiten | Unterstützt von |
|---|---|---|---|---|---|
| **Seeed Xiao ESP32-C6 + ext. SX1262** | SX1262 | — | — | WiFi 6, 802.15.4, ultra-low-power, Zigbee/Thread | MC |

**Strategisch interessant:** C6 hat 802.15.4 (Zigbee/Thread) — potentiell als zusätzliches Reticulum-Interface nutzbar.

### 2.4 RP2040 (ARM Cortex-M0+)

Target: `thumbv6m-none-eabi`. HAL: `embassy-rp`. Kein WiFi/BLE nativ (außer Pico W mit CYW43).

| Device | LoRa | Display | GPS | Besonderheiten | Unterstützt von |
|---|---|---|---|---|---|
| **Raspberry Pi Pico + Waveshare SX1262 Shield** | SX1262 (SPI) | Optional (ext. SSD1306/SH1106) | — | Billig, universell, UF2-Flash | MT, MC |
| **RAK WisBlock (RAK11310 Core)** | SX1262 | Variabel | Optional | RP2040-basiertes WisBlock Core-Modul | MT |

### 2.5 LLCC68 (SX1262-kompatibel mit Einschränkung)

LLCC68 ist software-kompatibel mit SX1262, hat aber eingeschränkten SF-Bereich (max SF11 bei ≤250 kHz BW). Bestehender SX1262-Treiber funktioniert — nur SF-Validierung einschränken.

| Device | MCU | Besonderheiten | Unterstützt von |
|---|---|---|---|
| **Diverse Billig-LoRa-Boards** | ESP32/S3 | Weniger Range als SX1262 bei hohen SF | MT |

---

## Phase 3 — Linux-native (std Rust, kein no_std)

Eigenes Platform-Crate mit `std`. LoRa-Chip via `linux-embedded-hal` über SPI/GPIO oder USB-Serial (KISS-Protokoll). Zusätzlich: TCP/UDP/I2P/Pipe als Reticulum-Interfaces.

| Plattform | LoRa-Anbindung | Besonderheiten | Unterstützt von |
|---|---|---|---|
| **Raspberry Pi (3/4/5/Zero 2W)** | SPI HAT (SX1262/SX1276) oder USB-RNode | `linux-embedded-hal`, `spidev` | MT (meshtasticd), RN |
| **MESHSTICK (CH341 USB-to-SPI)** | SX1262 oder LR1121 via USB-SPI | USB-Dongle für jeden Linux-Rechner | MT |
| **OpenWRT Router** | USB-RNode oder SPI-Modul | MIPS/ARM Router mit LoRa-Erweiterung | RN |
| **Generisches Linux (x86/ARM)** | USB-RNode, TCP/UDP, I2P, Pipe | Desktop, Server, VPS als Reticulum-Transport | RN |
| **Android (Termux/native)** | BLE zu RNode, oder USB-Serial | Mobile Reticulum-Node | RN (Sideband) |

### Reticulum-spezifische Interface-Typen (nicht LoRa)

Diese Interfaces sind nicht hardware-gebunden sondern Netzwerk-Transports im Reticulum-Protokoll:

| Interface | Medium | Beschreibung |
|---|---|---|
| **AutoInterface** | Ethernet/WiFi (Broadcast) | Zero-Config lokale Discovery über Link-Local |
| **TCPServerInterface** | TCP | Eingehende Verbindungen akzeptieren |
| **TCPClientInterface** | TCP | Ausgehende Verbindung zu anderem Reticulum-Node |
| **UDPInterface** | UDP | Multicast oder Unicast |
| **I2PInterface** | I2P (Garlic Routing) | Anonymer Transport über I2P-Netzwerk |
| **PipeInterface** | stdin/stdout | Beliebiges Programm als Transport |
| **KISSInterface** | Serial/USB | Packet-Radio TNCs, AX.25 Modems |
| **RNodeInterface** | Serial/USB/BLE/TCP | RNode-Firmware als LoRa-Modem |
| **RNodeMultiInterface** | Serial/USB/BLE | Mehrere virtuelle Interfaces auf einem Multi-Radio-RNode |

---

## Phase 4 — Neue LoRa-Chip-Familien (mittlerer bis hoher Aufwand)

### 4.1 LR1110 / LR1120 / LR1121 (Gen 3 — Kein Rust-Treiber vorhanden)

Semtech C-Treiber (SWDR001) existiert, ~2000 Zeilen relevanter Code. Muss als neuer `RadioKind` in `lora-phy` implementiert oder via FFI eingebunden werden. Strategisch wichtig — Meshtastic bewegt sich hierhin.

| Device | MCU | LoRa | Display | GPS | Besonderheiten | Unterstützt von |
|---|---|---|---|---|---|---|
| **Elecrow ThinkNode M3** | nRF52840 | **LR1110** | OLED (I2C) | **GNSS on-chip** (!) | Multi-Band, GNSS-Scanning im LoRa-Chip | MT |
| **MESHSTICK LR1121 Variante** | CH341 (USB-SPI) | **LR1121** | — | — | USB-Dongle, Sub-GHz + 2.4 GHz + S-Band | Community |
| **Zukünftige RAK/Heltec/LilyGO Boards** | ESP32-S3 / nRF52840 | LR1121 | Variabel | Variabel | Hersteller bewegen sich Richtung Gen 3 | Erwartet |

**Aufwand:** ~2-4 Wochen für einen sauberen Rust-Treiber. Strategischer Vorteil: Wer den ersten Rust-LR11xx-Treiber liefert, gewinnt Community-Aufmerksamkeit.

### 4.2 SX1280/81 (2.4 GHz)

Anderes Frequenzband, anderes Regulatory. `lora-phy` hat keinen SX1280-Treiber. Relevant für Dual-Band-Setups (Sub-GHz + 2.4 GHz auf einem Device).

| Device | MCU | LoRa | Besonderheiten | Unterstützt von |
|---|---|---|---|---|
| **OpenCom XL** | nRF52840 | SX1262 **+ SX1280** | Dual-Transceiver, Sub-GHz + 2.4 GHz | RN |
| **Diverse DIY Setups** | Variabel | SX1280 standalone | 2.4 GHz LoRa, kürzere Range, höhere Datenrate | RN |

**Aufwand:** Neuer `RadioKind`. SX1280 hat anderes Register-Layout als SX126x. Mittlerer Aufwand.

---

## Phase 5 — Zukunfts-Plattformen

### 5.1 RP2350 (Nachfolger RP2040)

Target: `thumbv8m.main-none-eabihf` (ARM Cortex-M33) oder RISC-V. `embassy-rp` unterstützt es bereits. Drop-in-Replacement für RP2040-Boards mit mehr RAM und Security-Features (ARM TrustZone).

| Device | LoRa | Besonderheiten |
|---|---|---|
| **Raspberry Pi Pico 2 + Waveshare Shield** | SX1262 (SPI) | Schneller, mehr RAM, Dual-Arch (ARM/RISC-V) |
| **Zukünftige WisBlock Core Module** | SX1262 | RAK wird vermutlich RP2350-Cores bringen |

### 5.2 STM32 (diverse)

MeshCore hat STM32-Support. `embassy-stm32` deckt 1400+ Chips ab. Wenn sich konkrete Boards durchsetzen, ist die Anbindung trivial.

| Device | MCU | LoRa | Besonderheiten |
|---|---|---|---|
| **STM32WL** | STM32WL (integrierter SX126x!) | SX1262 **on-chip** | LoRa-Transceiver direkt im MCU, kein externer Chip nötig |
| **MeshCore STM32 Varianten** | STM32 diverse | SX1262 (ext.) | Community-Boards |

**STM32WL ist besonders interessant:** Der LoRa-Transceiver sitzt direkt im MCU. Kein SPI, keine externen Pins. `lora-phy` hat expliziten STM32WL-Support.

### 5.3 ESP32-H2 (802.15.4 only)

Kein WiFi, kein klassisches BLE. Nur Zigbee/Thread (802.15.4) + BLE 5 (LE). Könnte als Low-Power Reticulum-Interface über 802.15.4 dienen. Exotisch, aber architektonisch passend.

### 5.4 nRF9160 (LTE-M / NB-IoT)

Cellular-Modem für Reticulum-Transport über Mobilfunk als Fallback. Embassy hat experimentellen Support. Nische, aber für Disaster-Recovery-Szenarien interessant.

### 5.5 CH32V-Serie (WCH RISC-V)

Extrem billig (~$0.10-$0.50 pro Chip). `ch32-hal` für Embassy existiert. Wenn jemand ein LoRa-Board damit baut, ist der Aufwand gering. Aktuell keine bekannten LoRa-Mesh-Boards.

### 5.6 LR2021 (Gen 4 — LoRa Plus)

Neueste Semtech-Generation mit FLRC-Modus (bis 2.6 Mbps!), verbesserter Sub-GHz-Empfindlichkeit, Sub-GHz + 2.4 GHz auf einem Chip. Kein Rust-Treiber, kein bekanntes Meshtastic/MeshCore-Board. Aber: wird kommen.

---

## Zusammenfassung: Aufwand pro Phase

| Phase | Neue MCU-Plattformen | Neue LoRa-Treiber | Neue Board-Configs | Geschätzter Aufwand |
|---|---|---|---|---|
| **1** | ESP32-S3 (Xtensa), nRF52840 (ARM) | SX1262 (vorhanden) | ~15-20 Boards | 2-3 Monate |
| **2** | ESP32 classic, ESP32-C3, ESP32-C6, RP2040 | SX1276 (vorhanden), LLCC68 (=SX1262) | ~10 Boards | 1-2 Monate |
| **3** | Linux (std) | Keiner (USB-Serial, SPI via linux-embedded-hal) | 5+ Plattformen | 1 Monat |
| **4** | — | **LR11xx (neu!)**, SX1280 (neu!) | ~5 Boards | 2-4 Monate |
| **5** | RP2350, STM32WL, ggf. ESP32-H2 | STM32WL (vorhanden in lora-phy) | Je nach Markt | Fortlaufend |

## Priorisierungsmatrix

```
                        Verbreitung hoch
                              │
         Heltec V3 ──────────┼──────────── T-Beam Supreme
         T-Echo               │             RAK WisBlock (4631)
         T-Deck               │             Station G2
                              │
   Aufwand gering ────────────┼──────────── Aufwand hoch
                              │
         Heltec V2 (SX1276) ──┼──────────── ThinkNode M3 (LR1110)
         RP2040 + Waveshare   │             OpenCom XL (Dual-Band)
         Xiao C3/C6           │             STM32WL
         Linux-native         │             LR2021
                              │
                        Verbreitung niedrig
```

Low Hanging Fruits: Links oben (verbreitet + geringer Aufwand).
Strategische Investitionen: Rechts oben (verbreitet + hoher Aufwand = Phase 4 LoRa-Treiber).
Quick Wins: Links unten (wenig verbreitet, aber trivial mitzunehmen).
Moonshots: Rechts unten (abwarten, ob sich Hardware etabliert).
