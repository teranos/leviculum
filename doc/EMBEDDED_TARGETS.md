# Embedded Targets for leviculum

This document lists all Meshtastic-compatible embedded devices and their corresponding Rust compilation targets. The goal is to ensure `reticulum-core` builds successfully for all supported hardware.

## Overview

Meshtastic devices use three main MCU families:

| MCU Family | Architecture | Rust Target | Stock Rustup? |
|------------|--------------|-------------|---------------|
| nRF52840 | ARM Cortex-M4F | `thumbv7em-none-eabihf` | Yes (Tier 2) |
| RP2040 | ARM Cortex-M0+ | `thumbv6m-none-eabi` | Yes (Tier 2) |
| ESP32-S3/S2 | Xtensa LX7/LX6 | `xtensa-esp32*-none-elf` | No (requires espup) |
| ESP32-C3/C6 | RISC-V | `riscv32imc-unknown-none-elf` | Yes (Tier 2) |

## Supported Targets

### Tier 1: Stock Rustup Targets

These targets work with standard `rustup target add` and are verified in CI:

| Target | MCU | Architecture | Primary Use |
|--------|-----|--------------|-------------|
| `thumbv7em-none-eabihf` | nRF52840 | ARM Cortex-M4F | Battery/solar devices |
| `thumbv6m-none-eabi` | RP2040 | ARM Cortex-M0+ | Maker boards |
| `riscv32imc-unknown-none-elf` | ESP32-C3/C6 | RISC-V | Rare in Meshtastic |

### Tier 2: Espressif Toolchain Required

These targets require the `espup` toolchain and are optional for verification:

| Target | MCU | Primary Use |
|--------|-----|-------------|
| `xtensa-esp32s3-none-elf` | ESP32-S3 | WiFi + Bluetooth devices |
| `xtensa-esp32-none-elf` | ESP32 | Older devices |

## Device Reference by Manufacturer

### RAKwireless

| Device | MCU | LoRa Radio | Notes |
|--------|-----|------------|-------|
| RAK4631 (WisBlock Core) | nRF52840 | SX1262 | Most popular WisBlock core |
| RAK11310 (WisBlock Core) | RP2040 | SX1262 | Raspberry Pi RP2040 based |
| WisMesh Pocket V2 | nRF52840 | SX1262 | Standalone device |
| WisMesh Pocket Mini | nRF52840 | SX1262 | Compact version |
| WisMesh Tag | nRF52840 | SX1262 | Asset tracking |
| WisMesh TAP | nRF52840 | SX1262 | Tracker with display |
| WisMesh Board ONE | nRF52840 | SX1262 | All-in-one board |
| RAK WiFi Gateway | ESP32 | SX1276 | Legacy device |

### LILYGO

| Device | MCU | LoRa Radio | Notes |
|--------|-----|------------|-------|
| T-Echo | nRF52840 | SX1262 | E-paper display, GPS |
| T-Beam S3-Core | ESP32-S3 | SX1262 | GPS, 18650 battery |
| T-Beam Supreme | ESP32-S3 | SX1262 | Premium T-Beam |
| T-Deck | ESP32-S3 | SX1262 | Keyboard + display |
| T-LoRa Pager | ESP32-S3 | SX1262 | Pager form factor |
| LoRa32 T3-S3 | ESP32-S3 | SX1262 | Compact dev board |
| T-Beam (older) | ESP32 | SX1276/SX1262 | Original T-Beam |

### Heltec

| Device | MCU | LoRa Radio | Notes |
|--------|-----|------------|-------|
| LoRa32 V3 | ESP32-S3 | SX1262 | Popular dev board |
| LoRa32 V4 | ESP32-S3 | SX1262 | Updated V3 |
| Vision Master | ESP32-S3 | SX1262 | E-paper display |
| Wireless Paper | ESP32-S3 | SX1262 | E-paper, compact |
| Wireless Stick | ESP32-S3 | SX1262 | USB stick form |
| Wireless Tracker | ESP32-S3 | SX1262 | GPS tracking |
| Mesh Node T114 | nRF52840 | SX1262 | Power efficient |

### Seeed Studio

| Device | MCU | LoRa Radio | Notes |
|--------|-----|------------|-------|
| Card Tracker T1000-E | nRF52840 | SX1262 | Credit card size |
| Solar Node | nRF52840 | SX1262 | Solar powered |
| Wio Tracker 1110 | nRF52840 | SX1262 | Asset tracking |
| SenseCAP Indicator | ESP32-S3 + RP2040 | SX1262 | Dual MCU, display |

### B&Q Consulting

| Device | MCU | LoRa Radio | Notes |
|--------|-----|------------|-------|
| Nano G2 Ultra (nRF) | nRF52840 | SX1262 | Compact, solar |
| Nano G2 Ultra (ESP) | ESP32-S3 | SX1262 | WiFi variant |

### Elecrow

| Device | MCU | LoRa Radio | Notes |
|--------|-----|------------|-------|
| ThinkNode M2 | ESP32-S3 | SX1262 | Display device |
| CrowPanel series | ESP32-S3 | SX1262 | Various displays |

### muzi works

| Device | MCU | LoRa Radio | Notes |
|--------|-----|------------|-------|
| R1 Neo | nRF52840 | SX1262 | Compact design |

### Raspberry Pi

| Device | MCU | LoRa Radio | Notes |
|--------|-----|------------|-------|
| Pico + LoRa HAT | RP2040 | Various | DIY solution |

## Building for Embedded

### Quick Check (Stock Targets)

Verify `reticulum-core` compiles for all stock embedded targets:

```bash
./scripts/check-embedded.sh
```

### Full Check (Including Xtensa)

Include ESP32 Xtensa targets (requires espup):

```bash
./scripts/check-embedded.sh --with-xtensa
```

### Cargo Aliases

Quick builds for specific targets:

```bash
cargo check-nrf52    # nRF52840 (thumbv7em-none-eabihf)
cargo check-rp2040   # RP2040 (thumbv6m-none-eabi)
cargo check-embedded # All stock targets
```

## Toolchain Setup

### Stock Targets (ARM + RISC-V)

These are automatically installed via `rust-toolchain.toml`, or manually:

```bash
rustup target add thumbv7em-none-eabihf thumbv6m-none-eabi
```

### Xtensa Targets (ESP32)

ESP32 Xtensa targets require the Espressif toolchain:

```bash
# Install espup
cargo install espup

# Install Espressif toolchain
espup install

# Source the environment (add to shell profile for persistence)
source ~/export-esp.sh
```

## Target Selection Guide

| Use Case | Recommended MCU | Rust Target |
|----------|-----------------|-------------|
| Battery/solar powered | nRF52840 | `thumbv7em-none-eabihf` |
| WiFi connectivity needed | ESP32-S3 | `xtensa-esp32s3-none-elf` |
| Maker/DIY projects | RP2040 | `thumbv6m-none-eabi` |
| Maximum compatibility | nRF52840 | `thumbv7em-none-eabihf` |

## Notes

- **Build verification only**: This infrastructure verifies compilation, not runtime behavior (which requires actual hardware or emulators).
- **nRF52840 recommended**: Most power-efficient option for battery/solar deployments.
- **ESP32-S3 common**: Most new devices use ESP32-S3 for WiFi/Bluetooth support.
- **RP2040 rare**: Few Meshtastic devices use RP2040, but it's a good test target.

## References

- [Meshtastic Hardware Documentation](https://meshtastic.org/docs/hardware/devices/)
- [Rust Embedded Working Group](https://docs.rust-embedded.org/)
- [espup Documentation](https://github.com/esp-rs/espup)
