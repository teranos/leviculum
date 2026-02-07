# reticulum-nrf — Embedded Reticulum for nRF52840

Firmware for the Heltec Mesh Node T114 (nRF52840 + SX1262 LoRa).

## Prerequisites

```bash
rustup target add thumbv7em-none-eabihf
rustup component add llvm-tools
```

## Build

```bash
cargo build --release
```

## Flash

Put the T114 into bootloader mode by double-tapping RESET, then:

```bash
cargo run --release
```

The runner automatically:
1. Converts the ELF to a flat binary (via `llvm-objcopy`)
2. Converts the binary to UF2 format (via `tools/bin2uf2.rs`)
3. Finds the UF2 bootloader drive and copies the firmware
4. Waits for the device to reboot and enumerate its serial port

If the device is not in bootloader mode, the runner will prompt you to
double-tap RESET and wait up to 30 seconds (configurable via `UF2_TIMEOUT`).

## Memory layout

The T114 uses the Adafruit nRF52 UF2 bootloader with SoftDevice S140 v6.1.1.

| Region       | Address      | Size   |
|--------------|-------------|--------|
| SoftDevice   | 0x00000000  | 152 KB |
| Application  | 0x00026000  | 824 KB |
| Bootloader   | 0x000F4000  | 48 KB  |
| RAM (SD)     | 0x20000000  | 12 KB  |
| RAM (App)    | 0x20003000  | 244 KB |

**Important**: The flash base address in `memory.x` (`FLASH ORIGIN = 0x26000`)
and in `tools/uf2-runner.sh` (`--base 0x26000`) must match. If these diverge,
the firmware is written to the wrong flash address and the device will crash.

## Troubleshooting

- **"No objcopy found"**: Run `rustup component add llvm-tools`, or install
  `gcc-arm-none-eabi`.
- **"Timeout: No UF2 drive found"**: Double-tap RESET to enter bootloader.
  The drive should appear as `NRF52BOOT`. You can also copy the `.uf2` file
  manually (the path is printed on timeout).
- **"Device did not enumerate"**: The firmware may have crashed. Check that
  `memory.x` has the correct RAM origin (`0x20003000` — SoftDevice reserves
  the first 12 KB).
