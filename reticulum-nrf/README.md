# reticulum-nrf — Embedded Reticulum for nRF52840

Firmware for the Heltec Mesh Node T114 (nRF52840 + SX1262 LoRa).

## Prerequisites

```bash
rustup target add thumbv7em-none-eabihf
rustup component add llvm-tools

# Required for USB serial port access (log out + back in after this)
sudo usermod -aG dialout $USER
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
4. Waits for the device to reboot and identifies both USB serial ports
5. Writes the debug port path to `target/debug-port` for tooling

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

## USB serial ports

The firmware exposes a USB composite device with two CDC-ACM serial ports:

| Port | Interface | Purpose |
|------|-----------|---------|
| `/dev/ttyACM0` | 00 | Debug log output |
| `/dev/ttyACM1` | 02 | Reticulum transport (idle for now) |

The actual `/dev/ttyACM*` numbers depend on what other USB devices are connected.

### Reading debug output

```bash
picocom /dev/ttyACM0 -b 115200
```

Or, if you installed the udev rules (see below):

```bash
picocom /dev/leviculum-debug -b 115200
```

Expected output:
```
[INFO] leviculum T114 booting
[INFO] heartbeat 1
[INFO] heartbeat 2
```

### Writing log messages in firmware code

Use the `info!` and `warn!` macros (same syntax as `println!`):

```rust
use reticulum_nrf::{info, warn};

info!("booting");
info!("counter = {}", some_value);
warn!("buffer full: {} bytes dropped", n);
```

Messages are formatted into a fixed 256-byte buffer with `\r\n` line endings and
sent through a bounded channel (capacity 16) to the USB debug writer task.
If the channel is full (host not reading), messages are silently dropped.
There is no blocking and no heap allocation in the log path.

### Stable device symlinks (udev rules)

Without udev rules, the ttyACM numbers shift when other USB devices are
plugged in. Install the udev rules for stable `/dev/leviculum-*` symlinks:

```bash
sudo cp udev/99-leviculum.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
```

After the next plug-in or reboot:

```
/dev/leviculum-debug       -> /dev/ttyACM2  (debug log port)
/dev/leviculum-transport   -> /dev/ttyACM3  (reticulum transport port)
```

With multiple boards, each gets a serial-number-suffixed symlink
(`/dev/leviculum-debug-A1B2C3D4E5F6G7H8`). The serial number comes from
the nRF52840 factory-programmed device ID (FICR DEVICEID registers).

### Automated test harness

Flash and verify firmware output in one command:

```bash
tools/flash-and-read.sh target/thumbv7em-none-eabihf/release/t114 \
    --expect "heartbeat 1" --timeout 15
```

Exits 0 if the pattern is found, 1 on timeout.

## Troubleshooting

- **"No objcopy found"**: Run `rustup component add llvm-tools`, or install
  `gcc-arm-none-eabi`.
- **"Timeout: No UF2 drive found"**: Double-tap RESET to enter bootloader.
  The drive should appear as `NRF52BOOT`. You can also copy the `.uf2` file
  manually (the path is printed on timeout).
- **"Device did not enumerate"**: The firmware may have crashed. Check that
  `memory.x` has the correct RAM origin (`0x20003000` — SoftDevice reserves
  the first 12 KB).
