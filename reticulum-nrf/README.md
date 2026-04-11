# reticulum-nrf

Firmware for the Heltec Mesh Node T114 (nRF52840 + SX1262). It turns the T114 into a standalone Reticulum transport node that routes packets between USB serial, LoRa radio, and BLE. The transport engine is the same `reticulum-core` library that powers the Linux daemon, compiled for Cortex-M4F.

The firmware speaks the RNode LoRa framing protocol, so T114 and RNode devices interoperate on the same LoRa network. On the BLE side, it implements the Columba v2.2 protocol and can be used with the Columba Android app. On the host side, it connects to `lnsd` or `rnsd` over USB serial with HDLC framing.

The default radio profile uses 869.525 MHz (EU ISM band), SF7, 125 kHz bandwidth, and 17 dBm TX power. These parameters are compiled into the firmware and must match the RNode configuration on the same network.

## Prerequisites

Install the Rust embedded toolchain, the ARM cross-compiler (needed by `nrf-sdc` for C header bindgen), and add your user to the `dialout` group for serial port access (log out and back in afterwards).

```
rustup target add thumbv7em-none-eabihf
rustup component add llvm-tools
sudo apt install gcc-arm-none-eabi
sudo usermod -aG dialout $USER
```

## Build and flash

Build the firmware with `cargo build --release`. To flash, put the T114 into bootloader mode by double-tapping RESET, then run `cargo run --release`. The runner converts the ELF to UF2, copies it to the bootloader drive, waits for the device to reboot, and reports the two USB serial ports. If the device is not in bootloader mode, the runner waits up to 30 seconds for you to double-tap RESET.

The device stores its Reticulum identity in internal flash and preserves it across firmware updates.

## USB serial ports

The firmware exposes two USB CDC-ACM serial ports. The lower-numbered port is the debug log output. The higher-numbered port is the Reticulum transport interface that carries HDLC frames. The actual `/dev/ttyACM*` numbers depend on other connected USB devices.

To get stable device paths, install the udev rules:

```
sudo cp udev/99-leviculum.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
```

After the next plug-in, `/dev/leviculum-debug` and `/dev/leviculum-transport` point to the correct ports regardless of enumeration order.

## Reading debug output

```
picocom /dev/leviculum-debug -b 115200
```
