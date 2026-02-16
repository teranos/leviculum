# Hardware Reference Firmware

Machine-specific paths to reference firmware sources used for understanding
device hardware (read-only, not built as part of leviculum).

## RNode Firmware

**Path**: `/home/lew/coding/RNode_Firmware/`

LoRa modem firmware supporting T114. Contains SX1262 SPI driver, pin mappings,
power management, KISS protocol, NeoPixel handling, DFU flashing via
`arduino-cli`/`adafruit-nrfutil`.

## Meshtastic Firmware

**Path**: `/home/lew/coding/meshtastic_firmware/`

Mesh networking firmware. T114 variant at
`variants/nrf52840/heltec_mesh_node_t114/`. Contains pin definitions, NeoPixel
config, peripheral initialization patterns.
