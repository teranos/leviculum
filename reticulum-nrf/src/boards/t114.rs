//! Heltec Mesh Node T114 pin mappings
//!
//! nRF52840 + SX1262 LoRa radio + optional ST7789 TFT display.
//! Pin assignments verified from Heltec Rev 2.0 Pin Map, datasheet,
//! and Meshtastic firmware variant.h.
//!
//! Reference: <https://resource.heltec.cn/download/Mesh_Node_T114/Mesh_node_t114_Pin_Map.png>

use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::peripherals;
use embassy_nrf::Peri;

// ─── SX1262 LoRa Radio (SPI0) ──────────────────────────────────────────────

/// SX1262 SPI clock
pub type LoRaSck = peripherals::P0_19;
/// SX1262 SPI MOSI
pub type LoRaMosi = peripherals::P0_22;
/// SX1262 SPI MISO
pub type LoRaMiso = peripherals::P0_23;
/// SX1262 SPI chip-select (active low)
pub type LoRaCs = peripherals::P0_24;
/// SX1262 reset (active low)
pub type LoRaReset = peripherals::P0_25;
/// SX1262 busy indicator (high = busy)
pub type LoRaBusy = peripherals::P0_17;
/// SX1262 DIO1 interrupt output
pub type LoRaDio1 = peripherals::P0_20;

// ─── Green LED ──────────────────────────────────────────────────────────────

/// Green indicator LED (active LOW)
pub type LedPin = peripherals::P1_03;

// ─── NeoPixel (2x SK6812) ───────────────────────────────────────────────────

/// NeoPixel data pin (GRB, 800 kHz)
pub type NeoPixelPin = peripherals::P0_14;

// ─── UART (NFC pins repurposed as GPIO) ─────────────────────────────────────

/// UART1 RX (header P1)
pub type Uart1Rx = peripherals::P0_09;
/// UART1 TX (header P1)
pub type Uart1Tx = peripherals::P0_10;

// ─── I2C ────────────────────────────────────────────────────────────────────

/// I2C1 SDA (general purpose, header P1)
pub type I2c1Sda = peripherals::P0_16;
/// I2C1 SCL (general purpose, header P1)
pub type I2c1Scl = peripherals::P0_13;

// ─── TFT Display (ST7789, optional, SPI1) ───────────────────────────────────

/// TFT SPI clock
pub type TftSck = peripherals::P1_08;
/// TFT SPI MOSI
pub type TftMosi = peripherals::P1_09;
/// TFT chip-select (active low)
pub type TftCs = peripherals::P0_11;
/// TFT data/command select
pub type TftDc = peripherals::P0_12;
/// TFT reset (active low)
pub type TftReset = peripherals::P0_02;
/// TFT backlight control (active LOW = on)
pub type TftBacklight = peripherals::P0_15;
/// TFT power enable
pub type TftPowerEn = peripherals::P0_03;

// ─── Battery / ADC ──────────────────────────────────────────────────────────

/// Battery voltage sense (AIN2, multiplier 4.916)
pub type BatteryAdc = peripherals::P0_04;
/// ADC divider enable (HIGH = enabled)
pub type AdcCtrl = peripherals::P0_06;

// ─── External peripheral power ──────────────────────────────────────────────

/// VEXT enable (HIGH = on, controls GPS/external peripherals, 1s warmup)
pub type VextEnable = peripherals::P0_21;

// ─── User button ────────────────────────────────────────────────────────────

/// User button
pub type UserButton = peripherals::P1_10;

/// Create the green LED output (active low)
pub fn led(pin: Peri<'static, LedPin>) -> Output<'static> {
    // LED is active LOW — start with Level::High (LED off)
    Output::new(pin, Level::High, OutputDrive::Standard)
}
