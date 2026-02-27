//! RNode command protocol — encoding, decoding, and constants
//!
//! This module implements the RNode serial command protocol as a pure data
//! transformation layer (`no_std + alloc`). It defines command constants,
//! encoding functions that produce complete KISS frames, and decoding
//! functions that parse raw payloads from deframed KISS data.
//!
//! The RNode protocol is a KISS superset: standard KISS framing
//! (FEND/FESC/TFEND/TFESC) with RNode-specific command bytes for radio
//! configuration, statistics reporting, and device management.
//!
//! # Encoding
//!
//! Each `build_*` function returns a `Vec<u8>` containing one or more
//! complete KISS frames ready for serial transmission.
//!
//! # Decoding
//!
//! Each `decode_*` function takes the raw payload bytes (already extracted
//! from a KISS frame by [`KissDeframer`](crate::framing::kiss::KissDeframer))
//! and returns `Option<T>`, returning `None` if the payload is too short.
//! All values are returned as raw device integers — no float conversion
//! is performed in core.

use alloc::vec::Vec;

use crate::framing::kiss;

// ---------------------------------------------------------------------------
// Configuration commands
// ---------------------------------------------------------------------------

/// Data packet (standard KISS CMD_DATA)
pub const CMD_DATA: u8 = 0x00;
/// Set/report operating frequency (4 bytes BE, Hz)
pub const CMD_FREQUENCY: u8 = 0x01;
/// Set/report channel bandwidth (4 bytes BE, Hz)
pub const CMD_BANDWIDTH: u8 = 0x02;
/// Set/report TX power (1 byte, dBm)
pub const CMD_TXPOWER: u8 = 0x03;
/// Set/report spreading factor (1 byte, 5-12)
pub const CMD_SF: u8 = 0x04;
/// Set/report coding rate (1 byte, 5-8)
pub const CMD_CR: u8 = 0x05;
/// Set/report radio on/off state
pub const CMD_RADIO_STATE: u8 = 0x06;
/// Report radio lock state
pub const CMD_RADIO_LOCK: u8 = 0x07;
/// Device presence detection handshake
pub const CMD_DETECT: u8 = 0x08;
/// Host disconnecting (shutdown notification)
pub const CMD_LEAVE: u8 = 0x0A;
/// Short-term airtime limit (2 bytes BE, value/100 = percent)
pub const CMD_ST_ALOCK: u8 = 0x0B;
/// Long-term airtime limit (2 bytes BE, value/100 = percent)
pub const CMD_LT_ALOCK: u8 = 0x0C;
/// Device ready for next TX packet
pub const CMD_READY: u8 = 0x0F;
/// Select subinterface for next command (multi-interface)
pub const CMD_SEL_INT: u8 = 0x1F;

// ---------------------------------------------------------------------------
// Statistics commands
// ---------------------------------------------------------------------------

/// Total RX packet count (4 bytes BE)
pub const CMD_STAT_RX: u8 = 0x21;
/// Total TX packet count (4 bytes BE)
pub const CMD_STAT_TX: u8 = 0x22;
/// Last packet RSSI (1 byte, unsigned + 157 offset)
pub const CMD_STAT_RSSI: u8 = 0x23;
/// Last packet SNR (1 byte, signed * 0.25 dB)
pub const CMD_STAT_SNR: u8 = 0x24;
/// Channel time/utilization stats (11 bytes single, 8 bytes multi)
pub const CMD_STAT_CHTM: u8 = 0x25;
/// Physical layer parameters (12 bytes single, 10 bytes multi)
pub const CMD_STAT_PHYPRM: u8 = 0x26;
/// Battery status (2 bytes: state, percent)
pub const CMD_STAT_BAT: u8 = 0x27;
/// CSMA contention window params (3 bytes)
pub const CMD_STAT_CSMA: u8 = 0x28;
/// CPU temperature (1 byte, value - 120 = Celsius)
pub const CMD_STAT_TEMP: u8 = 0x29;

// ---------------------------------------------------------------------------
// System commands
// ---------------------------------------------------------------------------

/// Blink LED for identification
pub const CMD_BLINK: u8 = 0x30;
/// Hardware random byte
pub const CMD_RANDOM: u8 = 0x40;
/// External framebuffer control
pub const CMD_FB_EXT: u8 = 0x41;
/// Read framebuffer
pub const CMD_FB_READ: u8 = 0x42;
/// Write framebuffer line
pub const CMD_FB_WRITE: u8 = 0x43;
/// Bluetooth control
pub const CMD_BT_CTRL: u8 = 0x46;
/// Query/report platform
pub const CMD_PLATFORM: u8 = 0x48;
/// Query/report MCU type
pub const CMD_MCU: u8 = 0x49;
/// Query/report firmware version (2 bytes: major, minor)
pub const CMD_FW_VERSION: u8 = 0x50;
/// Read ROM data
pub const CMD_ROM_READ: u8 = 0x51;
/// Hard reset / reset notification
pub const CMD_RESET: u8 = 0x55;
/// Read display buffer
pub const CMD_DISP_READ: u8 = 0x66;

// ---------------------------------------------------------------------------
// Multi-interface data commands
// ---------------------------------------------------------------------------

/// List available radio interfaces
pub const CMD_INTERFACES: u8 = 0x71;

/// Data commands for multi-interface RNodes (indexed by subinterface)
pub const CMD_INT_DATA: [u8; 12] = [
    0x00, // INT0
    0x10, // INT1
    0x20, // INT2
    0x70, // INT3
    0x75, // INT4
    0x90, // INT5
    0xA0, // INT6
    0xB0, // INT7
    0xC0, // INT8 (collides with FEND — see research doc)
    0xD0, // INT9
    0xE0, // INT10
    0xF0, // INT11
];

// ---------------------------------------------------------------------------
// Error command and codes
// ---------------------------------------------------------------------------

/// Error report from device
pub const CMD_ERROR: u8 = 0x90;

/// Radio initialization failed
pub const ERROR_INITRADIO: u8 = 0x01;
/// Transmission failed
pub const ERROR_TXFAILED: u8 = 0x02;
/// EEPROM is locked
pub const ERROR_EEPROM_LOCKED: u8 = 0x03;
/// TX queue full (single-interface only)
pub const ERROR_QUEUE_FULL: u8 = 0x04;
/// Memory exhausted (single-interface only)
pub const ERROR_MEMORY_LOW: u8 = 0x05;
/// Modem communication timeout (single-interface only)
pub const ERROR_MODEM_TIMEOUT: u8 = 0x06;

// ---------------------------------------------------------------------------
// Protocol values
// ---------------------------------------------------------------------------

/// Detect request payload (host -> device)
pub const DETECT_REQ: u8 = 0x73;
/// Detect response payload (device -> host)
pub const DETECT_RESP: u8 = 0x46;
/// Radio off
pub const RADIO_STATE_OFF: u8 = 0x00;
/// Radio on
pub const RADIO_STATE_ON: u8 = 0x01;
/// Query radio state
pub const RADIO_STATE_ASK: u8 = 0xFF;

// ---------------------------------------------------------------------------
// Platform constants
// ---------------------------------------------------------------------------

/// AVR-based RNode
pub const PLATFORM_AVR: u8 = 0x90;
/// ESP32-based RNode
pub const PLATFORM_ESP32: u8 = 0x80;
/// nRF52-based RNode
pub const PLATFORM_NRF52: u8 = 0x70;

// ---------------------------------------------------------------------------
// Radio chip types (multi-interface)
// ---------------------------------------------------------------------------

/// SX127X family (sub-GHz)
pub const SX127X: u8 = 0x00;
/// SX1276 (sub-GHz)
pub const SX1276: u8 = 0x01;
/// SX1278 (sub-GHz)
pub const SX1278: u8 = 0x02;
/// SX126X family (sub-GHz)
pub const SX126X: u8 = 0x10;
/// SX1262 (sub-GHz)
pub const SX1262: u8 = 0x11;
/// SX128X family (2.4 GHz)
pub const SX128X: u8 = 0x20;
/// SX1280 (2.4 GHz)
pub const SX1280: u8 = 0x21;

// ---------------------------------------------------------------------------
// Hardware MTU
// ---------------------------------------------------------------------------

/// Hardware MTU for all RNode variants (bytes)
pub const HW_MTU: usize = 508;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Battery state reported by the device
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatteryState {
    Unknown,
    Discharging,
    Charging,
    Charged,
}

/// Channel time/utilization statistics from CMD_STAT_CHTM
///
/// All `u16` values are raw device values. Divide by 100 for percent.
/// RSSI fields are already converted to dBm (raw byte - 157).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelStats {
    /// Short-term airtime (raw; /100 for percent)
    pub airtime_short: u16,
    /// Long-term airtime (raw; /100 for percent)
    pub airtime_long: u16,
    /// Short-term channel load (raw; /100 for percent)
    pub channel_load_short: u16,
    /// Long-term channel load (raw; /100 for percent)
    pub channel_load_long: u16,
    /// Current RSSI in dBm (single-interface only)
    pub current_rssi: Option<i16>,
    /// Noise floor in dBm (single-interface only)
    pub noise_floor: Option<i16>,
    /// Interference in dBm, None if 0xFF (single-interface only)
    pub interference: Option<i16>,
}

/// Physical layer parameters from CMD_STAT_PHYPRM
///
/// All `u16` values are raw device values unless otherwise noted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhyParams {
    /// Symbol time (raw; /1000 for ms)
    pub symbol_time_raw: u16,
    /// Symbol rate (baud)
    pub symbol_rate: u16,
    /// Preamble symbols
    pub preamble_symbols: u16,
    /// Preamble time (ms)
    pub preamble_time_ms: u16,
    /// CSMA slot time (ms)
    pub csma_slot_time_ms: u16,
    /// DIFS time (ms), None for multi-interface
    pub difs_time_ms: Option<u16>,
}

// ---------------------------------------------------------------------------
// Encoding functions
// ---------------------------------------------------------------------------

/// Build a single KISS frame: FEND + command + escaped payload + FEND
fn build_single_frame(cmd: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    kiss::frame(cmd, payload, &mut out);
    out
}

/// Build the 4-frame detect + query sequence
///
/// Returns the fixed 13-byte sequence that queries device presence,
/// firmware version, platform, and MCU. Frames share FEND delimiters.
///
/// ```text
/// C0 08 73 C0 50 00 C0 48 00 C0 49 00 C0
/// ```
pub fn build_detect_query() -> Vec<u8> {
    // This is a fixed sequence with shared FENDs between frames.
    // Cannot use frame() directly since it clears the output each time.
    alloc::vec![
        kiss::FEND,
        CMD_DETECT,
        DETECT_REQ,
        kiss::FEND,
        CMD_FW_VERSION,
        0x00,
        kiss::FEND,
        CMD_PLATFORM,
        0x00,
        kiss::FEND,
        CMD_MCU,
        0x00,
        kiss::FEND,
    ]
}

/// Build a CMD_FREQUENCY frame (4 bytes big-endian Hz)
pub fn build_set_frequency(hz: u32) -> Vec<u8> {
    build_single_frame(CMD_FREQUENCY, &hz.to_be_bytes())
}

/// Build a CMD_BANDWIDTH frame (4 bytes big-endian Hz)
pub fn build_set_bandwidth(hz: u32) -> Vec<u8> {
    build_single_frame(CMD_BANDWIDTH, &hz.to_be_bytes())
}

/// Build a CMD_TXPOWER frame (1 byte dBm)
pub fn build_set_txpower(dbm: u8) -> Vec<u8> {
    build_single_frame(CMD_TXPOWER, &[dbm])
}

/// Build a CMD_SF frame (1 byte spreading factor)
pub fn build_set_sf(sf: u8) -> Vec<u8> {
    build_single_frame(CMD_SF, &[sf])
}

/// Build a CMD_CR frame (1 byte coding rate)
pub fn build_set_cr(cr: u8) -> Vec<u8> {
    build_single_frame(CMD_CR, &[cr])
}

/// Build a CMD_RADIO_STATE frame (1 byte state)
pub fn build_set_radio_state(state: u8) -> Vec<u8> {
    build_single_frame(CMD_RADIO_STATE, &[state])
}

/// Build a CMD_ST_ALOCK frame (2 bytes big-endian)
///
/// Caller computes `(percent * 100.0) as u16` before calling.
pub fn build_set_st_alock(value: u16) -> Vec<u8> {
    build_single_frame(CMD_ST_ALOCK, &value.to_be_bytes())
}

/// Build a CMD_LT_ALOCK frame (2 bytes big-endian)
///
/// Caller computes `(percent * 100.0) as u16` before calling.
pub fn build_set_lt_alock(value: u16) -> Vec<u8> {
    build_single_frame(CMD_LT_ALOCK, &value.to_be_bytes())
}

/// Build a CMD_DATA frame with KISS-escaped payload
pub fn build_data_frame(data: &[u8]) -> Vec<u8> {
    build_single_frame(CMD_DATA, data)
}

/// Build a CMD_LEAVE frame (0xFF payload)
pub fn build_leave() -> Vec<u8> {
    build_single_frame(CMD_LEAVE, &[0xFF])
}

// ---------------------------------------------------------------------------
// Decoding functions
// ---------------------------------------------------------------------------

/// Decode RSSI from CMD_STAT_RSSI payload
///
/// Returns RSSI in dBm: `raw_byte as i16 - 157`.
pub fn decode_rssi(payload: &[u8]) -> Option<i16> {
    let &byte = payload.first()?;
    Some(byte as i16 - 157)
}

/// Decode SNR from CMD_STAT_SNR payload
///
/// Returns the raw signed byte. Caller multiplies by 0.25 for dB.
pub fn decode_snr(payload: &[u8]) -> Option<i8> {
    let &byte = payload.first()?;
    Some(byte as i8)
}

/// Decode battery status from CMD_STAT_BAT payload
///
/// Returns `(BatteryState, percent)`.
pub fn decode_battery(payload: &[u8]) -> Option<(BatteryState, u8)> {
    if payload.len() < 2 {
        return None;
    }
    let state = match payload[0] {
        0x01 => BatteryState::Discharging,
        0x02 => BatteryState::Charging,
        0x03 => BatteryState::Charged,
        _ => BatteryState::Unknown,
    };
    Some((state, payload[1]))
}

/// Decode temperature from CMD_STAT_TEMP payload
///
/// Returns temperature in Celsius: `raw_byte as i16 - 120`.
pub fn decode_temperature(payload: &[u8]) -> Option<i16> {
    let &byte = payload.first()?;
    Some(byte as i16 - 120)
}

/// Decode firmware version from CMD_FW_VERSION payload
///
/// Returns `(major, minor)`.
pub fn decode_firmware_version(payload: &[u8]) -> Option<(u8, u8)> {
    if payload.len() < 2 {
        return None;
    }
    Some((payload[0], payload[1]))
}

/// Read a big-endian u16 from a slice at a given offset
fn read_be_u16(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() {
        return None;
    }
    Some(u16::from_be_bytes([data[offset], data[offset + 1]]))
}

/// Decode channel statistics from CMD_STAT_CHTM payload
///
/// Accepts 11-byte (single-interface) or 8-byte (multi-interface) payloads.
/// For single-interface, includes RSSI/noise_floor/interference fields.
/// Interference is `None` when the raw byte is 0xFF.
pub fn decode_channel_stats(payload: &[u8]) -> Option<ChannelStats> {
    if payload.len() < 8 {
        return None;
    }

    let airtime_short = read_be_u16(payload, 0)?;
    let airtime_long = read_be_u16(payload, 2)?;
    let channel_load_short = read_be_u16(payload, 4)?;
    let channel_load_long = read_be_u16(payload, 6)?;

    let (current_rssi, noise_floor, interference) = if payload.len() >= 11 {
        let rssi = payload[8] as i16 - 157;
        let noise = payload[9] as i16 - 157;
        let interf = if payload[10] == 0xFF {
            None
        } else {
            Some(payload[10] as i16 - 157)
        };
        (Some(rssi), Some(noise), interf)
    } else {
        (None, None, None)
    };

    Some(ChannelStats {
        airtime_short,
        airtime_long,
        channel_load_short,
        channel_load_long,
        current_rssi,
        noise_floor,
        interference,
    })
}

/// Decode physical parameters from CMD_STAT_PHYPRM payload
///
/// Accepts 12-byte (single-interface) or 10-byte (multi-interface) payloads.
/// For multi-interface, `difs_time_ms` is `None`.
pub fn decode_phy_params(payload: &[u8]) -> Option<PhyParams> {
    if payload.len() < 10 {
        return None;
    }

    let symbol_time_raw = read_be_u16(payload, 0)?;
    let symbol_rate = read_be_u16(payload, 2)?;
    let preamble_symbols = read_be_u16(payload, 4)?;
    let preamble_time_ms = read_be_u16(payload, 6)?;
    let csma_slot_time_ms = read_be_u16(payload, 8)?;

    let difs_time_ms = if payload.len() >= 12 {
        Some(read_be_u16(payload, 10)?)
    } else {
        None
    };

    Some(PhyParams {
        symbol_time_raw,
        symbol_rate,
        preamble_symbols,
        preamble_time_ms,
        csma_slot_time_ms,
        difs_time_ms,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::kiss::{KissDeframeResult, KissDeframer};
    use alloc::vec;

    // --- Encoding tests ---

    #[test]
    fn test_build_detect_query() {
        let query = build_detect_query();
        assert_eq!(
            query,
            vec![0xC0, 0x08, 0x73, 0xC0, 0x50, 0x00, 0xC0, 0x48, 0x00, 0xC0, 0x49, 0x00, 0xC0]
        );
        assert_eq!(query.len(), 13);
    }

    #[test]
    fn test_build_set_frequency() {
        // 868.0 MHz = 868_000_000 Hz = 0x33BCA100
        let frame = build_set_frequency(868_000_000);
        let mut deframer = KissDeframer::with_max_payload(HW_MTU);
        let results = deframer.process(&frame);
        assert_eq!(results.len(), 1);
        match &results[0] {
            KissDeframeResult::Frame { command, payload } => {
                assert_eq!(*command, CMD_FREQUENCY);
                assert_eq!(payload.as_slice(), &[0x33, 0xBC, 0xA1, 0x00]);
            }
            _ => panic!("Expected frame"),
        }
    }

    #[test]
    fn test_build_set_bandwidth() {
        // 125 kHz = 125_000 Hz = 0x0001E848
        let frame = build_set_bandwidth(125_000);
        let mut deframer = KissDeframer::with_max_payload(HW_MTU);
        let results = deframer.process(&frame);
        assert_eq!(results.len(), 1);
        match &results[0] {
            KissDeframeResult::Frame { command, payload } => {
                assert_eq!(*command, CMD_BANDWIDTH);
                assert_eq!(payload.as_slice(), &[0x00, 0x01, 0xE8, 0x48]);
            }
            _ => panic!("Expected frame"),
        }
    }

    #[test]
    fn test_build_set_txpower() {
        let frame = build_set_txpower(17);
        let mut deframer = KissDeframer::with_max_payload(HW_MTU);
        let results = deframer.process(&frame);
        assert_eq!(results.len(), 1);
        match &results[0] {
            KissDeframeResult::Frame { command, payload } => {
                assert_eq!(*command, CMD_TXPOWER);
                assert_eq!(payload.as_slice(), &[17]);
            }
            _ => panic!("Expected frame"),
        }
    }

    #[test]
    fn test_build_set_sf() {
        let frame = build_set_sf(7);
        let mut deframer = KissDeframer::with_max_payload(HW_MTU);
        let results = deframer.process(&frame);
        assert_eq!(results.len(), 1);
        match &results[0] {
            KissDeframeResult::Frame { command, payload } => {
                assert_eq!(*command, CMD_SF);
                assert_eq!(payload.as_slice(), &[7]);
            }
            _ => panic!("Expected frame"),
        }
    }

    #[test]
    fn test_build_set_cr() {
        let frame = build_set_cr(5);
        let mut deframer = KissDeframer::with_max_payload(HW_MTU);
        let results = deframer.process(&frame);
        assert_eq!(results.len(), 1);
        match &results[0] {
            KissDeframeResult::Frame { command, payload } => {
                assert_eq!(*command, CMD_CR);
                assert_eq!(payload.as_slice(), &[5]);
            }
            _ => panic!("Expected frame"),
        }
    }

    #[test]
    fn test_build_set_radio_state_on() {
        let frame = build_set_radio_state(RADIO_STATE_ON);
        let mut deframer = KissDeframer::with_max_payload(HW_MTU);
        let results = deframer.process(&frame);
        assert_eq!(results.len(), 1);
        match &results[0] {
            KissDeframeResult::Frame { command, payload } => {
                assert_eq!(*command, CMD_RADIO_STATE);
                assert_eq!(payload.as_slice(), &[0x01]);
            }
            _ => panic!("Expected frame"),
        }
    }

    #[test]
    fn test_build_set_st_alock() {
        // 50.0% -> 5000
        let frame = build_set_st_alock(5000);
        let mut deframer = KissDeframer::with_max_payload(HW_MTU);
        let results = deframer.process(&frame);
        assert_eq!(results.len(), 1);
        match &results[0] {
            KissDeframeResult::Frame { command, payload } => {
                assert_eq!(*command, CMD_ST_ALOCK);
                assert_eq!(payload.as_slice(), &[0x13, 0x88]);
            }
            _ => panic!("Expected frame"),
        }
    }

    #[test]
    fn test_build_set_lt_alock() {
        let frame = build_set_lt_alock(1000);
        let mut deframer = KissDeframer::with_max_payload(HW_MTU);
        let results = deframer.process(&frame);
        assert_eq!(results.len(), 1);
        match &results[0] {
            KissDeframeResult::Frame { command, payload } => {
                assert_eq!(*command, CMD_LT_ALOCK);
                assert_eq!(payload.as_slice(), &[0x03, 0xE8]);
            }
            _ => panic!("Expected frame"),
        }
    }

    #[test]
    fn test_build_data_frame() {
        let data = b"Hello RNode";
        let frame = build_data_frame(data);
        let mut deframer = KissDeframer::with_max_payload(HW_MTU);
        let results = deframer.process(&frame);
        assert_eq!(results.len(), 1);
        match &results[0] {
            KissDeframeResult::Frame { command, payload } => {
                assert_eq!(*command, CMD_DATA);
                assert_eq!(payload.as_slice(), data);
            }
            _ => panic!("Expected frame"),
        }
    }

    #[test]
    fn test_build_leave() {
        let frame = build_leave();
        let mut deframer = KissDeframer::with_max_payload(HW_MTU);
        let results = deframer.process(&frame);
        assert_eq!(results.len(), 1);
        match &results[0] {
            KissDeframeResult::Frame { command, payload } => {
                assert_eq!(*command, CMD_LEAVE);
                assert_eq!(payload.as_slice(), &[0xFF]);
            }
            _ => panic!("Expected frame"),
        }
    }

    // --- Decoding tests ---

    #[test]
    fn test_decode_rssi() {
        // raw 157 -> 157 - 157 = 0 dBm
        assert_eq!(decode_rssi(&[157]), Some(0));
        // raw 0 -> 0 - 157 = -157 dBm
        assert_eq!(decode_rssi(&[0]), Some(-157));
        // raw 200 -> 200 - 157 = 43 dBm
        assert_eq!(decode_rssi(&[200]), Some(43));
        // empty
        assert_eq!(decode_rssi(&[]), None);
    }

    #[test]
    fn test_decode_snr() {
        // raw 0x80 = 128 unsigned, but as i8 = -128
        assert_eq!(decode_snr(&[0x80]), Some(-128_i8));
        // raw 0x00 = 0
        assert_eq!(decode_snr(&[0x00]), Some(0_i8));
        // raw 0x7F = 127
        assert_eq!(decode_snr(&[0x7F]), Some(127_i8));
        // empty
        assert_eq!(decode_snr(&[]), None);
    }

    #[test]
    fn test_decode_battery() {
        // Charging, 85%
        assert_eq!(
            decode_battery(&[0x02, 85]),
            Some((BatteryState::Charging, 85))
        );
        // Discharging, 50%
        assert_eq!(
            decode_battery(&[0x01, 50]),
            Some((BatteryState::Discharging, 50))
        );
        // Charged, 100%
        assert_eq!(
            decode_battery(&[0x03, 100]),
            Some((BatteryState::Charged, 100))
        );
        // Unknown state byte
        assert_eq!(decode_battery(&[0x00, 0]), Some((BatteryState::Unknown, 0)));
        // Too short
        assert_eq!(decode_battery(&[0x02]), None);
        assert_eq!(decode_battery(&[]), None);
    }

    #[test]
    fn test_decode_temperature() {
        // raw 150 -> 150 - 120 = 30 Celsius
        assert_eq!(decode_temperature(&[150]), Some(30));
        // raw 120 -> 120 - 120 = 0 Celsius
        assert_eq!(decode_temperature(&[120]), Some(0));
        // raw 90 -> 90 - 120 = -30 Celsius
        assert_eq!(decode_temperature(&[90]), Some(-30));
        // empty
        assert_eq!(decode_temperature(&[]), None);
    }

    #[test]
    fn test_decode_firmware_version() {
        assert_eq!(decode_firmware_version(&[1, 85]), Some((1, 85)));
        assert_eq!(decode_firmware_version(&[2, 0]), Some((2, 0)));
        // Too short
        assert_eq!(decode_firmware_version(&[1]), None);
        assert_eq!(decode_firmware_version(&[]), None);
    }

    #[test]
    fn test_decode_channel_stats_single() {
        // 11-byte single-interface payload
        let payload = [
            0x00, 0x64, // airtime_short = 100
            0x01, 0xF4, // airtime_long = 500
            0x00, 0xC8, // channel_load_short = 200
            0x02, 0x58, // channel_load_long = 600
            200,  // current_rssi raw -> 200 - 157 = 43
            100,  // noise_floor raw -> 100 - 157 = -57
            50,   // interference raw -> 50 - 157 = -107
        ];
        let stats = decode_channel_stats(&payload).unwrap();
        assert_eq!(stats.airtime_short, 100);
        assert_eq!(stats.airtime_long, 500);
        assert_eq!(stats.channel_load_short, 200);
        assert_eq!(stats.channel_load_long, 600);
        assert_eq!(stats.current_rssi, Some(43));
        assert_eq!(stats.noise_floor, Some(-57));
        assert_eq!(stats.interference, Some(-107));
    }

    #[test]
    fn test_decode_channel_stats_multi() {
        // 8-byte multi-interface payload (no RSSI fields)
        let payload = [
            0x00, 0x64, // airtime_short = 100
            0x01, 0xF4, // airtime_long = 500
            0x00, 0xC8, // channel_load_short = 200
            0x02, 0x58, // channel_load_long = 600
        ];
        let stats = decode_channel_stats(&payload).unwrap();
        assert_eq!(stats.airtime_short, 100);
        assert_eq!(stats.airtime_long, 500);
        assert_eq!(stats.channel_load_short, 200);
        assert_eq!(stats.channel_load_long, 600);
        assert_eq!(stats.current_rssi, None);
        assert_eq!(stats.noise_floor, None);
        assert_eq!(stats.interference, None);
    }

    #[test]
    fn test_decode_channel_stats_interference_ff() {
        // 11-byte payload with 0xFF interference -> None
        let payload = [
            0x00, 0x64, // airtime_short = 100
            0x01, 0xF4, // airtime_long = 500
            0x00, 0xC8, // channel_load_short = 200
            0x02, 0x58, // channel_load_long = 600
            200,  // current_rssi
            100,  // noise_floor
            0xFF, // interference = 0xFF -> None
        ];
        let stats = decode_channel_stats(&payload).unwrap();
        assert_eq!(stats.current_rssi, Some(43));
        assert_eq!(stats.noise_floor, Some(-57));
        assert_eq!(stats.interference, None);
    }

    #[test]
    fn test_decode_phy_params_single() {
        // 12-byte single-interface payload
        let payload = [
            0x00, 0x0A, // symbol_time_raw = 10
            0x03, 0xE8, // symbol_rate = 1000
            0x00, 0x08, // preamble_symbols = 8
            0x00, 0x50, // preamble_time_ms = 80
            0x00, 0x0F, // csma_slot_time_ms = 15
            0x00, 0x1E, // difs_time_ms = 30
        ];
        let params = decode_phy_params(&payload).unwrap();
        assert_eq!(params.symbol_time_raw, 10);
        assert_eq!(params.symbol_rate, 1000);
        assert_eq!(params.preamble_symbols, 8);
        assert_eq!(params.preamble_time_ms, 80);
        assert_eq!(params.csma_slot_time_ms, 15);
        assert_eq!(params.difs_time_ms, Some(30));
    }

    #[test]
    fn test_decode_phy_params_multi() {
        // 10-byte multi-interface payload (no difs_time)
        let payload = [
            0x00, 0x0A, // symbol_time_raw = 10
            0x03, 0xE8, // symbol_rate = 1000
            0x00, 0x08, // preamble_symbols = 8
            0x00, 0x50, // preamble_time_ms = 80
            0x00, 0x0F, // csma_slot_time_ms = 15
        ];
        let params = decode_phy_params(&payload).unwrap();
        assert_eq!(params.symbol_time_raw, 10);
        assert_eq!(params.symbol_rate, 1000);
        assert_eq!(params.preamble_symbols, 8);
        assert_eq!(params.preamble_time_ms, 80);
        assert_eq!(params.csma_slot_time_ms, 15);
        assert_eq!(params.difs_time_ms, None);
    }

    #[test]
    fn test_decode_too_short() {
        // All decode functions return None for empty/short payloads
        assert_eq!(decode_rssi(&[]), None);
        assert_eq!(decode_snr(&[]), None);
        assert_eq!(decode_battery(&[]), None);
        assert_eq!(decode_battery(&[0x01]), None);
        assert_eq!(decode_temperature(&[]), None);
        assert_eq!(decode_firmware_version(&[]), None);
        assert_eq!(decode_firmware_version(&[1]), None);
        assert_eq!(decode_channel_stats(&[]), None);
        assert_eq!(decode_channel_stats(&[0; 7]), None);
        assert_eq!(decode_phy_params(&[]), None);
        assert_eq!(decode_phy_params(&[0; 9]), None);
    }

    // --- Round-trip tests ---

    #[test]
    fn test_roundtrip_frequency() {
        let frame = build_set_frequency(868_000_000);
        let mut deframer = KissDeframer::with_max_payload(HW_MTU);
        let results = deframer.process(&frame);
        assert_eq!(results.len(), 1);
        match &results[0] {
            KissDeframeResult::Frame { command, payload } => {
                assert_eq!(*command, CMD_FREQUENCY);
                let hz = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                assert_eq!(hz, 868_000_000);
            }
            _ => panic!("Expected frame"),
        }
    }

    #[test]
    fn test_roundtrip_detect_query() {
        let query = build_detect_query();
        let mut deframer = KissDeframer::with_max_payload(HW_MTU);
        let results = deframer.process(&query);

        assert_eq!(results.len(), 4);

        // Frame 1: CMD_DETECT with DETECT_REQ
        match &results[0] {
            KissDeframeResult::Frame { command, payload } => {
                assert_eq!(*command, CMD_DETECT);
                assert_eq!(payload.as_slice(), &[DETECT_REQ]);
            }
            _ => panic!("Expected detect frame"),
        }

        // Frame 2: CMD_FW_VERSION query
        match &results[1] {
            KissDeframeResult::Frame { command, payload } => {
                assert_eq!(*command, CMD_FW_VERSION);
                assert_eq!(payload.as_slice(), &[0x00]);
            }
            _ => panic!("Expected fw_version frame"),
        }

        // Frame 3: CMD_PLATFORM query
        match &results[2] {
            KissDeframeResult::Frame { command, payload } => {
                assert_eq!(*command, CMD_PLATFORM);
                assert_eq!(payload.as_slice(), &[0x00]);
            }
            _ => panic!("Expected platform frame"),
        }

        // Frame 4: CMD_MCU query
        match &results[3] {
            KissDeframeResult::Frame { command, payload } => {
                assert_eq!(*command, CMD_MCU);
                assert_eq!(payload.as_slice(), &[0x00]);
            }
            _ => panic!("Expected mcu frame"),
        }
    }

    #[test]
    fn test_roundtrip_data_with_special_bytes() {
        // Data containing FEND and FESC bytes — must survive escaping
        let data = [0xC0, 0xDB, 0x42, 0xC0, 0xDB];
        let frame = build_data_frame(&data);
        let mut deframer = KissDeframer::with_max_payload(HW_MTU);
        let results = deframer.process(&frame);
        assert_eq!(results.len(), 1);
        match &results[0] {
            KissDeframeResult::Frame { command, payload } => {
                assert_eq!(*command, CMD_DATA);
                assert_eq!(payload.as_slice(), &data);
            }
            _ => panic!("Expected frame"),
        }
    }

    #[test]
    fn test_cmd_int_data_values() {
        assert_eq!(CMD_INT_DATA[0], 0x00);
        assert_eq!(CMD_INT_DATA[1], 0x10);
        assert_eq!(CMD_INT_DATA[2], 0x20);
        assert_eq!(CMD_INT_DATA[3], 0x70);
        assert_eq!(CMD_INT_DATA[4], 0x75);
        assert_eq!(CMD_INT_DATA[5], 0x90);
        assert_eq!(CMD_INT_DATA[6], 0xA0);
        assert_eq!(CMD_INT_DATA[7], 0xB0);
        assert_eq!(CMD_INT_DATA[8], 0xC0);
        assert_eq!(CMD_INT_DATA[9], 0xD0);
        assert_eq!(CMD_INT_DATA[10], 0xE0);
        assert_eq!(CMD_INT_DATA[11], 0xF0);
    }
}
