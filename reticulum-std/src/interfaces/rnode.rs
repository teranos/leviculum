//! RNode serial interface — device detection
//!
//! Provides `detect_rnode()` for probing an RNode device on a serial port.
//! Behind `#[cfg(feature = "serial")]`.

use reticulum_core::framing::kiss::{KissDeframeResult, KissDeframer};
use reticulum_core::rnode;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Result of an RNode detection probe
#[derive(Debug)]
pub(crate) struct RNodeDetectResult {
    /// Whether the device responded with DETECT_RESP
    pub detected: bool,
    /// Firmware version (major, minor) if reported
    pub firmware_version: Option<(u8, u8)>,
    /// Platform byte if reported
    pub platform: Option<u8>,
    /// MCU byte if reported
    pub mcu: Option<u8>,
}

/// Errors from RNode serial operations
#[derive(Debug, thiserror::Error)]
pub(crate) enum RNodeError {
    #[error("serial port error: {0}")]
    SerialPort(String),
    #[error("detection timed out")]
    Timeout,
    #[error("device not detected")]
    NotDetected,
}

/// Probe a serial port for an RNode device
///
/// Opens the port at 115200 8N1, waits for the device to settle, sends the
/// detect query sequence, and parses response frames for up to 200ms.
///
/// # Errors
///
/// Returns `RNodeError::SerialPort` if the port cannot be opened,
/// `RNodeError::Timeout` if no response arrives within the detection window,
/// or `RNodeError::NotDetected` if the device does not send DETECT_RESP.
pub(crate) async fn detect_rnode(port_path: &str) -> Result<RNodeDetectResult, RNodeError> {
    let builder = tokio_serial::new(port_path, 115_200)
        .data_bits(tokio_serial::DataBits::Eight)
        .stop_bits(tokio_serial::StopBits::One)
        .parity(tokio_serial::Parity::None)
        .flow_control(tokio_serial::FlowControl::None);

    let mut port = tokio_serial::SerialStream::open(&builder)
        .map_err(|e| RNodeError::SerialPort(e.to_string()))?;

    // Wait for device to settle after USB enumeration / power-on
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Send detect + query sequence
    let query = rnode::build_detect_query();
    port.write_all(&query)
        .await
        .map_err(|e| RNodeError::SerialPort(e.to_string()))?;

    // Read responses for up to 200ms
    let mut deframer = KissDeframer::with_max_payload(rnode::HW_MTU);
    let mut buf = [0u8; 256];
    let mut result = RNodeDetectResult {
        detected: false,
        firmware_version: None,
        platform: None,
        mcu: None,
    };

    let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, port.read(&mut buf)).await {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => {
                let frames = deframer.process(&buf[..n]);
                for frame in frames {
                    if let KissDeframeResult::Frame { command, payload } = frame {
                        match command {
                            rnode::CMD_DETECT => {
                                if payload.first() == Some(&rnode::DETECT_RESP) {
                                    result.detected = true;
                                }
                            }
                            rnode::CMD_FW_VERSION => {
                                result.firmware_version = rnode::decode_firmware_version(&payload);
                            }
                            rnode::CMD_PLATFORM => {
                                result.platform = payload.first().copied();
                            }
                            rnode::CMD_MCU => {
                                result.mcu = payload.first().copied();
                            }
                            _ => {} // Ignore other frames (e.g. battery reports)
                        }
                    }
                }
            }
            Ok(Err(e)) => return Err(RNodeError::SerialPort(e.to_string())),
            Err(_) => break, // Timeout
        }
    }

    if !result.detected {
        return Err(RNodeError::NotDetected);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires RNode hardware at /dev/ttyACM0
    async fn test_detect_real_rnode() {
        let result = detect_rnode("/dev/ttyACM0").await;
        match result {
            Ok(info) => {
                assert!(info.detected);
                println!("Detected RNode:");
                if let Some((major, minor)) = info.firmware_version {
                    println!("  Firmware: {major}.{minor}");
                }
                if let Some(platform) = info.platform {
                    let name = match platform {
                        rnode::PLATFORM_ESP32 => "ESP32",
                        rnode::PLATFORM_NRF52 => "nRF52",
                        rnode::PLATFORM_AVR => "AVR",
                        _ => "Unknown",
                    };
                    println!("  Platform: {name} (0x{platform:02X})");
                }
                if let Some(mcu) = info.mcu {
                    println!("  MCU: 0x{mcu:02X}");
                }
            }
            Err(e) => {
                panic!("Detection failed: {e}");
            }
        }
    }
}
