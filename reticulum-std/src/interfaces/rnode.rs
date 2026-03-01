//! RNode serial interface — detection, configuration, and data path
//!
//! Implements the full RNode lifecycle: detect → configure radio → validate →
//! go online → bidirectional data → reconnect on failure → graceful shutdown.
//!
//! Behind `#[cfg(feature = "serial")]`.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use rand_core::RngCore;
use reticulum_core::framing::kiss::{KissDeframeResult, KissDeframer};
use reticulum_core::rnode;
use reticulum_core::transport::InterfaceId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::{IncomingPacket, InterfaceCounters, InterfaceHandle, InterfaceInfo, OutgoingPacket};

/// Result of an RNode detection probe
#[derive(Debug)]
struct RNodeDetectResult {
    detected: bool,
    firmware_version: Option<(u8, u8)>,
    platform: Option<u8>,
    mcu: Option<u8>,
}

/// Errors from RNode serial operations
#[derive(Debug, thiserror::Error)]
pub(crate) enum RNodeError {
    #[error("serial port error: {0}")]
    SerialPort(String),
    #[error("device not detected")]
    NotDetected,
    #[error("firmware {0}.{1} below minimum {2}.{3}")]
    FirmwareTooOld(u8, u8, u8, u8),
    #[error("radio config mismatch: {0}")]
    RadioMismatch(String),
}

/// Radio parameters for RNode configuration
struct RadioParams {
    frequency: u32,
    bandwidth: u32,
    tx_power: u8,
    sf: u8,
    cr: u8,
    st_alock: Option<u16>,
    lt_alock: Option<u16>,
}

/// Configuration for spawning an RNode interface
pub(crate) struct RNodeInterfaceConfig {
    pub id: InterfaceId,
    pub name: String,
    pub port_path: String,
    pub frequency: u32,
    pub bandwidth: u32,
    pub tx_power: u8,
    pub sf: u8,
    pub cr: u8,
    pub st_alock: Option<u16>,
    pub lt_alock: Option<u16>,
    pub flow_control: bool,
    pub buffer_size: usize,
    pub reconnect_notify: Option<mpsc::Sender<InterfaceId>>,
}

impl RNodeInterfaceConfig {
    fn radio_params(&self) -> RadioParams {
        RadioParams {
            frequency: self.frequency,
            bandwidth: self.bandwidth,
            tx_power: self.tx_power,
            sf: self.sf,
            cr: self.cr,
            st_alock: self.st_alock,
            lt_alock: self.lt_alock,
        }
    }
}

/// Default channel buffer size for RNode interfaces.
/// Smaller than TCP because LoRa bitrates are orders of magnitude lower.
pub(crate) const RNODE_DEFAULT_BUFFER_SIZE: usize = 64;

/// Maximum queued TX packets when flow control is active and device is busy.
/// Python uses an unbounded queue. Bounded to 64 here because at LoRa bitrates,
/// a full unbounded queue contains minutes-old stale packets. Drop oldest with warn!.
const FLOW_CONTROL_QUEUE_LIMIT: usize = 64;

// ---------------------------------------------------------------------------
// Configuration (includes detection)
// ---------------------------------------------------------------------------

/// Open a serial port, detect the RNode, validate firmware, and configure radio.
///
/// Sequence matches Python RNodeInterface.configure_device():
/// 1. Open serial 115200/8N1
/// 2. Sleep 2s (device settle)
/// 3. Detect + validate firmware >= 1.52
/// 4. Send config commands: frequency, bandwidth, txpower, sf, cr, [st_alock], [lt_alock], radio ON
/// 5. Sleep 250ms, read confirmation frames 250ms
/// 6. Validate: frequency within 100 Hz, others exact match
/// 7. Sleep 300ms
async fn configure_rnode(
    port_path: &str,
    radio: &RadioParams,
) -> Result<(tokio_serial::SerialStream, RNodeDetectResult), RNodeError> {
    let builder = tokio_serial::new(port_path, 115_200)
        .data_bits(tokio_serial::DataBits::Eight)
        .stop_bits(tokio_serial::StopBits::One)
        .parity(tokio_serial::Parity::None)
        .flow_control(tokio_serial::FlowControl::None);

    let mut port = tokio_serial::SerialStream::open(&builder)
        .map_err(|e| RNodeError::SerialPort(e.to_string()))?;

    // Wait for device to settle
    tokio::time::sleep(Duration::from_secs(2)).await;

    // --- Detection phase ---
    let detect_result = detect_on_port(&mut port).await?;

    // Validate firmware version
    if let Some((major, minor)) = detect_result.firmware_version {
        if !rnode::validate_firmware(major, minor) {
            return Err(RNodeError::FirmwareTooOld(
                major,
                minor,
                rnode::REQUIRED_FW_MAJ,
                rnode::REQUIRED_FW_MIN,
            ));
        }
    } else {
        return Err(RNodeError::NotDetected);
    }

    // --- Configuration phase ---
    send_radio_config(&mut port, radio).await?;

    // Wait for device to process configuration
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Read and validate confirmation frames
    validate_radio_config(&mut port, radio, port_path).await?;

    // Final settle
    tokio::time::sleep(Duration::from_millis(300)).await;

    Ok((port, detect_result))
}

/// Send detect query and parse response frames from an open port.
async fn detect_on_port(
    port: &mut tokio_serial::SerialStream,
) -> Result<RNodeDetectResult, RNodeError> {
    let query = rnode::build_detect_query();
    port.write_all(&query)
        .await
        .map_err(|e| RNodeError::SerialPort(e.to_string()))?;

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
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                for frame in deframer.process(&buf[..n]) {
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
                            _ => {}
                        }
                    }
                }
            }
            Ok(Err(e)) => return Err(RNodeError::SerialPort(e.to_string())),
            Err(_) => break,
        }
    }

    if !result.detected {
        return Err(RNodeError::NotDetected);
    }

    Ok(result)
}

/// Send radio configuration commands to the RNode.
async fn send_radio_config(
    port: &mut tokio_serial::SerialStream,
    radio: &RadioParams,
) -> Result<(), RNodeError> {
    let mut config_bytes = Vec::with_capacity(64);
    config_bytes.extend_from_slice(&rnode::build_set_frequency(radio.frequency));
    config_bytes.extend_from_slice(&rnode::build_set_bandwidth(radio.bandwidth));
    config_bytes.extend_from_slice(&rnode::build_set_txpower(radio.tx_power));
    config_bytes.extend_from_slice(&rnode::build_set_sf(radio.sf));
    config_bytes.extend_from_slice(&rnode::build_set_cr(radio.cr));
    if let Some(st) = radio.st_alock {
        config_bytes.extend_from_slice(&rnode::build_set_st_alock(st));
    }
    if let Some(lt) = radio.lt_alock {
        config_bytes.extend_from_slice(&rnode::build_set_lt_alock(lt));
    }
    config_bytes.extend_from_slice(&rnode::build_set_radio_state(rnode::RADIO_STATE_ON));

    port.write_all(&config_bytes)
        .await
        .map_err(|e| RNodeError::SerialPort(e.to_string()))
}

/// Read confirmation frames and validate they match the requested config.
async fn validate_radio_config(
    port: &mut tokio_serial::SerialStream,
    radio: &RadioParams,
    name: &str,
) -> Result<(), RNodeError> {
    let mut confirmed_freq: Option<u32> = None;
    let mut confirmed_bw: Option<u32> = None;
    let mut confirmed_txp: Option<u8> = None;
    let mut confirmed_sf: Option<u8> = None;
    let mut confirmed_cr: Option<u8> = None;
    let mut confirmed_radio_state: Option<u8> = None;

    let mut deframer = KissDeframer::with_max_payload(rnode::HW_MTU);
    let mut buf = [0u8; 256];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, port.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                for frame in deframer.process(&buf[..n]) {
                    if let KissDeframeResult::Frame { command, payload } = frame {
                        match command {
                            rnode::CMD_FREQUENCY if payload.len() >= 4 => {
                                confirmed_freq = Some(u32::from_be_bytes([
                                    payload[0], payload[1], payload[2], payload[3],
                                ]));
                            }
                            rnode::CMD_BANDWIDTH if payload.len() >= 4 => {
                                confirmed_bw = Some(u32::from_be_bytes([
                                    payload[0], payload[1], payload[2], payload[3],
                                ]));
                            }
                            rnode::CMD_TXPOWER if !payload.is_empty() => {
                                confirmed_txp = Some(payload[0]);
                            }
                            rnode::CMD_SF if !payload.is_empty() => {
                                confirmed_sf = Some(payload[0]);
                            }
                            rnode::CMD_CR if !payload.is_empty() => {
                                confirmed_cr = Some(payload[0]);
                            }
                            rnode::CMD_RADIO_STATE if !payload.is_empty() => {
                                confirmed_radio_state = Some(payload[0]);
                            }
                            _ => {}
                        }
                    }
                }
            }
            Ok(Err(e)) => return Err(RNodeError::SerialPort(e.to_string())),
            Err(_) => break,
        }
    }

    // Log warnings for missing confirmations to aid debugging
    if confirmed_freq.is_none() {
        tracing::debug!("{}: no frequency confirmation received", name);
    }
    if confirmed_bw.is_none() {
        tracing::debug!("{}: no bandwidth confirmation received", name);
    }
    if confirmed_txp.is_none() {
        tracing::debug!("{}: no tx_power confirmation received", name);
    }
    if confirmed_sf.is_none() {
        tracing::debug!("{}: no spreading factor confirmation received", name);
    }
    if confirmed_cr.is_none() {
        tracing::debug!("{}: no coding rate confirmation received", name);
    }
    if confirmed_radio_state.is_none() {
        tracing::debug!("{}: no radio_state confirmation received", name);
    }

    if let Some(cf) = confirmed_freq {
        if cf.abs_diff(radio.frequency) > 100 {
            return Err(RNodeError::RadioMismatch(format!(
                "frequency: requested {} Hz, got {} Hz",
                radio.frequency, cf
            )));
        }
    }
    if let Some(cb) = confirmed_bw {
        if cb != radio.bandwidth {
            return Err(RNodeError::RadioMismatch(format!(
                "bandwidth: requested {} Hz, got {} Hz",
                radio.bandwidth, cb
            )));
        }
    }
    if let Some(ct) = confirmed_txp {
        if ct != radio.tx_power {
            return Err(RNodeError::RadioMismatch(format!(
                "tx_power: requested {} dBm, got {} dBm",
                radio.tx_power, ct
            )));
        }
    }
    if let Some(cs) = confirmed_sf {
        if cs != radio.sf {
            return Err(RNodeError::RadioMismatch(format!(
                "sf: requested {}, got {}",
                radio.sf, cs
            )));
        }
    }
    if let Some(cc) = confirmed_cr {
        if cc != radio.cr {
            return Err(RNodeError::RadioMismatch(format!(
                "cr: requested {}, got {}",
                radio.cr, cc
            )));
        }
    }
    if confirmed_radio_state == Some(rnode::RADIO_STATE_OFF) {
        return Err(RNodeError::RadioMismatch(
            "radio did not turn on".to_string(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// I/O task
// ---------------------------------------------------------------------------

/// Bidirectional I/O loop for a configured RNode.
///
/// Returns the `outgoing_rx` on disconnect so the reconnect wrapper can
/// reuse the same channel (matching TCP interface pattern).
///
/// Send-side jitter: packets are not sent immediately. The first packet after
/// idle gets a random 0–500ms delay (desynchronizes rebroadcasts from multiple
/// nodes). Subsequent queued packets use a fixed 50ms spacing to avoid serial
/// buffer overrun. RNode firmware CSMA handles radio-level collision avoidance.
async fn rnode_io_task(
    name: String,
    mut port: tokio_serial::SerialStream,
    incoming_tx: mpsc::Sender<IncomingPacket>,
    mut outgoing_rx: mpsc::Receiver<OutgoingPacket>,
    counters: Arc<InterfaceCounters>,
    flow_control: bool,
    bitrate_bps: u32,
) -> mpsc::Receiver<OutgoingPacket> {
    let mut deframer = KissDeframer::with_max_payload(rnode::HW_MTU);
    let mut buf = [0u8; 1024];
    let mut interface_ready = !flow_control; // If no flow control, always ready
    let mut send_queue: VecDeque<(Vec<u8>, u64)> = VecDeque::new();
    let mut send_timer: Option<Pin<Box<tokio::time::Sleep>>> = None;
    let mut timer_ready = false;

    tracing::debug!(
        "{}: jitter: bitrate={} bps, min_spacing={}ms, jitter_max={}ms",
        name,
        bitrate_bps,
        rnode::MIN_SPACING_MS,
        rnode::JITTER_MAX_MS
    );

    loop {
        tokio::select! {
            // Branch 1: Read from serial port
            result = port.read(&mut buf) => {
                match result {
                    Ok(0) => {
                        tracing::warn!("{}: serial port EOF", name);
                        return outgoing_rx;
                    }
                    Ok(n) => {
                        let frames = deframer.process(&buf[..n]);
                        for frame in frames {
                            if let KissDeframeResult::Frame { command, payload } = frame {
                                match command {
                                    rnode::CMD_DATA => {
                                        counters.rx_bytes.fetch_add(
                                            payload.len() as u64,
                                            std::sync::atomic::Ordering::Relaxed,
                                        );
                                        let pkt = IncomingPacket { data: payload.to_vec() };
                                        if incoming_tx.send(pkt).await.is_err() {
                                            // Event loop shut down
                                            send_goodbye(&mut port).await;
                                            return outgoing_rx;
                                        }
                                    }
                                    rnode::CMD_READY => {
                                        if flow_control {
                                            interface_ready = true;
                                        }
                                    }
                                    rnode::CMD_RESET => {
                                        if payload.first() == Some(&0xF8) {
                                            tracing::warn!("{}: device reset (0xF8)", name);
                                            return outgoing_rx;
                                        }
                                    }
                                    rnode::CMD_ERROR => {
                                        let code = payload.first().copied().unwrap_or(0);
                                        match code {
                                            rnode::ERROR_INITRADIO => {
                                                tracing::error!("{}: INITRADIO error", name);
                                                return outgoing_rx;
                                            }
                                            rnode::ERROR_TXFAILED => {
                                                tracing::error!("{}: TXFAILED error", name);
                                                return outgoing_rx;
                                            }
                                            _ => {
                                                tracing::warn!(
                                                    "{}: device error code 0x{:02X}",
                                                    name, code
                                                );
                                            }
                                        }
                                    }
                                    // Statistics — log at trace level
                                    // TODO: Parse stat values (RSSI, SNR, channel time,
                                    // battery, temperature) and store for rnstatus reporting
                                    // — see ROADMAP "RNode Stats Parsing"
                                    rnode::CMD_STAT_RSSI
                                    | rnode::CMD_STAT_SNR
                                    | rnode::CMD_STAT_CHTM
                                    | rnode::CMD_STAT_PHYPRM
                                    | rnode::CMD_STAT_BAT
                                    | rnode::CMD_STAT_TEMP => {
                                        tracing::trace!(
                                            "{}: stat cmd 0x{:02X} ({} bytes)",
                                            name, command, payload.len()
                                        );
                                    }
                                    _ => {
                                        tracing::trace!(
                                            "{}: unhandled cmd 0x{:02X}",
                                            name, command
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("{}: serial read error: {}", name, e);
                        return outgoing_rx;
                    }
                }
            }

            // Branch 2: Outgoing packet from driver → enqueue with jitter
            recv = outgoing_rx.recv() => {
                match recv {
                    Some(pkt) => {
                        let frame = rnode::build_data_frame(&pkt.data);
                        if send_queue.len() >= FLOW_CONTROL_QUEUE_LIMIT {
                            tracing::warn!("{}: send queue full, dropping oldest", name);
                            send_queue.pop_front();
                        }
                        send_queue.push_back((frame, pkt.data.len() as u64));
                        // Start jitter timer if idle (no active timer, no pending send)
                        if send_timer.is_none() && !timer_ready {
                            let delay = rand_core::OsRng.next_u64() % rnode::JITTER_MAX_MS;
                            tracing::debug!(
                                "{}: send queue: {} packets, jitter {}ms",
                                name, send_queue.len(), delay
                            );
                            send_timer = Some(Box::pin(
                                tokio::time::sleep(Duration::from_millis(delay))
                            ));
                        }
                    }
                    None => {
                        // Event loop shut down
                        send_goodbye(&mut port).await;
                        return outgoing_rx;
                    }
                }
            }

            // Branch 3: Send timer fires
            _ = async { send_timer.as_mut().unwrap().await },
                if send_timer.is_some() => {
                send_timer = None;
                timer_ready = true;
            }
        }

        // After any branch: try to send if both gates are open
        //   Gate 1: timer_ready (jitter/spacing delay elapsed)
        //   Gate 2: interface_ready || !flow_control
        if timer_ready && (interface_ready || !flow_control) {
            if let Some((frame, payload_len)) = send_queue.pop_front() {
                if let Err(e) = port.write_all(&frame).await {
                    tracing::warn!("{}: write error: {}", name, e);
                    return outgoing_rx;
                }
                counters
                    .tx_bytes
                    .fetch_add(payload_len, std::sync::atomic::Ordering::Relaxed);
                tracing::trace!("{}: TX {} bytes", name, payload_len);

                timer_ready = false;
                if flow_control {
                    interface_ready = false;
                }

                // Schedule next if queue not empty
                if !send_queue.is_empty() {
                    send_timer = Some(Box::pin(tokio::time::sleep(Duration::from_millis(
                        rnode::MIN_SPACING_MS,
                    ))));
                }
            } else {
                timer_ready = false;
            }
        }
    }
}

/// Best-effort send radio-off + leave commands on shutdown
async fn send_goodbye(port: &mut tokio_serial::SerialStream) {
    let mut goodbye = rnode::build_set_radio_state(rnode::RADIO_STATE_OFF);
    goodbye.extend_from_slice(&rnode::build_leave());
    let _ = port.write_all(&goodbye).await;
}

// ---------------------------------------------------------------------------
// Reconnect wrapper
// ---------------------------------------------------------------------------

/// Reconnect loop: configure → I/O → on disconnect → wait → retry.
async fn rnode_reconnect_task(
    config: RNodeInterfaceConfig,
    incoming_tx: mpsc::Sender<IncomingPacket>,
    mut outgoing_rx: mpsc::Receiver<OutgoingPacket>,
    counters: Arc<InterfaceCounters>,
) {
    let radio = config.radio_params();
    let bitrate_bps = rnode::compute_bitrate(radio.sf, radio.cr, radio.bandwidth);
    let mut has_connected_before = false;

    loop {
        match configure_rnode(&config.port_path, &radio).await {
            Ok((port, detect)) => {
                let is_reconnect = has_connected_before;
                has_connected_before = true;

                if let Some((major, minor)) = detect.firmware_version {
                    tracing::info!(
                        "{}: configured (FW {}.{}, freq={} Hz, bw={} Hz, sf={}, cr={}, txp={} dBm)",
                        config.name,
                        major,
                        minor,
                        radio.frequency,
                        radio.bandwidth,
                        radio.sf,
                        radio.cr,
                        radio.tx_power
                    );
                }

                // Notify driver about reconnection so it can re-announce
                if is_reconnect {
                    if let Some(ref notify) = config.reconnect_notify {
                        let _ = notify.try_send(config.id);
                    }
                }

                outgoing_rx = rnode_io_task(
                    config.name.clone(),
                    port,
                    incoming_tx.clone(),
                    outgoing_rx,
                    Arc::clone(&counters),
                    config.flow_control,
                    bitrate_bps,
                )
                .await;

                tracing::warn!("{}: disconnected", config.name);
            }
            Err(e) => {
                tracing::warn!("{}: configuration failed: {}", config.name, e);
            }
        }

        // Check if event loop shut down
        if incoming_tx.is_closed() {
            tracing::debug!("{}: event loop shut down, stopping reconnect", config.name);
            return;
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

// ---------------------------------------------------------------------------
// Spawn
// ---------------------------------------------------------------------------

/// Spawn a complete RNode interface with reconnection support.
///
/// Creates channels + counters, spawns the reconnect task, and returns an
/// `InterfaceHandle` for the event loop.
pub(crate) fn spawn_rnode_interface(config: RNodeInterfaceConfig) -> InterfaceHandle {
    let (incoming_tx, incoming_rx) = mpsc::channel(config.buffer_size);
    let (outgoing_tx, outgoing_rx) = mpsc::channel(config.buffer_size);
    let counters = Arc::new(InterfaceCounters::new());

    let id = config.id;
    let name = config.name.clone();
    let task_counters = Arc::clone(&counters);
    let bitrate = rnode::compute_bitrate(config.sf, config.cr, config.bandwidth);

    tokio::spawn(async move {
        rnode_reconnect_task(config, incoming_tx, outgoing_rx, task_counters).await;
    });

    InterfaceHandle {
        info: InterfaceInfo {
            id,
            name,
            hw_mtu: Some(rnode::HW_MTU as u32),
            is_local_client: false,
            bitrate: Some(bitrate),
        },
        incoming: incoming_rx,
        outgoing: outgoing_tx,
        counters,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires RNode hardware at /dev/ttyACM0
    async fn test_configure_real_rnode() {
        let radio = RadioParams {
            frequency: 868_000_000,
            bandwidth: 125_000,
            tx_power: 17,
            sf: 7,
            cr: 5,
            st_alock: None,
            lt_alock: None,
        };
        let result = configure_rnode("/dev/ttyACM0", &radio).await;

        match result {
            Ok((mut port, detect)) => {
                println!("RNode configured successfully!");
                if let Some((major, minor)) = detect.firmware_version {
                    println!("  Firmware: {major}.{minor}");
                }
                if let Some(platform) = detect.platform {
                    let name = match platform {
                        rnode::PLATFORM_ESP32 => "ESP32",
                        rnode::PLATFORM_NRF52 => "nRF52",
                        rnode::PLATFORM_AVR => "AVR",
                        _ => "Unknown",
                    };
                    println!("  Platform: {name} (0x{platform:02X})");
                }
                if let Some(mcu) = detect.mcu {
                    println!("  MCU: 0x{mcu:02X}");
                }
                // Turn radio off and send leave
                send_goodbye(&mut port).await;
                println!("  Radio off, leave sent");
            }
            Err(e) => {
                panic!("Configuration failed: {e}");
            }
        }
    }

    #[tokio::test]
    #[ignore] // Requires RNode hardware at /dev/ttyACM0
    async fn test_rnode_interface_lifecycle() {
        let config = RNodeInterfaceConfig {
            id: InterfaceId(0),
            name: "test_rnode".to_string(),
            port_path: "/dev/ttyACM0".to_string(),
            frequency: 868_000_000,
            bandwidth: 125_000,
            tx_power: 17,
            sf: 7,
            cr: 5,
            st_alock: None,
            lt_alock: None,
            flow_control: true,
            buffer_size: RNODE_DEFAULT_BUFFER_SIZE,
            reconnect_notify: None,
        };

        let mut handle = spawn_rnode_interface(config);

        // Wait for the interface to come online (~5s for detect + configure)
        println!("Waiting for RNode to come online...");
        tokio::time::sleep(Duration::from_secs(6)).await;

        assert!(
            handle.info.bitrate.is_some(),
            "bitrate should be computed at spawn"
        );
        println!("Bitrate: {} bps", handle.info.bitrate.unwrap());

        // Send a test packet via outgoing channel
        let test_data = b"Hello from Rust RNode test";
        handle
            .outgoing
            .send(OutgoingPacket {
                data: test_data.to_vec(),
            })
            .await
            .expect("send should succeed");
        println!("Sent test packet ({} bytes)", test_data.len());

        // Brief wait, then drop the handle to trigger shutdown
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drop outgoing sender to signal shutdown
        drop(handle.outgoing);

        // Read remaining incoming (drain)
        while let Ok(pkt) = handle.incoming.try_recv() {
            println!("Received: {} bytes", pkt.data.len());
        }

        println!("Interface lifecycle test complete");
    }
}
