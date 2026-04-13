//! Serial interface — HDLC-framed bidirectional serial port
//!
//! Implements a plain serial interface matching Python Reticulum's
//! `SerialInterface`. Uses HDLC simplified framing (same as TCP and
//! LocalInterface) over a serial port.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use reticulum_core::constants::MTU;
use reticulum_core::framing::hdlc::{frame, DeframeResult, Deframer};
use reticulum_core::transport::InterfaceId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::{IncomingPacket, InterfaceCounters, InterfaceHandle, InterfaceInfo, OutgoingPacket};

/// Python SerialInterface HW_MTU
const SERIAL_HW_MTU: u32 = 564;

/// Default channel buffer size for serial interfaces.
pub(crate) const SERIAL_DEFAULT_BUFFER_SIZE: usize = 64;

/// Frame buffer multiplier (accounts for HDLC escaping overhead)
const FRAME_BUFFER_MULTIPLIER: usize = 2;

/// Read buffer size
const READ_BUF_SIZE: usize = 1024;

/// Incomplete frame timeout (ms). Matches Python SerialInterface.timeout = 100.
/// If no data arrives for this duration while in_frame, the partial frame is
/// discarded to prevent desynchronization from noise/corruption.
const FRAME_TIMEOUT: Duration = Duration::from_millis(100);

/// Reconnect interval after serial port loss
const RECONNECT_INTERVAL: Duration = Duration::from_secs(5);

/// Radio configuration to send to LNode firmware over serial (test infrastructure).
pub(crate) struct SerialRadioConfig {
    pub frequency: u64,
    pub bandwidth: u32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub tx_power: i8,
    pub preamble_len: u16,
    pub csma_enabled: bool,
}

/// Configuration for a serial interface.
pub(crate) struct SerialInterfaceConfig {
    pub id: InterfaceId,
    pub name: String,
    pub port: String,
    pub speed: u32,
    pub data_bits: tokio_serial::DataBits,
    pub parity: tokio_serial::Parity,
    pub stop_bits: tokio_serial::StopBits,
    pub buffer_size: usize,
    pub reconnect_notify: Option<mpsc::Sender<InterfaceId>>,
    pub radio_config: Option<SerialRadioConfig>,
}

/// Spawn a serial interface with automatic reconnection.
///
/// Creates channel pair once, spawns a reconnect task that reopens the port
/// on failure. The `InterfaceHandle` stays alive across reconnections.
pub(crate) fn spawn_serial_interface(config: SerialInterfaceConfig) -> InterfaceHandle {
    let (incoming_tx, incoming_rx) = mpsc::channel(config.buffer_size);
    let (outgoing_tx, outgoing_rx) = mpsc::channel(config.buffer_size);
    let counters = Arc::new(InterfaceCounters::new());

    let id = config.id;
    let handle_name = config.name.clone();
    let task_name = config.name.clone();
    let task_counters = Arc::clone(&counters);

    tokio::spawn(async move {
        serial_reconnect_task(
            id,
            config,
            task_name,
            incoming_tx,
            outgoing_rx,
            task_counters,
        )
        .await;
    });

    InterfaceHandle {
        info: InterfaceInfo {
            id,
            name: handle_name,
            hw_mtu: Some(SERIAL_HW_MTU),
            is_local_client: false,
            bitrate: None,
            ifac: None,
        },
        incoming: incoming_rx,
        outgoing: outgoing_tx,
        counters,
    }
}

/// Send a radio config frame to the LNode firmware and wait for ACK.
///
/// Retries up to 3 times with 2-second ACK timeout each. Returns true on success.
/// This is test infrastructure — normal usage never calls this.
async fn send_radio_config(
    port: &mut tokio_serial::SerialStream,
    config: &SerialRadioConfig,
    name: &str,
) -> bool {
    use reticulum_core::rnode::{RadioConfigWire, RADIO_CONFIG_ACK};

    let wire = RadioConfigWire {
        frequency_hz: config.frequency as u32,
        bandwidth_hz: config.bandwidth,
        sf: config.spreading_factor,
        cr: config.coding_rate,
        tx_power_dbm: config.tx_power,
        preamble_len: config.preamble_len,
        csma_enabled: config.csma_enabled,
    };
    let payload = reticulum_core::rnode::build_radio_config_frame(&wire);
    let mut frame_buf = Vec::new();
    frame(&payload, &mut frame_buf);

    for attempt in 1..=3u8 {
        tracing::info!(
            "Serial {}: sending radio config (attempt {}/3): freq={} sf={} bw={} cr={} txp={}",
            name,
            attempt,
            config.frequency,
            config.spreading_factor,
            config.bandwidth,
            config.coding_rate,
            config.tx_power
        );
        if let Err(e) = port.write_all(&frame_buf).await {
            tracing::warn!("Serial {}: config write failed: {}", name, e);
            continue;
        }
        if let Err(e) = port.flush().await {
            tracing::warn!("Serial {}: config flush failed: {}", name, e);
            continue;
        }

        // Wait for ACK
        let mut deframer = Deframer::new();
        let mut buf = [0u8; 64];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                tracing::warn!("Serial {}: config ACK timeout (attempt {})", name, attempt);
                break;
            }
            match tokio::time::timeout(remaining, port.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    for r in deframer.process(&buf[..n]) {
                        if let DeframeResult::Frame(data) = r {
                            if data.len() == RADIO_CONFIG_ACK.len()
                                && data[..] == RADIO_CONFIG_ACK[..]
                            {
                                tracing::info!("Serial {}: radio config ACK received", name);
                                return true;
                            }
                        }
                    }
                }
                Ok(Ok(_)) => break, // EOF
                Ok(Err(e)) => {
                    tracing::warn!("Serial {}: config ACK read error: {}", name, e);
                    break;
                }
                Err(_) => break, // timeout
            }
        }
    }
    tracing::error!("Serial {}: radio config failed after 3 attempts", name);
    false
}

/// Reconnect wrapper for serial port connections.
///
/// Owns channel endpoints across reconnection cycles. On port loss, waits
/// RECONNECT_INTERVAL and retries. Follows the TCP reconnect pattern.
async fn serial_reconnect_task(
    id: InterfaceId,
    config: SerialInterfaceConfig,
    name: String,
    incoming_tx: mpsc::Sender<IncomingPacket>,
    mut outgoing_rx: mpsc::Receiver<OutgoingPacket>,
    counters: Arc<InterfaceCounters>,
) {
    let mut has_connected_before = false;
    loop {
        // Set low_latency mode so the kernel batches USB CDC-ACM writes into
        // 64-byte bulk transfers instead of sending byte-by-byte. Without this,
        // HDLC frames arrive one byte at a time and the receiver's frame timeout
        // discards most frames. pyserial does this via set_low_latency_mode().
        let _ = std::process::Command::new("stty")
            .args(["-F", &config.port, "low_latency"])
            .output();

        let builder = tokio_serial::new(&config.port, config.speed)
            .data_bits(config.data_bits)
            .stop_bits(config.stop_bits)
            .parity(config.parity)
            .flow_control(tokio_serial::FlowControl::None);

        match tokio_serial::SerialStream::open(&builder) {
            Ok(mut port) => {
                let is_reconnect = has_connected_before;
                has_connected_before = true;
                tracing::info!("Serial interface {} online on {}", name, config.port);

                if is_reconnect {
                    if let Some(ref notify) = config.reconnect_notify {
                        let _ = notify.try_send(id);
                    }
                }

                // Send radio config if configured (test infrastructure)
                if let Some(ref radio_cfg) = config.radio_config {
                    if !send_radio_config(&mut port, radio_cfg, &name).await {
                        tracing::warn!(
                            "Serial {}: radio config not acknowledged, T114 uses defaults",
                            name
                        );
                    }
                }

                outgoing_rx = serial_io_task(
                    name.clone(),
                    port,
                    incoming_tx.clone(),
                    outgoing_rx,
                    Arc::clone(&counters),
                )
                .await;
                tracing::warn!("Serial interface {}: port lost, will reconnect", name);
            }
            Err(e) => {
                tracing::warn!(
                    "Serial interface {}: open {} failed: {}",
                    name,
                    config.port,
                    e
                );
            }
        }

        if incoming_tx.is_closed() {
            tracing::debug!("Serial interface {}: event loop shut down", name);
            return;
        }
        tracing::info!(
            "Serial interface {}: reconnecting in {}s",
            name,
            RECONNECT_INTERVAL.as_secs()
        );
        tokio::time::sleep(RECONNECT_INTERVAL).await;
    }
}

/// Bidirectional serial I/O task.
///
/// Read path: serial read → HDLC deframe → incoming channel
/// Write path: outgoing channel → HDLC frame → serial write → flush
///
/// Enforces:
/// - Frame timeout: partial frames discarded after 100ms of silence (Python parity)
/// - HW_MTU: deframer buffer exceeding 564 bytes is reset (prevents OOM on embedded)
///
/// Returns `outgoing_rx` on port loss for reconnect reuse.
async fn serial_io_task(
    name: String,
    mut port: tokio_serial::SerialStream,
    incoming_tx: mpsc::Sender<IncomingPacket>,
    mut outgoing_rx: mpsc::Receiver<OutgoingPacket>,
    counters: Arc<InterfaceCounters>,
) -> mpsc::Receiver<OutgoingPacket> {
    let mut deframer = Deframer::new();
    let mut read_buf = vec![0u8; READ_BUF_SIZE];
    let mut frame_buf = Vec::with_capacity(MTU * FRAME_BUFFER_MULTIPLIER);
    let mut last_read_at = Instant::now();

    loop {
        // Compute timeout: if mid-frame, use FRAME_TIMEOUT; otherwise wait indefinitely
        let timeout = if deframer.is_in_frame() {
            let elapsed = last_read_at.elapsed();
            if elapsed >= FRAME_TIMEOUT {
                // Already expired — reset immediately
                tracing::trace!("Serial {}: frame timeout, discarding partial frame", name);
                deframer.reset();
                tokio::time::sleep(Duration::from_millis(1)).await;
                continue;
            }
            FRAME_TIMEOUT - elapsed
        } else {
            Duration::from_secs(3600) // effectively infinite
        };

        tokio::select! {
            // Read path
            result = port.read(&mut read_buf) => {
                match result {
                    Ok(0) => {
                        tracing::debug!("Serial interface {} EOF", name);
                        return outgoing_rx;
                    }
                    Ok(n) => {
                        last_read_at = Instant::now();
                        let results = deframer.process(&read_buf[..n]);
                        for r in results {
                            if let DeframeResult::Frame(data) = r {
                                counters.rx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                                if incoming_tx.send(IncomingPacket { data }).await.is_err() {
                                    return outgoing_rx;
                                }
                            }
                        }
                        // HW_MTU enforcement: reset if buffer grew beyond limit
                        if deframer.buffer_len() > SERIAL_HW_MTU as usize {
                            tracing::trace!(
                                "Serial {}: frame exceeds HW_MTU ({}), discarding",
                                name, deframer.buffer_len()
                            );
                            deframer.reset();
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Serial interface {} read error: {}", name, e);
                        return outgoing_rx;
                    }
                }
            }

            // Write path
            msg = outgoing_rx.recv() => {
                match msg {
                    Some(pkt) => {
                        tracing::debug!("Serial interface {} TX {} bytes", name, pkt.data.len());
                        frame(&pkt.data, &mut frame_buf);
                        if let Err(e) = port.write_all(&frame_buf).await {
                            tracing::debug!("Serial interface {} write error: {}", name, e);
                            return outgoing_rx;
                        }
                        if let Err(e) = port.flush().await {
                            tracing::debug!("Serial interface {} flush error: {}", name, e);
                            return outgoing_rx;
                        }
                        counters.tx_bytes.fetch_add(frame_buf.len() as u64, Ordering::Relaxed);
                    }
                    None => {
                        tracing::debug!("Serial interface {} outgoing channel closed", name);
                        return outgoing_rx;
                    }
                }
            }

            // Frame timeout
            _ = tokio::time::sleep(timeout) => {
                if deframer.is_in_frame() {
                    tracing::trace!("Serial {}: frame timeout, discarding partial frame", name);
                    deframer.reset();
                }
            }
        }
    }
}

/// Parse a parity string ("N", "E"/"even", "O"/"odd") to tokio_serial::Parity.
pub(crate) fn parse_parity(s: &str) -> tokio_serial::Parity {
    match s.to_lowercase().as_str() {
        "e" | "even" => tokio_serial::Parity::Even,
        "o" | "odd" => tokio_serial::Parity::Odd,
        _ => tokio_serial::Parity::None,
    }
}

/// Parse a data bits value to tokio_serial::DataBits.
pub(crate) fn parse_data_bits(n: u8) -> tokio_serial::DataBits {
    match n {
        5 => tokio_serial::DataBits::Five,
        6 => tokio_serial::DataBits::Six,
        7 => tokio_serial::DataBits::Seven,
        _ => tokio_serial::DataBits::Eight,
    }
}

/// Parse a stop bits value to tokio_serial::StopBits.
pub(crate) fn parse_stop_bits(n: u8) -> tokio_serial::StopBits {
    match n {
        2 => tokio_serial::StopBits::Two,
        _ => tokio_serial::StopBits::One,
    }
}
