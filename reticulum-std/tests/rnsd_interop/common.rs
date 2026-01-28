//! Shared test infrastructure for rnsd interop tests

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use rand_core::{OsRng, RngCore};

use reticulum_core::constants::{MTU, TRUNCATED_HASHBYTES};
use reticulum_core::crypto::{full_hash, truncated_hash};
use reticulum_core::destination::DestinationType;
use reticulum_core::identity::Identity;
use reticulum_core::packet::{
    HeaderType, Packet, PacketContext, PacketData, PacketFlags, PacketType, TransportType,
};
use reticulum_std::interfaces::hdlc::{frame, DeframeResult, Deframer};

pub const RNSD_ADDR: &str = "127.0.0.1:4242";
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Time to wait after opening TCP connections before sending data.
/// rnsd needs time to fully initialize spawned TCPClientInterfaces
/// (including interface_post_init which sets OUT=True).
pub const INTERFACE_SETTLE_TIME: Duration = Duration::from_millis(1500);

/// Time to wait for announce propagation between two connections.
/// rnsd retransmits announces with a random 0-0.5s delay, checked every ~1s.
pub const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Default path to rnsd log file
const RNSD_LOG_PATH: &str = concat!(env!("HOME"), "/.reticulum/logfile");

/// Errors that indicate packet format problems in rnsd logs
const RNSD_ERROR_PATTERNS: &[&str] = &[
    "Error while loading public key",
    "Invalid announce",
    "Dropped invalid",
    "Could not unpack",
    "Signature validation failed",
    "Error while validating",
];

/// Log monitor for checking rnsd errors during tests
pub struct RnsdLogMonitor {
    path: String,
    start_position: u64,
}

impl RnsdLogMonitor {
    /// Create a new log monitor, recording current end of file
    pub fn new() -> Option<Self> {
        let path = std::env::var("RNSD_LOG_PATH").unwrap_or_else(|_| RNSD_LOG_PATH.to_string());

        let file = File::open(&path).ok()?;
        let start_position = file.metadata().ok()?.len();

        Some(Self {
            path,
            start_position,
        })
    }

    /// Check for errors in log entries since monitor was created
    pub fn check_for_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();

        let mut file = match File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return errors,
        };

        if file.seek(SeekFrom::Start(self.start_position)).is_err() {
            return errors;
        }

        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(line) = line {
                for pattern in RNSD_ERROR_PATTERNS {
                    if line.contains(pattern) {
                        errors.push(line.clone());
                        break;
                    }
                }
            }
        }

        errors
    }

    /// Get all new log entries since monitor was created
    #[allow(dead_code)]
    pub fn get_new_entries(&self) -> Vec<String> {
        let mut entries = Vec::new();

        let mut file = match File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return entries,
        };

        if file.seek(SeekFrom::Start(self.start_position)).is_err() {
            return entries;
        }

        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            entries.push(line);
        }

        entries
    }
}

/// Helper to check if rnsd is available
pub async fn rnsd_available() -> bool {
    timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

/// Parsed announce data for verification
pub struct ParsedAnnounce {
    pub destination_hash: [u8; 16],
    pub public_key: Vec<u8>,
    pub name_hash: Vec<u8>,
    pub random_hash: Vec<u8>,
    pub ratchet: Vec<u8>,
    pub signature: Vec<u8>,
    pub app_data: Vec<u8>,
    pub has_ratchet: bool,
}

impl ParsedAnnounce {
    /// Parse an announce payload
    ///
    /// Announce format depends on context_flag:
    /// - context_flag=0: public_key(64) + name_hash(10) + random_hash(10) + signature(64) + app_data
    /// - context_flag=1: public_key(64) + name_hash(10) + random_hash(10) + ratchet(32) + signature(64) + app_data
    pub fn from_packet(packet: &Packet) -> Option<Self> {
        let payload = packet.data.as_slice();
        let has_ratchet = packet.flags.context_flag;

        if has_ratchet {
            if payload.len() < 180 {
                return None;
            }
            Some(Self {
                destination_hash: packet.destination_hash,
                public_key: payload[0..64].to_vec(),
                name_hash: payload[64..74].to_vec(),
                random_hash: payload[74..84].to_vec(),
                ratchet: payload[84..116].to_vec(),
                signature: payload[116..180].to_vec(),
                app_data: payload[180..].to_vec(),
                has_ratchet: true,
            })
        } else {
            if payload.len() < 148 {
                return None;
            }
            Some(Self {
                destination_hash: packet.destination_hash,
                public_key: payload[0..64].to_vec(),
                name_hash: payload[64..74].to_vec(),
                random_hash: payload[74..84].to_vec(),
                ratchet: Vec::new(),
                signature: payload[84..148].to_vec(),
                app_data: payload[148..].to_vec(),
                has_ratchet: false,
            })
        }
    }

    /// Compute the signed data for signature verification
    pub fn signed_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(100 + self.ratchet.len() + self.app_data.len());
        data.extend_from_slice(&self.destination_hash);
        data.extend_from_slice(&self.public_key);
        data.extend_from_slice(&self.name_hash);
        data.extend_from_slice(&self.random_hash);
        data.extend_from_slice(&self.ratchet);
        data.extend_from_slice(&self.app_data);
        data
    }

    /// Compute identity hash from public key
    pub fn computed_identity_hash(&self) -> [u8; 16] {
        truncated_hash(&self.public_key)
    }

    /// Compute destination hash from name_hash and identity_hash
    pub fn computed_destination_hash(&self) -> [u8; 16] {
        let identity_hash = self.computed_identity_hash();
        let mut hash_material = Vec::with_capacity(26);
        hash_material.extend_from_slice(&self.name_hash);
        hash_material.extend_from_slice(&identity_hash);
        truncated_hash(&hash_material)
    }

    /// Get app_data as string if valid UTF-8
    #[allow(dead_code)]
    pub fn app_data_string(&self) -> Option<String> {
        std::str::from_utf8(&self.app_data)
            .ok()
            .map(|s| s.to_string())
    }
}

/// Helper to generate a random hash (10 bytes: 5 random + 5 timestamp)
pub fn generate_random_hash() -> [u8; 10] {
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut random_16 = [08; 16];
    OsRng.fill_bytes(&mut random_16);
    let random_hash = truncated_hash(&random_16);

    let timestamp_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let timestamp_bytes = timestamp_secs.to_be_bytes();

    let mut result = [0u8; 10];
    result[0..5].copy_from_slice(&random_hash[0..5]);
    result[5..10].copy_from_slice(&timestamp_bytes[3..8]);
    result
}

/// Helper to compute name_hash from app_name and aspects
pub fn compute_name_hash(app_name: &str, aspects: &[&str]) -> [u8; 10] {
    let mut full_name = app_name.to_string();
    for aspect in aspects {
        full_name.push('.');
        full_name.push_str(aspect);
    }

    let hash = full_hash(full_name.as_bytes());
    let mut result = [0u8; 10];
    result.copy_from_slice(&hash[..10]);
    result
}

/// Helper to compute destination_hash from name_hash and identity_hash
pub fn compute_destination_hash(name_hash: &[u8; 10], identity_hash: &[u8; 16]) -> [u8; 16] {
    let mut hash_material = Vec::with_capacity(26);
    hash_material.extend_from_slice(name_hash);
    hash_material.extend_from_slice(identity_hash);
    truncated_hash(&hash_material)
}

/// Build and send a valid announce on the given stream.
/// Returns (destination_hash, identity) for verification.
pub async fn build_and_send_announce(
    stream: &mut TcpStream,
    app_name: &str,
    aspects: &[&str],
    app_data: &[u8],
) -> ([u8; TRUNCATED_HASHBYTES], Identity) {
    let identity = Identity::generate_with_rng(&mut rand_core::OsRng);
    let public_key = identity.public_key_bytes();
    let identity_hash = *identity.hash();

    let name_hash = compute_name_hash(app_name, aspects);
    let random_hash = generate_random_hash();
    let destination_hash = compute_destination_hash(&name_hash, &identity_hash);

    let mut signed_data = Vec::with_capacity(100 + app_data.len());
    signed_data.extend_from_slice(&destination_hash);
    signed_data.extend_from_slice(&public_key);
    signed_data.extend_from_slice(&name_hash);
    signed_data.extend_from_slice(&random_hash);
    signed_data.extend_from_slice(app_data);

    let signature = identity.sign(&signed_data).expect("Failed to sign");

    let mut payload = Vec::with_capacity(148 + app_data.len());
    payload.extend_from_slice(&public_key);
    payload.extend_from_slice(&name_hash);
    payload.extend_from_slice(&random_hash);
    payload.extend_from_slice(&signature);
    payload.extend_from_slice(app_data);

    let packet = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Single,
            packet_type: PacketType::Announce,
        },
        hops: 0,
        transport_id: None,
        destination_hash,
        context: PacketContext::None,
        data: PacketData::Owned(payload),
    };

    let mut raw_packet = [0u8; MTU];
    let size = packet.pack(&mut raw_packet).expect("Failed to pack packet");

    let mut framed = Vec::new();
    frame(&raw_packet[..size], &mut framed);

    stream.write_all(&framed).await.expect("Failed to send");
    stream.flush().await.expect("Failed to flush");

    (destination_hash, identity)
}

/// Build a valid announce as raw bytes (not framed), returning (raw_bytes, dest_hash, identity).
pub fn build_announce_raw(
    app_name: &str,
    aspects: &[&str],
    app_data: &[u8],
) -> (Vec<u8>, [u8; TRUNCATED_HASHBYTES], Identity) {
    let identity = Identity::generate_with_rng(&mut rand_core::OsRng);
    let public_key = identity.public_key_bytes();
    let identity_hash = *identity.hash();

    let name_hash = compute_name_hash(app_name, aspects);
    let random_hash = generate_random_hash();
    let destination_hash = compute_destination_hash(&name_hash, &identity_hash);

    let mut signed_data = Vec::with_capacity(100 + app_data.len());
    signed_data.extend_from_slice(&destination_hash);
    signed_data.extend_from_slice(&public_key);
    signed_data.extend_from_slice(&name_hash);
    signed_data.extend_from_slice(&random_hash);
    signed_data.extend_from_slice(app_data);

    let signature = identity.sign(&signed_data).expect("Failed to sign");

    let mut payload = Vec::with_capacity(148 + app_data.len());
    payload.extend_from_slice(&public_key);
    payload.extend_from_slice(&name_hash);
    payload.extend_from_slice(&random_hash);
    payload.extend_from_slice(&signature);
    payload.extend_from_slice(app_data);

    let packet = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Single,
            packet_type: PacketType::Announce,
        },
        hops: 0,
        transport_id: None,
        destination_hash,
        context: PacketContext::None,
        data: PacketData::Owned(payload),
    };

    let mut raw_packet = [0u8; MTU];
    let size = packet.pack(&mut raw_packet).expect("Failed to pack packet");

    (raw_packet[..size].to_vec(), destination_hash, identity)
}

/// Build announce raw bytes with a specific hops value
pub fn build_announce_raw_with_hops(
    app_name: &str,
    aspects: &[&str],
    app_data: &[u8],
    hops: u8,
) -> (Vec<u8>, [u8; TRUNCATED_HASHBYTES], Identity) {
    let (mut raw, dest_hash, identity) = build_announce_raw(app_name, aspects, app_data);
    // Hops is the second byte (offset 1) in the raw packet
    raw[1] = hops;
    (raw, dest_hash, identity)
}

/// Wait for an announce with a specific destination hash on the given stream.
/// Returns true if found within the timeout.
pub async fn wait_for_announce(
    stream: &mut TcpStream,
    dest_hash: &[u8; TRUNCATED_HASHBYTES],
    timeout_duration: Duration,
) -> bool {
    let mut deframer = Deframer::new();
    let mut buffer = [0u8; 2048];
    let start = std::time::Instant::now();

    while start.elapsed() < timeout_duration {
        match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                let results = deframer.process(&buffer[..n]);
                for result in results {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == PacketType::Announce
                                && pkt.destination_hash == *dest_hash
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Collect all announces received on a stream within a timeout.
/// Returns a list of (destination_hash, raw_data) pairs.
pub async fn collect_announces(
    stream: &mut TcpStream,
    timeout_duration: Duration,
) -> Vec<([u8; TRUNCATED_HASHBYTES], Vec<u8>)> {
    let mut deframer = Deframer::new();
    let mut buffer = [0u8; 2048];
    let mut announces = Vec::new();
    let start = std::time::Instant::now();

    while start.elapsed() < timeout_duration {
        match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                let results = deframer.process(&buffer[..n]);
                for result in results {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == PacketType::Announce {
                                announces.push((pkt.destination_hash, data));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    announces
}

/// Send raw bytes (already packed, not framed) over a stream with HDLC framing
pub async fn send_framed(stream: &mut TcpStream, raw: &[u8]) {
    let mut framed = Vec::new();
    frame(raw, &mut framed);
    stream.write_all(&framed).await.expect("Failed to send");
    stream.flush().await.expect("Failed to flush");
}

/// Check that a connection is still open by waiting briefly for data or timeout
pub async fn connection_alive(stream: &mut TcpStream) -> bool {
    let mut buffer = [0u8; 1];
    match timeout(Duration::from_millis(200), stream.read(&mut buffer)).await {
        Ok(Ok(0)) => false, // Connection closed
        Ok(Err(_)) => false, // Error
        _ => true,           // Timeout or got data = alive
    }
}
