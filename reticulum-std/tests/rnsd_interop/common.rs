//! Shared test infrastructure for rnsd interop tests

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use rand_core::OsRng;

use reticulum_core::constants::{MTU, TRUNCATED_HASHBYTES};
use reticulum_core::crypto::truncated_hash;
use reticulum_core::destination::{Destination, DestinationType, Direction};
use reticulum_core::identity::Identity;
use reticulum_core::packet::{Packet, PacketType};
use reticulum_core::traits::{NoStorage, PlatformContext};
use reticulum_std::interfaces::hdlc::{frame, DeframeResult, Deframer};
use reticulum_std::SystemClock;

/// Create a platform context for tests
fn test_context() -> PlatformContext<OsRng, SystemClock, NoStorage> {
    PlatformContext {
        rng: OsRng,
        clock: SystemClock::new(),
        storage: NoStorage,
    }
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
}

/// Helper to compute name_hash from app_name and aspects
/// Delegates to Destination::compute_name_hash
pub fn compute_name_hash(app_name: &str, aspects: &[&str]) -> [u8; 10] {
    Destination::compute_name_hash(app_name, aspects)
}

/// Helper to compute destination_hash from name_hash and identity_hash
pub fn compute_destination_hash(name_hash: &[u8; 10], identity_hash: &[u8; 16]) -> [u8; 16] {
    let mut hash_material = Vec::with_capacity(26);
    hash_material.extend_from_slice(name_hash);
    hash_material.extend_from_slice(identity_hash);
    truncated_hash(&hash_material)
}

/// Build and send a valid announce on the given stream.
/// Returns (destination_hash, destination) for verification.
pub async fn build_and_send_announce(
    stream: &mut TcpStream,
    app_name: &str,
    aspects: &[&str],
    app_data: &[u8],
) -> ([u8; TRUNCATED_HASHBYTES], Destination) {
    let identity = Identity::generate_with_rng(&mut OsRng);
    let dest = Destination::new(
        Some(identity),
        Direction::In,
        DestinationType::Single,
        app_name,
        aspects,
    );

    let mut ctx = test_context();
    let packet = dest
        .announce(Some(app_data), &mut ctx)
        .expect("Failed to create announce");

    let mut raw_packet = [0u8; MTU];
    let size = packet.pack(&mut raw_packet).expect("Failed to pack packet");

    let mut framed = Vec::new();
    frame(&raw_packet[..size], &mut framed);

    stream.write_all(&framed).await.expect("Failed to send");
    stream.flush().await.expect("Failed to flush");

    let dest_hash = *dest.hash();
    (dest_hash, dest)
}

/// Build a valid announce as raw bytes (not framed), returning (raw_bytes, dest_hash, destination).
pub fn build_announce_raw(
    app_name: &str,
    aspects: &[&str],
    app_data: &[u8],
) -> (Vec<u8>, [u8; TRUNCATED_HASHBYTES], Destination) {
    let identity = Identity::generate_with_rng(&mut OsRng);
    let dest = Destination::new(
        Some(identity),
        Direction::In,
        DestinationType::Single,
        app_name,
        aspects,
    );

    let mut ctx = test_context();
    let packet = dest
        .announce(Some(app_data), &mut ctx)
        .expect("Failed to create announce");

    let mut raw_packet = [0u8; MTU];
    let size = packet.pack(&mut raw_packet).expect("Failed to pack packet");

    let dest_hash = *dest.hash();
    (raw_packet[..size].to_vec(), dest_hash, dest)
}

/// Build announce raw bytes with a specific hops value
pub fn build_announce_raw_with_hops(
    app_name: &str,
    aspects: &[&str],
    app_data: &[u8],
    hops: u8,
) -> (Vec<u8>, [u8; TRUNCATED_HASHBYTES], Destination) {
    let (mut raw, dest_hash, dest) = build_announce_raw(app_name, aspects, app_data);
    // Hops is the second byte (offset 1) in the raw packet
    raw[1] = hops;
    (raw, dest_hash, dest)
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

/// Transport routing information extracted from an announce packet.
/// This contains the information needed to route link requests through intermediate nodes.
#[derive(Debug)]
pub struct AnnounceRouteInfo {
    /// The announce packet
    pub packet: Packet,
    /// The transport_id from HEADER_2 announces, or None for direct announces
    pub transport_id: Option<[u8; 16]>,
    /// The hop count from the announce
    pub hops: u8,
}

impl AnnounceRouteInfo {
    /// Extract the destination's signing key from the announce payload.
    /// The signing key is bytes 32-64 of the public key in the announce data.
    pub fn signing_key(&self) -> Option<[u8; 32]> {
        let data = self.packet.data.as_slice();
        if data.len() >= 64 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[32..64]);
            Some(key)
        } else {
            None
        }
    }
}

/// Wait for any announce packet on the given stream.
/// Returns the Packet if found within the timeout, allowing the caller to extract
/// the signing key and other data from the announce.
pub async fn wait_for_any_announce_packet(
    stream: &mut TcpStream,
    deframer: &mut Deframer,
    timeout_duration: Duration,
) -> Option<Packet> {
    wait_for_any_announce_with_route_info(stream, deframer, timeout_duration)
        .await
        .map(|info| info.packet)
}

/// Wait for any announce packet and return full routing information.
/// This includes the transport_id and hops needed for multi-hop link establishment.
pub async fn wait_for_any_announce_with_route_info(
    stream: &mut TcpStream,
    deframer: &mut Deframer,
    timeout_duration: Duration,
) -> Option<AnnounceRouteInfo> {
    let mut buffer = [0u8; 2048];
    let start = std::time::Instant::now();

    while start.elapsed() < timeout_duration {
        match timeout(Duration::from_millis(100), stream.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                let results = deframer.process(&buffer[..n]);
                for result in results {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == PacketType::Announce {
                                return Some(AnnounceRouteInfo {
                                    transport_id: pkt.transport_id,
                                    hops: pkt.hops,
                                    packet: pkt,
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
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

// =========================================================================
// Test daemon helpers
// =========================================================================

use crate::harness::TestDaemon;

/// Time to wait after connecting to daemon before sending data.
/// The daemon's TCPServerInterface needs time to initialize client connections.
pub const DAEMON_SETTLE_TIME: Duration = Duration::from_millis(500);

/// Time to wait for daemon to process a packet and update its state.
pub const DAEMON_PROCESS_TIME: Duration = Duration::from_millis(200);

/// Build and send a valid announce to a daemon, returning the destination hash.
/// This is a convenience wrapper that handles stream creation and timing.
pub async fn send_announce_to_daemon(
    daemon: &TestDaemon,
    app_name: &str,
    aspects: &[&str],
    app_data: &[u8],
) -> [u8; TRUNCATED_HASHBYTES] {
    let mut stream = TcpStream::connect(daemon.rns_addr())
        .await
        .expect("Failed to connect to daemon");

    // Wait for interface to settle
    tokio::time::sleep(DAEMON_SETTLE_TIME).await;

    let (dest_hash, _dest) = build_and_send_announce(&mut stream, app_name, aspects, app_data).await;

    // Wait for daemon to process the announce
    tokio::time::sleep(DAEMON_PROCESS_TIME).await;

    dest_hash
}

/// Build and send raw announce bytes to a daemon.
pub async fn send_raw_to_daemon(daemon: &TestDaemon, raw: &[u8]) {
    let mut stream = TcpStream::connect(daemon.rns_addr())
        .await
        .expect("Failed to connect to daemon");

    // Wait for interface to settle
    tokio::time::sleep(DAEMON_SETTLE_TIME).await;

    send_framed(&mut stream, raw).await;

    // Wait for daemon to process
    tokio::time::sleep(DAEMON_PROCESS_TIME).await;
}

/// Connect to daemon and wait for interface to settle.
pub async fn connect_to_daemon(daemon: &TestDaemon) -> TcpStream {
    let stream = TcpStream::connect(daemon.rns_addr())
        .await
        .expect("Failed to connect to daemon");

    // Wait for interface to settle
    tokio::time::sleep(DAEMON_SETTLE_TIME).await;

    stream
}

// =========================================================================
// Link test helpers
// =========================================================================

use reticulum_core::packet::PacketContext;

/// Wait for a proof packet for a specific link ID.
pub async fn receive_proof_for_link(
    stream: &mut TcpStream,
    deframer: &mut Deframer,
    link_id: &[u8; 16],
    timeout_duration: Duration,
) -> Option<Packet> {
    let mut buffer = [0u8; 2048];
    let start = std::time::Instant::now();

    while start.elapsed() < timeout_duration {
        match timeout(Duration::from_millis(100), stream.read(&mut buffer)).await {
            Ok(Ok(0)) => return None,
            Ok(Ok(n)) => {
                let results = deframer.process(&buffer[..n]);
                for result in results {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == PacketType::Proof
                                && pkt.destination_hash == *link_id
                            {
                                return Some(pkt);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// Receive a data packet on a link and decrypt it.
/// Returns the decrypted data if successful.
pub async fn receive_link_data(
    stream: &mut TcpStream,
    deframer: &mut Deframer,
    link: &reticulum_core::link::Link,
    timeout_duration: Duration,
) -> Option<Vec<u8>> {
    let mut buffer = [0u8; 2048];
    let start = std::time::Instant::now();

    while start.elapsed() < timeout_duration {
        match timeout(Duration::from_millis(100), stream.read(&mut buffer)).await {
            Ok(Ok(0)) => return None,
            Ok(Ok(n)) => {
                let results = deframer.process(&buffer[..n]);
                for result in results {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == PacketType::Data
                                && pkt.destination_hash == *link.id()
                                && pkt.context == PacketContext::None
                            {
                                let mut decrypted = vec![0u8; pkt.data.len()];
                                if let Ok(len) = link.decrypt(pkt.data.as_slice(), &mut decrypted)
                                {
                                    decrypted.truncate(len);
                                    return Some(decrypted);
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
}
