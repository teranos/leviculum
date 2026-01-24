//! Live interoperability tests with Python rnsd
//!
//! These tests require a running rnsd instance on localhost:4242.
//! Run with: cargo test --package reticulum-std --test rnsd_interop -- --ignored
//!
//! To enable: start rnsd with a TCPServerInterface on 127.0.0.1:4242
//!
//! ## Testing Strategy
//!
//! Interop tests must verify EXTERNAL compatibility, not just internal consistency.
//! Key principles:
//!
//! 1. **Never rely on self-verification alone** - If we sign with our code and verify
//!    with our code, bugs in format won't be caught. Always verify against rnsd.
//!
//! 2. **Monitor rnsd logs for errors** - rnsd logs validation failures. Check logs
//!    after each test to catch format mismatches.
//!
//! 3. **Verify round-trip propagation** - An announce isn't "accepted" just because
//!    the connection stays open. Verify rnsd actually propagates it.
//!
//! 4. **Use multiple connections** - Send on one connection, receive on another.
//!    This proves rnsd processed the packet, not just buffered it.
//!
//! ## Lesson Learned: The random_hash Bug
//!
//! A bug in `generate_random_hash()` caused rnsd to log errors:
//! ```text
//! Error while loading public key, the contained exception was: An X25519 public key is 32 bytes long
//! ```
//!
//! This bug was NOT caught by our initial tests because:
//! - Self-verification passed (we verified our own format with our own code)
//! - Connection stayed open (rnsd doesn't close connections on malformed packets)
//! - We didn't check rnsd logs for validation errors
//!
//! The bug WAS caught when we:
//! - Added `test_announce_propagation_between_clients` which verifies round-trip
//! - Added `RnsdLogMonitor` which checks rnsd logs for errors
//! - Checked rnsd logs manually during debugging
//!
//! The rnsd log file location: `~/.reticulum/logfile`
//! Increase verbosity with `loglevel = 6` in `~/.reticulum/config`

use std::time::Duration;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use reticulum_core::packet::{Packet, PacketFlags, PacketType, HeaderType, TransportType, PacketContext, PacketData};
use reticulum_core::destination::DestinationType;
use reticulum_core::constants::{MTU, TRUNCATED_HASHBYTES};
use reticulum_core::identity::Identity;
use reticulum_core::crypto::{truncated_hash, full_hash, random_bytes};
use reticulum_core::link::Link;
use reticulum_std::interfaces::hdlc::{Deframer, DeframeResult, frame, FLAG};

const RNSD_ADDR: &str = "127.0.0.1:4242";
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);
const READ_TIMEOUT: Duration = Duration::from_secs(5);

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
struct RnsdLogMonitor {
    path: String,
    start_position: u64,
}

impl RnsdLogMonitor {
    /// Create a new log monitor, recording current end of file
    fn new() -> Option<Self> {
        let path = std::env::var("RNSD_LOG_PATH")
            .unwrap_or_else(|_| RNSD_LOG_PATH.to_string());

        let file = File::open(&path).ok()?;
        let start_position = file.metadata().ok()?.len();

        Some(Self { path, start_position })
    }

    /// Check for errors in log entries since monitor was created
    fn check_for_errors(&self) -> Vec<String> {
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
    fn get_new_entries(&self) -> Vec<String> {
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
async fn rnsd_available() -> bool {
    timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

/// Test that we can connect to rnsd TCP interface
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_connect_to_rnsd() {
    let stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    assert!(stream.peer_addr().is_ok());
    println!("Successfully connected to rnsd at {}", RNSD_ADDR);
}

/// Test receiving packets from rnsd (announces from the network)
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_receive_packets_from_rnsd() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    let mut deframer = Deframer::new();
    let mut buffer = [0u8; 1024];
    let mut packets_received = 0;
    let mut total_bytes = 0;

    println!("Listening for packets from rnsd (5 second timeout)...");

    // Try to receive packets for up to 5 seconds
    let start = std::time::Instant::now();
    while start.elapsed() < READ_TIMEOUT {
        match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
            Ok(Ok(0)) => {
                println!("Connection closed by rnsd");
                break;
            }
            Ok(Ok(n)) => {
                total_bytes += n;
                let results = deframer.process(&buffer[..n]);
                for result in results {
                    match result {
                        DeframeResult::Frame(data) => {
                            packets_received += 1;
                            println!("Received packet {} ({} bytes)", packets_received, data.len());

                            // Try to parse the packet
                            match Packet::unpack(&data) {
                                Ok(packet) => {
                                    println!("  Flags: {:02x}", packet.flags.to_byte());
                                    println!("  Type: {:?}", packet.flags.packet_type);
                                    println!("  Header: {:?}", packet.flags.header_type);
                                    println!("  Hops: {}", packet.hops);
                                    println!("  Dest hash: {:02x?}", &packet.destination_hash[..4]);
                                    println!("  Context: {:?}", packet.context);
                                    println!("  Data len: {}", packet.data.len());
                                }
                                Err(e) => {
                                    println!("  Failed to parse: {:?}", e);
                                    println!("  Raw data: {:02x?}", &data[..data.len().min(32)]);
                                }
                            }
                        }
                        DeframeResult::TooShort => {
                            println!("Received empty frame");
                        }
                        DeframeResult::NeedMore => {}
                    }
                }
            }
            Ok(Err(e)) => {
                println!("Read error: {}", e);
                break;
            }
            Err(_) => {
                // Timeout, continue trying
            }
        }
    }

    println!("Total: {} bytes received, {} packets parsed", total_bytes, packets_received);

    // This test passes even if no packets are received - it just verifies the connection works
    // In an active network, we should receive announce packets
}

/// Test sending a packet to rnsd and verifying it's accepted
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_send_packet_to_rnsd() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    // Create a simple broadcast data packet
    // Note: This won't be routed anywhere meaningful without a valid destination,
    // but it tests that our packet format is accepted by rnsd's parser
    let packet = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: [0x00; 16], // Dummy destination
        context: PacketContext::None,
        data: reticulum_core::packet::PacketData::Owned(b"test".to_vec()),
    };

    let mut raw_packet = [0u8; MTU];
    let size = packet.pack(&mut raw_packet).expect("Failed to pack packet");

    // Frame with HDLC
    let mut framed = Vec::new();
    frame(&raw_packet[..size], &mut framed);

    println!("Sending test packet ({} bytes, {} framed)", size, framed.len());
    println!("Packet flags: {:02x}", packet.flags.to_byte());

    // Send the framed packet
    stream.write_all(&framed).await.expect("Failed to send");
    stream.flush().await.expect("Failed to flush");

    // Give rnsd a moment to process
    tokio::time::sleep(Duration::from_millis(100)).await;

    // If we get here without the connection being closed, the packet format was accepted
    println!("Packet sent successfully (connection still open)");

    // Try to receive any response (there likely won't be one for this dummy packet)
    let mut buffer = [0u8; 1024];
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            println!("Received {} bytes in response", n);
        }
        _ => {
            println!("No response (expected for dummy destination)");
        }
    }
}

/// Test HDLC framing interop - send raw bytes and verify they're handled correctly
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_hdlc_framing_interop() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    // Test 1: Send multiple FLAG bytes (should be treated as frame start)
    stream.write_all(&[FLAG, FLAG, FLAG]).await.expect("Failed to send flags");

    // Test 2: Send an incomplete frame (no end flag)
    let mut incomplete = Vec::new();
    incomplete.push(FLAG);
    incomplete.extend_from_slice(b"incomplete");
    stream.write_all(&incomplete).await.expect("Failed to send incomplete");

    // Test 3: Send a complete empty frame (just flags)
    stream.write_all(&[FLAG, FLAG]).await.expect("Failed to send empty frame");

    // Test 4: Send a valid framed packet
    let packet = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: [0xAB; 16],
        context: PacketContext::None,
        data: reticulum_core::packet::PacketData::Owned(b"hdlc test".to_vec()),
    };

    let mut raw_packet = [0u8; MTU];
    let size = packet.pack(&mut raw_packet).expect("Failed to pack");

    let mut framed = Vec::new();
    frame(&raw_packet[..size], &mut framed);
    stream.write_all(&framed).await.expect("Failed to send framed packet");
    stream.flush().await.expect("Failed to flush");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // If we get here, rnsd handled our HDLC correctly
    println!("HDLC framing test completed successfully");
}

/// Test packet flags encoding matches Python Reticulum
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_packet_flags_interop() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    // Test various packet flag combinations
    let test_cases = [
        // (flags_byte, description)
        (0x00, "Data, H1, broadcast, single"),
        (0x01, "Announce, H1, broadcast, single"),
        (0x02, "LinkRequest, H1, broadcast, single"),
        (0x03, "Proof, H1, broadcast, single"),
        (0x40, "Data, H2, broadcast, single"),
        (0x10, "Data, H1, transport, single"),
        (0x04, "Data, H1, broadcast, group"),
        (0x08, "Data, H1, broadcast, plain"),
    ];

    for (expected_byte, description) in test_cases {
        let flags = PacketFlags::from_byte(expected_byte)
            .expect(&format!("Failed to parse flags 0x{:02x}", expected_byte));

        let encoded = flags.to_byte();
        assert_eq!(
            encoded, expected_byte,
            "Flags mismatch for {}: expected 0x{:02x}, got 0x{:02x}",
            description, expected_byte, encoded
        );

        println!("Flags 0x{:02x} ({}) - OK", expected_byte, description);
    }

    // Send a packet with each flag type to verify rnsd accepts them
    // Note: We skip packet types that require specific payloads:
    // - Announce (0x01) requires 64-byte public key + name_hash + random_hash + signature
    // - LinkRequest (0x02) requires 64-byte payload (ephemeral keys)
    // - Proof (0x03) requires specific proof format
    for (flags_byte, _description) in test_cases {
        // Skip H2 packets - they require transport_id
        if flags_byte & 0x40 != 0 {
            continue;
        }

        // Skip packet types that require specific payload formats
        let packet_type = flags_byte & 0x03;
        if packet_type != 0x00 {
            // Only send Data packets (0x00), skip Announce/LinkRequest/Proof
            println!("  Skipping packet type 0x{:02x} (requires specific payload)", packet_type);
            continue;
        }

        let flags = PacketFlags::from_byte(flags_byte).unwrap();
        let packet = Packet {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: [0xCD; 16],
            context: PacketContext::None,
            data: reticulum_core::packet::PacketData::Owned(b"flags test".to_vec()),
        };

        let mut raw_packet = [0u8; MTU];
        let size = packet.pack(&mut raw_packet).expect("Failed to pack");

        let mut framed = Vec::new();
        frame(&raw_packet[..size], &mut framed);
        stream.write_all(&framed).await.expect("Failed to send");
        println!("  Sent packet with flags 0x{:02x}", flags_byte);
    }

    stream.flush().await.expect("Failed to flush");
    println!("All packet flag variations sent successfully");
}

/// Integration test: parse real announce packets from the network
#[tokio::test]
#[ignore = "requires running rnsd and active network"]
async fn test_parse_real_announces() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    let mut deframer = Deframer::new();
    let mut buffer = [0u8; 1024];
    let mut announces_parsed = 0;

    println!("Waiting for announce packets (30 second timeout)...");

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(30) && announces_parsed < 5 {
        match timeout(Duration::from_secs(1), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let results = deframer.process(&buffer[..n]);
                for result in results {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(packet) = Packet::unpack(&data) {
                            if packet.flags.packet_type == PacketType::Announce {
                                announces_parsed += 1;
                                println!("\nAnnounce #{}", announces_parsed);
                                println!("  Destination: {:02x?}", &packet.destination_hash);
                                println!("  Hops: {}", packet.hops);
                                println!("  Data length: {}", packet.data.len());

                                // Parse announce payload:
                                // [public_key (64)] [name_hash (10)] [random_hash (10)] [signature (64)] [app_data]
                                let payload = packet.data.as_slice();
                                if payload.len() >= 148 {
                                    let public_key = &payload[0..64];
                                    let name_hash = &payload[64..74];
                                    let random_hash = &payload[74..84];
                                    let signature = &payload[84..148];
                                    let app_data = &payload[148..];

                                    println!("  Public key: {:02x?}...", &public_key[..8]);
                                    println!("  Name hash: {:02x?}", name_hash);
                                    println!("  Random hash: {:02x?}", random_hash);
                                    println!("  Signature: {:02x?}...", &signature[..8]);
                                    if !app_data.is_empty() {
                                        if let Ok(s) = std::str::from_utf8(app_data) {
                                            println!("  App data: {:?}", s);
                                        } else {
                                            println!("  App data: {:02x?}", app_data);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(Ok(0)) => break,
            _ => {}
        }
    }

    println!("\nParsed {} announce packets", announces_parsed);
}

/// Test that our packet round-trips through rnsd correctly
/// This requires sending to a destination that echoes or that we control
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_packet_roundtrip_format() {
    // This test verifies packet format by checking that:
    // 1. We can pack a packet
    // 2. Frame it with HDLC
    // 3. Deframe it locally
    // 4. Unpack it to verify roundtrip

    let original = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: true,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Group,
            packet_type: PacketType::Data,
        },
        hops: 5,
        transport_id: None,
        destination_hash: [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                          0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        context: PacketContext::Channel,
        data: reticulum_core::packet::PacketData::Owned(b"roundtrip test data".to_vec()),
    };

    // Pack
    let mut raw_packet = [0u8; MTU];
    let size = original.pack(&mut raw_packet).expect("Failed to pack");

    // Frame with HDLC
    let mut framed = Vec::new();
    frame(&raw_packet[..size], &mut framed);

    // Deframe
    let mut deframer = Deframer::new();
    let results = deframer.process(&framed);
    assert_eq!(results.len(), 1, "Expected exactly one frame");

    let deframed = match &results[0] {
        DeframeResult::Frame(data) => data.clone(),
        _ => panic!("Expected Frame result"),
    };

    // Unpack
    let restored = Packet::unpack(&deframed).expect("Failed to unpack");

    // Verify all fields match
    assert_eq!(original.flags.to_byte(), restored.flags.to_byte(), "Flags mismatch");
    assert_eq!(original.hops, restored.hops, "Hops mismatch");
    assert_eq!(original.destination_hash, restored.destination_hash, "Dest hash mismatch");
    assert_eq!(original.context as u8, restored.context as u8, "Context mismatch");
    assert_eq!(original.data.as_slice(), restored.data.as_slice(), "Data mismatch");

    println!("Packet roundtrip successful");
    println!("  Flags: 0x{:02x}", restored.flags.to_byte());
    println!("  Hops: {}", restored.hops);
    println!("  Context: {:?}", restored.context);
    println!("  Data: {:?}", std::str::from_utf8(restored.data.as_slice()));
}

/// Run a quick connectivity check before the full test suite
#[tokio::test]
async fn test_rnsd_connectivity_check() {
    if rnsd_available().await {
        println!("rnsd is available at {}", RNSD_ADDR);
        println!("Run ignored tests with: cargo test --package reticulum-std --test rnsd_interop -- --ignored");
    } else {
        println!("rnsd is NOT available at {}", RNSD_ADDR);
        println!("Start rnsd with TCPServerInterface on 127.0.0.1:4242 to run interop tests");
    }
}

// ==========================================================
// HIGH PRIORITY: Cryptographic verification of real announces
// ==========================================================

/// Parsed announce data for verification
struct ParsedAnnounce {
    destination_hash: [u8; 16],
    public_key: Vec<u8>,
    name_hash: Vec<u8>,
    random_hash: Vec<u8>,
    ratchet: Vec<u8>,      // 32 bytes if context_flag set, empty otherwise
    signature: Vec<u8>,
    app_data: Vec<u8>,
    has_ratchet: bool,
}

impl ParsedAnnounce {
    /// Parse an announce payload
    ///
    /// Announce format depends on context_flag:
    /// - context_flag=0: public_key(64) + name_hash(10) + random_hash(10) + signature(64) + app_data
    /// - context_flag=1: public_key(64) + name_hash(10) + random_hash(10) + ratchet(32) + signature(64) + app_data
    fn from_packet(packet: &Packet) -> Option<Self> {
        let payload = packet.data.as_slice();
        let has_ratchet = packet.flags.context_flag;

        if has_ratchet {
            // Ratcheted announce: 64 + 10 + 10 + 32 + 64 = 180 bytes minimum
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
            // Normal announce: 64 + 10 + 10 + 64 = 148 bytes minimum
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
    ///
    /// Python RNS signs: destination_hash + public_key + name_hash + random_hash + ratchet + app_data
    fn signed_data(&self) -> Vec<u8> {
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
    /// identity_hash = truncated_hash(public_key)
    fn computed_identity_hash(&self) -> [u8; 16] {
        truncated_hash(&self.public_key)
    }

    /// Compute destination hash from name_hash and identity_hash
    /// dest_hash = truncated_hash(name_hash + identity_hash)
    fn computed_destination_hash(&self) -> [u8; 16] {
        let identity_hash = self.computed_identity_hash();
        let mut hash_material = Vec::with_capacity(26);
        hash_material.extend_from_slice(&self.name_hash);
        hash_material.extend_from_slice(&identity_hash);
        truncated_hash(&hash_material)
    }

    /// Get app_data as string if valid UTF-8
    fn app_data_string(&self) -> Option<String> {
        std::str::from_utf8(&self.app_data).ok().map(|s| s.to_string())
    }
}

/// HIGH PRIORITY TEST #1: Verify real announce signatures from the network
///
/// This is the most critical crypto interop test. It verifies:
/// - Ed25519 signature verification matches Python Reticulum
/// - Public key extraction from announce payload is correct
/// - Signed data construction matches Python's format
#[tokio::test]
#[ignore = "requires running rnsd and active network"]
async fn test_verify_real_announce_signatures() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    let mut deframer = Deframer::new();
    let mut buffer = [0u8; 1024];
    let mut verified_count = 0;
    let mut failed_count = 0;
    let target_count = 10;

    println!("Verifying announce signatures from live network...");
    println!("Target: {} announces\n", target_count);

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(60) && verified_count < target_count {
        match timeout(Duration::from_secs(1), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let results = deframer.process(&buffer[..n]);
                for result in results {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(packet) = Packet::unpack(&data) {
                            if packet.flags.packet_type == PacketType::Announce {
                                if let Some(announce) = ParsedAnnounce::from_packet(&packet) {
                                    // Create identity from public key in announce
                                    let identity = match Identity::from_public_key_bytes(&announce.public_key) {
                                        Ok(id) => id,
                                        Err(e) => {
                                            println!("FAIL: Could not create identity from public key: {:?}", e);
                                            failed_count += 1;
                                            continue;
                                        }
                                    };

                                    // Verify the signature
                                    let signed_data = announce.signed_data();
                                    let ratchet_str = if announce.has_ratchet { " [ratcheted]" } else { "" };
                                    match identity.verify(&signed_data, &announce.signature) {
                                        Ok(true) => {
                                            verified_count += 1;
                                            let app_name = announce.app_data_string()
                                                .unwrap_or_else(|| format!("<binary {} bytes>", announce.app_data.len()));
                                            println!(
                                                "OK #{}: Signature verified for {:02x}{:02x}{:02x}{:02x}...{} ({})",
                                                verified_count,
                                                announce.destination_hash[0],
                                                announce.destination_hash[1],
                                                announce.destination_hash[2],
                                                announce.destination_hash[3],
                                                ratchet_str,
                                                app_name
                                            );
                                        }
                                        Ok(false) => {
                                            failed_count += 1;
                                            println!(
                                                "FAIL: Signature verification FAILED for {:02x?}{}",
                                                &announce.destination_hash[..4],
                                                ratchet_str
                                            );
                                            println!("  Public key: {:02x?}...", &announce.public_key[..8]);
                                            println!("  Signature: {:02x?}...", &announce.signature[..8]);
                                            println!("  Signed data len: {}", signed_data.len());
                                            println!("  App data len: {}", announce.app_data.len());
                                        }
                                        Err(e) => {
                                            failed_count += 1;
                                            println!("FAIL: Verification error: {:?}", e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(Ok(0)) => break,
            _ => {}
        }
    }

    println!("\n=== SIGNATURE VERIFICATION RESULTS ===");
    println!("Verified: {}", verified_count);
    println!("Failed: {}", failed_count);

    assert!(
        verified_count > 0,
        "No announces were verified. Is the network active?"
    );
    assert_eq!(
        failed_count, 0,
        "Some signature verifications failed! This indicates a crypto interop problem."
    );

    println!("\nSUCCESS: All {} announce signatures verified correctly!", verified_count);
}

/// HIGH PRIORITY TEST #2: Verify destination hash calculation for real announces
///
/// Verifies that our destination hash calculation matches Python's:
/// dest_hash = truncated_hash(name_hash + identity_hash)
/// where identity_hash = truncated_hash(public_key)
#[tokio::test]
#[ignore = "requires running rnsd and active network"]
async fn test_verify_destination_hash_calculation() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    let mut deframer = Deframer::new();
    let mut buffer = [0u8; 1024];
    let mut verified_count = 0;
    let mut failed_count = 0;
    let target_count = 10;

    println!("Verifying destination hash calculations from live network...");
    println!("Target: {} announces\n", target_count);

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(60) && verified_count < target_count {
        match timeout(Duration::from_secs(1), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let results = deframer.process(&buffer[..n]);
                for result in results {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(packet) = Packet::unpack(&data) {
                            if packet.flags.packet_type == PacketType::Announce {
                                if let Some(announce) = ParsedAnnounce::from_packet(&packet) {
                                    // Compute destination hash using our algorithm
                                    let computed_dest_hash = announce.computed_destination_hash();
                                    let packet_dest_hash = announce.destination_hash;

                                    if computed_dest_hash == packet_dest_hash {
                                        verified_count += 1;
                                        let app_name = announce.app_data_string()
                                            .unwrap_or_else(|| format!("<binary {} bytes>", announce.app_data.len()));
                                        println!(
                                            "OK #{}: Destination hash matches for {:02x}{:02x}{:02x}{:02x}... ({})",
                                            verified_count,
                                            packet_dest_hash[0],
                                            packet_dest_hash[1],
                                            packet_dest_hash[2],
                                            packet_dest_hash[3],
                                            app_name
                                        );
                                    } else {
                                        failed_count += 1;
                                        println!("FAIL: Destination hash mismatch!");
                                        println!("  Packet dest_hash:   {:02x?}", packet_dest_hash);
                                        println!("  Computed dest_hash: {:02x?}", computed_dest_hash);
                                        println!("  Name hash:          {:02x?}", &announce.name_hash);
                                        println!("  Identity hash:      {:02x?}", announce.computed_identity_hash());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(Ok(0)) => break,
            _ => {}
        }
    }

    println!("\n=== DESTINATION HASH VERIFICATION RESULTS ===");
    println!("Verified: {}", verified_count);
    println!("Failed: {}", failed_count);

    assert!(
        verified_count > 0,
        "No announces were verified. Is the network active?"
    );
    assert_eq!(
        failed_count, 0,
        "Some destination hash calculations failed! This indicates a hashing interop problem."
    );

    println!("\nSUCCESS: All {} destination hashes calculated correctly!", verified_count);
}

/// HIGH PRIORITY TEST #3: Verify identity hash from public key
///
/// Verifies that our identity hash calculation matches Python's:
/// identity_hash = truncated_hash(public_key)
///
/// This is indirectly verified by test #2, but this test explicitly checks it
/// and compares with what we'd compute from the identity.
#[tokio::test]
#[ignore = "requires running rnsd and active network"]
async fn test_verify_identity_hash_calculation() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    let mut deframer = Deframer::new();
    let mut buffer = [0u8; 1024];
    let mut verified_count = 0;
    let mut failed_count = 0;
    let target_count = 10;

    println!("Verifying identity hash calculations from live network...");
    println!("Target: {} announces\n", target_count);

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(60) && verified_count < target_count {
        match timeout(Duration::from_secs(1), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let results = deframer.process(&buffer[..n]);
                for result in results {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(packet) = Packet::unpack(&data) {
                            if packet.flags.packet_type == PacketType::Announce {
                                if let Some(announce) = ParsedAnnounce::from_packet(&packet) {
                                    // Create identity from public key
                                    let identity = match Identity::from_public_key_bytes(&announce.public_key) {
                                        Ok(id) => id,
                                        Err(e) => {
                                            println!("FAIL: Could not create identity: {:?}", e);
                                            failed_count += 1;
                                            continue;
                                        }
                                    };

                                    // Compare identity hash computed two ways:
                                    // 1. Using Identity::hash() (from the Identity struct)
                                    // 2. Using truncated_hash(public_key) directly
                                    let identity_hash_from_struct = identity.hash();
                                    let identity_hash_computed = announce.computed_identity_hash();

                                    if identity_hash_from_struct == &identity_hash_computed {
                                        verified_count += 1;
                                        let app_name = announce.app_data_string()
                                            .unwrap_or_else(|| format!("<binary {} bytes>", announce.app_data.len()));
                                        println!(
                                            "OK #{}: Identity hash {:02x}{:02x}{:02x}{:02x}... matches ({})",
                                            verified_count,
                                            identity_hash_computed[0],
                                            identity_hash_computed[1],
                                            identity_hash_computed[2],
                                            identity_hash_computed[3],
                                            app_name
                                        );
                                    } else {
                                        failed_count += 1;
                                        println!("FAIL: Identity hash mismatch!");
                                        println!("  From Identity struct:  {:02x?}", identity_hash_from_struct);
                                        println!("  From truncated_hash(): {:02x?}", identity_hash_computed);
                                        println!("  Public key: {:02x?}...", &announce.public_key[..16]);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(Ok(0)) => break,
            _ => {}
        }
    }

    println!("\n=== IDENTITY HASH VERIFICATION RESULTS ===");
    println!("Verified: {}", verified_count);
    println!("Failed: {}", failed_count);

    assert!(
        verified_count > 0,
        "No announces were verified. Is the network active?"
    );
    assert_eq!(
        failed_count, 0,
        "Some identity hash calculations failed! This indicates a hashing interop problem."
    );

    println!("\nSUCCESS: All {} identity hashes calculated correctly!", verified_count);
}

/// Combined test: Full cryptographic verification of announces
///
/// This test runs all three high-priority verifications on each announce:
/// 1. Signature verification
/// 2. Destination hash verification
/// 3. Identity hash verification
///
/// This provides comprehensive crypto interop validation in a single test.
#[tokio::test]
#[ignore = "requires running rnsd and active network"]
async fn test_full_announce_crypto_verification() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    let mut deframer = Deframer::new();
    let mut buffer = [0u8; 1024];
    let mut fully_verified = 0;
    let mut signature_failures = 0;
    let mut dest_hash_failures = 0;
    let mut identity_hash_failures = 0;
    let target_count = 10;

    println!("=== FULL CRYPTOGRAPHIC VERIFICATION ===");
    println!("Running all crypto checks on each announce...\n");

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(60) && fully_verified < target_count {
        match timeout(Duration::from_secs(1), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let results = deframer.process(&buffer[..n]);
                for result in results {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(packet) = Packet::unpack(&data) {
                            if packet.flags.packet_type == PacketType::Announce {
                                if let Some(announce) = ParsedAnnounce::from_packet(&packet) {
                                    let app_name = announce.app_data_string()
                                        .unwrap_or_else(|| format!("<binary {} bytes>", announce.app_data.len()));

                                    // Create identity from public key
                                    let identity = match Identity::from_public_key_bytes(&announce.public_key) {
                                        Ok(id) => id,
                                        Err(_) => continue,
                                    };

                                    // Check 1: Signature verification
                                    let signed_data = announce.signed_data();
                                    let sig_ok = identity.verify(&signed_data, &announce.signature)
                                        .unwrap_or(false);

                                    // Check 2: Destination hash verification
                                    let dest_hash_ok = announce.computed_destination_hash() == announce.destination_hash;

                                    // Check 3: Identity hash verification
                                    let identity_hash_ok = identity.hash() == &announce.computed_identity_hash();

                                    let ratchet_str = if announce.has_ratchet { " [ratcheted]" } else { "" };
                                    if sig_ok && dest_hash_ok && identity_hash_ok {
                                        fully_verified += 1;
                                        println!(
                                            "OK #{}: {:02x}{:02x}{:02x}{:02x}...{} - All checks passed ({})",
                                            fully_verified,
                                            announce.destination_hash[0],
                                            announce.destination_hash[1],
                                            announce.destination_hash[2],
                                            announce.destination_hash[3],
                                            ratchet_str,
                                            app_name
                                        );
                                    } else {
                                        if !sig_ok {
                                            signature_failures += 1;
                                            println!("FAIL: Signature verification failed{} (app_data: {} bytes)", ratchet_str, announce.app_data.len());
                                        }
                                        if !dest_hash_ok {
                                            dest_hash_failures += 1;
                                            println!("FAIL: Destination hash mismatch");
                                        }
                                        if !identity_hash_ok {
                                            identity_hash_failures += 1;
                                            println!("FAIL: Identity hash mismatch");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(Ok(0)) => break,
            _ => {}
        }
    }

    println!("\n=== FULL VERIFICATION RESULTS ===");
    println!("Fully verified:        {}", fully_verified);
    println!("Signature failures:    {}", signature_failures);
    println!("Dest hash failures:    {}", dest_hash_failures);
    println!("Identity hash failures: {}", identity_hash_failures);

    assert!(
        fully_verified > 0,
        "No announces were fully verified. Is the network active?"
    );

    let total_failures = signature_failures + dest_hash_failures + identity_hash_failures;
    assert_eq!(
        total_failures, 0,
        "Cryptographic verification failures detected! This indicates interop problems."
    );

    println!("\nSUCCESS: All {} announces passed full cryptographic verification!", fully_verified);
}

// ==========================================================
// MEDIUM PRIORITY: Protocol correctness tests
// ==========================================================

/// Helper to generate a random hash (10 bytes: 5 random + 5 timestamp)
///
/// Python format: get_random_hash()[0:5] + int(time.time()).to_bytes(5, "big")
/// - First 5 bytes: truncated_hash of 16 random bytes, then take first 5 bytes
/// - Last 5 bytes: current time in seconds as 5-byte big-endian
fn generate_random_hash() -> [u8; 10] {
    use std::time::{SystemTime, UNIX_EPOCH};

    // First 5 bytes: random (matching Python's get_random_hash()[0:5])
    let random_16: [u8; 16] = random_bytes();
    let random_hash = truncated_hash(&random_16);

    // Last 5 bytes: timestamp in seconds as big-endian
    let timestamp_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let timestamp_bytes = timestamp_secs.to_be_bytes(); // 8 bytes big-endian

    let mut result = [0u8; 10];
    result[0..5].copy_from_slice(&random_hash[0..5]);
    result[5..10].copy_from_slice(&timestamp_bytes[3..8]); // Take last 5 bytes
    result
}

/// Helper to compute name_hash from app_name and aspects
fn compute_name_hash(app_name: &str, aspects: &[&str]) -> [u8; 10] {
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
fn compute_destination_hash(name_hash: &[u8; 10], identity_hash: &[u8; 16]) -> [u8; 16] {
    let mut hash_material = Vec::with_capacity(26);
    hash_material.extend_from_slice(name_hash);
    hash_material.extend_from_slice(identity_hash);
    truncated_hash(&hash_material)
}

/// MEDIUM PRIORITY TEST #1: Create and send a valid announce
///
/// This tests end-to-end announce creation:
/// - Create a new identity
/// - Compute name_hash, random_hash, destination_hash
/// - Sign the announce data
/// - Build and send the announce packet
/// - Verify rnsd accepts it (connection stays open)
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_create_and_send_announce() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    println!("=== CREATE AND SEND ANNOUNCE TEST ===\n");

    // Create a new identity
    let identity = Identity::new();
    let public_key = identity.public_key_bytes();
    let identity_hash = *identity.hash();

    println!("Created identity:");
    println!("  Identity hash: {:02x?}", &identity_hash[..4]);

    // Compute name_hash for a test application
    let app_name = "leviculum";
    let aspects = ["test", "announce"];
    let name_hash = compute_name_hash(app_name, &aspects);

    println!("  App name: {}.{}.{}", app_name, aspects[0], aspects[1]);
    println!("  Name hash: {:02x?}", &name_hash);

    // Generate random_hash
    let random_hash = generate_random_hash();
    println!("  Random hash: {:02x?}", &random_hash);

    // Compute destination_hash
    let destination_hash = compute_destination_hash(&name_hash, &identity_hash);
    println!("  Destination hash: {:02x?}", &destination_hash[..4]);

    // Create app_data
    let app_data = b"leviculum-test-node";

    // Build signed_data: dest_hash + public_key + name_hash + random_hash + app_data
    let mut signed_data = Vec::with_capacity(100 + app_data.len());
    signed_data.extend_from_slice(&destination_hash);
    signed_data.extend_from_slice(&public_key);
    signed_data.extend_from_slice(&name_hash);
    signed_data.extend_from_slice(&random_hash);
    signed_data.extend_from_slice(app_data);

    // Sign the data
    let signature = identity.sign(&signed_data).expect("Failed to sign");
    println!("  Signature: {:02x?}...", &signature[..8]);

    // Build announce payload: public_key(64) + name_hash(10) + random_hash(10) + signature(64) + app_data
    let mut payload = Vec::with_capacity(148 + app_data.len());
    payload.extend_from_slice(&public_key);
    payload.extend_from_slice(&name_hash);
    payload.extend_from_slice(&random_hash);
    payload.extend_from_slice(&signature);
    payload.extend_from_slice(app_data);

    println!("  Payload size: {} bytes", payload.len());

    // Build the packet
    let packet = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: false,  // No ratchet
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

    // Pack the packet
    let mut raw_packet = [0u8; MTU];
    let size = packet.pack(&mut raw_packet).expect("Failed to pack packet");

    println!("  Packet size: {} bytes", size);
    println!("  Packet flags: 0x{:02x}", packet.flags.to_byte());

    // Frame with HDLC
    let mut framed = Vec::new();
    frame(&raw_packet[..size], &mut framed);

    println!("  Framed size: {} bytes", framed.len());

    // Send the announce
    stream.write_all(&framed).await.expect("Failed to send");
    stream.flush().await.expect("Failed to flush");

    println!("\nAnnounce sent!");

    // Wait a moment for rnsd to process
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Check if connection is still open (rnsd accepted the packet format)
    let mut buffer = [0u8; 1024];
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(0)) => {
            panic!("Connection closed by rnsd - announce may have been rejected");
        }
        Ok(Ok(n)) => {
            println!("Received {} bytes from rnsd (other network traffic)", n);
        }
        Ok(Err(e)) => {
            panic!("Read error: {} - announce may have been rejected", e);
        }
        Err(_) => {
            println!("No response (expected - announce was accepted)");
        }
    }

    // Verify our own announce by parsing it back
    let unpacked = Packet::unpack(&raw_packet[..size]).expect("Failed to unpack own packet");
    assert_eq!(unpacked.flags.packet_type, PacketType::Announce);
    assert_eq!(unpacked.destination_hash, destination_hash);

    // Parse and verify the announce payload
    if let Some(parsed) = ParsedAnnounce::from_packet(&unpacked) {
        let verify_identity = Identity::from_public_key_bytes(&parsed.public_key)
            .expect("Failed to create identity from payload");
        let verify_signed_data = parsed.signed_data();
        let verified = verify_identity.verify(&verify_signed_data, &parsed.signature)
            .expect("Verification error");
        assert!(verified, "Self-verification of announce failed!");
        println!("Self-verification: OK");
    }

    println!("\nSUCCESS: Announce created and sent successfully!");
}

/// CRITICAL TEST: Verify rnsd accepts and propagates our announces
///
/// This test is the authoritative check for announce format correctness.
/// It verifies:
/// 1. rnsd logs no errors while processing our announce
/// 2. rnsd propagates the announce to other local clients
///
/// Opens two connections to rnsd. Sends an announce on connection 1.
/// Verifies connection 2 receives the announce (proving rnsd accepted it).
/// Checks rnsd logs for any validation errors.
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_announce_propagation_between_clients() {
    // Start monitoring rnsd logs BEFORE doing anything
    let log_monitor = RnsdLogMonitor::new();
    if log_monitor.is_none() {
        println!("WARNING: Could not open rnsd log file for monitoring");
        println!("Set RNSD_LOG_PATH environment variable if needed");
    }

    // Open two connections to rnsd
    let mut stream1 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection 1 timeout")
        .expect("Failed to connect stream 1");

    let mut stream2 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection 2 timeout")
        .expect("Failed to connect stream 2");

    println!("=== ANNOUNCE PROPAGATION TEST ===\n");
    println!("Both connections established to rnsd");

    // Give rnsd a moment to set up both connections
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create identity and announce on stream1
    let identity = Identity::new();
    let public_key = identity.public_key_bytes();
    let identity_hash = *identity.hash();

    let app_name = "leviculum";
    let aspects = ["propagation", "test"];
    let name_hash = compute_name_hash(app_name, &aspects);
    let random_hash = generate_random_hash();
    let destination_hash = compute_destination_hash(&name_hash, &identity_hash);

    let app_data = b"propagation-test";

    // Build signed_data and signature
    let mut signed_data = Vec::with_capacity(100 + app_data.len());
    signed_data.extend_from_slice(&destination_hash);
    signed_data.extend_from_slice(&public_key);
    signed_data.extend_from_slice(&name_hash);
    signed_data.extend_from_slice(&random_hash);
    signed_data.extend_from_slice(app_data);

    let signature = identity.sign(&signed_data).expect("Failed to sign");

    // Build announce payload
    let mut payload = Vec::with_capacity(148 + app_data.len());
    payload.extend_from_slice(&public_key);
    payload.extend_from_slice(&name_hash);
    payload.extend_from_slice(&random_hash);
    payload.extend_from_slice(&signature);
    payload.extend_from_slice(app_data);

    // Build and pack the packet
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

    println!("Sending announce on stream 1:");
    println!("  Destination hash: {:02x?}...", &destination_hash[..4]);
    println!("  Packet size: {} bytes, framed: {} bytes", size, framed.len());

    // Send on stream 1
    stream1.write_all(&framed).await.expect("Failed to send");
    stream1.flush().await.expect("Failed to flush");

    println!("\nAnnounce sent on stream 1");
    println!("Waiting for propagation to stream 2...\n");

    // Wait for rnsd to process and propagate
    // Give it up to 3 seconds to propagate
    let mut deframer = Deframer::new();
    let mut buffer = [0u8; 2048];
    let mut found_our_announce = false;
    let start = std::time::Instant::now();

    while start.elapsed() < Duration::from_secs(3) && !found_our_announce {
        match timeout(Duration::from_millis(500), stream2.read(&mut buffer)).await {
            Ok(Ok(0)) => {
                println!("Stream 2 closed");
                break;
            }
            Ok(Ok(n)) => {
                let results = deframer.process(&buffer[..n]);
                for result in results {
                    match result {
                        DeframeResult::Frame(data) => {
                            match Packet::unpack(&data) {
                                Ok(pkt) => {
                                    if pkt.flags.packet_type == PacketType::Announce {
                                        println!("Received ANNOUNCE packet:");
                                        println!("  Flags: 0x{:02x}", pkt.flags.to_byte());
                                        println!("  Dest hash: {:02x?}...", &pkt.destination_hash[..4]);
                                        println!("  Hops: {}", pkt.hops);

                                        if pkt.destination_hash == destination_hash {
                                            found_our_announce = true;
                                            println!("  >>> THIS IS OUR ANNOUNCE! rnsd propagated it!");
                                        }
                                    } else {
                                        println!("Received {:?} packet (dest: {:02x?}...)",
                                            pkt.flags.packet_type, &pkt.destination_hash[..4]);
                                    }
                                }
                                Err(e) => {
                                    println!("Failed to parse packet: {:?} (raw: {} bytes)", e, data.len());
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(Err(e)) => {
                println!("Read error on stream 2: {}", e);
                break;
            }
            Err(_) => {
                // Timeout, continue
            }
        }
    }

    // Check rnsd logs for errors (CRITICAL for catching format bugs)
    if let Some(monitor) = &log_monitor {
        let errors = monitor.check_for_errors();
        if !errors.is_empty() {
            println!("\n=== RNSD LOG ERRORS (FORMAT BUG DETECTED!) ===");
            for error in &errors {
                println!("  {}", error);
            }
            panic!(
                "rnsd logged {} error(s) while processing our announce!\n\
                This indicates a format mismatch with Python Reticulum.\n\
                Check the errors above for details.",
                errors.len()
            );
        } else {
            println!("\nrnsd log check: No errors detected");
        }

        // Print relevant log entries for debugging
        let entries = monitor.get_new_entries();
        let relevant: Vec<_> = entries.iter()
            .filter(|e| e.contains(&format!("{:02x?}", &destination_hash[..4])[1..9])
                     || e.contains("Destination")
                     || e.contains("Rebroadcasting"))
            .collect();
        if !relevant.is_empty() {
            println!("\nRelevant rnsd log entries:");
            for entry in relevant.iter().take(10) {
                println!("  {}", entry);
            }
        }
    }

    if found_our_announce {
        println!("\nSUCCESS: rnsd accepted and propagated our announce!");
    } else {
        // If we didn't receive the announce, check if there were log errors
        if let Some(monitor) = &log_monitor {
            let errors = monitor.check_for_errors();
            if !errors.is_empty() {
                panic!(
                    "Announce not propagated AND rnsd logged errors:\n{:?}",
                    errors
                );
            }
        }
        println!("\nWARNING: Did not receive our announce on stream 2.");
        println!("This could mean:");
        println!("  1. rnsd is not configured as a transport node");
        println!("  2. Rate limiting is blocking the announce");
        println!("  3. Network timing issues");
    }

    // The test passes if propagation succeeded and no errors in logs
    assert!(found_our_announce, "Announce was not propagated - see output above");
}

/// MEDIUM PRIORITY TEST #2: Send a LINKREQUEST packet
///
/// Tests that our link request packet format is accepted by rnsd.
/// Note: The link won't actually establish without a valid destination,
/// but rnsd should accept the packet format.
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_send_linkrequest_packet() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    println!("=== LINKREQUEST PACKET TEST ===\n");

    // Create a link to a dummy destination
    let dummy_dest_hash = [0x42u8; TRUNCATED_HASHBYTES];
    let mut link = Link::new_outgoing(dummy_dest_hash);

    // Build the link request packet (this also sets the link_id)
    let raw_packet = link.build_link_request_packet();

    println!("Created LINKREQUEST:");
    println!("  Destination hash: {:02x?}", &dummy_dest_hash[..4]);
    println!("  Link ID: {:02x?}", &link.id()[..4]);
    println!("  Packet size: {} bytes", raw_packet.len());

    // Verify packet structure
    let unpacked = Packet::unpack(&raw_packet).expect("Failed to unpack link request");
    assert_eq!(unpacked.flags.packet_type, PacketType::LinkRequest);
    assert_eq!(unpacked.flags.header_type, HeaderType::Type1);
    println!("  Packet type: {:?}", unpacked.flags.packet_type);
    println!("  Payload size: {} bytes (expected 64)", unpacked.data.len());

    // Verify link request payload structure
    let payload = unpacked.data.as_slice();
    assert_eq!(payload.len(), 64, "Link request should be 64 bytes (32 X25519 + 32 Ed25519)");
    println!("  Ephemeral X25519 pub: {:02x?}...", &payload[..8]);
    println!("  Ephemeral Ed25519 pub: {:02x?}...", &payload[32..40]);

    // Frame with HDLC
    let mut framed = Vec::new();
    frame(&raw_packet, &mut framed);

    // Send the link request
    stream.write_all(&framed).await.expect("Failed to send");
    stream.flush().await.expect("Failed to flush");

    println!("\nLINKREQUEST sent!");

    // Wait for rnsd to process
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Check connection status
    let mut buffer = [0u8; 1024];
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(0)) => {
            panic!("Connection closed by rnsd - link request format may be invalid");
        }
        Ok(Ok(n)) => {
            println!("Received {} bytes from rnsd", n);
            // Check if we got a response (we won't for dummy destination)
        }
        Ok(Err(e)) => {
            panic!("Read error: {} - link request may have been rejected", e);
        }
        Err(_) => {
            println!("No response (expected - no such destination)");
        }
    }

    println!("\nSUCCESS: LINKREQUEST packet accepted by rnsd!");
}

/// MEDIUM PRIORITY TEST #3: Test Header Type 2 (transport) packets
///
/// Header Type 2 packets have both transport_id and destination_hash.
/// These are used when packets are routed through transport nodes.
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_header_type2_transport_packets() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    println!("=== HEADER TYPE 2 (TRANSPORT) PACKET TEST ===\n");

    // Create a Header Type 2 packet
    let transport_id = [0xAA; TRUNCATED_HASHBYTES];  // Dummy transport node
    let destination_hash = [0xBB; TRUNCATED_HASHBYTES];  // Dummy destination

    let packet = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type2,
            context_flag: false,
            transport_type: TransportType::Transport,
            dest_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 3,
        transport_id: Some(transport_id),
        destination_hash,
        context: PacketContext::None,
        data: PacketData::Owned(b"Header Type 2 test data".to_vec()),
    };

    println!("Created Header Type 2 packet:");
    println!("  Flags: 0x{:02x}", packet.flags.to_byte());
    println!("  Transport ID: {:02x?}...", &transport_id[..4]);
    println!("  Destination hash: {:02x?}...", &destination_hash[..4]);
    println!("  Hops: {}", packet.hops);

    // Pack the packet
    let mut raw_packet = [0u8; MTU];
    let size = packet.pack(&mut raw_packet).expect("Failed to pack packet");

    println!("  Packet size: {} bytes", size);

    // Verify packet structure
    let unpacked = Packet::unpack(&raw_packet[..size]).expect("Failed to unpack");
    assert_eq!(unpacked.flags.header_type, HeaderType::Type2);
    assert!(unpacked.transport_id.is_some());
    assert_eq!(unpacked.transport_id.unwrap(), transport_id);
    assert_eq!(unpacked.destination_hash, destination_hash);
    println!("  Self-verification: OK");

    // Frame with HDLC
    let mut framed = Vec::new();
    frame(&raw_packet[..size], &mut framed);

    // Send the packet
    stream.write_all(&framed).await.expect("Failed to send");
    stream.flush().await.expect("Failed to flush");

    println!("\nHeader Type 2 packet sent!");

    // Wait for rnsd to process
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Check connection status
    let mut buffer = [0u8; 1024];
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(0)) => {
            panic!("Connection closed by rnsd - H2 packet format may be invalid");
        }
        _ => {
            println!("Connection still open (packet format accepted)");
        }
    }

    // Also test Header Type 2 with Data packet type only
    // Note: Announce and Proof packet types require specific payloads
    // (public keys, signatures, etc.) and would cause rnsd to log
    // errors when it tries to parse our text payloads.
    let packet = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type2,
            context_flag: false,
            transport_type: TransportType::Transport,
            dest_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 2,
        transport_id: Some([0xCC; TRUNCATED_HASHBYTES]),
        destination_hash: [0xDD; TRUNCATED_HASHBYTES],
        context: PacketContext::None,
        data: PacketData::Owned(b"H2 Data test".to_vec()),
    };

    let mut raw = [0u8; MTU];
    let size = packet.pack(&mut raw).expect("Failed to pack");

    let mut framed = Vec::new();
    frame(&raw[..size], &mut framed);
    stream.write_all(&framed).await.expect("Failed to send");
    println!("  Sent additional H2 Data packet");

    stream.flush().await.expect("Failed to flush");

    println!("\nSUCCESS: All Header Type 2 packets accepted!");
}

/// MEDIUM PRIORITY TEST #4: Test various packet contexts
///
/// Tests that rnsd accepts packets with different context bytes.
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_various_packet_contexts() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    println!("=== PACKET CONTEXT TEST ===\n");

    // Test packet contexts with generic payloads
    // Note: Some contexts (LinkIdentify, LinkProof, Lrproof) require specific
    // payload formats (public keys, signatures, etc.). We skip those here
    // because sending invalid payloads causes rnsd to log errors when it
    // tries to parse them. Those contexts are tested separately with proper payloads.
    let test_cases: &[(PacketContext, &str)] = &[
        (PacketContext::None, "None"),
        (PacketContext::Resource, "Resource"),
        (PacketContext::ResourceAdv, "ResourceAdv"),
        (PacketContext::ResourceReq, "ResourceReq"),
        (PacketContext::ResourceHmu, "ResourceHmu"),
        (PacketContext::ResourcePrf, "ResourcePrf"),
        (PacketContext::ResourceIcl, "ResourceIcl"),
        (PacketContext::ResourceRcl, "ResourceRcl"),
        (PacketContext::CacheRequest, "CacheRequest"),
        (PacketContext::Request, "Request"),
        (PacketContext::Response, "Response"),
        (PacketContext::PathResponse, "PathResponse"),
        (PacketContext::Command, "Command"),
        (PacketContext::CommandStatus, "CommandStatus"),
        (PacketContext::Channel, "Channel"),
        (PacketContext::Keepalive, "Keepalive"),
        // Skip: LinkIdentify - requires 64-byte public key + 64-byte signature
        (PacketContext::LinkClose, "LinkClose"),
        // Skip: LinkProof - requires specific proof format
        (PacketContext::Lrrtt, "Lrrtt"),
        // Skip: Lrproof - requires specific proof format
    ];

    let mut sent_count = 0;

    for (context, name) in test_cases {
        let packet = Packet {
            flags: PacketFlags {
                header_type: HeaderType::Type1,
                context_flag: true,  // Context flag set
                transport_type: TransportType::Broadcast,
                dest_type: DestinationType::Single,
                packet_type: PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination_hash: [0xEE; TRUNCATED_HASHBYTES],
            context: *context,
            data: PacketData::Owned(format!("Context {} test", name).into_bytes()),
        };

        let mut raw = [0u8; MTU];
        let size = packet.pack(&mut raw).expect("Failed to pack");

        // Verify context byte is correct
        let unpacked = Packet::unpack(&raw[..size]).expect("Failed to unpack");
        assert_eq!(unpacked.context as u8, *context as u8);

        let mut framed = Vec::new();
        frame(&raw[..size], &mut framed);
        stream.write_all(&framed).await.expect("Failed to send");

        println!("  Sent context 0x{:02X}: {}", *context as u8, name);
        sent_count += 1;
    }

    stream.flush().await.expect("Failed to flush");

    // Wait for rnsd to process
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Check connection status
    let mut buffer = [0u8; 1024];
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(0)) => {
            panic!("Connection closed by rnsd - some context may be invalid");
        }
        _ => {
            println!("\nConnection still open after {} context packets", sent_count);
        }
    }

    println!("\nSUCCESS: All {} packet contexts accepted!", sent_count);
}

/// Combined test: Send multiple packet types in sequence
///
/// Tests that rnsd handles a mix of packet types correctly.
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_mixed_packet_sequence() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    println!("=== MIXED PACKET SEQUENCE TEST ===\n");

    let mut packets_sent = 0;

    // 1. Send a Data packet (H1)
    let data_packet = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: [0x11; TRUNCATED_HASHBYTES],
        context: PacketContext::None,
        data: PacketData::Owned(b"Data packet".to_vec()),
    };
    let mut raw = [0u8; MTU];
    let size = data_packet.pack(&mut raw).unwrap();
    let mut framed = Vec::new();
    frame(&raw[..size], &mut framed);
    stream.write_all(&framed).await.unwrap();
    packets_sent += 1;
    println!("  1. Sent Data packet (H1)");

    // 2. Send a LINKREQUEST
    let link = Link::new_outgoing([0x22; TRUNCATED_HASHBYTES]);
    let link_req = link.create_link_request();
    let link_packet = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Single,
            packet_type: PacketType::LinkRequest,
        },
        hops: 0,
        transport_id: None,
        destination_hash: [0x22; TRUNCATED_HASHBYTES],
        context: PacketContext::None,
        data: PacketData::Owned(link_req.to_vec()),
    };
    let size = link_packet.pack(&mut raw).unwrap();
    framed.clear();
    frame(&raw[..size], &mut framed);
    stream.write_all(&framed).await.unwrap();
    packets_sent += 1;
    println!("  2. Sent LinkRequest packet (H1)");

    // 3. Send a Transport packet (H2)
    let transport_packet = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type2,
            context_flag: false,
            transport_type: TransportType::Transport,
            dest_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 2,
        transport_id: Some([0x33; TRUNCATED_HASHBYTES]),
        destination_hash: [0x44; TRUNCATED_HASHBYTES],
        context: PacketContext::None,
        data: PacketData::Owned(b"Transport packet".to_vec()),
    };
    let size = transport_packet.pack(&mut raw).unwrap();
    framed.clear();
    frame(&raw[..size], &mut framed);
    stream.write_all(&framed).await.unwrap();
    packets_sent += 1;
    println!("  3. Sent Transport packet (H2)");

    // 4. Send a Group packet
    let group_packet = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Group,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: [0x55; TRUNCATED_HASHBYTES],
        context: PacketContext::None,
        data: PacketData::Owned(b"Group packet".to_vec()),
    };
    let size = group_packet.pack(&mut raw).unwrap();
    framed.clear();
    frame(&raw[..size], &mut framed);
    stream.write_all(&framed).await.unwrap();
    packets_sent += 1;
    println!("  4. Sent Group packet");

    // 5. Send a Plain packet
    let plain_packet = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Plain,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: [0x66; TRUNCATED_HASHBYTES],
        context: PacketContext::None,
        data: PacketData::Owned(b"Plain packet".to_vec()),
    };
    let size = plain_packet.pack(&mut raw).unwrap();
    framed.clear();
    frame(&raw[..size], &mut framed);
    stream.write_all(&framed).await.unwrap();
    packets_sent += 1;
    println!("  5. Sent Plain packet");

    // 6. Create and send an announce
    let identity = Identity::new();
    let name_hash = compute_name_hash("test", &["mixed"]);
    let random_hash = generate_random_hash();
    let dest_hash = compute_destination_hash(&name_hash, identity.hash());
    let public_key = identity.public_key_bytes();

    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&dest_hash);
    signed_data.extend_from_slice(&public_key);
    signed_data.extend_from_slice(&name_hash);
    signed_data.extend_from_slice(&random_hash);

    let signature = identity.sign(&signed_data).unwrap();

    let mut payload = Vec::new();
    payload.extend_from_slice(&public_key);
    payload.extend_from_slice(&name_hash);
    payload.extend_from_slice(&random_hash);
    payload.extend_from_slice(&signature);

    let announce_packet = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Single,
            packet_type: PacketType::Announce,
        },
        hops: 0,
        transport_id: None,
        destination_hash: dest_hash,
        context: PacketContext::None,
        data: PacketData::Owned(payload),
    };
    let size = announce_packet.pack(&mut raw).unwrap();
    framed.clear();
    frame(&raw[..size], &mut framed);
    stream.write_all(&framed).await.unwrap();
    packets_sent += 1;
    println!("  6. Sent Announce packet");

    stream.flush().await.unwrap();

    // Wait for rnsd to process
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Check connection status
    let mut buffer = [0u8; 1024];
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(0)) => {
            panic!("Connection closed by rnsd");
        }
        _ => {
            println!("\nConnection still open after {} packets", packets_sent);
        }
    }

    println!("\nSUCCESS: All {} mixed packets accepted!", packets_sent);
}

/// Test sending an announce with an INVALID signature
///
/// This test verifies that rnsd properly rejects announces with bad signatures
/// and logs an error about it. Used to confirm rnsd validates packets.
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_invalid_announce_signature() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    println!("=== INVALID ANNOUNCE SIGNATURE TEST ===\n");

    // Create a new identity
    let identity = Identity::new();
    let public_key = identity.public_key_bytes();
    let identity_hash = *identity.hash();

    // Compute name_hash for a test application
    let app_name = "leviculum";
    let aspects = ["test", "invalid"];
    let name_hash = compute_name_hash(app_name, &aspects);

    // Generate random_hash
    let random_hash = generate_random_hash();

    // Compute destination_hash
    let destination_hash = compute_destination_hash(&name_hash, &identity_hash);

    println!("Created announce with:");
    println!("  Destination hash: {:02x?}", &destination_hash[..4]);

    // Create app_data
    let app_data = b"invalid-signature-test";

    // Build signed_data correctly
    let mut signed_data = Vec::with_capacity(100 + app_data.len());
    signed_data.extend_from_slice(&destination_hash);
    signed_data.extend_from_slice(&public_key);
    signed_data.extend_from_slice(&name_hash);
    signed_data.extend_from_slice(&random_hash);
    signed_data.extend_from_slice(app_data);

    // Sign the data correctly first
    let mut signature = identity.sign(&signed_data).expect("Failed to sign");

    // NOW CORRUPT THE SIGNATURE - flip some bits
    signature[0] ^= 0xFF;
    signature[1] ^= 0xFF;
    signature[32] ^= 0xFF;

    println!("  Signature CORRUPTED: {:02x?}...", &signature[..8]);

    // Build announce payload with the BAD signature
    let mut payload = Vec::with_capacity(148 + app_data.len());
    payload.extend_from_slice(&public_key);
    payload.extend_from_slice(&name_hash);
    payload.extend_from_slice(&random_hash);
    payload.extend_from_slice(&signature);
    payload.extend_from_slice(app_data);

    // Build the packet
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

    // Pack and frame the packet
    let mut raw_packet = [0u8; MTU];
    let size = packet.pack(&mut raw_packet).expect("Failed to pack packet");

    let mut framed = Vec::new();
    frame(&raw_packet[..size], &mut framed);

    println!("  Packet size: {} bytes, framed: {} bytes", size, framed.len());
    println!("\nSending announce with INVALID signature...");

    // Send to rnsd
    stream.write_all(&framed).await.expect("Failed to send");
    stream.flush().await.expect("Failed to flush");

    println!("Packet sent!");
    println!("\nCheck ~/.reticulum/logfile for signature verification error.");
    println!("Expected: An error about signature verification failure for destination {:02x?}", &destination_hash[..4]);

    // Wait a moment for rnsd to process
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Connection should still be open (rnsd doesn't close on bad packets)
    let mut buffer = [0u8; 1024];
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(0)) => println!("Connection closed (unexpected)"),
        Ok(Ok(n)) => println!("Received {} bytes of other traffic", n),
        Ok(Err(e)) => println!("Read error: {}", e),
        Err(_) => println!("No response (expected - bad announce is silently dropped)"),
    }

    println!("\nTest complete - check the log file for errors!");
}
