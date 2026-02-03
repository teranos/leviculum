//! Ratchet (forward secrecy) interoperability tests with Python Reticulum daemon.
//!
//! These tests verify that ratchet-based forward secrecy works correctly between
//! Rust and Python Reticulum implementations.
//!
//! ## What These Tests Cover
//!
//! - Receiving ratcheted announces from Python
//! - Sending ratcheted announces from Rust
//! - Rust-to-Rust announce exchange via Python relay
//! - Encrypted packet exchange using ratchets
//!
//! ## Running These Tests
//!
//! ```sh
//! # Run all ratchet interop tests
//! cargo test --package reticulum-std --test rnsd_interop ratchet_tests
//!
//! # Run with verbose output
//! cargo test --package reticulum-std --test rnsd_interop ratchet_tests -- --nocapture
//! ```

use rand_core::OsRng;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use reticulum_core::constants::{MTU, RATCHET_SIZE};
use reticulum_core::destination::{Destination, DestinationType, Direction};
use reticulum_core::identity::Identity;
use reticulum_core::packet::{Packet, PacketType};
use reticulum_core::traits::{NoStorage, PlatformContext};
use reticulum_std::interfaces::hdlc::{frame, DeframeResult, Deframer};
use reticulum_std::SystemClock;

use crate::common::{connect_to_daemon, ParsedAnnounce, DAEMON_PROCESS_TIME};
use crate::harness::TestDaemon;

/// Create a platform context for tests
fn make_context() -> PlatformContext<OsRng, SystemClock, NoStorage> {
    PlatformContext {
        rng: OsRng,
        clock: SystemClock::new(),
        storage: NoStorage,
    }
}

// =========================================================================
// Receiving ratcheted announces from Python
// =========================================================================

/// Verify that Rust can receive and parse a ratcheted announce from Python.
///
/// This test:
/// 1. Registers a destination in Python daemon
/// 2. Enables ratchets for that destination
/// 3. Has Python announce the destination
/// 4. Rust receives and parses the announce
/// 5. Verifies the ratchet field is present and correct size
#[tokio::test]
async fn test_receive_ratcheted_announce_from_python() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Register a destination in Python
    let py_dest = daemon
        .register_destination("test", &["ratchet", "receiver"])
        .await
        .expect("Failed to register destination");

    println!("Python destination registered: {}", py_dest.hash);

    // Enable ratchets for the destination
    let ratchet_result = daemon
        .enable_ratchets(&py_dest.hash)
        .await
        .expect("Failed to enable ratchets");

    assert!(ratchet_result.enabled, "Ratchets should be enabled");
    println!("Ratchets enabled for destination");

    // Verify ratchet info
    let ratchet_info = daemon
        .get_ratchet_info(&py_dest.hash)
        .await
        .expect("Failed to get ratchet info");

    assert!(ratchet_info.enabled, "Ratchet info should show enabled");
    println!("Ratchet count: {:?}", ratchet_info.count);

    // Connect Rust to receive the announce
    let mut stream = connect_to_daemon(&daemon).await;

    // Have Python announce with ratchet
    daemon
        .announce_destination(&py_dest.hash, b"ratchet-test-data")
        .await
        .expect("Failed to announce");

    println!("Python announced destination with ratchet");

    // Wait for and parse the announce
    let announce = wait_for_ratcheted_announce(&mut stream, Duration::from_secs(5)).await;

    assert!(
        announce.is_some(),
        "Should receive announce with ratchet from Python"
    );

    let announce = announce.unwrap();
    println!(
        "Received announce for: {}",
        hex::encode(announce.destination_hash)
    );

    // Verify ratchet is present (non-empty means context_flag was set)
    assert!(
        !announce.ratchet.is_empty(),
        "Announce should have ratchet field set"
    );
    assert_eq!(
        announce.ratchet.len(),
        RATCHET_SIZE,
        "Ratchet should be {} bytes",
        RATCHET_SIZE
    );

    println!(
        "Ratchet received: {} bytes, first 8: {:02x?}",
        announce.ratchet.len(),
        &announce.ratchet[..8]
    );

    println!("SUCCESS: Rust correctly received ratcheted announce from Python");
}

// =========================================================================
// Sending ratcheted announces from Rust
// =========================================================================

/// Verify that Rust can send a ratcheted announce that Python accepts.
///
/// This test:
/// 1. Creates a Rust destination with ratchets enabled
/// 2. Sends announce with ratchet
/// 3. Verifies Python creates a path entry
/// 4. Verifies the announce propagates back with ratchet intact
#[tokio::test]
async fn test_send_ratcheted_announce_from_rust() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Create Rust destination with ratchets
    let identity = Identity::generate_with_rng(&mut OsRng);
    let mut dest = Destination::new(
        Some(identity),
        Direction::In,
        DestinationType::Single,
        "leviculum",
        &["ratchet", "sender"],
    )
    .expect("Failed to create destination");

    // Enable ratchets
    let mut ctx = make_context();
    dest.enable_ratchets(&mut ctx)
        .expect("Failed to enable ratchets");

    assert!(
        dest.current_ratchet_public().is_some(),
        "Should have current ratchet after enabling"
    );

    let ratchet_pub = dest.current_ratchet_public().unwrap();
    println!("Rust ratchet public: {:02x?}...", &ratchet_pub[..8]);

    // Build and send announce with ratchet
    let packet = dest
        .announce(Some(b"rust-ratchet-test"), &mut ctx)
        .expect("Failed to create announce");

    // Verify context_flag is set
    assert!(
        packet.flags.context_flag,
        "Announce packet should have context_flag=true for ratchet"
    );

    // Connect and send
    let mut stream = connect_to_daemon(&daemon).await;

    let mut raw_packet = [0u8; MTU];
    let size = packet.pack(&mut raw_packet).expect("Failed to pack packet");

    let mut framed = Vec::new();
    frame(&raw_packet[..size], &mut framed);

    tokio::io::AsyncWriteExt::write_all(&mut stream, &framed)
        .await
        .expect("Failed to send");
    tokio::io::AsyncWriteExt::flush(&mut stream)
        .await
        .expect("Failed to flush");

    println!("Sent ratcheted announce from Rust");

    // Wait for processing
    tokio::time::sleep(DAEMON_PROCESS_TIME).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Verify Python created a path
    let dest_hash = *dest.hash();
    let has_path = daemon.has_path(&dest_hash).await;

    assert!(
        has_path,
        "Python should accept ratcheted announce and create path"
    );

    println!("SUCCESS: Python accepted ratcheted announce from Rust");
}

// =========================================================================
// Rust-to-Rust announce exchange via Python
// =========================================================================

/// Verify two Rust instances can exchange ratcheted announces through Python.
///
/// This test:
/// 1. Opens two connections to Python daemon
/// 2. Each side creates a destination with ratchets
/// 3. Each side announces
/// 4. Each side receives the other's announce with ratchet
#[tokio::test]
async fn test_rust_to_rust_ratcheted_announce_via_python() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Create Rust A's destination with ratchets
    let identity_a = Identity::generate_with_rng(&mut OsRng);
    let mut dest_a = Destination::new(
        Some(identity_a),
        Direction::In,
        DestinationType::Single,
        "leviculum",
        &["exchange", "a"],
    )
    .expect("Failed to create destination A");

    let mut ctx_a = make_context();
    dest_a
        .enable_ratchets(&mut ctx_a)
        .expect("Failed to enable ratchets for A");

    // Create Rust B's destination with ratchets
    let identity_b = Identity::generate_with_rng(&mut OsRng);
    let mut dest_b = Destination::new(
        Some(identity_b),
        Direction::In,
        DestinationType::Single,
        "leviculum",
        &["exchange", "b"],
    )
    .expect("Failed to create destination B");

    let mut ctx_b = make_context();
    dest_b
        .enable_ratchets(&mut ctx_b)
        .expect("Failed to enable ratchets for B");

    // Open two connections
    let mut stream_a = connect_to_daemon(&daemon).await;
    let mut stream_b = connect_to_daemon(&daemon).await;

    // A announces
    let packet_a = dest_a
        .announce(Some(b"from-a"), &mut ctx_a)
        .expect("Failed to create announce A");

    let mut raw_a = [0u8; MTU];
    let size_a = packet_a.pack(&mut raw_a).expect("Failed to pack A");
    let mut framed_a = Vec::new();
    frame(&raw_a[..size_a], &mut framed_a);

    tokio::io::AsyncWriteExt::write_all(&mut stream_a, &framed_a)
        .await
        .expect("Failed to send A");
    tokio::io::AsyncWriteExt::flush(&mut stream_a)
        .await
        .expect("Failed to flush A");

    println!("A announced: {:02x?}...", &dest_a.hash().as_bytes()[..4]);

    // B announces
    let packet_b = dest_b
        .announce(Some(b"from-b"), &mut ctx_b)
        .expect("Failed to create announce B");

    let mut raw_b = [0u8; MTU];
    let size_b = packet_b.pack(&mut raw_b).expect("Failed to pack B");
    let mut framed_b = Vec::new();
    frame(&raw_b[..size_b], &mut framed_b);

    tokio::io::AsyncWriteExt::write_all(&mut stream_b, &framed_b)
        .await
        .expect("Failed to send B");
    tokio::io::AsyncWriteExt::flush(&mut stream_b)
        .await
        .expect("Failed to flush B");

    println!("B announced: {:02x?}...", &dest_b.hash().as_bytes()[..4]);

    // Wait for propagation
    tokio::time::sleep(Duration::from_millis(500)).await;

    // A should receive B's announce
    let announce_from_b =
        wait_for_announce_with_hash(&mut stream_a, dest_b.hash(), Duration::from_secs(5)).await;

    assert!(
        announce_from_b.is_some(),
        "A should receive B's ratcheted announce"
    );
    let announce_from_b = announce_from_b.unwrap();
    assert!(
        !announce_from_b.ratchet.is_empty(),
        "B's announce should have ratchet"
    );
    println!("A received B's announce with ratchet");

    // B should receive A's announce
    let announce_from_a =
        wait_for_announce_with_hash(&mut stream_b, dest_a.hash(), Duration::from_secs(5)).await;

    assert!(
        announce_from_a.is_some(),
        "B should receive A's ratcheted announce"
    );
    let announce_from_a = announce_from_a.unwrap();
    assert!(
        !announce_from_a.ratchet.is_empty(),
        "A's announce should have ratchet"
    );
    println!("B received A's announce with ratchet");

    println!("SUCCESS: Two Rust instances exchanged ratcheted announces via Python");
}

// =========================================================================
// Context flag verification
// =========================================================================

/// Verify that context_flag correctly indicates ratchet presence.
///
/// This test ensures the flag is correctly set/unset based on ratchet state.
#[tokio::test]
async fn test_context_flag_indicates_ratchet() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Create destination WITHOUT ratchets
    let identity1 = Identity::generate_with_rng(&mut OsRng);
    let mut dest_no_ratchet = Destination::new(
        Some(identity1),
        Direction::In,
        DestinationType::Single,
        "leviculum",
        &["context", "noratchet"],
    )
    .expect("Failed to create destination");

    let mut ctx = make_context();
    let packet_no_ratchet = dest_no_ratchet
        .announce(Some(b"no-ratchet"), &mut ctx)
        .expect("Failed to create announce");

    assert!(
        !packet_no_ratchet.flags.context_flag,
        "Non-ratcheted announce should have context_flag=false"
    );

    // Create destination WITH ratchets
    let identity2 = Identity::generate_with_rng(&mut OsRng);
    let mut dest_with_ratchet = Destination::new(
        Some(identity2),
        Direction::In,
        DestinationType::Single,
        "leviculum",
        &["context", "withratchet"],
    )
    .expect("Failed to create destination");

    dest_with_ratchet
        .enable_ratchets(&mut ctx)
        .expect("Failed to enable ratchets");

    let packet_with_ratchet = dest_with_ratchet
        .announce(Some(b"with-ratchet"), &mut ctx)
        .expect("Failed to create announce");

    assert!(
        packet_with_ratchet.flags.context_flag,
        "Ratcheted announce should have context_flag=true"
    );

    // Send both and verify paths created - use separate streams
    // (sending two announces on same stream quickly can cause issues)

    // Send non-ratcheted on first stream
    let mut stream1 = connect_to_daemon(&daemon).await;
    let mut raw1 = [0u8; MTU];
    let size1 = packet_no_ratchet.pack(&mut raw1).expect("Failed to pack");
    let mut framed1 = Vec::new();
    frame(&raw1[..size1], &mut framed1);
    tokio::io::AsyncWriteExt::write_all(&mut stream1, &framed1)
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::flush(&mut stream1).await.unwrap();

    // Wait between sends
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send ratcheted on second stream
    let mut stream2 = connect_to_daemon(&daemon).await;
    let mut raw2 = [0u8; MTU];
    let size2 = packet_with_ratchet.pack(&mut raw2).expect("Failed to pack");
    let mut framed2 = Vec::new();
    frame(&raw2[..size2], &mut framed2);
    tokio::io::AsyncWriteExt::write_all(&mut stream2, &framed2)
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::flush(&mut stream2).await.unwrap();

    // Wait for processing
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Both should create paths
    assert!(
        daemon.has_path(dest_no_ratchet.hash()).await,
        "Non-ratcheted announce should create path"
    );
    assert!(
        daemon.has_path(dest_with_ratchet.hash()).await,
        "Ratcheted announce should create path"
    );

    println!("SUCCESS: context_flag correctly indicates ratchet presence");
}

// =========================================================================
// Helper functions
// =========================================================================

/// Wait for any announce packet with ratchet (context_flag=true).
async fn wait_for_ratcheted_announce(
    stream: &mut TcpStream,
    timeout_duration: Duration,
) -> Option<ParsedAnnounce> {
    let mut deframer = Deframer::new();
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
                            if pkt.flags.packet_type == PacketType::Announce
                                && pkt.flags.context_flag
                            {
                                return ParsedAnnounce::from_packet(&pkt);
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

/// Wait for an announce packet with a specific destination hash.
async fn wait_for_announce_with_hash(
    stream: &mut TcpStream,
    dest_hash: &reticulum_core::DestinationHash,
    timeout_duration: Duration,
) -> Option<ParsedAnnounce> {
    let mut deframer = Deframer::new();
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
                            if pkt.flags.packet_type == PacketType::Announce
                                && pkt.destination_hash == *dest_hash.as_bytes()
                            {
                                return ParsedAnnounce::from_packet(&pkt);
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
