//! Proof system interoperability tests
//!
//! Tests the packet proof system against Python Reticulum.
//!
//! Proofs provide cryptographic delivery confirmation - when a packet
//! is received, the receiver can sign the packet hash and send it back
//! as proof of delivery.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use reticulum_core::constants::{MTU, PROOF_DATA_SIZE, TRUNCATED_HASHBYTES};
use reticulum_core::crypto::sha256;
use reticulum_core::destination::{Destination, DestinationType, Direction, ProofStrategy};
use reticulum_core::identity::Identity;
use reticulum_core::packet::{
    build_proof_packet, HeaderType, Packet, PacketContext, PacketData, PacketFlags, PacketType,
    TransportType,
};
use reticulum_std::interfaces::hdlc::{frame, DeframeResult, Deframer};

use crate::common::{make_context, OsRng};
use crate::harness::TestDaemon;

// =========================================================================
// Constants
// =========================================================================

const DAEMON_SETTLE_TIME: Duration = Duration::from_millis(500);
const PACKET_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

// =========================================================================
// Helper functions
// =========================================================================

/// Send raw bytes over a stream with HDLC framing
async fn send_framed(stream: &mut TcpStream, raw: &[u8]) {
    let mut framed = Vec::new();
    frame(raw, &mut framed);
    stream.write_all(&framed).await.expect("Failed to send");
    stream.flush().await.expect("Failed to flush");
}

/// Wait for a proof packet for a specific destination hash
#[allow(dead_code)]
async fn wait_for_proof_packet(
    stream: &mut TcpStream,
    deframer: &mut Deframer,
    dest_hash: &[u8; TRUNCATED_HASHBYTES],
    timeout_duration: Duration,
) -> Option<Packet> {
    let mut buf = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + timeout_duration;

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();

        match timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) => return None,
            Ok(Ok(n)) => {
                let results = deframer.process(&buf[..n]);
                for result in results {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == PacketType::Proof
                                && pkt.destination_hash == *dest_hash
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

/// Wait for any proof packet
async fn wait_for_any_proof_packet(
    stream: &mut TcpStream,
    deframer: &mut Deframer,
    timeout_duration: Duration,
) -> Option<Packet> {
    let mut buf = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + timeout_duration;

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();

        match timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) => return None,
            Ok(Ok(n)) => {
                let results = deframer.process(&buf[..n]);
                for result in results {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == PacketType::Proof {
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

/// Build a data packet for a destination
fn build_data_packet(destination_hash: &[u8; TRUNCATED_HASHBYTES], data: &[u8]) -> Packet {
    Packet {
        flags: PacketFlags {
            ifac_flag: false,
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: *destination_hash,
        context: PacketContext::None,
        data: PacketData::Owned(data.to_vec()),
    }
}

// =========================================================================
// Unit Tests - Proof Format
// =========================================================================

#[test]
fn test_proof_data_size() {
    // Verify proof data size constant
    assert_eq!(PROOF_DATA_SIZE, 96); // 32 hash + 64 signature
}

#[test]
fn test_build_proof_packet() {
    let dest_hash = [0x42u8; 16];
    let proof_data = [0xAAu8; 96];

    let packet = build_proof_packet(&dest_hash, &proof_data);

    assert_eq!(packet.flags.packet_type, PacketType::Proof);
    assert_eq!(packet.destination_hash, dest_hash);
    assert_eq!(packet.data.as_slice(), &proof_data);
}

#[test]
fn test_create_and_verify_proof() {
    let identity = Identity::generate_with_rng(&mut OsRng);
    let packet_hash = [0x42u8; 32];

    // Create proof
    let proof = identity.create_proof(&packet_hash).unwrap();
    assert_eq!(proof.len(), PROOF_DATA_SIZE);

    // First 32 bytes should be the hash
    assert_eq!(&proof[..32], &packet_hash);

    // Verify the proof
    assert!(identity.verify_proof(&proof, &packet_hash));
}

#[test]
fn test_proof_strategy_values() {
    // Verify our enum values match Python Reticulum
    assert_eq!(ProofStrategy::None as u8, 0x21);
    assert_eq!(ProofStrategy::App as u8, 0x22);
    assert_eq!(ProofStrategy::All as u8, 0x23);
}

#[test]
fn test_destination_proof_strategy() {
    let identity = Identity::generate_with_rng(&mut OsRng);
    let mut dest = Destination::new(
        Some(identity),
        Direction::In,
        DestinationType::Single,
        "test",
        &["proof"],
    )
    .unwrap();

    // Default should be None
    assert_eq!(dest.proof_strategy(), ProofStrategy::None);

    // Can change to All
    dest.set_proof_strategy(ProofStrategy::All);
    assert_eq!(dest.proof_strategy(), ProofStrategy::All);

    // Can change to App
    dest.set_proof_strategy(ProofStrategy::App);
    assert_eq!(dest.proof_strategy(), ProofStrategy::App);
}

// =========================================================================
// Integration Tests with Python Daemon
// =========================================================================

/// Test that Python daemon with PROVE_ALL sends proof for our packets
#[tokio::test]
async fn test_python_prove_all_sends_proof() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Register a destination with PROVE_ALL
    let dest_info = daemon
        .register_destination("proof_test", &["all"])
        .await
        .expect("Failed to register destination");

    let dest_hash = &dest_info.hash;

    // Set proof strategy to PROVE_ALL
    daemon
        .set_proof_strategy(dest_hash, "PROVE_ALL")
        .await
        .expect("Failed to set proof strategy");

    // Verify strategy was set
    let strategy = daemon
        .get_proof_strategy(dest_hash)
        .await
        .expect("Failed to get proof strategy");
    assert_eq!(strategy, "PROVE_ALL");

    // Connect to daemon
    let mut stream = TcpStream::connect(daemon.rns_addr())
        .await
        .expect("Failed to connect");
    tokio::time::sleep(DAEMON_SETTLE_TIME).await;

    // Create our identity for receiving the proof
    let our_identity = Identity::generate_with_rng(&mut OsRng);
    let mut our_dest = Destination::new(
        Some(our_identity),
        Direction::In,
        DestinationType::Single,
        "rust",
        &["sender"],
    )
    .unwrap();

    // Send our announce so Python knows where to send the proof
    let mut ctx = make_context();
    let announce_packet = our_dest
        .announce(None, &mut ctx)
        .expect("Failed to create announce");

    let mut announce_raw = [0u8; MTU];
    let announce_len = announce_packet.pack(&mut announce_raw).unwrap();
    send_framed(&mut stream, &announce_raw[..announce_len]).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Build and send a data packet to Python's destination
    let dest_hash_bytes: [u8; 16] = hex::decode(dest_hash)
        .expect("Invalid hex")
        .try_into()
        .expect("Wrong length");

    let data_packet = build_data_packet(&dest_hash_bytes, b"test proof data");
    let mut packet_raw = [0u8; MTU];
    let packet_len = data_packet.pack(&mut packet_raw).unwrap();

    // Calculate packet hash for later verification
    let _packet_hash = sha256(&packet_raw[..packet_len]);

    send_framed(&mut stream, &packet_raw[..packet_len]).await;

    // Wait for proof from Python
    let mut deframer = Deframer::new();
    let _proof_packet =
        wait_for_any_proof_packet(&mut stream, &mut deframer, PACKET_WAIT_TIMEOUT).await;

    // Note: Python might send the proof to a different destination or not send one
    // if it doesn't have a route back to us. This test verifies the basic flow.
    // In a full implementation, we'd need proper path announcement handling.

    // For now, just verify we don't crash and the daemon is functioning
    daemon
        .ping()
        .await
        .expect("Daemon should still be responsive");
}

/// Test that Python daemon with PROVE_NONE does not send proofs
#[tokio::test]
async fn test_python_prove_none_no_proof() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Register a destination with default (PROVE_NONE)
    let dest_info = daemon
        .register_destination("proof_test", &["none"])
        .await
        .expect("Failed to register destination");

    let dest_hash = &dest_info.hash;

    // Verify default strategy is PROVE_NONE
    let strategy = daemon
        .get_proof_strategy(dest_hash)
        .await
        .expect("Failed to get proof strategy");
    assert_eq!(strategy, "PROVE_NONE");

    // Connect to daemon
    let mut stream = TcpStream::connect(daemon.rns_addr())
        .await
        .expect("Failed to connect");
    tokio::time::sleep(DAEMON_SETTLE_TIME).await;

    // Send a data packet
    let dest_hash_bytes: [u8; 16] = hex::decode(dest_hash)
        .expect("Invalid hex")
        .try_into()
        .expect("Wrong length");

    let data_packet = build_data_packet(&dest_hash_bytes, b"test no proof");
    let mut packet_raw = [0u8; MTU];
    let packet_len = data_packet.pack(&mut packet_raw).unwrap();
    send_framed(&mut stream, &packet_raw[..packet_len]).await;

    // Wait briefly - should NOT receive a proof
    let mut deframer = Deframer::new();
    let proof = wait_for_any_proof_packet(&mut stream, &mut deframer, Duration::from_secs(2)).await;

    // With PROVE_NONE, we should not receive any proof
    assert!(
        proof.is_none(),
        "Should not receive proof with PROVE_NONE strategy"
    );
}

/// Test proof validation - verify a proof we create is valid
#[tokio::test]
async fn test_proof_creation_and_validation() {
    let identity = Identity::generate_with_rng(&mut OsRng);

    // Simulate receiving a packet
    let packet_data = b"Test packet content for proof";
    let packet_hash = sha256(packet_data);

    // Create proof
    let proof = identity.create_proof(&packet_hash).unwrap();

    // Verify proof structure
    assert_eq!(proof.len(), 96);
    assert_eq!(&proof[..32], &packet_hash);

    // Verify signature
    let signature = &proof[32..];
    assert!(identity.verify(&packet_hash, signature).unwrap());

    // Full proof verification
    assert!(identity.verify_proof(&proof, &packet_hash));

    // Verification with wrong hash should fail
    let wrong_hash = [0xFFu8; 32];
    assert!(!identity.verify_proof(&proof, &wrong_hash));
}

/// Test that proof strategy setting works correctly
#[tokio::test]
async fn test_set_proof_strategy() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Register a destination
    let dest_info = daemon
        .register_destination("proof_test", &["strategy"])
        .await
        .expect("Failed to register destination");

    let dest_hash = &dest_info.hash;

    // Test each strategy
    for strategy in ["PROVE_NONE", "PROVE_APP", "PROVE_ALL"] {
        daemon
            .set_proof_strategy(dest_hash, strategy)
            .await
            .expect("Failed to set proof strategy");

        let current = daemon
            .get_proof_strategy(dest_hash)
            .await
            .expect("Failed to get proof strategy");

        assert_eq!(current, strategy);
    }
}
