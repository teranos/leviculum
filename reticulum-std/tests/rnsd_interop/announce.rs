//! Announce creation, propagation, and adversarial tests

use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use reticulum_core::constants::{MTU, PATHFINDER_MAX_HOPS, TRUNCATED_HASHBYTES};
use reticulum_core::crypto::truncated_hash;
use reticulum_core::destination::DestinationType;
use reticulum_core::identity::Identity;
use reticulum_core::packet::{
    HeaderType, Packet, PacketContext, PacketData, PacketFlags, PacketType, TransportType,
};

use crate::common::*;

// =========================================================================
// Existing tests (moved from monolithic file)
// =========================================================================

/// Create and send a valid announce, verify rnsd accepts it
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_create_and_send_announce() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    println!("=== CREATE AND SEND ANNOUNCE TEST ===\n");

    let (dest_hash, _identity) =
        build_and_send_announce(&mut stream, "leviculum", &["test", "announce"], b"leviculum-test-node").await;

    println!("  Destination hash: {:02x?}...", &dest_hash[..4]);
    println!("Announce sent!");

    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut buffer = [0u8; 1024];
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(0)) => panic!("Connection closed by rnsd - announce may have been rejected"),
        Ok(Err(e)) => panic!("Read error: {} - announce may have been rejected", e),
        _ => println!("Connection still open (announce accepted)"),
    }

    println!("SUCCESS: Announce created and sent successfully!");
}

/// Verify rnsd accepts and propagates our announces between two clients
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_announce_propagation_between_clients() {
    let log_monitor = RnsdLogMonitor::new();

    let mut stream1 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection 1 timeout")
        .expect("Failed to connect stream 1");

    let mut stream2 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection 2 timeout")
        .expect("Failed to connect stream 2");

    println!("=== ANNOUNCE PROPAGATION TEST ===\n");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    let (dest_hash, _identity) =
        build_and_send_announce(&mut stream1, "leviculum", &["propagation", "test"], b"propagation-test").await;

    println!("Sent announce on stream 1, dest: {:02x?}...", &dest_hash[..4]);
    println!("Waiting for propagation to stream 2...");

    let found = wait_for_announce(&mut stream2, &dest_hash, PROPAGATION_TIMEOUT).await;

    // Check rnsd logs
    if let Some(monitor) = &log_monitor {
        let errors = monitor.check_for_errors();
        if !errors.is_empty() {
            println!("\n=== RNSD LOG ERRORS ===");
            for error in &errors {
                println!("  {}", error);
            }
            panic!("rnsd logged {} error(s)!", errors.len());
        }
        println!("rnsd log check: No errors");
    }

    assert!(found, "Announce was not propagated to stream 2");
    println!("SUCCESS: rnsd accepted and propagated our announce!");
}

/// Send an announce with invalid signature, verify rejection
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_invalid_announce_signature() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    println!("=== INVALID ANNOUNCE SIGNATURE TEST ===\n");

    let (mut raw, _dest_hash, _identity) =
        build_announce_raw("leviculum", &["test", "invalid"], b"invalid-sig-test");

    // Corrupt the signature (bytes 84..148 of the payload, which starts at offset 19)
    // Packet: [flags(1)][hops(1)][dest_hash(16)][context(1)][payload...]
    // Payload: [public_key(64)][name_hash(10)][random_hash(10)][signature(64)][app_data]
    // So signature starts at offset 19 + 64 + 10 + 10 = 103
    raw[103] ^= 0xFF;
    raw[104] ^= 0xFF;
    raw[135] ^= 0xFF;

    send_framed(&mut stream, &raw).await;
    println!("Sent announce with CORRUPTED signature");

    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        connection_alive(&mut stream).await,
        "Connection should stay open after bad announce"
    );
    println!("Connection still open (expected - bad announce silently dropped)");
}

// =========================================================================
// NEW tests: Boundary and edge cases
// =========================================================================

/// 1.1: Send announce with minimal app_data (1 byte)
///
/// Note: rnsd rejects announces with empty (zero-length) app_data as invalid.
/// The minimum valid announce has at least 1 byte of app_data.
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_minimum_valid_announce() {
    let log_monitor = RnsdLogMonitor::new();

    let mut conn1 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn1");
    let mut conn2 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn2");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    // Build announce with minimal (1 byte) app_data
    // rnsd requires non-empty app_data for valid announces
    let (dest_hash, _identity) =
        build_and_send_announce(&mut conn1, "leviculum", &["minimal", "test"], b"m").await;

    println!("Sent minimum announce (1 byte app_data), dest: {:02x?}...", &dest_hash[..4]);

    let found = wait_for_announce(&mut conn2, &dest_hash, PROPAGATION_TIMEOUT).await;

    if let Some(monitor) = &log_monitor {
        let errors = monitor.check_for_errors();
        assert!(errors.is_empty(), "rnsd logged errors: {:?}", errors);
    }

    assert!(found, "Minimum announce should propagate");
    println!("SUCCESS: Minimum valid announce (1 byte app_data) propagated");
}

/// 1.2: Test announce at MTU boundary
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_announce_at_mtu_boundary() {
    let log_monitor = RnsdLogMonitor::new();

    let mut conn1 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn1");
    let mut conn2 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn2");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    // Type1 packed_size = 2 + HEADER_MINSIZE(19) + 1 + data.len() = 22 + data.len()
    // pack() rejects when packed_size() > MTU (500), so max data = 478
    // Payload = public_key(64) + name_hash(10) + random_hash(10) + signature(64) + app_data = 148 + app_data
    // So max app_data for Type1 = 478 - 148 = 330
    //
    // BUT: rnsd retransmits announces as Type2 Transport packets, which adds
    // TRUNCATED_HASHBYTES (16) for the transport_id. If the Type1 packet is at
    // the absolute MTU limit, the Type2 retransmission will EXCEED the MTU and
    // crash rnsd's jobloop thread (unhandled exception), killing ALL announce
    // retransmission for the remainder of the rnsd process.
    //
    // Max propagatable app_data = 330 - 16 = 314
    let packed_overhead = 22; // 2 + HEADER_MINSIZE(19) + 1
    let fixed_payload = 148; // pub_key + name_hash + random_hash + signature
    let type2_transport_overhead = TRUNCATED_HASHBYTES; // 16 bytes for transport_id
    let max_propagatable_app_data = MTU - packed_overhead - fixed_payload - type2_transport_overhead;
    assert_eq!(max_propagatable_app_data, 314);
    let at_mtu_app_data = vec![0x41u8; max_propagatable_app_data];

    let (dest_hash, _identity) =
        build_and_send_announce(&mut conn1, "leviculum", &["mtu", "test"], &at_mtu_app_data).await;

    println!("Sent at-MTU announce ({} byte app_data), dest: {:02x?}...", max_propagatable_app_data, &dest_hash[..4]);

    let found = wait_for_announce(&mut conn2, &dest_hash, PROPAGATION_TIMEOUT).await;

    if let Some(monitor) = &log_monitor {
        let errors = monitor.check_for_errors();
        assert!(errors.is_empty(), "rnsd logged errors for at-MTU announce: {:?}", errors);
    }

    assert!(found, "At-MTU announce should propagate");
    println!("SUCCESS: At-MTU announce propagated");

    // Now try one byte over Type1 MTU - this should fail to pack
    let max_type1_app_data = MTU - packed_overhead - fixed_payload;
    let over_mtu_app_data = vec![0x42u8; max_type1_app_data + 1];
    let identity = Identity::new();
    let public_key = identity.public_key_bytes();
    let identity_hash = *identity.hash();
    let name_hash = compute_name_hash("leviculum", &["mtu", "over"]);
    let random_hash = generate_random_hash();
    let destination_hash = compute_destination_hash(&name_hash, &identity_hash);

    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&destination_hash);
    signed_data.extend_from_slice(&public_key);
    signed_data.extend_from_slice(&name_hash);
    signed_data.extend_from_slice(&random_hash);
    signed_data.extend_from_slice(&over_mtu_app_data);

    let signature = identity.sign(&signed_data).unwrap();

    let mut payload = Vec::new();
    payload.extend_from_slice(&public_key);
    payload.extend_from_slice(&name_hash);
    payload.extend_from_slice(&random_hash);
    payload.extend_from_slice(&signature);
    payload.extend_from_slice(&over_mtu_app_data);

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

    let mut raw = [0u8; 600]; // bigger than MTU to allow pack to try
    let result = packet.pack(&mut raw);
    assert!(result.is_err(), "Over-MTU packet should fail to pack");
    println!("SUCCESS: Over-MTU announce correctly rejected by pack()");
}

/// 1.3: Test announce with hops at PATHFINDER_MAX_HOPS boundary
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_announce_with_maximum_hops() {
    let mut conn1 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn1");
    let mut conn2 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn2");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    // Send with hops = PATHFINDER_MAX_HOPS - 1 (127): should propagate
    let (raw_below, dest_hash_below, _id) =
        build_announce_raw_with_hops("leviculum", &["hops", "below"], b"hops-below", PATHFINDER_MAX_HOPS - 1);
    send_framed(&mut conn1, &raw_below).await;

    println!("Sent announce with hops={}, dest: {:02x?}...", PATHFINDER_MAX_HOPS - 1, &dest_hash_below[..4]);

    let found_below = wait_for_announce(&mut conn2, &dest_hash_below, PROPAGATION_TIMEOUT).await;
    // Note: rnsd may or may not propagate based on its own hop limit logic
    println!("Hops {} announce propagated: {}", PATHFINDER_MAX_HOPS - 1, found_below);

    // Send with hops = PATHFINDER_MAX_HOPS (128): should NOT propagate
    let (raw_at, dest_hash_at, _id2) =
        build_announce_raw_with_hops("leviculum", &["hops", "at"], b"hops-at", PATHFINDER_MAX_HOPS);
    send_framed(&mut conn1, &raw_at).await;

    println!("Sent announce with hops={}, dest: {:02x?}...", PATHFINDER_MAX_HOPS, &dest_hash_at[..4]);

    let found_at = wait_for_announce(&mut conn2, &dest_hash_at, Duration::from_secs(5)).await;
    assert!(!found_at, "Announce at PATHFINDER_MAX_HOPS should NOT propagate");
    println!("SUCCESS: Announce at max hops correctly NOT propagated");
}

// =========================================================================
// NEW tests: Negative and adversarial
// =========================================================================

/// 2.1: Announce with wrong destination hash in header
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_announce_with_wrong_destination_hash() {
    let log_monitor = RnsdLogMonitor::new();

    let mut conn1 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn1");
    let mut conn2 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn2");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    let (mut raw, dest_hash, _identity) =
        build_announce_raw("leviculum", &["wronghash", "test"], b"wrong-hash-test");

    // Flip one byte of the destination hash in the header (offset 2..18)
    raw[2] ^= 0xFF;

    let corrupted_dest_hash: [u8; 16] = raw[2..18].try_into().unwrap();
    send_framed(&mut conn1, &raw).await;

    println!("Sent announce with corrupted dest hash");
    println!("  Original: {:02x?}...", &dest_hash[..4]);
    println!("  Corrupted: {:02x?}...", &corrupted_dest_hash[..4]);

    // Should NOT be propagated (hash won't match identity)
    let found_orig = wait_for_announce(&mut conn2, &dest_hash, Duration::from_secs(5)).await;
    assert!(!found_orig, "Original hash should not appear (it was corrupted)");

    let found_corrupt = wait_for_announce(&mut conn2, &corrupted_dest_hash, Duration::from_secs(5)).await;
    assert!(!found_corrupt, "Corrupted-hash announce should not propagate");

    if let Some(monitor) = &log_monitor {
        let errors = monitor.check_for_errors();
        println!("rnsd errors (expected): {:?}", errors);
    }

    println!("SUCCESS: Wrong-hash announce rejected");
}

/// 2.2: Announce with swapped X25519/Ed25519 key halves
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_announce_with_swapped_public_keys() {
    let mut conn1 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn1");
    let mut conn2 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn2");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    let identity = Identity::new();
    let public_key = identity.public_key_bytes();

    // Swap X25519 (0..32) and Ed25519 (32..64) halves
    let mut swapped_key = [0u8; 64];
    swapped_key[..32].copy_from_slice(&public_key[32..64]);
    swapped_key[32..64].copy_from_slice(&public_key[..32]);

    // Compute hashes using swapped key (identity hash will differ)
    let swapped_identity_hash = truncated_hash(&swapped_key);
    let name_hash = compute_name_hash("leviculum", &["swapped", "test"]);
    let random_hash = generate_random_hash();
    let dest_hash = compute_destination_hash(&name_hash, &swapped_identity_hash);

    // Sign with real key (but payload has swapped key => hash won't match)
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&dest_hash);
    signed_data.extend_from_slice(&swapped_key);
    signed_data.extend_from_slice(&name_hash);
    signed_data.extend_from_slice(&random_hash);

    let signature = identity.sign(&signed_data).unwrap();

    let mut payload = Vec::new();
    payload.extend_from_slice(&swapped_key);
    payload.extend_from_slice(&name_hash);
    payload.extend_from_slice(&random_hash);
    payload.extend_from_slice(&signature);

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
        destination_hash: dest_hash,
        context: PacketContext::None,
        data: PacketData::Owned(payload),
    };

    let mut raw = [0u8; MTU];
    let size = packet.pack(&mut raw).unwrap();
    send_framed(&mut conn1, &raw[..size]).await;

    println!("Sent announce with swapped public key halves");

    // Should be rejected: Ed25519 key verification will fail because the
    // signature was made with the real key, but the embedded key is swapped
    let found = wait_for_announce(&mut conn2, &dest_hash, Duration::from_secs(5)).await;
    assert!(!found, "Swapped-key announce should be rejected");
    println!("SUCCESS: Swapped-key announce rejected");
}

/// 2.3: Replay deduplication - same announce twice
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_announce_replay_deduplication() {
    let mut conn1 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn1");
    let mut conn2 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn2");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    let (raw, dest_hash, _identity) =
        build_announce_raw("leviculum", &["replay", "test"], b"replay-test");

    // Send the exact same bytes twice in rapid succession
    send_framed(&mut conn1, &raw).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    send_framed(&mut conn1, &raw).await;

    println!("Sent same announce twice, dest: {:02x?}...", &dest_hash[..4]);

    // Collect announces for enough time to capture retransmissions
    let announces = collect_announces(&mut conn2, PROPAGATION_TIMEOUT).await;

    let matching: Vec<_> = announces
        .iter()
        .filter(|(h, _)| *h == dest_hash)
        .collect();

    println!("Received {} matching announces (expected: 1)", matching.len());
    assert_eq!(
        matching.len(),
        1,
        "rnsd should deduplicate: expected 1 copy, got {}",
        matching.len()
    );
    println!("SUCCESS: Replay deduplication works");
}

/// 2.6: Announce with zeroed signature
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_announce_with_zeroed_signature() {
    let log_monitor = RnsdLogMonitor::new();

    let mut conn1 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn1");
    let mut conn2 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn2");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    let (mut raw, dest_hash, _identity) =
        build_announce_raw("leviculum", &["zeroedsig", "test"], b"zeroed-sig");

    // Zero out the signature (payload offset 19, signature at payload offset 84..148)
    // Raw packet: [flags(1)][hops(1)][dest_hash(16)][context(1)] = 19 bytes header
    // Payload: [pub_key(64)][name_hash(10)][random_hash(10)][signature(64)][app_data]
    // Signature starts at raw offset 19 + 64 + 10 + 10 = 103
    for i in 103..103 + 64 {
        raw[i] = 0;
    }

    send_framed(&mut conn1, &raw).await;
    println!("Sent announce with zeroed signature");

    let found = wait_for_announce(&mut conn2, &dest_hash, Duration::from_secs(5)).await;
    assert!(!found, "Zeroed-signature announce should NOT propagate");

    if let Some(monitor) = &log_monitor {
        let errors = monitor.check_for_errors();
        println!("rnsd errors (expected for bad sig): {:?}", errors);
    }

    assert!(
        connection_alive(&mut conn1).await,
        "Connection should stay open after bad announce"
    );
    println!("SUCCESS: Zeroed-signature announce rejected, connection alive");
}

/// 2.7: Announce with truncated payload
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_announce_with_truncated_payload() {
    let mut conn1 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn1");
    let mut conn2 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn2");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    let (raw, dest_hash, _identity) =
        build_announce_raw("leviculum", &["truncated", "test"], b"truncated");

    // Truncate at 100 bytes (mid-payload, before signature completes)
    let truncated = &raw[..100.min(raw.len())];

    send_framed(&mut conn1, truncated).await;
    println!("Sent truncated announce ({} bytes)", truncated.len());

    let found = wait_for_announce(&mut conn2, &dest_hash, Duration::from_secs(5)).await;
    assert!(!found, "Truncated announce should NOT propagate");

    assert!(
        connection_alive(&mut conn1).await,
        "Connection should survive truncated announce"
    );
    println!("SUCCESS: Truncated announce rejected, connection alive");
}

// =========================================================================
// NEW: App data variant propagation tests
// =========================================================================

/// 5.3: Announces with various app_data content types
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_announce_propagation_with_app_data_variants() {
    // Note: rnsd rejects announces with empty (zero-length) app_data
    let test_cases: Vec<(&str, Vec<u8>)> = vec![
        ("single_byte", vec![0x42]),
        ("100_bytes", vec![0xAB; 100]),
        ("utf8_text", "Hello, Reticulum! \u{1F680}".as_bytes().to_vec()),
        ("binary_with_nulls", vec![0x00, 0x01, 0x00, 0xFF, 0x00]),
        ("max_reasonable", vec![0xCC; 200]),
    ];

    let mut propagated_count = 0;

    for (name, app_data) in &test_cases {
        let mut conn1 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
            .await
            .expect("Timeout")
            .expect("connect1");
        let mut conn2 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
            .await
            .expect("Timeout")
            .expect("connect2");

        tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

        let unique_aspect = format!("appdata_{}", name);
        let (dest_hash, _identity) =
            build_and_send_announce(&mut conn1, "leviculum", &[&unique_aspect], app_data).await;

        let found = wait_for_announce(&mut conn2, &dest_hash, PROPAGATION_TIMEOUT).await;

        if found {
            propagated_count += 1;
            println!("  OK: '{}' ({} bytes) propagated", name, app_data.len());
        } else {
            println!("  WARN: '{}' ({} bytes) not propagated", name, app_data.len());
        }

        // Delay between test cases to avoid overwhelming rnsd
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    assert!(propagated_count >= 3,
        "Expected at least 3 of {} app_data variants to propagate, got {}",
        test_cases.len(), propagated_count);
    println!("App data variant test complete: {}/{} propagated", propagated_count, test_cases.len());
}
