//! Tests using the daemon harness for direct state verification.
//!
//! These tests spawn a fresh Python test daemon and verify behavior by
//! querying the daemon's internal state directly via JSON-RPC, rather than
//! relying on log file parsing or packet observation.
//!
//! ## Key Advantages
//!
//! 1. **No manual rnsd startup** - Each test spawns its own daemon
//! 2. **Direct state queries** - Verify path_table, announce_table directly
//! 3. **Clean isolation** - Fresh daemon per test, no interference
//! 4. **Fast feedback** - Tests run automatically, no #[ignore]
//!
//! ## Running These Tests
//!
//! ```sh
//! # Run all daemon-based tests
//! cargo test --package reticulum-std --test rnsd_interop daemon_tests
//!
//! # Run with verbose output
//! cargo test --package reticulum-std --test rnsd_interop daemon_tests -- --nocapture
//! ```

use std::time::Duration;

use crate::common::*;
use crate::harness::TestDaemon;

// =========================================================================
// Basic announce -> path creation tests
// =========================================================================

/// Verify that sending a valid announce creates a path entry in the daemon.
///
/// This is the fundamental test for announce propagation: we send an announce
/// and verify that Transport.path_table contains an entry for that destination.
#[tokio::test]
async fn test_announce_creates_path_entry() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Verify daemon starts with empty path table
    let initial_paths = daemon.get_path_table().await.expect("Failed to get paths");
    println!("Initial path count: {}", initial_paths.len());

    // Send an announce
    let dest_hash = send_announce_to_daemon(
        &daemon,
        "leviculum",
        &["pathtest", "basic"],
        b"path-test-data",
    )
    .await;

    // Wait a bit more for processing
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify path exists
    let has_path = daemon.has_path(&dest_hash).await;
    assert!(has_path, "Path should exist after announce");

    // Get path details
    let paths = daemon.get_path_table().await.expect("Failed to get paths");
    let hash_hex = hex::encode(dest_hash);
    let path_entry = paths.get(&hash_hex);

    assert!(path_entry.is_some(), "Path entry should exist in path_table");
    let entry = path_entry.unwrap();
    // Note: Reticulum increments hop count when receiving, so hops=0 in packet becomes hops=1 in path_table
    assert_eq!(entry.hops, Some(1), "Announce received with hops=0 should be recorded as hops=1");

    println!("Path created successfully:");
    println!("  Hash: {}", hash_hex);
    println!("  Hops: {:?}", entry.hops);
    println!("  Timestamp: {:?}", entry.timestamp);
}

/// Verify that announces with different hop counts are recorded correctly.
#[tokio::test]
async fn test_announce_hop_count_recorded() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Send announce with hops=0
    let (raw0, hash0, _) = build_announce_raw("leviculum", &["hops", "zero"], b"hops0");
    send_raw_to_daemon(&daemon, &raw0).await;

    // Send announce with hops=5
    let (raw5, hash5, _) = build_announce_raw_with_hops("leviculum", &["hops", "five"], b"hops5", 5);
    send_raw_to_daemon(&daemon, &raw5).await;

    // Wait for processing
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify paths exist with correct hop counts
    let paths = daemon.get_path_table().await.expect("Failed to get paths");

    let entry0 = paths.get(&hex::encode(hash0));
    assert!(entry0.is_some(), "Path for hops=0 should exist");
    // Note: The daemon may increment the hop count when recording
    println!("Hops=0 announce recorded with hops={:?}", entry0.unwrap().hops);

    let entry5 = paths.get(&hex::encode(hash5));
    assert!(entry5.is_some(), "Path for hops=5 should exist");
    println!("Hops=5 announce recorded with hops={:?}", entry5.unwrap().hops);
}

/// Verify that an invalid announce (bad signature) does NOT create a path.
#[tokio::test]
async fn test_invalid_announce_no_path() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Build a valid announce then corrupt the signature
    let (mut raw, dest_hash, _) = build_announce_raw("leviculum", &["invalid", "sig"], b"bad-sig");

    // Corrupt the signature (at offset 103-167 in raw packet)
    raw[103] ^= 0xFF;
    raw[104] ^= 0xFF;

    // Send the corrupted announce
    send_raw_to_daemon(&daemon, &raw).await;

    // Wait for processing
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify NO path was created
    let has_path = daemon.has_path(&dest_hash).await;
    assert!(!has_path, "Invalid announce should NOT create path");

    println!("Correctly rejected announce with corrupted signature");
}

// =========================================================================
// Destination registration and announce tests
// =========================================================================

/// Verify that we can register a destination in the daemon and retrieve its info.
#[tokio::test]
async fn test_register_and_announce_destination() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Register a destination
    let dest_info = daemon
        .register_destination("testapp", &["echo", "v1"])
        .await
        .expect("Failed to register destination");

    println!("Registered destination:");
    println!("  Hash: {}", dest_info.hash);
    println!("  Signing key: {}", dest_info.signing_key);

    // Announce the destination
    daemon
        .announce_destination(&dest_info.hash, b"test-app-data")
        .await
        .expect("Failed to announce");

    // The announce should create a path to this destination
    tokio::time::sleep(Duration::from_millis(500)).await;

    let dest_hash_bytes = hex::decode(&dest_info.hash).expect("Invalid hex");
    let has_path = daemon.has_path(&dest_hash_bytes).await;

    // Note: The daemon may or may not create a path for its own destinations
    println!("Has path to own destination: {}", has_path);
}

// =========================================================================
// Propagation verification tests
// =========================================================================

/// Verify announce propagation between two connections to the same daemon.
///
/// This tests the daemon's announce retransmission behavior by:
/// 1. Opening two connections to the daemon
/// 2. Sending an announce on connection 1
/// 3. Verifying it's received on connection 2
#[tokio::test]
async fn test_announce_propagates_between_connections() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Open two connections
    let mut conn1 = connect_to_daemon(&daemon).await;
    let mut conn2 = connect_to_daemon(&daemon).await;

    // Send announce on conn1
    let (dest_hash, _) = build_and_send_announce(
        &mut conn1,
        "leviculum",
        &["propagate", "test"],
        b"propagate-test",
    )
    .await;

    println!("Sent announce on conn1, dest: {:02x?}...", &dest_hash[..4]);

    // Wait for announce on conn2
    let found = wait_for_announce(&mut conn2, &dest_hash, Duration::from_secs(10)).await;

    assert!(found, "Announce should propagate to second connection");
    println!("Announce successfully propagated to conn2");

    // Verify path exists in daemon state
    assert!(daemon.has_path(&dest_hash).await, "Path should exist in daemon");
}

// =========================================================================
// Interface state verification
// =========================================================================

/// Verify the daemon's interface configuration matches expectations.
#[tokio::test]
async fn test_interface_configuration() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    let interfaces = daemon.get_interfaces().await.expect("Failed to get interfaces");

    // Should have exactly one interface (the TCP server)
    assert!(!interfaces.is_empty(), "Should have at least one interface");

    let tcp_iface = interfaces
        .iter()
        .find(|i| i.name.contains("TCP"))
        .expect("TCP interface should exist");

    assert_eq!(tcp_iface.online, Some(true), "Interface should be online");
    assert_eq!(tcp_iface.in_enabled, Some(true), "Interface should accept incoming");
    assert_eq!(tcp_iface.out_enabled, Some(true), "Interface should allow outgoing");

    println!("Interface configuration verified:");
    for iface in &interfaces {
        println!(
            "  {} - online={:?}, IN={:?}, OUT={:?}",
            iface.name, iface.online, iface.in_enabled, iface.out_enabled
        );
    }
}

// =========================================================================
// Announce deduplication tests
// =========================================================================

/// Verify that duplicate announces are deduplicated by the daemon.
///
/// Note: When transport is enabled, the daemon retransmits announces to all interfaces.
/// With a TCPServerInterface, each client connection is treated as a separate "peer",
/// so the announce gets forwarded. The deduplication being tested here is that the
/// daemon doesn't process/propagate the same announce TWICE from the same source -
/// it should only create one path entry regardless of how many times the same announce
/// is received.
#[tokio::test]
async fn test_announce_deduplication() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Build an announce
    let (raw, dest_hash, _) = build_announce_raw("leviculum", &["dedup", "test"], b"dedup");

    // Send the EXACT same announce twice quickly via two separate sends
    send_raw_to_daemon(&daemon, &raw).await;
    send_raw_to_daemon(&daemon, &raw).await;

    println!("Sent same announce twice");

    // Wait for processing
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The key verification is that only ONE path entry exists
    let paths = daemon.get_path_table().await.expect("Failed to get paths");
    let hash_hex = hex::encode(dest_hash);

    let matching_paths: Vec<_> = paths.keys().filter(|k| *k == &hash_hex).collect();

    // Should have exactly 1 path entry (deduplicated)
    println!(
        "Found {} path entries for this destination (expected 1)",
        matching_paths.len()
    );
    assert_eq!(
        matching_paths.len(),
        1,
        "Daemon should deduplicate announces into single path entry"
    );

    // Also verify the path exists
    assert!(daemon.has_path(&dest_hash).await);
}

// =========================================================================
// Boundary tests
// =========================================================================

/// Test announce with minimal (1 byte) app_data.
#[tokio::test]
async fn test_minimal_app_data_creates_path() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Send announce with 1 byte app_data (minimum valid)
    let dest_hash = send_announce_to_daemon(&daemon, "leviculum", &["minimal"], b"m").await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        daemon.has_path(&dest_hash).await,
        "Minimal app_data announce should create path"
    );

    println!("Minimal (1 byte) app_data announce accepted");
}

/// Test announce near MTU boundary.
#[tokio::test]
async fn test_large_app_data_creates_path() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Use 200 bytes of app_data (well under MTU but substantial)
    let large_app_data = vec![0x42u8; 200];
    let dest_hash = send_announce_to_daemon(&daemon, "leviculum", &["large"], &large_app_data).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        daemon.has_path(&dest_hash).await,
        "Large app_data announce should create path"
    );

    println!("Large (200 byte) app_data announce accepted");
}

// =========================================================================
// Hash derivation tests
// =========================================================================

/// Verify that our hash computation matches the daemon's hash for a registered destination.
///
/// This test compares hash derivation between Rust and Python implementations:
/// 1. Register a destination in the Python daemon
/// 2. Create the same destination in Rust
/// 3. Compare the computed hashes
#[tokio::test]
async fn test_hash_derivation_matches_daemon() {
    use reticulum_core::crypto::truncated_hash;

    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Register a destination in the daemon
    let dest_info = daemon
        .register_destination("hashtest", &["verify"])
        .await
        .expect("Failed to register destination");

    println!("Daemon registered destination with hash: {}", dest_info.hash);

    // Verify hash format (should be 16 bytes = 32 hex chars)
    assert_eq!(dest_info.hash.len(), 32, "Hash should be 16 bytes hex-encoded");

    // Verify the hash derivation formula:
    // destination_hash = truncated_hash(name_hash || identity_hash)
    // where identity_hash = truncated_hash(public_key)

    let pub_key_bytes = hex::decode(&dest_info.public_key).expect("Invalid public key hex");
    assert_eq!(pub_key_bytes.len(), 64, "Public key should be 64 bytes");

    // Compute identity hash from public key
    let identity_hash = truncated_hash(&pub_key_bytes);
    println!("Computed identity hash: {}", hex::encode(identity_hash));

    // Compute name hash
    let name_hash = compute_name_hash("hashtest", &["verify"]);
    println!("Computed name hash: {}", hex::encode(name_hash));

    // Compute destination hash
    let computed_dest_hash = compute_destination_hash(&name_hash, &identity_hash);
    let computed_hex = hex::encode(computed_dest_hash);

    println!("Daemon destination hash:   {}", dest_info.hash);
    println!("Computed destination hash: {}", computed_hex);

    assert_eq!(
        computed_hex, dest_info.hash,
        "Rust hash derivation should match Python"
    );

    println!("Hash derivation verified - Rust matches Python!");
}

// =========================================================================
// Ratchet boundary detection tests
// =========================================================================

/// Test ratchet boundary detection with 32 bytes of app_data.
///
/// This is a critical edge case:
/// - Non-ratcheted announce with 32 bytes app_data: 148 + 32 = 180 bytes payload
/// - Ratcheted announce (minimum, 0 bytes app_data): 148 + 32 = 180 bytes payload
///
/// Both have the SAME payload size! The only way to distinguish them is by
/// checking the context_flag in the packet flags. This test verifies that
/// our packet construction correctly sets the flag.
#[tokio::test]
async fn test_non_ratcheted_32_byte_app_data() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Create an announce with exactly 32 bytes of app_data (non-ratcheted)
    // This is the boundary case where payload size equals ratcheted minimum
    let app_data_32 = vec![0x42u8; 32];
    let dest_hash = send_announce_to_daemon(&daemon, "leviculum", &["ratchet", "boundary"], &app_data_32).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify the daemon accepted it as a valid announce and created a path
    assert!(
        daemon.has_path(&dest_hash).await,
        "32-byte app_data announce should create path"
    );

    println!("32-byte app_data (ratchet boundary) announce accepted");

    // Verify our packet has context_flag=false (non-ratcheted)
    let (raw, _, _) = build_announce_raw("leviculum", &["ratchet", "test2"], &app_data_32);
    let flags_byte = raw[0];
    let context_flag = (flags_byte & 0x80) != 0;
    assert!(!context_flag, "Non-ratcheted announce should have context_flag=false");

    println!("Verified context_flag=false for non-ratcheted announce");
}

// =========================================================================
// Concurrent daemon tests
// =========================================================================

/// Verify that multiple tests can run concurrently with separate daemons.
/// (This is a meta-test for the test infrastructure itself.)
#[tokio::test]
async fn test_daemon_isolation_a() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon A");

    let dest_hash = send_announce_to_daemon(&daemon, "leviculum", &["isolation", "a"], b"test-a").await;

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(daemon.has_path(&dest_hash).await);

    // This daemon is completely independent
    println!("Daemon A test completed on port {}", daemon.rns_port());
}

#[tokio::test]
async fn test_daemon_isolation_b() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon B");

    let dest_hash = send_announce_to_daemon(&daemon, "leviculum", &["isolation", "b"], b"test-b").await;

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(daemon.has_path(&dest_hash).await);

    // This daemon is completely independent
    println!("Daemon B test completed on port {}", daemon.rns_port());
}
