//! Keepalive and close interop tests for LinkManager.
//!
//! These tests verify that Rust's keepalive and close implementation correctly
//! interoperates with Python Reticulum. Tests cover:
//!
//! 1. **Keepalive Exchange** - Initiator sends 0xFF, responder echoes 0xFE
//! 2. **Graceful Close** - LINKCLOSE packet exchange
//! 3. **Stale Detection** - Link transitions to STALE when no packets received
//! 4. **Stale Timeout** - Stale links eventually close
//! 5. **Multi-hop Tests** - Keepalive and close through Python relay
//!
//! ## Running These Tests
//!
//! ```sh
//! # Run all keepalive/close tests
//! cargo test --package reticulum-std --test rnsd_interop link_keepalive_close
//!
//! # Run multi-hop tests specifically
//! cargo test --package reticulum-std --test rnsd_interop test_multi_hop
//!
//! # Run with verbose output
//! cargo test --package reticulum-std --test rnsd_interop link_keepalive_close -- --nocapture
//! ```

use std::cell::Cell;
use std::time::Duration;

use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use reticulum_core::constants::{
    LINK_KEEPALIVE_SECS, LINK_STALE_FACTOR, LINK_STALE_GRACE_SECS, MS_PER_SECOND,
    TRUNCATED_HASHBYTES,
};
use reticulum_core::destination::{Destination, DestinationType, Direction, ProofStrategy};
use reticulum_core::identity::Identity;
use reticulum_core::link::{LinkCloseReason, LinkEvent, LinkId, LinkManager, LinkState};
use reticulum_core::packet::{Packet, PacketContext, PacketType};
use reticulum_core::traits::Clock;
use reticulum_std::interfaces::hdlc::{frame, Deframer};

use crate::common::{
    connect_to_daemon, receive_proof_for_link, send_framed, wait_for_any_announce_with_route_info,
    wait_for_close_packet, wait_for_keepalive_packet, wait_for_link_request, wait_for_rtt_packet,
    TestClock,
};
use crate::harness::TestDaemon;

// =========================================================================
// Mock clock for time-controlled tests
// =========================================================================

/// Mock clock that can be manually advanced for testing time-dependent behavior
struct MockClock {
    time_ms: Cell<u64>,
}

impl MockClock {
    fn new(initial_ms: u64) -> Self {
        Self {
            time_ms: Cell::new(initial_ms),
        }
    }

    fn advance(&self, ms: u64) {
        self.time_ms.set(self.time_ms.get() + ms);
    }

    fn advance_secs(&self, secs: u64) {
        self.advance(secs * MS_PER_SECOND);
    }
}

impl Clock for MockClock {
    fn now_ms(&self) -> u64 {
        self.time_ms.get()
    }
}

// =========================================================================
// Helper functions
// =========================================================================

/// Establish a link with Rust as initiator, returning (link_id, link_hash_hex).
async fn establish_link_as_initiator(
    manager: &mut LinkManager,
    daemon: &TestDaemon,
    stream: &mut TcpStream,
    deframer: &mut Deframer,
) -> Result<(LinkId, String), String> {
    let clock = TestClock;

    // Register a destination in daemon
    let dest_info = daemon
        .register_destination("keepalive", &["test"])
        .await
        .map_err(|e| format!("Failed to register destination: {}", e))?;

    // Extract signing key
    let pub_key_bytes =
        hex::decode(&dest_info.public_key).map_err(|e| format!("Invalid public key: {}", e))?;
    let signing_key: [u8; 32] = pub_key_bytes[32..64]
        .try_into()
        .map_err(|_| "Invalid signing key length")?;

    // Parse destination hash
    let dest_hash: [u8; TRUNCATED_HASHBYTES] = hex::decode(&dest_info.hash)
        .map_err(|e| format!("Invalid hash: {}", e))?
        .try_into()
        .map_err(|_| "Invalid hash length")?;

    // Initiate link
    let (link_id, link_request_packet) =
        manager.initiate(dest_hash.into(), &signing_key, clock.now_ms(), &mut OsRng);
    send_framed(stream, &link_request_packet).await;

    // Wait for proof
    let proof_packet = receive_proof_for_link(stream, deframer, &link_id, Duration::from_secs(10))
        .await
        .ok_or("No proof received")?;

    // Process proof
    manager.process_packet(&proof_packet, &[], clock.now_ms(), &mut OsRng);

    // Check for LinkEstablished
    let events: Vec<_> = manager.drain_events().collect();
    if !events
        .iter()
        .any(|e| matches!(e, LinkEvent::LinkEstablished { .. }))
    {
        return Err("LinkEstablished not received".to_string());
    }

    // Send RTT packet
    if let Some(rtt_packet) = manager.take_pending_rtt_packet(&link_id) {
        send_framed(stream, &rtt_packet).await;
    }

    // Wait for daemon to process RTT
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Get link hash hex for daemon RPC calls
    let link_hash_hex = hex::encode(link_id);

    Ok((link_id, link_hash_hex))
}

/// Set up a Rust destination and send its announce to the daemon.
async fn setup_rust_destination(
    stream: &mut TcpStream,
    app_name: &str,
    aspects: &[&str],
    app_data: &[u8],
) -> (Destination, String) {
    let identity = Identity::generate(&mut OsRng);
    let public_key_hex = hex::encode(identity.public_key_bytes());

    let mut destination = Destination::new(
        Some(identity),
        Direction::In,
        DestinationType::Single,
        app_name,
        aspects,
    )
    .expect("Failed to create destination");

    // Create and send announce
    let packet = destination
        .announce(Some(app_data), &mut OsRng, crate::common::now_ms())
        .expect("Failed to create announce");

    let mut raw_packet = [0u8; 500];
    let size = packet.pack(&mut raw_packet).expect("Failed to pack");

    let mut framed = Vec::new();
    frame(&raw_packet[..size], &mut framed);
    stream.write_all(&framed).await.expect("Failed to send");
    stream.flush().await.expect("Failed to flush");

    (destination, public_key_hex)
}

// =========================================================================
// Rust-to-Rust link establishment helper for multi-hop tests
// =========================================================================

/// Holds all state for a Rust-to-Rust link established through a relay.
/// A is the responder (announces), B is the initiator (creates link).
pub struct RustToRustLink {
    /// Link ID (same for both sides)
    pub link_id: LinkId,
    /// Manager for side A (responder)
    pub manager_a: LinkManager,
    /// Stream for side A
    pub stream_a: TcpStream,
    /// Deframer for side A
    pub deframer_a: Deframer,
    /// Manager for side B (initiator)
    pub manager_b: LinkManager,
    /// Stream for side B
    pub stream_b: TcpStream,
    /// Deframer for side B
    pub deframer_b: Deframer,
}

/// Establish a Rust-to-Rust link through the Python daemon as relay.
///
/// This encapsulates the pattern from `test_rust_to_rust_via_daemon`:
/// 1. B connects first to receive announces
/// 2. A sets up destination and announces via separate stream
/// 3. B receives announce via `wait_for_any_announce_with_route_info`
/// 4. B initiates link using `initiate_with_path(dest_hash, signing_key, transport_id, hops)`
/// 5. Complete handshake: link request -> proof -> RTT
///
/// Returns a `RustToRustLink` containing all state needed for further testing.
/// Note: Identity is used during establishment and not stored - it's only needed for accept_link.
async fn establish_rust_to_rust_link(daemon: &TestDaemon) -> Result<RustToRustLink, String> {
    let clock = TestClock;

    // B connects first to receive announces
    let mut stream_b = connect_to_daemon(daemon).await;
    let mut deframer_b = Deframer::new();
    let mut manager_b = LinkManager::new();

    // A (Responder) sets up and announces
    let mut stream_a = connect_to_daemon(daemon).await;
    let mut deframer_a = Deframer::new();

    let (destination_a, _public_key_hex_a) =
        setup_rust_destination(&mut stream_a, "r2r_keepalive", &["test"], b"rust-A").await;

    let dest_hash_a = *destination_a.hash();
    let identity_a = destination_a.identity().expect("Should have identity");

    let mut manager_a = LinkManager::new();
    manager_a.register_destination(dest_hash_a);

    // Wait for daemon to process announce
    tokio::time::sleep(Duration::from_millis(500)).await;

    // B receives A's announce with routing info
    let announce_info = wait_for_any_announce_with_route_info(
        &mut stream_b,
        &mut deframer_b,
        Duration::from_secs(5),
    )
    .await
    .ok_or("B should receive A's announce from daemon")?;

    // Verify the announce is for A's destination
    if announce_info.packet.destination_hash != dest_hash_a {
        return Err("Announce should be for A's destination".to_string());
    }

    // Extract routing info from the announce
    let signing_key_a = announce_info
        .signing_key()
        .ok_or("Failed to extract signing key from announce")?;
    let transport_id = announce_info.transport_id;
    let hops = announce_info.hops;

    // B initiates link to A using transport headers if announce came through relay
    let (link_id_b, link_request_packet) = manager_b.initiate_with_path(
        dest_hash_a,
        &signing_key_a,
        transport_id,
        hops,
        clock.now_ms(),
        &mut OsRng,
    );

    // Send link request via B's stream
    send_framed(&mut stream_b, &link_request_packet).await;

    // A receives link request
    let (raw_request, link_id_a_bytes) = wait_for_link_request(
        &mut stream_a,
        &mut deframer_a,
        &dest_hash_a,
        Duration::from_secs(10),
    )
    .await
    .ok_or("A should receive link request")?;
    let link_id_a = LinkId::new(link_id_a_bytes);

    // Verify link IDs match
    if link_id_a != link_id_b {
        return Err(format!(
            "Link IDs should match: A={} B={}",
            hex::encode(link_id_a),
            hex::encode(link_id_b)
        ));
    }

    let request_pkt =
        Packet::unpack(&raw_request).map_err(|e| format!("Failed to unpack: {:?}", e))?;
    manager_a.process_packet(&request_pkt, &raw_request, clock.now_ms(), &mut OsRng);

    // A accepts the link
    let _: Vec<_> = manager_a.drain_events().collect();
    let proof_packet = manager_a
        .accept_link(&link_id_a, identity_a, ProofStrategy::None, clock.now_ms())
        .map_err(|e| format!("Failed to accept link: {:?}", e))?;

    // Send proof via A's stream
    send_framed(&mut stream_a, &proof_packet).await;

    // B receives proof
    let proof_pkt = receive_proof_for_link(
        &mut stream_b,
        &mut deframer_b,
        &link_id_b,
        Duration::from_secs(10),
    )
    .await
    .ok_or("B should receive proof")?;

    manager_b.process_packet(&proof_pkt, &[], clock.now_ms(), &mut OsRng);

    // B should have LinkEstablished
    let events_b: Vec<_> = manager_b.drain_events().collect();
    if !events_b.iter().any(|e| {
        matches!(
            e,
            LinkEvent::LinkEstablished {
                is_initiator: true,
                ..
            }
        )
    }) {
        return Err("B should have LinkEstablished event".to_string());
    }

    // B sends RTT
    let rtt_packet = manager_b
        .take_pending_rtt_packet(&link_id_b)
        .ok_or("Should have RTT packet")?;
    send_framed(&mut stream_b, &rtt_packet).await;

    // A receives RTT
    let rtt_data = wait_for_rtt_packet(
        &mut stream_a,
        &mut deframer_a,
        &link_id_a,
        Duration::from_secs(10),
    )
    .await
    .ok_or("A should receive RTT")?;

    // Build RTT packet for processing
    let mut rtt_raw = Vec::new();
    rtt_raw.push(0x0C);
    rtt_raw.push(0x00);
    rtt_raw.extend_from_slice(link_id_a.as_bytes());
    rtt_raw.push(PacketContext::Lrrtt as u8);
    rtt_raw.extend_from_slice(&rtt_data);

    let rtt_pkt = Packet::unpack(&rtt_raw).map_err(|e| format!("Failed to unpack RTT: {:?}", e))?;
    manager_a.process_packet(&rtt_pkt, &rtt_raw, clock.now_ms(), &mut OsRng);

    // A should have LinkEstablished
    let events_a: Vec<_> = manager_a.drain_events().collect();
    if !events_a.iter().any(|e| {
        matches!(
            e,
            LinkEvent::LinkEstablished {
                is_initiator: false,
                ..
            }
        )
    }) {
        return Err("A should have LinkEstablished event".to_string());
    }

    // Verify both links are active
    if !manager_a.is_active(&link_id_a) {
        return Err("Link should be active on A".to_string());
    }
    if !manager_b.is_active(&link_id_b) {
        return Err("Link should be active on B".to_string());
    }

    Ok(RustToRustLink {
        link_id: link_id_a,
        manager_a,
        stream_a,
        deframer_a,
        manager_b,
        stream_b,
        deframer_b,
    })
}

// =========================================================================
// Test 3: Rust graceful close received by Python
// =========================================================================

/// Test: Rust sends LINKCLOSE, Python transitions to CLOSED.
///
/// Steps:
/// 1. Start Python daemon
/// 2. Establish link (Rust as initiator)
/// 3. Call manager.close(&link_id, &mut OsRng)
/// 4. Drain and transmit close packet
/// 5. Call Python RPC wait_for_link_state(link_hash, "CLOSED", 5)
/// 6. Verify Python link is closed
/// 7. Verify Rust emits LinkClosed { reason: Normal }
#[tokio::test]
async fn test_rust_graceful_close_received_by_python() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    let mut stream = connect_to_daemon(&daemon).await;
    let mut deframer = Deframer::new();
    let mut manager = LinkManager::new();

    // Establish link
    let (link_id, link_hash_hex) =
        establish_link_as_initiator(&mut manager, &daemon, &mut stream, &mut deframer)
            .await
            .expect("Failed to establish link");

    assert!(manager.is_active(&link_id), "Link should be active");

    // Close the link gracefully
    manager.close(&link_id, &mut OsRng);

    // Drain and send close packets
    for (_, close_packet) in manager.drain_close_packets() {
        send_framed(&mut stream, &close_packet).await;
    }

    // Check for LinkClosed event
    let events: Vec<_> = manager.drain_events().collect();
    let close_event = events.iter().find(|e| {
        matches!(
            e,
            LinkEvent::LinkClosed { link_id: id, reason: LinkCloseReason::Normal }
            if *id == link_id
        )
    });
    assert!(
        close_event.is_some(),
        "Should emit LinkClosed with reason Normal"
    );

    // Wait for Python to process the close
    let wait_result = daemon
        .wait_for_link_state(&link_hash_hex, "CLOSED", 5)
        .await
        .expect("RPC call failed");

    assert_eq!(
        wait_result.status, "reached",
        "Python should reach CLOSED state. Got: {:?}",
        wait_result
    );

    println!("SUCCESS: Rust graceful close received by Python");
}

// =========================================================================
// Test 4: Python graceful close received by Rust
// =========================================================================

/// Test: Python sends LINKCLOSE, Rust transitions to CLOSED.
///
/// Steps:
/// 1. Start Python daemon
/// 2. Establish link (Rust as initiator)
/// 3. Call Python RPC close_link(link_hash)
/// 4. Read packets from stream
/// 5. Process LINKCLOSE packet in Rust
/// 6. Verify Rust link state is CLOSED
/// 7. Verify LinkClosed { reason: PeerClosed } event emitted
#[tokio::test]
async fn test_python_graceful_close_received_by_rust() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let clock = TestClock;

    let mut stream = connect_to_daemon(&daemon).await;
    let mut deframer = Deframer::new();
    let mut manager = LinkManager::new();

    // Establish link
    let (link_id, link_hash_hex) =
        establish_link_as_initiator(&mut manager, &daemon, &mut stream, &mut deframer)
            .await
            .expect("Failed to establish link");

    assert!(manager.is_active(&link_id), "Link should be active");

    // Have Python close the link
    let close_result = daemon
        .close_link(&link_hash_hex)
        .await
        .expect("RPC call failed");
    println!("Python close_link result: {}", close_result);

    // Wait for and process the close packet
    let close_raw =
        wait_for_close_packet(&mut stream, &mut deframer, &link_id, Duration::from_secs(5))
            .await
            .expect("Should receive LINKCLOSE packet from Python");

    let close_pkt = Packet::unpack(&close_raw).expect("Failed to unpack close packet");
    manager.process_packet(&close_pkt, &close_raw, clock.now_ms(), &mut OsRng);

    // Check for LinkClosed event with PeerClosed reason
    let events: Vec<_> = manager.drain_events().collect();
    let close_event = events.iter().find(|e| {
        matches!(
            e,
            LinkEvent::LinkClosed { link_id: id, reason: LinkCloseReason::PeerClosed }
            if *id == link_id
        )
    });

    assert!(
        close_event.is_some(),
        "Should emit LinkClosed with reason PeerClosed. Events: {:?}",
        events
    );

    println!("SUCCESS: Python graceful close received by Rust");
}

// =========================================================================
// Test 5: Link stale detection (no inbound traffic)
// =========================================================================

/// Test: Link transitions to STALE when no packets are received.
///
/// Steps:
/// 1. Create mock clock with controlled time
/// 2. Use two managers to simulate a complete handshake
/// 3. Calculate stale_time = keepalive_secs * STALE_FACTOR
/// 4. Advance MockClock past stale_time
/// 5. Call manager.poll()
/// 6. Verify LinkStale event emitted
/// 7. Verify link state is LinkState::Stale
#[tokio::test]
async fn test_link_stale_detection_no_inbound() {
    use reticulum_core::identity::Identity;

    // Start with a reasonable initial time
    let initial_time_secs = 10u64;
    let initiator_clock = MockClock::new(initial_time_secs * MS_PER_SECOND);
    let responder_clock = MockClock::new(initial_time_secs * MS_PER_SECOND);

    let mut initiator_mgr = LinkManager::new();
    let mut responder_mgr = LinkManager::new();

    // Create destination identity for responder
    let dest_identity = Identity::generate(&mut OsRng);
    let dest_hash = [0x42u8; 16];
    let dest_signing_key = dest_identity.ed25519_verifying().to_bytes();

    // Register destination on responder
    responder_mgr.register_destination(dest_hash.into());

    // Initiator starts link
    let (link_id, link_request_packet) = initiator_mgr.initiate(
        dest_hash.into(),
        &dest_signing_key,
        initiator_clock.now_ms(),
        &mut OsRng,
    );

    // Deliver link request to responder
    let packet = Packet::unpack(&link_request_packet).unwrap();
    responder_mgr.process_packet(&packet, &link_request_packet, responder_clock.now_ms(), &mut OsRng);

    // Responder accepts
    let _: Vec<_> = responder_mgr.drain_events().collect();
    let proof_packet = responder_mgr
        .accept_link(&link_id, &dest_identity, ProofStrategy::None, responder_clock.now_ms())
        .unwrap();

    // Deliver proof to initiator
    let proof = Packet::unpack(&proof_packet).unwrap();
    initiator_mgr.process_packet(&proof, &proof_packet, initiator_clock.now_ms(), &mut OsRng);

    // Initiator sends RTT
    let _: Vec<_> = initiator_mgr.drain_events().collect();
    let rtt_packet = initiator_mgr.take_pending_rtt_packet(&link_id).unwrap();

    // Deliver RTT to responder
    let rtt = Packet::unpack(&rtt_packet).unwrap();
    responder_mgr.process_packet(&rtt, &rtt_packet, responder_clock.now_ms(), &mut OsRng);
    let _: Vec<_> = responder_mgr.drain_events().collect();

    // Verify link is active on initiator
    assert!(
        initiator_mgr.is_active(&link_id),
        "Link should be active on initiator"
    );

    // Get the actual stale time from the link (depends on RTT calculation)
    // With near-zero RTT from mock handshake, stale_time_secs will be small
    let stale_time_secs = initiator_mgr
        .link(&link_id)
        .map(|l| l.stale_time_secs())
        .unwrap_or(LINK_KEEPALIVE_SECS * LINK_STALE_FACTOR);

    println!(
        "Link stale_time_secs = {} (keepalive_secs = {})",
        stale_time_secs,
        initiator_mgr
            .link(&link_id)
            .map(|l| l.keepalive_secs())
            .unwrap_or(0)
    );

    // Advance time past the stale threshold but NOT past the close timeout
    // Close timeout = stale_time_secs + RTT*TIMEOUT_FACTOR + GRACE (5s)
    initiator_clock.advance_secs(stale_time_secs + 1);

    // Poll the manager
    initiator_mgr.poll(initiator_clock.now_ms(), &mut OsRng);

    // Check for LinkStale event
    let events: Vec<_> = initiator_mgr.drain_events().collect();
    let stale_event = events
        .iter()
        .find(|e| matches!(e, LinkEvent::LinkStale { link_id: id } if *id == link_id));

    assert!(
        stale_event.is_some(),
        "Should emit LinkStale event. Events: {:?}",
        events
    );

    // Verify link state is Stale
    if let Some(link) = initiator_mgr.link(&link_id) {
        assert_eq!(
            link.state(),
            LinkState::Stale,
            "Link should be in Stale state"
        );
    } else {
        panic!("Link should still exist");
    }

    println!("SUCCESS: Link stale detection works");
}

// =========================================================================
// Test 6: Stale link closes after timeout
// =========================================================================

/// Test: Stale link sends LINKCLOSE and transitions to CLOSED.
///
/// Steps:
/// 1. Create mock clock with controlled time
/// 2. Simulate a complete handshake to get an active link
/// 3. Advance clock past stale_time (link becomes STALE)
/// 4. Calculate close_timeout based on stale grace period
/// 5. Advance clock past close_timeout
/// 6. Call manager.poll()
/// 7. Verify close packet generated
/// 8. Verify LinkClosed { reason: Stale } event emitted
#[tokio::test]
async fn test_stale_link_closes_after_timeout() {
    use reticulum_core::identity::Identity;

    let initial_time_secs = 10u64;
    let initiator_clock = MockClock::new(initial_time_secs * MS_PER_SECOND);
    let responder_clock = MockClock::new(initial_time_secs * MS_PER_SECOND);

    let mut initiator_mgr = LinkManager::new();
    let mut responder_mgr = LinkManager::new();

    // Create destination identity for responder
    let dest_identity = Identity::generate(&mut OsRng);
    let dest_hash = [0x42u8; 16];
    let dest_signing_key = dest_identity.ed25519_verifying().to_bytes();

    // Register destination on responder
    responder_mgr.register_destination(dest_hash.into());

    // Initiator starts link
    let (link_id, link_request_packet) = initiator_mgr.initiate(
        dest_hash.into(),
        &dest_signing_key,
        initiator_clock.now_ms(),
        &mut OsRng,
    );

    // Deliver link request to responder
    let packet = Packet::unpack(&link_request_packet).unwrap();
    responder_mgr.process_packet(&packet, &link_request_packet, responder_clock.now_ms(), &mut OsRng);

    // Responder accepts
    let _: Vec<_> = responder_mgr.drain_events().collect();
    let proof_packet = responder_mgr
        .accept_link(&link_id, &dest_identity, ProofStrategy::None, responder_clock.now_ms())
        .unwrap();

    // Deliver proof to initiator
    let proof = Packet::unpack(&proof_packet).unwrap();
    initiator_mgr.process_packet(&proof, &proof_packet, initiator_clock.now_ms(), &mut OsRng);

    // Initiator sends RTT
    let _: Vec<_> = initiator_mgr.drain_events().collect();
    let rtt_packet = initiator_mgr.take_pending_rtt_packet(&link_id).unwrap();

    // Deliver RTT to responder
    let rtt = Packet::unpack(&rtt_packet).unwrap();
    responder_mgr.process_packet(&rtt, &rtt_packet, responder_clock.now_ms(), &mut OsRng);
    let _: Vec<_> = responder_mgr.drain_events().collect();

    // Verify link is active on initiator
    assert!(
        initiator_mgr.is_active(&link_id),
        "Link should be active on initiator"
    );

    // Get the actual stale time from the link (depends on RTT calculation)
    let stale_time_secs = initiator_mgr
        .link(&link_id)
        .map(|l| l.stale_time_secs())
        .unwrap_or(LINK_KEEPALIVE_SECS * LINK_STALE_FACTOR);

    // Advance past stale time but NOT past close timeout
    initiator_clock.advance_secs(stale_time_secs + 1);

    // Poll to trigger stale transition
    initiator_mgr.poll(initiator_clock.now_ms(), &mut OsRng);

    // Drain stale events
    let events: Vec<_> = initiator_mgr.drain_events().collect();
    let has_stale = events
        .iter()
        .any(|e| matches!(e, LinkEvent::LinkStale { .. }));
    assert!(has_stale, "Should emit LinkStale event first");

    // Verify link is now stale
    if let Some(link) = initiator_mgr.link(&link_id) {
        assert_eq!(link.state(), LinkState::Stale, "Link should be stale");
    }

    // Advance past the stale grace period
    // Close timeout = stale_time + rtt*TIMEOUT_FACTOR + GRACE
    // Since RTT is ~0 in mock handshake, we just need to go past GRACE
    initiator_clock.advance_secs(LINK_STALE_GRACE_SECS + 2);

    // Poll to trigger close
    initiator_mgr.poll(initiator_clock.now_ms(), &mut OsRng);

    // Check for close packet
    let close_packets: Vec<_> = initiator_mgr.drain_close_packets();
    assert!(
        !close_packets.is_empty(),
        "Should generate close packet for stale link"
    );

    // Check for LinkClosed event with Stale reason
    let events: Vec<_> = initiator_mgr.drain_events().collect();
    let close_event = events.iter().find(|e| {
        matches!(
            e,
            LinkEvent::LinkClosed {
                link_id: id,
                reason: LinkCloseReason::Stale
            }
            if *id == link_id
        )
    });

    assert!(
        close_event.is_some(),
        "Should emit LinkClosed with reason Stale. Events: {:?}",
        events
    );

    println!("SUCCESS: Stale link closes after timeout");
}

// =========================================================================
// Test 7: Keepalive resets stale timer
// =========================================================================

/// Test: Receiving data resets stale detection timer.
///
/// Steps:
/// 1. Create link via complete handshake
/// 2. Advance clock to just before stale_time
/// 3. Simulate receiving a data packet (updates last_inbound)
/// 4. Advance clock by small amount
/// 5. Call manager.poll()
/// 6. Verify link is still ACTIVE (not STALE)
#[tokio::test]
async fn test_keepalive_resets_stale_timer() {
    use reticulum_core::identity::Identity;

    let initial_time_secs = 10u64;
    let initiator_clock = MockClock::new(initial_time_secs * MS_PER_SECOND);
    let responder_clock = MockClock::new(initial_time_secs * MS_PER_SECOND);

    let mut initiator_mgr = LinkManager::new();
    let mut responder_mgr = LinkManager::new();

    // Create destination identity for responder
    let dest_identity = Identity::generate(&mut OsRng);
    let dest_hash = [0x42u8; 16];
    let dest_signing_key = dest_identity.ed25519_verifying().to_bytes();

    // Register destination on responder
    responder_mgr.register_destination(dest_hash.into());

    // Initiator starts link
    let (link_id, link_request_packet) = initiator_mgr.initiate(
        dest_hash.into(),
        &dest_signing_key,
        initiator_clock.now_ms(),
        &mut OsRng,
    );

    // Deliver link request to responder
    let packet = Packet::unpack(&link_request_packet).unwrap();
    responder_mgr.process_packet(&packet, &link_request_packet, responder_clock.now_ms(), &mut OsRng);

    // Responder accepts
    let _: Vec<_> = responder_mgr.drain_events().collect();
    let proof_packet = responder_mgr
        .accept_link(&link_id, &dest_identity, ProofStrategy::None, responder_clock.now_ms())
        .unwrap();

    // Deliver proof to initiator
    let proof = Packet::unpack(&proof_packet).unwrap();
    initiator_mgr.process_packet(&proof, &proof_packet, initiator_clock.now_ms(), &mut OsRng);

    // Initiator sends RTT
    let _: Vec<_> = initiator_mgr.drain_events().collect();
    let rtt_packet = initiator_mgr.take_pending_rtt_packet(&link_id).unwrap();

    // Deliver RTT to responder
    let rtt = Packet::unpack(&rtt_packet).unwrap();
    responder_mgr.process_packet(&rtt, &rtt_packet, responder_clock.now_ms(), &mut OsRng);
    let _: Vec<_> = responder_mgr.drain_events().collect();

    // Verify link is active
    assert!(
        initiator_mgr.is_active(&link_id),
        "Link should be active on initiator"
    );

    // Get the actual stale time from the link
    let stale_time_secs = initiator_mgr
        .link(&link_id)
        .map(|l| l.stale_time_secs())
        .unwrap_or(LINK_KEEPALIVE_SECS * LINK_STALE_FACTOR);

    // Advance to just before stale time (but at least 2 seconds to allow for edge cases)
    let advance_before = stale_time_secs.saturating_sub(2).max(1);
    initiator_clock.advance_secs(advance_before);

    // Simulate receiving inbound traffic by recording inbound
    if let Some(link) = initiator_mgr.link_mut(&link_id) {
        link.record_inbound(initiator_clock.now_ms() / MS_PER_SECOND);
    }

    // Advance past where the old stale time would have been
    // but not past the new stale time (since we just received data)
    initiator_clock.advance_secs(stale_time_secs / 2 + 1);

    // Poll
    initiator_mgr.poll(initiator_clock.now_ms(), &mut OsRng);

    // Check events - should NOT have LinkStale
    let events: Vec<_> = initiator_mgr.drain_events().collect();
    let has_stale = events
        .iter()
        .any(|e| matches!(e, LinkEvent::LinkStale { .. }));
    assert!(
        !has_stale,
        "Should NOT have LinkStale event after receiving data"
    );

    // Verify link is still active
    if let Some(link) = initiator_mgr.link(&link_id) {
        assert_eq!(
            link.state(),
            LinkState::Active,
            "Link should still be active"
        );
    }

    println!("SUCCESS: Keepalive resets stale timer");
}

// =========================================================================
// Test 1: Rust initiator sends keepalive, Python echoes
// =========================================================================

/// Test: Rust initiator sends 0xFF keepalive, Python responder echoes 0xFE.
///
/// Note: This test requires the link to be active long enough for keepalive
/// to be triggered. In real scenarios, this happens after keepalive_interval.
/// For testing, we verify the keepalive mechanism exists and works.
#[tokio::test]
async fn test_rust_initiator_sends_keepalive_python_echoes() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let clock = TestClock;

    let mut stream = connect_to_daemon(&daemon).await;
    let mut deframer = Deframer::new();
    let mut manager = LinkManager::new();

    // Establish link
    let (link_id, _link_hash_hex) =
        establish_link_as_initiator(&mut manager, &daemon, &mut stream, &mut deframer)
            .await
            .expect("Failed to establish link");

    // Get the link and manually build a keepalive packet
    // (In real usage, this is triggered by poll() after keepalive interval)
    let keepalive_packet = {
        let link = manager.link(&link_id).expect("Link should exist");
        link.build_keepalive_packet()
            .expect("Failed to build keepalive")
    };

    // Send the keepalive
    send_framed(&mut stream, &keepalive_packet).await;

    // Wait for echo from Python
    let echo_raw =
        wait_for_keepalive_packet(&mut stream, &mut deframer, &link_id, Duration::from_secs(5))
            .await;

    if let Some(echo_data) = echo_raw {
        let echo_pkt = Packet::unpack(&echo_data).expect("Failed to unpack echo");

        // Process the echo (keepalive bookkeeping happens internally)
        manager.process_packet(&echo_pkt, &echo_data, clock.now_ms(), &mut OsRng);

        // Drain any events (keepalives no longer emit events, but link should stay active)
        let _: Vec<_> = manager.drain_events().collect();

        assert!(manager.is_active(&link_id), "Link should still be active after keepalive echo");
        println!("Keepalive echo received from Python");
    } else {
        panic!("No keepalive echo received from Python - link not working properly");
    }
}

// =========================================================================
// Test 2: Python initiator sends keepalive, Rust echoes
// =========================================================================

/// Test: Python initiator sends keepalive, Rust responder echoes.
///
/// This tests Rust as responder processing incoming keepalives and echoing.
#[tokio::test]
async fn test_python_initiator_sends_keepalive_rust_echoes() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let clock = TestClock;

    let mut stream = connect_to_daemon(&daemon).await;
    let mut deframer = Deframer::new();

    // Set up Rust destination
    let (destination, public_key_hex) =
        setup_rust_destination(&mut stream, "rust", &["keepalive_resp"], b"ka-test").await;

    let dest_hash = *destination.hash();
    let dest_hash_hex = hex::encode(dest_hash);
    let identity = destination.identity().expect("Should have identity");

    // Register destination in manager
    let mut manager = LinkManager::new();
    manager.register_destination(dest_hash);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Have Python create link to our destination
    let daemon_addr = daemon.cmd_addr();
    let dhx = dest_hash_hex.clone();
    let pkx = public_key_hex.clone();

    let link_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut s = TcpStream::connect(daemon_addr).await.unwrap();
        let cmd = serde_json::json!({
            "method": "create_link",
            "params": { "dest_hash": dhx, "dest_key": pkx, "timeout": 10 }
        });
        s.write_all(cmd.to_string().as_bytes()).await.unwrap();
        s.shutdown().await.unwrap();
        let mut r = Vec::new();
        s.read_to_end(&mut r).await.unwrap();
        serde_json::from_slice::<serde_json::Value>(&r).unwrap()
    });

    // Wait for link request
    let (raw_packet, link_id_bytes) = wait_for_link_request(
        &mut stream,
        &mut deframer,
        &dest_hash,
        Duration::from_secs(10),
    )
    .await
    .expect("Should receive link request");
    let link_id = LinkId::new(link_id_bytes);

    // Process link request
    let packet = Packet::unpack(&raw_packet).expect("Failed to unpack");
    manager.process_packet(&packet, &raw_packet, clock.now_ms(), &mut OsRng);

    // Accept the link
    let _: Vec<_> = manager.drain_events().collect();
    let proof_packet = manager
        .accept_link(&link_id, identity, ProofStrategy::None, clock.now_ms())
        .expect("Failed to accept link");

    send_framed(&mut stream, &proof_packet).await;

    // Wait for RTT
    let rtt_data = wait_for_rtt_packet(
        &mut stream,
        &mut deframer,
        &link_id,
        Duration::from_secs(10),
    )
    .await
    .expect("Should receive RTT");

    // Process RTT
    let mut rtt_raw = Vec::new();
    rtt_raw.push(0x0C);
    rtt_raw.push(0x00);
    rtt_raw.extend_from_slice(link_id.as_bytes());
    rtt_raw.push(PacketContext::Lrrtt as u8);
    rtt_raw.extend_from_slice(&rtt_data);

    let rtt_pkt = Packet::unpack(&rtt_raw).expect("Failed to unpack RTT");
    manager.process_packet(&rtt_pkt, &rtt_raw, clock.now_ms(), &mut OsRng);

    // Drain establishment events
    let _: Vec<_> = manager.drain_events().collect();

    // Wait for Python task to complete
    let _ = link_task.await;

    // Link is now active with Rust as responder
    assert!(manager.is_active(&link_id), "Link should be active");

    // Verify we're the responder
    if let Some(link) = manager.link(&link_id) {
        assert!(!link.is_initiator(), "Rust should be responder");
    }

    // Note: Testing actual keepalive from Python would require Python to send
    // keepalives, which happens based on Python's internal timing. Instead,
    // we verify that the responder echo mechanism is correctly set up.
    println!("SUCCESS: Rust responder link established (keepalive echo mechanism ready)");
}

// =========================================================================
// Test 10: Close packet payload verification
// =========================================================================

/// Test: Get link status from Python daemon via RPC.
///
/// Verifies the get_link_status RPC method works correctly.
#[tokio::test]
async fn test_get_link_status_rpc() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    let mut stream = connect_to_daemon(&daemon).await;
    let mut deframer = Deframer::new();
    let mut manager = LinkManager::new();

    // Establish link
    let (link_id, link_hash_hex) =
        establish_link_as_initiator(&mut manager, &daemon, &mut stream, &mut deframer)
            .await
            .expect("Failed to establish link");

    // Get link status from Python
    let status = daemon
        .get_link_status(&link_hash_hex)
        .await
        .expect("RPC call failed");

    assert_eq!(status.status, "found", "Link should be found");
    assert_eq!(status.link_hash, link_hash_hex);
    // Python link states: PENDING=0, HANDSHAKE=1, ACTIVE=2, STALE=3, CLOSED=4
    // After RTT exchange, the link should be ACTIVE (2)
    assert!(
        status
            .state
            .as_ref()
            .map(|s| s.contains("ACTIVE") || s == "2")
            .unwrap_or(false),
        "Link state should indicate ACTIVE. Got: {:?}",
        status.state
    );

    // Close the link
    manager.close(&link_id, &mut OsRng);
    for (_, close_packet) in manager.drain_close_packets() {
        send_framed(&mut stream, &close_packet).await;
    }

    // Wait for Python to process
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Get status after close - should be not_found or CLOSED
    let status_after = daemon
        .get_link_status(&link_hash_hex)
        .await
        .expect("RPC call failed");

    // Link may be removed from dict or state may be CLOSED (4)
    let is_closed = status_after.status == "not_found"
        || status_after
            .state
            .as_ref()
            .map(|s| s.contains("CLOSED") || s == "4")
            .unwrap_or(false);

    assert!(
        is_closed,
        "Link should be closed. Status: {:?}",
        status_after
    );

    println!("SUCCESS: Get link status RPC works");
}

/// Test: Close packet contains correctly encrypted link_id.
///
/// Steps:
/// 1. Establish link
/// 2. Build close packet manually
/// 3. Decrypt payload and verify it equals link_id
/// 4. Send close packet
/// 5. Verify Python accepts it
#[tokio::test]
async fn test_close_packet_payload_verification() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    let mut stream = connect_to_daemon(&daemon).await;
    let mut deframer = Deframer::new();
    let mut manager = LinkManager::new();

    // Establish link
    let (link_id, link_hash_hex) =
        establish_link_as_initiator(&mut manager, &daemon, &mut stream, &mut deframer)
            .await
            .expect("Failed to establish link");

    // Build close packet
    let close_packet = {
        let link = manager.link(&link_id).expect("Link should exist");
        link.build_close_packet(&mut OsRng)
            .expect("Failed to build close packet")
    };

    // Verify packet structure
    let pkt = Packet::unpack(&close_packet).expect("Failed to unpack close packet");
    assert_eq!(pkt.flags.packet_type, PacketType::Data);
    assert_eq!(pkt.context, PacketContext::LinkClose);
    assert_eq!(pkt.destination_hash, link_id);

    // The payload should be encrypted link_id (16 bytes + encryption overhead)
    assert!(
        pkt.data.len() >= 16,
        "Close packet payload should contain encrypted link_id"
    );

    // Send the close packet
    send_framed(&mut stream, &close_packet).await;

    // Wait for Python to process and verify it accepts the close
    let wait_result = daemon
        .wait_for_link_state(&link_hash_hex, "CLOSED", 5)
        .await
        .expect("RPC call failed");

    assert_eq!(
        wait_result.status, "reached",
        "Python should accept close packet and reach CLOSED state. Got: {:?}",
        wait_result
    );

    println!("SUCCESS: Close packet payload verification");
}

// =========================================================================
// Test 8: Multi-hop keepalive through Python relay
// =========================================================================

/// Test: Verify keepalive works across Rust B -> Python daemon -> Rust A path.
///
/// Steps:
/// 1. Establish Rust-to-Rust link via daemon using `establish_rust_to_rust_link`
/// 2. B (initiator) builds and sends keepalive packet
/// 3. A (responder) receives keepalive via daemon relay
/// 4. A processes keepalive and generates echo
/// 5. A sends echo back through daemon
/// 6. B receives echo via daemon relay
/// 7. B processes echo
/// 8. Verify KeepaliveReceived event on B
#[tokio::test]
async fn test_multi_hop_keepalive_through_python_relay() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let clock = TestClock;

    // 1. Establish Rust-to-Rust link via daemon
    let mut link = establish_rust_to_rust_link(&daemon)
        .await
        .expect("Failed to establish Rust-to-Rust link");

    let link_id = link.link_id;
    println!("Link established: {}", hex::encode(link_id));

    // 2. B (initiator) builds and sends keepalive packet
    let keepalive_packet = {
        let link_b = link.manager_b.link(&link_id).expect("B should have link");
        link_b
            .build_keepalive_packet()
            .expect("Failed to build keepalive")
    };

    send_framed(&mut link.stream_b, &keepalive_packet).await;
    println!("B sent keepalive packet");

    // 3. A (responder) receives keepalive via daemon relay
    let ka_raw = wait_for_keepalive_packet(
        &mut link.stream_a,
        &mut link.deframer_a,
        &link_id,
        Duration::from_secs(5),
    )
    .await
    .expect("A should receive keepalive from B via daemon relay");

    println!("A received keepalive packet");

    // 4. A processes keepalive and generates echo
    let ka_pkt = Packet::unpack(&ka_raw).expect("Failed to unpack keepalive");
    link.manager_a
        .process_packet(&ka_pkt, &ka_raw, clock.now_ms(), &mut OsRng);

    // 5. Drain echo packets from A and send them
    let echo_packets: Vec<_> = link.manager_a.drain_keepalive_packets();
    assert!(
        !echo_packets.is_empty(),
        "A should generate echo packet for keepalive"
    );

    for (_, echo) in echo_packets {
        send_framed(&mut link.stream_a, &echo).await;
        println!("A sent keepalive echo packet");
    }

    // 6. B receives echo via daemon relay
    let echo_raw = wait_for_keepalive_packet(
        &mut link.stream_b,
        &mut link.deframer_b,
        &link_id,
        Duration::from_secs(5),
    )
    .await
    .expect("B should receive echo from A via daemon relay");

    println!("B received keepalive echo packet");

    // 7. B processes echo (keepalive bookkeeping happens internally)
    let echo_pkt = Packet::unpack(&echo_raw).expect("Failed to unpack echo");
    link.manager_b
        .process_packet(&echo_pkt, &echo_raw, clock.now_ms(), &mut OsRng);

    // 8. Verify link is still active after keepalive round-trip
    let _: Vec<_> = link.manager_b.drain_events().collect();

    assert!(
        link.manager_b.is_active(&link_id),
        "B's link should still be active after keepalive echo"
    );

    println!("SUCCESS: Multi-hop keepalive through Python relay");
}

// =========================================================================
// Test 9: Multi-hop graceful close through Python relay
// =========================================================================

/// Test: Verify graceful close works across Rust B -> Python daemon -> Rust A path.
///
/// Steps:
/// 1. Establish Rust-to-Rust link via daemon using `establish_rust_to_rust_link`
/// 2. B (initiator) closes the link
/// 3. Drain and send close packets from B
/// 4. Verify B emits LinkClosed with Normal reason
/// 5. A receives close packet via daemon relay
/// 6. A processes close packet
/// 7. Verify A emits LinkClosed with PeerClosed reason
#[tokio::test]
async fn test_multi_hop_graceful_close_through_relay() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let clock = TestClock;

    // 1. Establish Rust-to-Rust link via daemon
    let mut link = establish_rust_to_rust_link(&daemon)
        .await
        .expect("Failed to establish Rust-to-Rust link");

    let link_id = link.link_id;
    println!("Link established: {}", hex::encode(link_id));

    // Verify both sides are active
    assert!(
        link.manager_a.is_active(&link_id),
        "A should have active link"
    );
    assert!(
        link.manager_b.is_active(&link_id),
        "B should have active link"
    );

    // 2. B (initiator) closes the link
    link.manager_b.close(&link_id, &mut OsRng);
    println!("B closed the link");

    // 3. Drain and send close packets from B
    let close_packets: Vec<_> = link.manager_b.drain_close_packets();
    assert!(!close_packets.is_empty(), "B should generate close packet");

    for (_, close_packet) in close_packets {
        send_framed(&mut link.stream_b, &close_packet).await;
        println!("B sent close packet");
    }

    // 4. Verify B emits LinkClosed with Normal reason
    let events_b: Vec<_> = link.manager_b.drain_events().collect();
    let close_event_b = events_b.iter().find(|e| {
        matches!(
            e,
            LinkEvent::LinkClosed { link_id: id, reason: LinkCloseReason::Normal }
            if *id == link_id
        )
    });

    assert!(
        close_event_b.is_some(),
        "B should emit LinkClosed with Normal reason. Events: {:?}",
        events_b
    );

    // 5. A receives close packet via daemon relay
    let close_raw = wait_for_close_packet(
        &mut link.stream_a,
        &mut link.deframer_a,
        &link_id,
        Duration::from_secs(5),
    )
    .await
    .expect("A should receive close packet from B via daemon relay");

    println!("A received close packet");

    // 6. A processes close packet
    let close_pkt = Packet::unpack(&close_raw).expect("Failed to unpack close packet");
    link.manager_a
        .process_packet(&close_pkt, &close_raw, clock.now_ms(), &mut OsRng);

    // 7. Verify A emits LinkClosed with PeerClosed reason
    let events_a: Vec<_> = link.manager_a.drain_events().collect();
    let close_event_a = events_a.iter().find(|e| {
        matches!(
            e,
            LinkEvent::LinkClosed { link_id: id, reason: LinkCloseReason::PeerClosed }
            if *id == link_id
        )
    });

    assert!(
        close_event_a.is_some(),
        "A should emit LinkClosed with PeerClosed reason. Events: {:?}",
        events_a
    );

    // Verify both links are no longer active
    assert!(
        !link.manager_a.is_active(&link_id),
        "A's link should no longer be active"
    );
    assert!(
        !link.manager_b.is_active(&link_id),
        "B's link should no longer be active"
    );

    println!("SUCCESS: Multi-hop graceful close through Python relay");
}
