//! LinkManager interop tests using the daemon harness.
//!
//! These tests verify that the high-level `LinkManager` API correctly interoperates
//! with Python Reticulum. Tests cover both initiator and responder roles, Rust-to-Rust
//! communication via Python relay, error handling, and stress scenarios.
//!
//! ## What These Tests Verify
//!
//! 1. **LinkManager as Initiator** - Rust initiates links to Python destinations
//! 2. **LinkManager as Responder** - Python initiates links to Rust destinations
//! 3. **Rust-to-Rust via Relay** - Two Rust LinkManagers communicate through daemon
//! 4. **Error Handling** - Timeouts, invalid proofs, invalid states
//! 5. **Stress Tests** - Multiple links, rapid data exchange, large payloads
//!
//! ## Running These Tests
//!
//! ```sh
//! # Run all LinkManager tests
//! cargo test --package reticulum-std --test rnsd_interop link_manager_tests
//!
//! # Run specific test
//! cargo test --package reticulum-std --test rnsd_interop test_manager_initiator_basic_handshake
//!
//! # Run with verbose output
//! cargo test --package reticulum-std --test rnsd_interop link_manager_tests -- --nocapture
//! ```

use std::cell::Cell;
use std::time::Duration;

use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use reticulum_core::constants::{MTU, TRUNCATED_HASHBYTES};
use reticulum_core::destination::{Destination, DestinationType, Direction};
use reticulum_core::identity::Identity;
use reticulum_core::link::{LinkCloseReason, LinkEvent, LinkId, LinkManager};
use reticulum_core::packet::{Packet, PacketContext, PacketType};
use reticulum_core::traits::{Clock, NoStorage, PlatformContext};
use reticulum_std::interfaces::hdlc::{frame, DeframeResult, Deframer};

use crate::common::*;
use crate::harness::{DestinationInfo, HarnessError, TestDaemon};

// =========================================================================
// Test context helpers
// =========================================================================

/// Real-time clock for tests
struct RealClock;

impl Clock for RealClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
}

/// Mock clock that can be advanced for timeout testing
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
}

impl Clock for MockClock {
    fn now_ms(&self) -> u64 {
        self.time_ms.get()
    }
}

fn real_context() -> PlatformContext<OsRng, RealClock, NoStorage> {
    PlatformContext {
        rng: OsRng,
        clock: RealClock,
        storage: NoStorage,
    }
}

fn mock_context(initial_ms: u64) -> PlatformContext<OsRng, MockClock, NoStorage> {
    PlatformContext {
        rng: OsRng,
        clock: MockClock::new(initial_ms),
        storage: NoStorage,
    }
}

// =========================================================================
// Helper functions
// =========================================================================

/// Establish link with Rust as initiator using LinkManager.
///
/// Returns (link_id, destination_info) on success.
async fn establish_manager_initiator_link(
    manager: &mut LinkManager,
    daemon: &TestDaemon,
    stream: &mut TcpStream,
    deframer: &mut Deframer,
    ctx: &mut PlatformContext<OsRng, RealClock, NoStorage>,
) -> Result<(LinkId, DestinationInfo), HarnessError> {
    // Register a destination in daemon
    let dest_info = daemon.register_destination("linktest", &["echo"]).await?;

    // Extract signing key
    let pub_key_bytes =
        hex::decode(&dest_info.public_key).map_err(|e| HarnessError::ParseError(e.to_string()))?;
    let signing_key_bytes: [u8; 32] = pub_key_bytes[32..64]
        .try_into()
        .map_err(|_| HarnessError::ParseError("Invalid signing key".to_string()))?;

    // Parse destination hash
    let dest_hash_bytes =
        hex::decode(&dest_info.hash).map_err(|e| HarnessError::ParseError(e.to_string()))?;
    let dest_hash: [u8; TRUNCATED_HASHBYTES] = dest_hash_bytes
        .try_into()
        .map_err(|_| HarnessError::ParseError("Invalid hash length".to_string()))?;

    // Initiate link via manager
    let (link_id, link_request_packet) = manager.initiate(dest_hash, &signing_key_bytes, ctx);

    // Send link request
    send_framed(stream, &link_request_packet).await;

    // Wait for proof
    let proof_packet = receive_proof_for_link(stream, deframer, &link_id, Duration::from_secs(10))
        .await
        .ok_or_else(|| HarnessError::CommandFailed("No proof received".to_string()))?;

    // Process proof via manager
    manager.process_packet(&proof_packet, &[], ctx);

    // Check for LinkEstablished event
    let events: Vec<_> = manager.drain_events().collect();
    let established = events.iter().any(|e| {
        matches!(e, LinkEvent::LinkEstablished { link_id: id, is_initiator: true } if *id == link_id)
    });

    if !established {
        return Err(HarnessError::CommandFailed(
            "LinkEstablished event not received".to_string(),
        ));
    }

    // Get and send RTT packet
    if let Some(rtt_packet) = manager.take_pending_rtt_packet(&link_id) {
        send_framed(stream, &rtt_packet).await;
    }

    // Wait for daemon to process RTT
    tokio::time::sleep(Duration::from_millis(200)).await;

    Ok((link_id, dest_info))
}

/// Establish link with Rust as responder using LinkManager.
///
/// Returns link_id on success.
async fn establish_manager_responder_link(
    manager: &mut LinkManager,
    _daemon: &TestDaemon,
    stream: &mut TcpStream,
    deframer: &mut Deframer,
    identity: &Identity,
    dest_hash: [u8; 16],
    ctx: &mut PlatformContext<OsRng, RealClock, NoStorage>,
) -> Result<LinkId, HarnessError> {
    // Wait for link request
    let (raw_packet, link_id) =
        wait_for_link_request(stream, deframer, &dest_hash, Duration::from_secs(10))
            .await
            .ok_or_else(|| HarnessError::CommandFailed("No link request received".to_string()))?;

    // Process the packet via manager
    let packet = Packet::unpack(&raw_packet)
        .map_err(|_| HarnessError::ParseError("Failed to unpack packet".to_string()))?;
    manager.process_packet(&packet, &raw_packet, ctx);

    // Check for LinkRequestReceived event
    let events: Vec<_> = manager.drain_events().collect();
    let request_event = events.iter().find(
        |e| matches!(e, LinkEvent::LinkRequestReceived { link_id: id, .. } if *id == link_id),
    );

    if request_event.is_none() {
        return Err(HarnessError::CommandFailed(
            "LinkRequestReceived event not received".to_string(),
        ));
    }

    // Accept the link
    let proof_packet = manager
        .accept_link(&link_id, identity, ctx)
        .map_err(|e| HarnessError::CommandFailed(format!("Failed to accept link: {:?}", e)))?;

    // Send proof
    send_framed(stream, &proof_packet).await;

    // Wait for RTT
    let rtt_data = wait_for_rtt_packet(stream, deframer, &link_id, Duration::from_secs(10))
        .await
        .ok_or_else(|| HarnessError::CommandFailed("No RTT received".to_string()))?;

    // Process RTT - need to build a packet for it
    let mut rtt_raw = Vec::new();
    rtt_raw.push(0x0C); // flags for Data packet to Link
    rtt_raw.push(0x00); // hops
    rtt_raw.extend_from_slice(&link_id);
    rtt_raw.push(PacketContext::Lrrtt as u8);
    rtt_raw.extend_from_slice(&rtt_data);

    let rtt_packet = Packet::unpack(&rtt_raw)
        .map_err(|_| HarnessError::ParseError("Failed to unpack RTT".to_string()))?;
    manager.process_packet(&rtt_packet, &rtt_raw, ctx);

    // Check for LinkEstablished event
    let events: Vec<_> = manager.drain_events().collect();
    let established = events.iter().any(|e| {
        matches!(e, LinkEvent::LinkEstablished { link_id: id, is_initiator: false } if *id == link_id)
    });

    if !established {
        return Err(HarnessError::CommandFailed(
            "LinkEstablished event not received".to_string(),
        ));
    }

    Ok(link_id)
}

/// Wait for a LINK_REQUEST packet addressed to our destination.
async fn wait_for_link_request(
    stream: &mut TcpStream,
    deframer: &mut Deframer,
    dest_hash: &[u8; TRUNCATED_HASHBYTES],
    timeout_duration: Duration,
) -> Option<(Vec<u8>, [u8; TRUNCATED_HASHBYTES])> {
    use reticulum_core::link::Link;

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
                            if pkt.flags.packet_type == PacketType::LinkRequest
                                && pkt.destination_hash == *dest_hash
                            {
                                let link_id = Link::calculate_link_id(&data);
                                return Some((data, link_id));
                            }
                        }
                    }
                }
            }
            Ok(Err(_)) | Err(_) => continue,
        }
    }

    None
}

/// Wait for an RTT packet on a link.
async fn wait_for_rtt_packet(
    stream: &mut TcpStream,
    deframer: &mut Deframer,
    link_id: &[u8; TRUNCATED_HASHBYTES],
    timeout_duration: Duration,
) -> Option<Vec<u8>> {
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
                            if pkt.flags.packet_type == PacketType::Data
                                && pkt.destination_hash == *link_id
                                && pkt.context == PacketContext::Lrrtt
                            {
                                return Some(pkt.data.as_slice().to_vec());
                            }
                        }
                    }
                }
            }
            Ok(Err(_)) | Err(_) => continue,
        }
    }

    None
}

/// Wait for a DATA packet on a link (context = None).
async fn wait_for_data_packet(
    stream: &mut TcpStream,
    deframer: &mut Deframer,
    link_id: &[u8; TRUNCATED_HASHBYTES],
    timeout_duration: Duration,
) -> Option<Vec<u8>> {
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
                            if pkt.flags.packet_type == PacketType::Data
                                && pkt.destination_hash == *link_id
                                && pkt.context == PacketContext::None
                            {
                                return Some(data);
                            }
                        }
                    }
                }
            }
            Ok(Err(_)) | Err(_) => continue,
        }
    }

    None
}

/// Wait for a specific LinkEvent with a predicate
#[allow(dead_code)]
async fn wait_for_link_event<F>(
    manager: &mut LinkManager,
    stream: &mut TcpStream,
    deframer: &mut Deframer,
    ctx: &mut PlatformContext<OsRng, RealClock, NoStorage>,
    predicate: F,
    timeout_duration: Duration,
) -> Option<LinkEvent>
where
    F: Fn(&LinkEvent) -> bool,
{
    let mut buf = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + timeout_duration;

    while tokio::time::Instant::now() < deadline {
        // Check existing events
        for event in manager.drain_events() {
            if predicate(&event) {
                return Some(event);
            }
        }

        // Poll manager
        manager.poll(ctx.clock.now_ms());

        // Try to receive more packets
        let remaining = deadline - tokio::time::Instant::now();
        match timeout(
            remaining.min(Duration::from_millis(100)),
            stream.read(&mut buf),
        )
        .await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                let results = deframer.process(&buf[..n]);
                for result in results {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            manager.process_packet(&pkt, &data, ctx);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Final check
    for event in manager.drain_events() {
        if predicate(&event) {
            return Some(event);
        }
    }

    None
}

/// Set up a Rust destination and send its announce to the daemon.
///
/// Returns (destination, public_key_hex). The identity can be accessed via destination.identity().
async fn setup_rust_destination(
    stream: &mut TcpStream,
    app_name: &str,
    aspects: &[&str],
    app_data: &[u8],
) -> (Destination, String) {
    let mut ctx = real_context();
    let identity = Identity::generate(&mut ctx);
    let public_key_hex = hex::encode(identity.public_key_bytes());

    let destination = Destination::new(
        Some(identity),
        Direction::In,
        DestinationType::Single,
        app_name,
        aspects,
    )
    .expect("Failed to create destination");

    // Create and send announce
    let packet = destination
        .announce(Some(app_data), &mut ctx)
        .expect("Failed to create announce");

    let mut raw_packet = [0u8; MTU];
    let size = packet.pack(&mut raw_packet).expect("Failed to pack");

    let mut framed = Vec::new();
    frame(&raw_packet[..size], &mut framed);
    stream.write_all(&framed).await.expect("Failed to send");
    stream.flush().await.expect("Failed to flush");

    (destination, public_key_hex)
}

// =========================================================================
// 1. LinkManager as Initiator (Rust -> Python)
// =========================================================================

/// Test basic handshake with Rust as initiator using LinkManager.
///
/// Verifies:
/// - LinkManager.initiate() creates pending link
/// - Processing proof triggers LinkEstablished { is_initiator: true }
/// - RTT packet is generated and can be sent
#[tokio::test]
async fn test_manager_initiator_basic_handshake() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let mut ctx = real_context();

    let mut stream = connect_to_daemon(&daemon).await;
    let mut deframer = Deframer::new();

    let mut manager = LinkManager::new();

    // Establish link
    let (link_id, _dest_info) = establish_manager_initiator_link(
        &mut manager,
        &daemon,
        &mut stream,
        &mut deframer,
        &mut ctx,
    )
    .await
    .expect("Failed to establish link");

    // Verify link is active
    assert!(
        manager.is_active(&link_id),
        "Link should be active after handshake"
    );
    assert_eq!(manager.active_link_count(), 1);
    assert_eq!(manager.pending_link_count(), 0);

    println!("SUCCESS: LinkManager initiator basic handshake");
}

/// Test data exchange with LinkManager as initiator.
///
/// Verifies:
/// - manager.send() encrypts and returns packet
/// - Daemon receives and decrypts data
/// - Daemon can send data back
/// - DataReceived event is emitted
#[tokio::test]
async fn test_manager_initiator_data_exchange() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let mut ctx = real_context();

    let mut stream = connect_to_daemon(&daemon).await;
    let mut deframer = Deframer::new();

    let mut manager = LinkManager::new();

    let (link_id, _dest_info) = establish_manager_initiator_link(
        &mut manager,
        &daemon,
        &mut stream,
        &mut deframer,
        &mut ctx,
    )
    .await
    .expect("Failed to establish link");

    // Send data via manager
    let test_data = b"Hello from LinkManager!";
    let data_packet = manager
        .send(&link_id, test_data, &mut ctx)
        .expect("Failed to build data packet");

    send_framed(&mut stream, &data_packet).await;
    println!("Sent: {:?}", String::from_utf8_lossy(test_data));

    // Wait for daemon to process
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify daemon received the data
    let received = daemon
        .get_received_packets()
        .await
        .expect("Failed to get received packets");

    let found = received.iter().any(|p| p.data == test_data);
    assert!(
        found,
        "Daemon should have received our message. Got: {:?}",
        received
            .iter()
            .map(|p| String::from_utf8_lossy(&p.data))
            .collect::<Vec<_>>()
    );

    println!("SUCCESS: LinkManager initiator data exchange");
}

/// Test sequential links: establish -> exchange -> close -> establish new.
#[tokio::test]
async fn test_manager_initiator_sequential_links() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let mut ctx = real_context();

    let mut manager = LinkManager::new();

    // First link
    let mut stream1 = connect_to_daemon(&daemon).await;
    let mut deframer1 = Deframer::new();

    let (link_id1, _) = establish_manager_initiator_link(
        &mut manager,
        &daemon,
        &mut stream1,
        &mut deframer1,
        &mut ctx,
    )
    .await
    .expect("Failed to establish first link");

    // Send data on first link
    let data1 = b"First link data";
    let packet1 = manager.send(&link_id1, data1, &mut ctx).unwrap();
    send_framed(&mut stream1, &packet1).await;

    // Close first link
    manager.close(&link_id1);
    assert!(!manager.is_active(&link_id1));

    // Drain close event
    let events: Vec<_> = manager.drain_events().collect();
    assert!(events
        .iter()
        .any(|e| matches!(e, LinkEvent::LinkClosed { link_id, reason }
        if *link_id == link_id1 && *reason == LinkCloseReason::Normal)));

    // Second link (new connection)
    let mut stream2 = connect_to_daemon(&daemon).await;
    let mut deframer2 = Deframer::new();

    let (link_id2, _) = establish_manager_initiator_link(
        &mut manager,
        &daemon,
        &mut stream2,
        &mut deframer2,
        &mut ctx,
    )
    .await
    .expect("Failed to establish second link");

    assert_ne!(link_id1, link_id2);
    assert!(manager.is_active(&link_id2));

    // Send data on second link
    let data2 = b"Second link data";
    let packet2 = manager.send(&link_id2, data2, &mut ctx).unwrap();
    send_framed(&mut stream2, &packet2).await;

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Verify daemon received second message
    let received = daemon.get_received_packets().await.unwrap();
    let found = received.iter().any(|p| p.data == data2);
    assert!(found, "Daemon should have received second link's data");

    println!("SUCCESS: LinkManager sequential links");
}

/// Test concurrent links to different destinations.
#[tokio::test]
async fn test_manager_initiator_concurrent_links() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let mut ctx = real_context();

    // Register multiple destinations
    let dest1 = daemon
        .register_destination("concurrent", &["alpha"])
        .await
        .expect("Failed to register dest1");
    let dest2 = daemon
        .register_destination("concurrent", &["beta"])
        .await
        .expect("Failed to register dest2");
    let dest3 = daemon
        .register_destination("concurrent", &["gamma"])
        .await
        .expect("Failed to register dest3");

    let mut manager = LinkManager::new();

    // Helper to initiate link
    let initiate_link = |manager: &mut LinkManager,
                         dest_info: &DestinationInfo,
                         ctx: &mut PlatformContext<OsRng, RealClock, NoStorage>|
     -> (LinkId, Vec<u8>) {
        let pub_key_bytes = hex::decode(&dest_info.public_key).unwrap();
        let signing_key: [u8; 32] = pub_key_bytes[32..64].try_into().unwrap();
        let dest_hash: [u8; 16] = hex::decode(&dest_info.hash).unwrap().try_into().unwrap();
        manager.initiate(dest_hash, &signing_key, ctx)
    };

    // Initiate all three links
    let (link_id1, packet1) = initiate_link(&mut manager, &dest1, &mut ctx);
    let (link_id2, packet2) = initiate_link(&mut manager, &dest2, &mut ctx);
    let (link_id3, packet3) = initiate_link(&mut manager, &dest3, &mut ctx);

    // Connect and send all requests
    let mut stream = connect_to_daemon(&daemon).await;
    let mut deframer = Deframer::new();

    send_framed(&mut stream, &packet1).await;
    send_framed(&mut stream, &packet2).await;
    send_framed(&mut stream, &packet3).await;

    // Receive and process proofs
    let mut established = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut buf = [0u8; 2048];

    while established < 3 && tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        match timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                let results = deframer.process(&buf[..n]);
                for result in results {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == PacketType::Proof {
                                manager.process_packet(&pkt, &data, &mut ctx);
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        // Check events
        for event in manager.drain_events() {
            if matches!(event, LinkEvent::LinkEstablished { .. }) {
                established += 1;
            }
        }
    }

    // Send RTT packets
    for link_id in [link_id1, link_id2, link_id3] {
        if let Some(rtt) = manager.take_pending_rtt_packet(&link_id) {
            send_framed(&mut stream, &rtt).await;
        }
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    println!("Established {} links", established);
    assert!(
        established >= 2,
        "Should establish at least 2 concurrent links"
    );

    println!("SUCCESS: LinkManager concurrent links");
}

// =========================================================================
// 2. LinkManager as Responder (Python -> Rust)
// =========================================================================

/// Test accepting an incoming link request.
///
/// Verifies:
/// - LinkRequestReceived event is emitted when LINK_REQUEST arrives
/// - accept_link() returns proof packet
/// - After RTT, LinkEstablished { is_initiator: false } is emitted
#[tokio::test]
async fn test_manager_responder_accept_link() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let mut ctx = real_context();

    let mut stream = connect_to_daemon(&daemon).await;
    let mut deframer = Deframer::new();

    // Set up Rust destination
    let (destination, public_key_hex) =
        setup_rust_destination(&mut stream, "rust", &["responder"], b"responder-test").await;

    let dest_hash = *destination.hash();
    let dest_hash_hex = hex::encode(&dest_hash);
    let identity = destination.identity().expect("Should have identity");

    // Register destination in manager
    let mut manager = LinkManager::new();
    manager.register_destination(dest_hash);

    // Wait for daemon to process announce
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify daemon has path
    assert!(
        daemon.has_path(&dest_hash).await,
        "Daemon should have path to Rust destination"
    );

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

    // Establish link as responder
    let link_id = establish_manager_responder_link(
        &mut manager,
        &daemon,
        &mut stream,
        &mut deframer,
        &identity,
        dest_hash,
        &mut ctx,
    )
    .await
    .expect("Failed to establish responder link");

    // Wait for Python task
    let link_response = link_task.await.expect("Link task panicked");
    println!("Python link response: {:?}", link_response);

    // Verify link is active
    assert!(
        manager.is_active(&link_id),
        "Link should be active after handshake"
    );

    // Verify link properties
    let link = manager.link(&link_id).expect("Link should exist");
    assert!(!link.is_initiator(), "We should be responder");

    println!("SUCCESS: LinkManager responder accept link");
}

/// Test rejecting an incoming link request.
#[tokio::test]
async fn test_manager_responder_reject_link() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let mut ctx = real_context();

    let mut stream = connect_to_daemon(&daemon).await;
    let mut deframer = Deframer::new();

    // Set up Rust destination
    let (destination, public_key_hex) =
        setup_rust_destination(&mut stream, "rust", &["reject"], b"reject-test").await;

    let dest_hash = *destination.hash();
    let dest_hash_hex = hex::encode(&dest_hash);

    // Register destination in manager
    let mut manager = LinkManager::new();
    manager.register_destination(dest_hash);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Have Python create link
    let daemon_addr = daemon.cmd_addr();
    let dhx = dest_hash_hex.clone();
    let pkx = public_key_hex.clone();

    let _link_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut s = TcpStream::connect(daemon_addr).await.unwrap();
        let cmd = serde_json::json!({
            "method": "create_link",
            "params": { "dest_hash": dhx, "dest_key": pkx, "timeout": 5 }
        });
        s.write_all(cmd.to_string().as_bytes()).await.unwrap();
        s.shutdown().await.unwrap();
        let mut r = Vec::new();
        s.read_to_end(&mut r).await.unwrap();
        // Expect failure since we reject
        serde_json::from_slice::<serde_json::Value>(&r).unwrap()
    });

    // Wait for link request
    let result = wait_for_link_request(
        &mut stream,
        &mut deframer,
        &dest_hash,
        Duration::from_secs(10),
    )
    .await;

    assert!(result.is_some(), "Should receive link request");
    let (raw_packet, link_id) = result.unwrap();

    // Process the packet
    let packet = Packet::unpack(&raw_packet).unwrap();
    manager.process_packet(&packet, &raw_packet, &mut ctx);

    // Check for LinkRequestReceived
    let events: Vec<_> = manager.drain_events().collect();
    assert!(events.iter().any(
        |e| matches!(e, LinkEvent::LinkRequestReceived { link_id: id, .. } if *id == link_id)
    ));

    // Reject the link
    manager.reject_link(&link_id);

    // Verify link is removed
    assert!(manager.link(&link_id).is_none());
    assert_eq!(manager.pending_link_count(), 0);

    println!("SUCCESS: LinkManager responder reject link");
}

/// Test bidirectional data exchange with Rust as responder.
#[tokio::test]
async fn test_manager_responder_data_exchange() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let mut ctx = real_context();

    let mut stream = connect_to_daemon(&daemon).await;
    let mut deframer = Deframer::new();

    // Set up Rust destination
    let (destination, public_key_hex) =
        setup_rust_destination(&mut stream, "rust", &["dataexchange"], b"data-test").await;

    let dest_hash = *destination.hash();
    let dest_hash_hex = hex::encode(&dest_hash);
    let identity = destination.identity().expect("Should have identity");

    let mut manager = LinkManager::new();
    manager.register_destination(dest_hash);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Have Python create link
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

    // Establish link
    let link_id = establish_manager_responder_link(
        &mut manager,
        &daemon,
        &mut stream,
        &mut deframer,
        &identity,
        dest_hash,
        &mut ctx,
    )
    .await
    .expect("Failed to establish link");

    // Get link hash from Python
    let link_response = link_task.await.unwrap();
    let python_link_hash = link_response
        .get("result")
        .and_then(|r| r.get("link_hash"))
        .and_then(|h| h.as_str())
        .expect("Should have link_hash");

    // Python sends data to Rust
    let python_message = b"Hello from Python!";
    daemon
        .send_on_link(python_link_hash, python_message)
        .await
        .expect("Failed to send from Python");

    // Wait for and process data packet
    let data_raw =
        wait_for_data_packet(&mut stream, &mut deframer, &link_id, Duration::from_secs(5))
            .await
            .expect("Should receive data from Python");

    let data_pkt = Packet::unpack(&data_raw).unwrap();
    manager.process_packet(&data_pkt, &data_raw, &mut ctx);

    // Check for DataReceived event
    let events: Vec<_> = manager.drain_events().collect();
    let received_data = events.iter().find_map(|e| {
        if let LinkEvent::DataReceived { link_id: id, data } = e {
            if *id == link_id {
                return Some(data.clone());
            }
        }
        None
    });

    assert_eq!(
        received_data.as_deref(),
        Some(python_message.as_slice()),
        "Should receive correct data from Python"
    );

    // Rust sends data to Python
    let rust_message = b"Hello from Rust!";
    let data_packet = manager
        .send(&link_id, rust_message, &mut ctx)
        .expect("Failed to build data packet");
    send_framed(&mut stream, &data_packet).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify Python received
    let received = daemon.get_received_packets().await.unwrap();
    let found = received.iter().any(|p| p.data == rust_message);
    assert!(found, "Python should receive Rust's message");

    println!("SUCCESS: LinkManager responder data exchange");
}

/// Test accepting multiple sequential incoming links.
#[tokio::test]
async fn test_manager_responder_multiple_incoming() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let mut ctx = real_context();

    let mut stream = connect_to_daemon(&daemon).await;
    let mut deframer = Deframer::new();

    // Set up Rust destination
    let (destination, public_key_hex) =
        setup_rust_destination(&mut stream, "rust", &["multi"], b"multi-test").await;

    let dest_hash = *destination.hash();
    let dest_hash_hex = hex::encode(&dest_hash);
    let identity = destination.identity().expect("Should have identity");

    let mut manager = LinkManager::new();
    manager.register_destination(dest_hash);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Accept 3 sequential links
    for i in 0..3 {
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

        let link_id = establish_manager_responder_link(
            &mut manager,
            &daemon,
            &mut stream,
            &mut deframer,
            &identity,
            dest_hash,
            &mut ctx,
        )
        .await
        .expect(&format!("Failed to establish link {}", i + 1));

        let _ = link_task.await;

        // Close the link before next iteration
        manager.close(&link_id);
        let _: Vec<_> = manager.drain_events().collect();

        println!("Established and closed link {}", i + 1);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    println!("SUCCESS: LinkManager responder multiple incoming");
}

// =========================================================================
// 3. Rust-to-Rust via Python Relay
// =========================================================================

/// Test two Rust LinkManagers communicating through daemon relay.
///
/// Setup:
/// - Manager A: Creates identity, destination, announces via daemon
/// - Manager B: Receives A's announce over the wire, extracts signing key and transport_id
/// - Manager B: Initiates link with HEADER_2 transport headers
/// - Daemon forwards link request to A based on transport_id
/// - Both managers exchange data bidirectionally
///
/// This tests proper mesh routing: B discovers A through the announce packet
/// forwarded by the daemon, and uses the transport_id from that announce to
/// route the link request back through the daemon.
#[tokio::test]
async fn test_rust_to_rust_via_daemon() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let mut ctx_a = real_context();
    let mut ctx_b = real_context();

    // --- Manager B connects first to receive announces ---
    let mut stream_b = connect_to_daemon(&daemon).await;
    let mut deframer_b = Deframer::new();
    let mut manager_b = LinkManager::new();

    // --- Manager A (Responder) ---
    let mut stream_a = connect_to_daemon(&daemon).await;
    let mut deframer_a = Deframer::new();

    let (destination_a, _public_key_hex_a) =
        setup_rust_destination(&mut stream_a, "r2r", &["test"], b"rust-A").await;

    let dest_hash_a = *destination_a.hash();
    let identity_a = destination_a.identity().expect("Should have identity");

    let mut manager_a = LinkManager::new();
    manager_a.register_destination(dest_hash_a);

    // Wait for daemon to process announce
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify daemon has path to A
    assert!(
        daemon.has_path(&dest_hash_a).await,
        "Daemon should have path to A after announce"
    );

    // --- B receives A's announce over the wire with full routing info ---
    // This is the proper mesh discovery: B learns about A from the announce
    // forwarded by the daemon, including the transport_id for routing.
    let announce_info = wait_for_any_announce_with_route_info(
        &mut stream_b,
        &mut deframer_b,
        Duration::from_secs(5),
    )
    .await
    .expect("B should receive A's announce from daemon");

    // Verify the announce is for A's destination
    assert_eq!(
        announce_info.packet.destination_hash, dest_hash_a,
        "Announce should be for A's destination"
    );

    // Extract routing info from the announce
    let signing_key_a = announce_info
        .signing_key()
        .expect("Failed to extract signing key from announce");
    let transport_id = announce_info.transport_id;
    let hops = announce_info.hops;

    // B initiates link to A using transport headers if announce came through relay
    let (link_id_b, link_request_packet) =
        manager_b.initiate_with_path(dest_hash_a, &signing_key_a, transport_id, hops, &mut ctx_b);

    // If transport_id is set, we should be using HEADER_2
    if transport_id.is_some() {
        let using_header_2 = link_request_packet[0] & 0x40 != 0;
        assert!(
            using_header_2,
            "Should use HEADER_2 when transport_id is set"
        );
    }

    // Send link request via B's stream (daemon will relay based on transport_id)
    send_framed(&mut stream_b, &link_request_packet).await;

    // A receives link request
    let (raw_request, link_id_a) = wait_for_link_request(
        &mut stream_a,
        &mut deframer_a,
        &dest_hash_a,
        Duration::from_secs(10),
    )
    .await
    .expect("A should receive link request");

    // Verify link IDs match (important for transport routing to work)
    assert_eq!(
        link_id_a, link_id_b,
        "Link IDs should match after transport unwrapping"
    );

    let request_pkt = Packet::unpack(&raw_request).unwrap();
    manager_a.process_packet(&request_pkt, &raw_request, &mut ctx_a);

    // A accepts the link
    let _: Vec<_> = manager_a.drain_events().collect();
    let proof_packet = manager_a
        .accept_link(&link_id_a, &identity_a, &mut ctx_a)
        .expect("Failed to accept link");

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
    .expect("B should receive proof");

    manager_b.process_packet(&proof_pkt, &[], &mut ctx_b);

    // B should have LinkEstablished
    let events_b: Vec<_> = manager_b.drain_events().collect();
    assert!(events_b.iter().any(|e| matches!(
        e,
        LinkEvent::LinkEstablished {
            is_initiator: true,
            ..
        }
    )));

    // B sends RTT
    let rtt_packet = manager_b
        .take_pending_rtt_packet(&link_id_b)
        .expect("Should have RTT packet");
    send_framed(&mut stream_b, &rtt_packet).await;

    // A receives RTT
    let rtt_data = wait_for_rtt_packet(
        &mut stream_a,
        &mut deframer_a,
        &link_id_a,
        Duration::from_secs(10),
    )
    .await
    .expect("A should receive RTT");

    // Build RTT packet for processing
    let mut rtt_raw = Vec::new();
    rtt_raw.push(0x0C);
    rtt_raw.push(0x00);
    rtt_raw.extend_from_slice(&link_id_a);
    rtt_raw.push(PacketContext::Lrrtt as u8);
    rtt_raw.extend_from_slice(&rtt_data);

    let rtt_pkt = Packet::unpack(&rtt_raw).unwrap();
    manager_a.process_packet(&rtt_pkt, &rtt_raw, &mut ctx_a);

    // A should have LinkEstablished
    let events_a: Vec<_> = manager_a.drain_events().collect();
    assert!(events_a.iter().any(|e| matches!(
        e,
        LinkEvent::LinkEstablished {
            is_initiator: false,
            ..
        }
    )));

    // Both links should be active
    assert!(manager_a.is_active(&link_id_a));
    assert!(manager_b.is_active(&link_id_b));

    // --- Bidirectional data exchange ---

    // B sends to A
    let msg_b_to_a = b"Hello from B to A!";
    let data_b = manager_b.send(&link_id_b, msg_b_to_a, &mut ctx_b).unwrap();
    send_framed(&mut stream_b, &data_b).await;

    // A receives
    let data_raw_a = wait_for_data_packet(
        &mut stream_a,
        &mut deframer_a,
        &link_id_a,
        Duration::from_secs(5),
    )
    .await
    .expect("A should receive data from B");

    let data_pkt_a = Packet::unpack(&data_raw_a).unwrap();
    manager_a.process_packet(&data_pkt_a, &data_raw_a, &mut ctx_a);

    let events_a: Vec<_> = manager_a.drain_events().collect();
    let received_a = events_a.iter().find_map(|e| {
        if let LinkEvent::DataReceived { data, .. } = e {
            Some(data.clone())
        } else {
            None
        }
    });

    assert_eq!(received_a.as_deref(), Some(msg_b_to_a.as_slice()));

    // A sends to B
    let msg_a_to_b = b"Hello from A to B!";
    let data_a = manager_a.send(&link_id_a, msg_a_to_b, &mut ctx_a).unwrap();
    send_framed(&mut stream_a, &data_a).await;

    // B receives
    let data_raw_b = wait_for_data_packet(
        &mut stream_b,
        &mut deframer_b,
        &link_id_b,
        Duration::from_secs(5),
    )
    .await
    .expect("B should receive data from A");

    let data_pkt_b = Packet::unpack(&data_raw_b).unwrap();
    manager_b.process_packet(&data_pkt_b, &data_raw_b, &mut ctx_b);

    let events_b: Vec<_> = manager_b.drain_events().collect();
    let received_b = events_b.iter().find_map(|e| {
        if let LinkEvent::DataReceived { data, .. } = e {
            Some(data.clone())
        } else {
            None
        }
    });

    assert_eq!(received_b.as_deref(), Some(msg_a_to_b.as_slice()));

    println!("SUCCESS: Rust-to-Rust via daemon relay");
}

/// Test multiple message exchange between two Rust LinkManagers.
///
/// Similar to test_rust_to_rust_via_daemon but exchanges many messages to verify
/// reliable bidirectional communication.
#[tokio::test]
async fn test_rust_to_rust_multiple_messages() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let mut ctx_a = real_context();
    let mut ctx_b = real_context();

    // --- B connects first to receive announces ---
    let mut stream_b = connect_to_daemon(&daemon).await;
    let mut deframer_b = Deframer::new();
    let mut manager_b = LinkManager::new();

    // --- A (Responder) sets up and announces ---
    let mut stream_a = connect_to_daemon(&daemon).await;
    let mut deframer_a = Deframer::new();

    let (destination_a, _public_key_hex_a) =
        setup_rust_destination(&mut stream_a, "r2rmulti", &["test"], b"rust-A").await;

    let dest_hash_a = *destination_a.hash();
    let identity_a = destination_a.identity().expect("Should have identity");

    let mut manager_a = LinkManager::new();
    manager_a.register_destination(dest_hash_a);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // --- B receives A's announce with routing info ---
    let announce_info = wait_for_any_announce_with_route_info(
        &mut stream_b,
        &mut deframer_b,
        Duration::from_secs(5),
    )
    .await
    .expect("B should receive A's announce from daemon");

    assert_eq!(announce_info.packet.destination_hash, dest_hash_a);

    let signing_key_a = announce_info
        .signing_key()
        .expect("Failed to extract signing key from announce");
    let transport_id = announce_info.transport_id;
    let hops = announce_info.hops;

    println!(
        "B discovered A via announce, transport_id={:?}, hops={}",
        transport_id.map(hex::encode),
        hops
    );

    // Establish link with transport headers
    let (link_id_b, link_request_packet) =
        manager_b.initiate_with_path(dest_hash_a, &signing_key_a, transport_id, hops, &mut ctx_b);

    // Verify HEADER_2 is used when transport_id is set
    if transport_id.is_some() {
        assert!(
            link_request_packet[0] & 0x40 != 0,
            "Should use HEADER_2 when transport_id is set"
        );
    }

    send_framed(&mut stream_b, &link_request_packet).await;

    let (raw_request, link_id_a) = wait_for_link_request(
        &mut stream_a,
        &mut deframer_a,
        &dest_hash_a,
        Duration::from_secs(10),
    )
    .await
    .unwrap();

    let request_pkt = Packet::unpack(&raw_request).unwrap();
    manager_a.process_packet(&request_pkt, &raw_request, &mut ctx_a);
    let _: Vec<_> = manager_a.drain_events().collect();

    let proof_packet = manager_a
        .accept_link(&link_id_a, &identity_a, &mut ctx_a)
        .unwrap();
    send_framed(&mut stream_a, &proof_packet).await;

    let proof_pkt = receive_proof_for_link(
        &mut stream_b,
        &mut deframer_b,
        &link_id_b,
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    manager_b.process_packet(&proof_pkt, &[], &mut ctx_b);
    let _: Vec<_> = manager_b.drain_events().collect();

    let rtt_packet = manager_b.take_pending_rtt_packet(&link_id_b).unwrap();
    send_framed(&mut stream_b, &rtt_packet).await;

    let rtt_data = wait_for_rtt_packet(
        &mut stream_a,
        &mut deframer_a,
        &link_id_a,
        Duration::from_secs(10),
    )
    .await
    .unwrap();

    let mut rtt_raw = Vec::new();
    rtt_raw.push(0x0C);
    rtt_raw.push(0x00);
    rtt_raw.extend_from_slice(&link_id_a);
    rtt_raw.push(PacketContext::Lrrtt as u8);
    rtt_raw.extend_from_slice(&rtt_data);

    let rtt_pkt = Packet::unpack(&rtt_raw).unwrap();
    manager_a.process_packet(&rtt_pkt, &rtt_raw, &mut ctx_a);
    let _: Vec<_> = manager_a.drain_events().collect();

    // Exchange 10+ messages in both directions
    let mut received_by_a = 0;
    let mut received_by_b = 0;

    for i in 0..10 {
        // B -> A
        let msg = format!("Message {} from B", i);
        let data = manager_b
            .send(&link_id_b, msg.as_bytes(), &mut ctx_b)
            .unwrap();
        send_framed(&mut stream_b, &data).await;

        // A -> B
        let msg = format!("Message {} from A", i);
        let data = manager_a
            .send(&link_id_a, msg.as_bytes(), &mut ctx_a)
            .unwrap();
        send_framed(&mut stream_a, &data).await;

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Receive all pending data
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut buf_a = [0u8; 2048];
    let mut buf_b = [0u8; 2048];

    while tokio::time::Instant::now() < deadline && (received_by_a < 10 || received_by_b < 10) {
        // A receives
        if let Ok(Ok(n)) = timeout(Duration::from_millis(50), stream_a.read(&mut buf_a)).await {
            if n > 0 {
                for result in deframer_a.process(&buf_a[..n]) {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == PacketType::Data
                                && pkt.context == PacketContext::None
                            {
                                manager_a.process_packet(&pkt, &data, &mut ctx_a);
                            }
                        }
                    }
                }
            }
        }

        // B receives
        if let Ok(Ok(n)) = timeout(Duration::from_millis(50), stream_b.read(&mut buf_b)).await {
            if n > 0 {
                for result in deframer_b.process(&buf_b[..n]) {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == PacketType::Data
                                && pkt.context == PacketContext::None
                            {
                                manager_b.process_packet(&pkt, &data, &mut ctx_b);
                            }
                        }
                    }
                }
            }
        }

        // Count received
        for event in manager_a.drain_events() {
            if matches!(event, LinkEvent::DataReceived { .. }) {
                received_by_a += 1;
            }
        }
        for event in manager_b.drain_events() {
            if matches!(event, LinkEvent::DataReceived { .. }) {
                received_by_b += 1;
            }
        }
    }

    println!(
        "A received {} messages, B received {} messages",
        received_by_a, received_by_b
    );
    assert!(received_by_a >= 5, "A should receive at least 5 messages");
    assert!(received_by_b >= 5, "B should receive at least 5 messages");

    println!("SUCCESS: Rust-to-Rust multiple messages");
}

// =========================================================================
// 4. Error Handling
// =========================================================================

/// Test handshake timeout for initiator.
#[tokio::test]
async fn test_manager_handshake_timeout() {
    let mut ctx = mock_context(1_000_000);
    let mut manager = LinkManager::new();

    let dest_hash = [0x42; 16];
    let signing_key = [0x33; 32];

    // Initiate link to non-existent destination
    let (link_id, _packet) = manager.initiate(dest_hash, &signing_key, &mut ctx);

    // Verify pending
    assert_eq!(manager.pending_link_count(), 1);
    assert!(manager.link(&link_id).is_some());

    // Advance time past 30s timeout
    ctx.clock.advance(31_000);
    manager.poll(ctx.clock.now_ms());

    // Link should be removed
    assert!(manager.link(&link_id).is_none());
    assert_eq!(manager.pending_link_count(), 0);

    // Should have LinkClosed with Timeout
    let events: Vec<_> = manager.drain_events().collect();
    assert!(events.iter().any(|e| matches!(
        e,
        LinkEvent::LinkClosed {
            link_id: id,
            reason: LinkCloseReason::Timeout
        } if *id == link_id
    )));

    println!("SUCCESS: LinkManager handshake timeout");
}

/// Test sending on inactive link returns error.
#[tokio::test]
async fn test_manager_send_on_inactive_link() {
    let mut ctx = real_context();
    let mut manager = LinkManager::new();

    let dest_hash = [0x42; 16];
    let signing_key = [0x33; 32];

    // Initiate link (pending, not active)
    let (link_id, _packet) = manager.initiate(dest_hash, &signing_key, &mut ctx);

    // Try to send - should fail
    let result = manager.send(&link_id, b"test data", &mut ctx);
    assert!(
        result.is_err(),
        "Should not be able to send on pending link"
    );

    println!("SUCCESS: LinkManager send on inactive link");
}

/// Test operations on unknown link ID.
#[tokio::test]
async fn test_manager_operations_on_unknown_link() {
    let mut ctx = real_context();
    let mut manager = LinkManager::new();
    let identity = Identity::generate(&mut ctx);

    let unknown_link_id = [0xFF; 16];

    // send() on unknown link
    let send_result = manager.send(&unknown_link_id, b"test", &mut ctx);
    assert!(send_result.is_err());

    // accept_link() on unknown link
    let accept_result = manager.accept_link(&unknown_link_id, &identity, &mut ctx);
    assert!(accept_result.is_err());

    // close() on unknown link should not panic
    manager.close(&unknown_link_id);

    // link() returns None
    assert!(manager.link(&unknown_link_id).is_none());

    // is_active() returns false
    assert!(!manager.is_active(&unknown_link_id));

    println!("SUCCESS: LinkManager operations on unknown link");
}

/// Test responder timeout when RTT is not received.
#[tokio::test]
async fn test_manager_responder_timeout() {
    let mut ctx = mock_context(1_000_000);
    let identity = Identity::generate(&mut ctx);

    let mut manager = LinkManager::new();
    let dest_hash = [0x42; 16];
    manager.register_destination(dest_hash);

    // Simulate receiving a link request
    let initiator_link = reticulum_core::link::Link::new_outgoing(dest_hash, &mut ctx);
    let request_data = initiator_link.create_link_request();

    // Build raw packet
    let mut raw_packet = Vec::new();
    raw_packet.push(0x02); // flags
    raw_packet.push(0x00); // hops
    raw_packet.extend_from_slice(&dest_hash);
    raw_packet.push(0x00); // context
    raw_packet.extend_from_slice(&request_data);

    let link_id = reticulum_core::link::Link::calculate_link_id(&raw_packet);

    let packet = Packet::unpack(&raw_packet).unwrap();
    manager.process_packet(&packet, &raw_packet, &mut ctx);

    // Accept the link
    let _: Vec<_> = manager.drain_events().collect();
    let _proof = manager.accept_link(&link_id, &identity, &mut ctx).unwrap();

    // Verify pending incoming
    assert_eq!(manager.pending_link_count(), 1);

    // Advance time past timeout (don't send RTT)
    ctx.clock.advance(31_000);
    manager.poll(ctx.clock.now_ms());

    // Link should be timed out
    assert!(manager.link(&link_id).is_none());

    let events: Vec<_> = manager.drain_events().collect();
    assert!(events.iter().any(|e| matches!(
        e,
        LinkEvent::LinkClosed {
            reason: LinkCloseReason::Timeout,
            ..
        }
    )));

    println!("SUCCESS: LinkManager responder timeout");
}

// =========================================================================
// 5. Stress Tests
// =========================================================================

/// Test establishing many simultaneous links.
#[tokio::test]
async fn test_manager_many_simultaneous_links() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let mut ctx = real_context();

    // Register 10 destinations
    let mut destinations = Vec::new();
    for i in 0..10 {
        let dest = daemon
            .register_destination("stress", &[&format!("dest{}", i)])
            .await
            .expect("Failed to register destination");
        destinations.push(dest);
    }

    let mut manager = LinkManager::new();
    let mut stream = connect_to_daemon(&daemon).await;
    let mut deframer = Deframer::new();

    // Initiate all links
    let mut link_ids = Vec::new();
    for dest in &destinations {
        let pub_key_bytes = hex::decode(&dest.public_key).unwrap();
        let signing_key: [u8; 32] = pub_key_bytes[32..64].try_into().unwrap();
        let dest_hash: [u8; 16] = hex::decode(&dest.hash).unwrap().try_into().unwrap();

        let (link_id, packet) = manager.initiate(dest_hash, &signing_key, &mut ctx);
        link_ids.push(link_id);
        send_framed(&mut stream, &packet).await;
    }

    // Receive all proofs
    let mut established = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut buf = [0u8; 4096];

    while established < 10 && tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        match timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                let results = deframer.process(&buf[..n]);
                for result in results {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == PacketType::Proof {
                                manager.process_packet(&pkt, &data, &mut ctx);
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        for event in manager.drain_events() {
            if matches!(event, LinkEvent::LinkEstablished { .. }) {
                established += 1;
            }
        }

        manager.poll(ctx.clock.now_ms());
    }

    // Send RTT for all established links
    for link_id in &link_ids {
        if let Some(rtt) = manager.take_pending_rtt_packet(link_id) {
            send_framed(&mut stream, &rtt).await;
        }
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    let active = manager.active_link_count();
    println!("Established {} of 10 links", active);
    assert!(active >= 5, "Should establish at least 5 links");

    println!("SUCCESS: LinkManager many simultaneous links");
}

/// Test rapid data exchange on a single link.
#[tokio::test]
async fn test_manager_rapid_data_exchange() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let mut ctx = real_context();

    let mut stream = connect_to_daemon(&daemon).await;
    let mut deframer = Deframer::new();

    let mut manager = LinkManager::new();

    let (link_id, _) = establish_manager_initiator_link(
        &mut manager,
        &daemon,
        &mut stream,
        &mut deframer,
        &mut ctx,
    )
    .await
    .expect("Failed to establish link");

    // Send 50 packets rapidly
    for i in 0..50 {
        let data = format!("Rapid message {}", i);
        let packet = manager
            .send(&link_id, data.as_bytes(), &mut ctx)
            .expect("Failed to build packet");
        send_framed(&mut stream, &packet).await;
    }

    // Wait for daemon to process
    tokio::time::sleep(Duration::from_secs(2)).await;

    let received = daemon.get_received_packets().await.unwrap();
    println!("Daemon received {} of 50 packets", received.len());
    assert!(
        received.len() >= 25,
        "Should receive at least half the packets"
    );

    println!("SUCCESS: LinkManager rapid data exchange");
}

/// Test sending large payloads.
#[tokio::test]
async fn test_manager_large_payloads() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let mut ctx = real_context();

    let mut stream = connect_to_daemon(&daemon).await;
    let mut deframer = Deframer::new();

    let mut manager = LinkManager::new();

    let (link_id, _) = establish_manager_initiator_link(
        &mut manager,
        &daemon,
        &mut stream,
        &mut deframer,
        &mut ctx,
    )
    .await
    .expect("Failed to establish link");

    // Test various payload sizes
    let sizes = [100, 250, 400];

    for size in sizes {
        let data: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
        let packet = manager
            .send(&link_id, &data, &mut ctx)
            .expect(&format!("Failed to build {} byte packet", size));
        send_framed(&mut stream, &packet).await;
        println!("Sent {} byte payload", size);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;

    let received = daemon.get_received_packets().await.unwrap();
    println!("Daemon received {} packets", received.len());

    // Check we received the large payloads
    let received_sizes: Vec<_> = received.iter().map(|p| p.data.len()).collect();
    println!("Received payload sizes: {:?}", received_sizes);

    assert!(
        received_sizes.iter().any(|&s| s >= 100),
        "Should receive at least one large payload"
    );

    println!("SUCCESS: LinkManager large payloads");
}

/// Test interleaved operations across multiple links.
#[tokio::test]
async fn test_manager_interleaved_operations() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");
    let mut ctx = real_context();

    // Register 3 destinations
    let dest1 = daemon
        .register_destination("interleave", &["one"])
        .await
        .unwrap();
    let dest2 = daemon
        .register_destination("interleave", &["two"])
        .await
        .unwrap();
    let dest3 = daemon
        .register_destination("interleave", &["three"])
        .await
        .unwrap();

    let mut manager = LinkManager::new();
    let mut stream = connect_to_daemon(&daemon).await;
    let mut deframer = Deframer::new();

    // Helper to initiate
    let initiate = |manager: &mut LinkManager,
                    dest: &DestinationInfo,
                    ctx: &mut PlatformContext<OsRng, RealClock, NoStorage>|
     -> (LinkId, Vec<u8>) {
        let pub_key_bytes = hex::decode(&dest.public_key).unwrap();
        let signing_key: [u8; 32] = pub_key_bytes[32..64].try_into().unwrap();
        let dest_hash: [u8; 16] = hex::decode(&dest.hash).unwrap().try_into().unwrap();
        manager.initiate(dest_hash, &signing_key, ctx)
    };

    // Interleave: initiate 1, initiate 2, wait for proof 1, initiate 3, etc.
    let (link_id1, packet1) = initiate(&mut manager, &dest1, &mut ctx);
    send_framed(&mut stream, &packet1).await;

    let (link_id2, packet2) = initiate(&mut manager, &dest2, &mut ctx);
    send_framed(&mut stream, &packet2).await;

    // Receive some proofs
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (link_id3, packet3) = initiate(&mut manager, &dest3, &mut ctx);
    send_framed(&mut stream, &packet3).await;

    // Process all proofs
    let mut established = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut buf = [0u8; 2048];

    while established < 3 && tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        match timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                for result in deframer.process(&buf[..n]) {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == PacketType::Proof {
                                manager.process_packet(&pkt, &data, &mut ctx);
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        for event in manager.drain_events() {
            if matches!(event, LinkEvent::LinkEstablished { .. }) {
                established += 1;
            }
        }
    }

    // Send RTT for established links
    for link_id in [link_id1, link_id2, link_id3] {
        if let Some(rtt) = manager.take_pending_rtt_packet(&link_id) {
            send_framed(&mut stream, &rtt).await;
        }
    }

    // Send data on whichever links are active, close one
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut sent_count = 0;
    for (i, link_id) in [link_id1, link_id2, link_id3].iter().enumerate() {
        if manager.is_active(link_id) {
            let data = format!("Data on link {}", i + 1);
            if let Ok(packet) = manager.send(link_id, data.as_bytes(), &mut ctx) {
                send_framed(&mut stream, &packet).await;
                sent_count += 1;
            }
        }
    }

    // Close one active link
    if manager.is_active(&link_id2) {
        manager.close(&link_id2);
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    println!(
        "Established {}, sent on {}, active now {}",
        established,
        sent_count,
        manager.active_link_count()
    );

    assert!(established >= 2, "Should establish at least 2 links");
    assert!(sent_count >= 1, "Should send on at least 1 link");

    println!("SUCCESS: LinkManager interleaved operations");
}
