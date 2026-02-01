//! Integration tests for the high-level Node API
//!
//! These tests verify that the ReticulumNode API works correctly with
//! a real Python Reticulum daemon, mirroring the functionality shown
//! in the examples (simple_send, echo_server, chat).
//!
//! # Test Coverage
//!
//! - Node creation and startup
//! - Event reception (announces, paths)
//! - Connection management
//! - Graceful shutdown

use std::time::Duration;

use tokio::time::timeout;

use reticulum_std::node::ReticulumNodeBuilder;
use reticulum_std::NodeEvent;

use crate::harness::TestDaemon;

/// Test that a node can be built and started successfully
#[tokio::test]
async fn test_node_creation_and_startup() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Build a node connecting to the daemon
    let mut node = ReticulumNodeBuilder::new()
        .add_tcp_client(daemon.rns_addr())
        .build()
        .await
        .expect("Failed to build node");

    // Start the node
    node.start().await.expect("Failed to start node");

    // Verify node is running
    assert!(node.is_running(), "Node should be running after start()");

    // Stop the node
    node.stop().await.expect("Failed to stop node");

    // Verify node is stopped
    assert!(!node.is_running(), "Node should not be running after stop()");
}

/// Test that a node can receive announce events from Python daemon
/// (mirrors simple_send.rs example behavior)
#[tokio::test]
async fn test_node_receives_announce_from_daemon() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    // Build and start node
    let mut node = ReticulumNodeBuilder::new()
        .add_tcp_client(daemon.rns_addr())
        .build()
        .await
        .expect("Failed to build node");

    node.start().await.expect("Failed to start node");

    // Take event receiver
    let mut events = node
        .take_event_receiver()
        .expect("Failed to get event receiver");

    // Register a destination on daemon and announce it
    let dest = daemon
        .register_destination("test", &["announce_test"])
        .await
        .expect("Failed to register destination");

    daemon
        .announce_destination(&dest.hash, b"test announce data")
        .await
        .expect("Failed to announce");

    // Wait for announce event with timeout
    let event_result = timeout(Duration::from_secs(5), events.recv()).await;

    assert!(
        event_result.is_ok(),
        "Should receive event within timeout"
    );

    let event = event_result
        .unwrap()
        .expect("Event channel should not be closed");

    // Verify we received an announce event
    match event {
        NodeEvent::AnnounceReceived { announce, .. } => {
            // Verify destination hash matches
            let received_hash = hex::encode(announce.destination_hash());
            assert_eq!(
                received_hash, dest.hash,
                "Announce destination hash should match"
            );
        }
        other => {
            panic!("Expected AnnounceReceived event, got: {:?}", other);
        }
    }

    // Clean up
    node.stop().await.expect("Failed to stop node");
}

/// Test that a node can receive multiple events
/// (mirrors echo_server.rs event handling pattern)
#[tokio::test]
async fn test_node_receives_multiple_announces() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    let mut node = ReticulumNodeBuilder::new()
        .add_tcp_client(daemon.rns_addr())
        .build()
        .await
        .expect("Failed to build node");

    node.start().await.expect("Failed to start node");

    let mut events = node
        .take_event_receiver()
        .expect("Failed to get event receiver");

    // Register and announce multiple destinations
    let dest1 = daemon
        .register_destination("app1", &["service1"])
        .await
        .expect("Failed to register dest1");

    let dest2 = daemon
        .register_destination("app2", &["service2"])
        .await
        .expect("Failed to register dest2");

    daemon
        .announce_destination(&dest1.hash, b"data1")
        .await
        .expect("Failed to announce dest1");

    // Small delay between announces
    tokio::time::sleep(Duration::from_millis(100)).await;

    daemon
        .announce_destination(&dest2.hash, b"data2")
        .await
        .expect("Failed to announce dest2");

    // Collect events with timeout
    let mut received_hashes = Vec::new();
    let collection_timeout = Duration::from_secs(5);
    let start = std::time::Instant::now();

    while received_hashes.len() < 2 && start.elapsed() < collection_timeout {
        match timeout(Duration::from_millis(500), events.recv()).await {
            Ok(Some(NodeEvent::AnnounceReceived { announce, .. })) => {
                received_hashes.push(hex::encode(announce.destination_hash()));
            }
            Ok(Some(_)) => {
                // Other event types, continue
            }
            Ok(None) => break, // Channel closed
            Err(_) => continue, // Timeout, try again
        }
    }

    // Verify both announces received
    assert!(
        received_hashes.contains(&dest1.hash),
        "Should receive first announce"
    );
    assert!(
        received_hashes.contains(&dest2.hash),
        "Should receive second announce"
    );

    node.stop().await.expect("Failed to stop node");
}

/// Test that node inner() accessor works for direct NodeCore access
/// (mirrors chat.rs /status command pattern)
#[tokio::test]
async fn test_node_inner_accessor() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    let mut node = ReticulumNodeBuilder::new()
        .add_tcp_client(daemon.rns_addr())
        .build()
        .await
        .expect("Failed to build node");

    node.start().await.expect("Failed to start node");

    // Access inner NodeCore (like chat.rs does for /status)
    let inner = node.inner();
    {
        let core = inner.lock().unwrap();

        // Verify connection counts are accessible
        let active = core.active_connection_count();
        let pending = core.pending_connection_count();

        // Initially should have no connections
        assert_eq!(active, 0, "Should have no active connections initially");
        assert_eq!(pending, 0, "Should have no pending connections initially");
    }

    node.stop().await.expect("Failed to stop node");
}

/// Test node shutdown behavior is graceful
#[tokio::test]
async fn test_node_graceful_shutdown() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    let mut node = ReticulumNodeBuilder::new()
        .add_tcp_client(daemon.rns_addr())
        .build()
        .await
        .expect("Failed to build node");

    node.start().await.expect("Failed to start node");
    let mut events = node.take_event_receiver().unwrap();

    // Register and announce to ensure activity
    let dest = daemon
        .register_destination("shutdown_test", &["app"])
        .await
        .expect("Failed to register");
    daemon
        .announce_destination(&dest.hash, b"data")
        .await
        .ok();

    // Let one event come through
    let _ = timeout(Duration::from_secs(2), events.recv()).await;

    // Stop should complete without hanging
    let stop_result = timeout(Duration::from_secs(5), node.stop()).await;

    assert!(
        stop_result.is_ok(),
        "Stop should complete within timeout"
    );
    assert!(
        stop_result.unwrap().is_ok(),
        "Stop should succeed"
    );
}

/// Test that node can be started and stopped multiple times
#[tokio::test]
async fn test_node_restart() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    let mut node = ReticulumNodeBuilder::new()
        .add_tcp_client(daemon.rns_addr())
        .build()
        .await
        .expect("Failed to build node");

    // First start/stop cycle
    node.start().await.expect("First start failed");
    assert!(node.is_running());
    node.stop().await.expect("First stop failed");
    assert!(!node.is_running());

    // Second start/stop cycle
    node.start().await.expect("Second start failed");
    assert!(node.is_running());
    node.stop().await.expect("Second stop failed");
    assert!(!node.is_running());
}

/// Test that announce processing creates a path in the node
///
/// Note: The PathFound event may or may not be exposed depending on how the
/// high-level ReticulumNode processes events. This test verifies that after
/// receiving an announce, the node knows a path to the destination.
#[tokio::test]
async fn test_node_learns_path_from_announce() {
    let daemon = TestDaemon::start().await.expect("Failed to start daemon");

    let mut node = ReticulumNodeBuilder::new()
        .add_tcp_client(daemon.rns_addr())
        .build()
        .await
        .expect("Failed to build node");

    node.start().await.expect("Failed to start node");

    let mut events = node
        .take_event_receiver()
        .expect("Failed to get event receiver");

    // Register a destination and announce
    let dest = daemon
        .register_destination("path_test", &["service"])
        .await
        .expect("Failed to register");

    daemon
        .announce_destination(&dest.hash, b"path test data")
        .await
        .expect("Failed to announce");

    // Wait for announce event
    let mut saw_announce = false;
    let collection_timeout = Duration::from_secs(5);
    let start = std::time::Instant::now();

    while !saw_announce && start.elapsed() < collection_timeout {
        match timeout(Duration::from_millis(500), events.recv()).await {
            Ok(Some(NodeEvent::AnnounceReceived { announce, .. })) => {
                let received_hash = hex::encode(announce.destination_hash());
                if received_hash == dest.hash {
                    saw_announce = true;
                }
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    assert!(saw_announce, "Should receive announce event");

    // Verify the node now has a path to the destination
    {
        let inner = node.inner();
        let core = inner.lock().unwrap();

        // Decode the destination hash
        let dest_hash_bytes: [u8; 16] = hex::decode(&dest.hash)
            .expect("Invalid hex")
            .try_into()
            .expect("Wrong length");

        let has_path = core.has_path(&dest_hash_bytes);
        assert!(has_path, "Node should have a path to the announced destination");
    } // Lock is dropped here before await

    node.stop().await.expect("Failed to stop node");
}

/// Test node builder can create node without immediately connecting
#[tokio::test]
async fn test_node_builder_creates_node_without_interfaces() {
    // This tests that the builder works even without daemon (no interfaces)
    let node = ReticulumNodeBuilder::new()
        .build()
        .await
        .expect("Failed to build node without interfaces");

    // Node should be created but have no interfaces
    let inner = node.inner();
    let core = inner.lock().unwrap();

    // Verify identity exists
    let identity = core.identity();
    assert_eq!(identity.hash().len(), 16, "Identity hash should be 16 bytes");
}
