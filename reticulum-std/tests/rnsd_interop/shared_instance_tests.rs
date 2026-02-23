//! Shared instance interop tests.
//!
//! Tests that a Rust client can connect to a Python daemon's shared instance
//! Unix socket and exchange HDLC-framed packets. Also tests end-to-end link
//! establishment through a Rust daemon's shared instance.

use std::net::SocketAddr;
use std::time::Duration;

use reticulum_core::framing::hdlc::{frame, DeframeResult, Deframer};
use reticulum_core::packet::Packet;
use reticulum_std::driver::ReticulumNodeBuilder;
use reticulum_std::NodeEvent;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{
    build_announce_raw, extract_signing_key, init_tracing, parse_dest_hash, wait_for_data_event,
    wait_for_event, wait_for_path_on_node, DAEMON_PROCESS_TIME,
};
use crate::harness::{find_available_ports, TestDaemon};

/// Connect to an abstract Unix socket.
///
/// Python's shared instance listens on `\0rns/{instance_name}`.
fn connect_abstract_unix(instance_name: &str) -> std::io::Result<tokio::net::UnixStream> {
    use std::os::linux::net::SocketAddrExt;
    let abstract_name = format!("rns/{}", instance_name);
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(abstract_name.as_bytes())?;
    let std_stream = std::os::unix::net::UnixStream::connect_addr(&addr)?;
    std_stream.set_nonblocking(true)?;
    tokio::net::UnixStream::from_std(std_stream)
}

/// Start a shared instance daemon with a unique instance name to avoid
/// conflicts with parallel tests and any real system daemon.
async fn start_shared_daemon() -> (TestDaemon, String) {
    let instance_name = format!("test_{}", std::process::id());
    let daemon = TestDaemon::start_with_shared_instance(&instance_name)
        .await
        .expect("Failed to start shared instance daemon");
    (daemon, instance_name)
}

/// Test: Python daemon announces a destination → announce arrives on the
/// Rust client's Unix socket (HDLC-framed).
#[tokio::test]
async fn test_shared_instance_receive_announce() {
    init_tracing();

    let (daemon, instance_name) = start_shared_daemon().await;

    // Register a destination on the Python daemon
    let dest_info = daemon
        .register_destination("sharedtest", &["announce"])
        .await
        .expect("Failed to register destination");

    // Connect Rust client to the daemon's shared instance socket
    let mut client =
        connect_abstract_unix(&instance_name).expect("Failed to connect to shared instance socket");

    // Give the connection time to be accepted and registered
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Tell Python to announce
    daemon
        .announce_destination(&dest_info.hash, b"")
        .await
        .expect("Failed to announce");

    // Read HDLC-framed packets from the Unix socket
    // The daemon should forward the announce to local clients
    let mut deframer = Deframer::new();
    let mut buf = [0u8; 4096];
    let mut received_announce = false;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), client.read(&mut buf)).await {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => {
                let results = deframer.process(&buf[..n]);
                for r in results {
                    if let DeframeResult::Frame(data) = r {
                        // Try to parse as a packet
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == reticulum_core::packet::PacketType::Announce
                            {
                                // Check if dest hash matches
                                let pkt_hash_hex = hex::encode(pkt.destination_hash);
                                if pkt_hash_hex == dest_info.hash {
                                    received_announce = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if received_announce {
                    break;
                }
            }
            Ok(Err(e)) => {
                panic!("Read error on Unix socket: {}", e);
            }
            Err(_) => continue, // timeout, try again
        }
    }

    assert!(
        received_announce,
        "Should have received the Python announce on the Unix socket"
    );
}

/// Test: Rust sends an announce over the Unix socket → Python daemon
/// creates a path for it.
#[tokio::test]
async fn test_shared_instance_send_announce() {
    init_tracing();

    let (daemon, instance_name) = start_shared_daemon().await;

    // Connect Rust client to the daemon's shared instance socket
    let mut client =
        connect_abstract_unix(&instance_name).expect("Failed to connect to shared instance socket");

    // Give the connection time to be accepted
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Build an announce packet
    let (raw, dest_hash, _dest) = build_announce_raw("rustclient", &["sharedtest"], b"hello");

    // Send HDLC-framed announce over the Unix socket
    let mut framed = Vec::new();
    frame(&raw, &mut framed);
    client
        .write_all(&framed)
        .await
        .expect("Failed to write announce");
    client.flush().await.expect("Failed to flush");

    // Wait for Python daemon to process the announce. Local client announces
    // go through Transport.inbound which may queue the announce for rebroadcast
    // before updating the path table. Allow ample time.
    let mut has_path = false;
    for _ in 0..10 {
        tokio::time::sleep(DAEMON_PROCESS_TIME).await;
        if daemon.has_path(dest_hash.as_bytes()).await {
            has_path = true;
            break;
        }
    }
    assert!(
        has_path,
        "Python daemon should have a path after receiving announce via Unix socket"
    );
}

/// Test: Full link establishment through a Rust daemon's shared instance.
///
/// Topology:
/// ```text
/// Rust node A ── TCP ── Rust daemon (in-process) ── Unix socket ── Python (shared instance client)
/// (initiator)           (transport, TCP server,                     (responder, registers dest,
///                        share_instance=true)                        announces, accepts links)
/// ```
///
/// This exercises the full pipeline: announce forwarding from local client to
/// network, link request routing from network to local client, proof routing
/// from local client to network, and bidirectional data exchange over the
/// established link.
#[tokio::test]
async fn test_shared_instance_link_through_daemon() {
    init_tracing();

    // ── Phase 1: Port allocation ─────────────────────────────────────────
    let ports = find_available_ports::<3>().expect("Failed to allocate ports");
    let [daemon_tcp_port, py_rns_port, py_cmd_port] = ports;
    let instance_name = format!("linktest_{}", std::process::id());

    // ── Phase 2: Start Rust daemon (in-process) ─────────────────────────
    // The Rust daemon owns the abstract Unix socket and has a TCP server
    // for Rust node A to connect to.
    let daemon_tcp_addr: SocketAddr = format!("127.0.0.1:{}", daemon_tcp_port).parse().unwrap();

    let mut daemon_node = ReticulumNodeBuilder::new()
        .enable_transport(true)
        .share_instance(true)
        .instance_name(instance_name.clone())
        .add_tcp_server(daemon_tcp_addr)
        .build()
        .await
        .expect("Failed to build Rust daemon node");
    daemon_node
        .start()
        .await
        .expect("Failed to start Rust daemon node");

    // Wait for Unix socket listener to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ── Phase 3: Start Python as shared instance client ──────────────────
    // Python detects the existing socket and falls back to LocalClientInterface.
    // Its TCP server is NOT created (Python skips external interfaces when
    // is_connected_to_shared_instance=True). JSON-RPC command port works
    // independently.
    let py_client =
        TestDaemon::start_with_shared_instance_echo(py_rns_port, py_cmd_port, &instance_name)
            .await
            .expect("Failed to start Python shared instance client");

    // ── Phase 4: Register destination and announce on Python ─────────────
    let dest_info = py_client
        .register_destination("sharedlinktest", &["echo"])
        .await
        .expect("Failed to register destination");

    py_client
        .announce_destination(&dest_info.hash, b"link-test")
        .await
        .expect("Failed to announce destination");

    let dest_hash = parse_dest_hash(&dest_info.hash);
    let signing_key = extract_signing_key(&dest_info.public_key);

    // ── Phase 5: Start Rust node A, wait for announce ────────────────────
    // Rust node A connects to the daemon's TCP server as a non-transport endpoint.
    let mut rust_a = ReticulumNodeBuilder::new()
        .enable_transport(false)
        .add_tcp_client(daemon_tcp_addr)
        .build()
        .await
        .expect("Failed to build Rust node A");

    let mut event_rx = rust_a
        .take_event_receiver()
        .expect("Event receiver should be available");
    rust_a.start().await.expect("Failed to start Rust node A");

    // Wait for announce to propagate: Python → Unix → daemon → TCP → Rust A
    assert!(
        wait_for_path_on_node(&rust_a, &dest_hash, Duration::from_secs(15)).await,
        "Rust A should learn path to Python destination through daemon"
    );

    // ── Phase 6: Establish link ──────────────────────────────────────────
    // Link request: Rust A → TCP → daemon → Unix socket → Python
    // Link proof:   Python → Unix socket → daemon → TCP → Rust A
    let mut link_handle = rust_a
        .connect(&dest_hash, &signing_key)
        .await
        .expect("Failed to initiate link");

    let link_id = *link_handle.link_id();

    let established = wait_for_event(
        &mut event_rx,
        Duration::from_secs(15),
        |event| match event {
            NodeEvent::LinkEstablished {
                link_id: id,
                is_initiator,
            } if id == link_id && is_initiator => Some(()),
            _ => None,
        },
    )
    .await;
    assert!(
        established.is_some(),
        "Link should be established within 15s"
    );

    // Verify Python also shows the link
    let mut py_has_link = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Ok(links) = py_client.get_links().await {
            if !links.is_empty() {
                py_has_link = true;
                break;
            }
        }
    }
    assert!(py_has_link, "Python should have an established link");

    // ── Phase 7: Bidirectional data exchange ─────────────────────────────

    // Rust A → Python (via Channel)
    link_handle
        .try_send(b"hello-from-rust")
        .await
        .expect("Failed to send channel message");

    // Poll Python for received data
    let mut rust_to_py_ok = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Ok(packets) = py_client.get_received_packets().await {
            for p in &packets {
                if String::from_utf8_lossy(&p.data).contains("hello-from-rust") {
                    rust_to_py_ok = true;
                    break;
                }
            }
        }
        if rust_to_py_ok {
            break;
        }
    }
    assert!(
        rust_to_py_ok,
        "Python should receive channel message from Rust A"
    );

    // Python → Rust A (echo via Channel — Python echoes the channel message back)
    let echo = wait_for_data_event(&mut event_rx, &link_id, Duration::from_secs(10)).await;
    assert!(echo.is_some(), "Should receive echo from Python");
    assert_eq!(
        echo.unwrap(),
        b"hello-from-rust",
        "Echo should match sent data"
    );

    // Python → Rust A (raw packet via send_on_link)
    let link_hash = {
        let links = py_client.get_links().await.expect("Failed to get links");
        links.keys().next().expect("Should have a link").clone()
    };

    py_client
        .send_on_link(&link_hash, b"hello-from-python")
        .await
        .expect("Python send_on_link should succeed");

    let raw_data = wait_for_data_event(&mut event_rx, &link_id, Duration::from_secs(10)).await;
    assert!(raw_data.is_some(), "Should receive raw data from Python");
    assert_eq!(
        raw_data.unwrap(),
        b"hello-from-python",
        "Raw data from Python should match"
    );

    // ── Cleanup ──────────────────────────────────────────────────────────
    link_handle.close().await.expect("Failed to close link");
    rust_a.stop().await.expect("Failed to stop Rust node A");
    daemon_node
        .stop()
        .await
        .expect("Failed to stop Rust daemon");
}
