//! Shared instance interop tests.
//!
//! Tests that a Rust client can connect to a Python daemon's shared instance
//! Unix socket and exchange HDLC-framed packets.

use std::time::Duration;

use reticulum_core::framing::hdlc::{frame, DeframeResult, Deframer};
use reticulum_core::packet::Packet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{build_announce_raw, init_tracing, DAEMON_PROCESS_TIME};
use crate::harness::TestDaemon;

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
