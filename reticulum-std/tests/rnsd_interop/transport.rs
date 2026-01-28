//! Transport + TcpClientInterface integration test

use std::time::Duration;

use reticulum_core::constants::MTU;
use reticulum_core::identity::Identity;
use reticulum_core::traits::InterfaceError;
use reticulum_core::transport::{Transport, TransportConfig, TransportEvent};
use reticulum_core::traits::NoStorage;
use reticulum_std::clock::SystemClock;
use reticulum_std::interfaces::TcpClientInterface;

use crate::common::*;

/// End-to-end test: Transport receives announces via TcpClientInterface
///
/// This test sends announces from a separate TCP connection to rnsd, which
/// retransmits them. Our Transport+TcpClientInterface should receive and
/// process these announces.
#[test]
#[ignore] // Requires rnsd running
fn test_transport_with_tcp_interface() {
    println!("\n=== TRANSPORT + TCP INTERFACE INTEGRATION TEST ===\n");

    let clock = SystemClock::new();
    let identity = Identity::new();
    let config = TransportConfig::default();
    let mut transport = Transport::new(config, clock, NoStorage, identity);

    let iface = TcpClientInterface::connect("IntegrationTest", RNSD_ADDR, CONNECTION_TIMEOUT)
        .expect("Failed to connect to rnsd");

    let iface_idx = transport.register_interface(Box::new(iface));
    println!("  Interface registered at index {}", iface_idx);
    assert_eq!(transport.interface_count(), 1);

    // Give rnsd time to set up our spawned interface
    std::thread::sleep(Duration::from_millis(1500));

    // Spawn a helper thread that sends announces via a separate TCP connection
    // so rnsd retransmits them to our Transport's interface
    let sender_handle = std::thread::spawn(|| {
        use std::io::Write;
        use std::net::TcpStream as StdTcpStream;

        let mut sender = StdTcpStream::connect(RNSD_ADDR).expect("sender connect");
        sender.set_write_timeout(Some(Duration::from_secs(2))).ok();

        // Wait for the sender interface to be set up in rnsd
        std::thread::sleep(Duration::from_millis(1500));

        // Send 3 announces with unique identities
        for i in 0..3 {
            let (raw, _dest, _id) = build_announce_raw(
                "leviculum",
                &[&format!("transport_test_{}", i)],
                format!("transport-sender-{}", i).as_bytes(),
            );
            let mut framed = Vec::new();
            reticulum_std::interfaces::hdlc::frame(&raw, &mut framed);
            sender.write_all(&framed).ok();
            sender.flush().ok();
            std::thread::sleep(Duration::from_secs(1));
        }
    });

    let start = std::time::Instant::now();
    let mut announce_count = 0;
    let mut packet_count = 0;
    let mut path_count = 0;
    let mut recv_buf = [0u8; MTU];

    println!("  Waiting for announces (20 second timeout)...\n");

    while start.elapsed() < Duration::from_secs(20) {
        let iface = transport.interface_mut(iface_idx).unwrap();
        match iface.recv(&mut recv_buf) {
            Ok(len) => {
                packet_count += 1;
                if let Err(e) = transport.process_incoming(iface_idx, &recv_buf[..len]) {
                    println!("  Packet {}: {} bytes (error: {:?})", packet_count, len, e);
                }
            }
            Err(InterfaceError::WouldBlock) => {
                transport.poll();
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                panic!("Interface error: {:?}", e);
            }
        }

        for event in transport.drain_events() {
            match event {
                TransportEvent::AnnounceReceived { announce, .. } => {
                    announce_count += 1;
                    let hash = announce.destination_hash();
                    let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
                    let app_data = announce.app_data_string().unwrap_or("<binary>");
                    println!(
                        "  Announce {}: dest={} app_data={:?}",
                        announce_count, hash_hex, app_data
                    );
                }
                TransportEvent::PathFound {
                    destination_hash,
                    hops,
                    ..
                } => {
                    path_count += 1;
                    let hash_hex: String =
                        destination_hash.iter().map(|b| format!("{:02x}", b)).collect();
                    println!("  Path found: dest={} hops={}", hash_hex, hops);
                }
                _ => {}
            }
        }

        if announce_count >= 3 {
            break;
        }
    }

    sender_handle.join().ok();

    println!("\n=== RESULTS ===");
    println!("  Packets received: {}", packet_count);
    println!("  Announces processed: {}", announce_count);
    println!("  Paths learned: {}", path_count);
    println!("  Path table size: {}", transport.path_count());

    assert!(
        announce_count > 0,
        "Should have received at least one announce"
    );
    assert!(
        transport.path_count() > 0,
        "Should have learned at least one path"
    );

    println!("\nSUCCESS: Transport + TcpClientInterface integration works!");
}
