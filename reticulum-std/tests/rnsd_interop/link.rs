//! Link establishment and data exchange tests

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use reticulum_core::constants::TRUNCATED_HASHBYTES;
use reticulum_core::link::{Link, LinkState};
use reticulum_core::packet::{Packet, PacketType};
use reticulum_std::interfaces::hdlc::{frame, DeframeResult, Deframer};

use crate::common::*;

/// Search for the linktest Python destination announce on a stream.
/// Returns (dest_hash, signing_key_bytes) or None if not found within timeout.
async fn find_linktest_announce(
    stream: &mut TcpStream,
    timeout_secs: u64,
) -> Option<([u8; TRUNCATED_HASHBYTES], [u8; 32])> {
    let mut deframer = Deframer::new();
    let mut buffer = [0u8; 2048];
    let start = std::time::Instant::now();

    while start.elapsed() < Duration::from_secs(timeout_secs) {
        match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
            Ok(Ok(0)) => return None,
            Ok(Ok(n)) => {
                for result in deframer.process(&buffer[..n]) {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == PacketType::Announce {
                                if let Some(ann) = ParsedAnnounce::from_packet(&pkt) {
                                    let app_str = String::from_utf8_lossy(&ann.app_data);
                                    if app_str.contains("leviculum.linktest") {
                                        let sk: [u8; 32] =
                                            ann.public_key[32..64].try_into().unwrap();
                                        return Some((ann.destination_hash, sk));
                                    }
                                }
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

/// Establish a link to the linktest destination.
/// Returns (active Link, TcpStream, Deframer) or panics with a descriptive message.
async fn establish_link(
    announce_timeout_secs: u64,
) -> (Link, TcpStream, Deframer) {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    let (dh, sk) = find_linktest_announce(&mut stream, announce_timeout_secs)
        .await
        .expect("No linktest announce received. Is link_test_destination.py running?");

    println!("Found linktest destination: {:02x?}", &dh[..4]);

    let mut link = Link::new_outgoing(dh);
    link.set_destination_keys(&sk).unwrap();

    let raw_packet = link.build_link_request_packet();
    let mut framed = Vec::new();
    frame(&raw_packet, &mut framed);
    stream.write_all(&framed).await.unwrap();
    stream.flush().await.unwrap();
    println!("Link request sent, link ID: {:02x?}", &link.id()[..4]);

    // Wait for proof
    let mut deframer = Deframer::new();
    let mut buffer = [0u8; 2048];
    let proof_start = std::time::Instant::now();
    use reticulum_core::traits::{Clock, PlatformContext, NoStorage};
    use rand_core::OsRng;
    struct TestClock;
    impl Clock for TestClock {
        fn now_ms(&self) -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        }
    }
    let mut ctx = PlatformContext {
        rng: OsRng,
        clock: TestClock,
        storage: NoStorage,
    };

    while proof_start.elapsed() < Duration::from_secs(10) {
        match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
            Ok(Ok(0)) => panic!("Connection closed while waiting for proof"),
            Ok(Ok(n)) => {
                for result in deframer.process(&buffer[..n]) {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == PacketType::Proof
                                && pkt.destination_hash == *link.id()
                            {
                                link.process_proof(pkt.data.as_slice())
                                    .expect("Proof verification failed");
                                println!("Proof verified! Link active.");

                                // Send RTT
                                let rtt_pkt = link.build_rtt_packet(0.05, &mut ctx).unwrap();
                                let mut rtt_framed = Vec::new();
                                frame(&rtt_pkt, &mut rtt_framed);
                                stream.write_all(&rtt_framed).await.unwrap();
                                stream.flush().await.unwrap();
                                tokio::time::sleep(Duration::from_millis(200)).await;

                                return (link, stream, deframer);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    panic!("Link proof not received within 10 seconds");
}

// =========================================================================
// Existing tests
// =========================================================================

/// Send a LINKREQUEST packet, verify rnsd accepts the format
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_send_linkrequest_packet() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    println!("=== LINKREQUEST PACKET TEST ===\n");

    let dummy_dest_hash = [0x42u8; TRUNCATED_HASHBYTES];
    let mut link = Link::new_outgoing(dummy_dest_hash);

    let raw_packet = link.build_link_request_packet();

    println!("  Destination hash: {:02x?}", &dummy_dest_hash[..4]);
    println!("  Link ID: {:02x?}", &link.id()[..4]);
    println!("  Packet size: {} bytes", raw_packet.len());

    let unpacked = Packet::unpack(&raw_packet).expect("Failed to unpack");
    assert_eq!(unpacked.flags.packet_type, PacketType::LinkRequest);
    assert_eq!(unpacked.data.len(), 64);

    let mut framed = Vec::new();
    frame(&raw_packet, &mut framed);
    stream.write_all(&framed).await.expect("Failed to send");
    stream.flush().await.expect("Failed to flush");

    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut buffer = [0u8; 1024];
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(0)) => panic!("Connection closed - link request format invalid"),
        _ => println!("LINKREQUEST accepted by rnsd"),
    }
}

/// Full link establishment with a Python destination
#[tokio::test]
#[ignore = "requires running rnsd AND python link_test_destination.py"]
async fn test_link_establishment_with_python() {
    println!("=== LINK ESTABLISHMENT TEST ===\n");

    let (link, _stream, _deframer) = establish_link(60).await;

    assert_eq!(link.state(), LinkState::Active);
    assert!(link.link_key().is_some());
    println!("SUCCESS: Link established and active!");
}

// =========================================================================
// NEW: Link protocol tests
// =========================================================================

/// 6.1: Link request with MTU signaling
#[tokio::test]
#[ignore = "requires running rnsd AND python link_test_destination.py"]
async fn test_link_request_with_mtu_signaling() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect");

    let (dh, sk) = find_linktest_announce(&mut stream, 60)
        .await
        .expect("No linktest announce. Is link_test_destination.py running?");

    println!("Found linktest destination: {:02x?}", &dh[..4]);

    let mut link = Link::new_outgoing(dh);
    link.set_destination_keys(&sk).unwrap();

    // Use create_link_request_with_mtu instead of standard
    let request_data = link.create_link_request_with_mtu(500, 1);
    assert_eq!(request_data.len(), 67, "MTU request should be 67 bytes");

    // Build raw packet manually (like build_link_request_packet but with MTU data)
    use reticulum_core::destination::DestinationType;
    use reticulum_core::packet::{HeaderType, PacketContext, PacketFlags, TransportType};

    let flags = PacketFlags {
        header_type: HeaderType::Type1,
        context_flag: false,
        transport_type: TransportType::Broadcast,
        dest_type: DestinationType::Single,
        packet_type: PacketType::LinkRequest,
    };

    let mut packet = Vec::with_capacity(86);
    packet.push(flags.to_byte());
    packet.push(0); // hops
    packet.extend_from_slice(&dh);
    packet.push(PacketContext::None as u8);
    packet.extend_from_slice(&request_data);

    // Calculate link_id (signaling bytes stripped per calculate_link_id)
    let link_id = Link::calculate_link_id(&packet);
    link.set_link_id(link_id);

    let mut framed = Vec::new();
    frame(&packet, &mut framed);
    stream.write_all(&framed).await.unwrap();
    stream.flush().await.unwrap();

    println!(
        "Sent MTU-signaled link request, link ID: {:02x?}",
        &link_id[..4]
    );

    // Wait for proof
    let mut deframer = Deframer::new();
    let mut buffer = [0u8; 2048];
    let proof_start = std::time::Instant::now();
    let mut established = false;

    while proof_start.elapsed() < Duration::from_secs(10) && !established {
        match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                for result in deframer.process(&buffer[..n]) {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == PacketType::Proof
                                && pkt.destination_hash == *link.id()
                            {
                                match link.process_proof(pkt.data.as_slice()) {
                                    Ok(()) => {
                                        established = true;
                                        println!("Link established with MTU signaling!");
                                    }
                                    Err(e) => println!("Proof failed: {:?}", e),
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    assert!(established, "Link with MTU signaling should establish");
    assert_eq!(link.state(), LinkState::Active);
    println!("SUCCESS: MTU-signaled link established");
}

/// 6.2: Send multiple data packets over a link at various sizes
#[tokio::test]
#[ignore = "requires running rnsd AND python link_test_destination.py"]
async fn test_multiple_data_packets_over_link() {
    let (link, mut stream, mut deframer) = establish_link(60).await;

    // Test various sizes: exercise PKCS7 padding boundaries
    let test_sizes: &[usize] = &[1, 15, 16, 17, 31, 32, 50, 100, 200, 300, 4, 5, 6, 7, 8];

    let mut sent_count = 0;
    let mut echo_count = 0;
    let mut framed = Vec::new();
    use reticulum_core::traits::{Clock, PlatformContext, NoStorage};
    use rand_core::OsRng;
    struct TestClock;
    impl Clock for TestClock {
        fn now_ms(&self) -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        }
    }
    let mut ctx = PlatformContext {
        rng: OsRng,
        clock: TestClock,
        storage: NoStorage,
    };

    for &size in test_sizes {
        let data: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();

        let data_pkt = link.build_data_packet(&data, &mut ctx).unwrap();
        framed.clear();
        frame(&data_pkt, &mut framed);
        stream.write_all(&framed).await.unwrap();
        stream.flush().await.unwrap();
        sent_count += 1;

        println!("  Sent {} bytes", size);
    }

    // Collect echo responses
    let mut buffer = [0u8; 2048];
    let echo_start = std::time::Instant::now();
    while echo_start.elapsed() < Duration::from_secs(15) && echo_count < sent_count {
        match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                for result in deframer.process(&buffer[..n]) {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == PacketType::Data
                                && pkt.destination_hash == *link.id()
                            {
                                let mut dec = vec![0u8; pkt.data.len()];
                                if let Ok(len) = link.decrypt(pkt.data.as_slice(), &mut dec) {
                                    echo_count += 1;
                                    println!("  Echo #{}: {} bytes decrypted", echo_count, len);
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    println!(
        "\nSent {} data packets, received {} echoes",
        sent_count, echo_count
    );
    assert!(
        echo_count > 0,
        "Should receive at least some echo responses"
    );
}
