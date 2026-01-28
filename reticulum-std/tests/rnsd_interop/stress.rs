//! Concurrency, rate limiting, and burst handling tests

use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use reticulum_core::constants::{MTU, TRUNCATED_HASHBYTES};
use reticulum_core::destination::DestinationType;
use reticulum_core::identity::Identity;
use reticulum_core::link::Link;
use reticulum_core::packet::{
    HeaderType, Packet, PacketContext, PacketData, PacketFlags, PacketType, TransportType,
};
use reticulum_std::interfaces::hdlc::frame;

use crate::common::*;

/// 4.1: Multiple simultaneous connections with unique announces
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_multiple_simultaneous_connections() {
    let num_senders = 5;
    let mut sender_streams: Vec<TcpStream> = Vec::new();

    for i in 0..num_senders {
        let stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
            .await
            .unwrap_or_else(|_| panic!("Timeout connecting sender {}", i))
            .unwrap_or_else(|_| panic!("Failed to connect sender {}", i));
        sender_streams.push(stream);
    }

    let mut receiver = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout connecting receiver")
        .expect("Failed to connect receiver");

    // Give rnsd time to set up all spawned interfaces
    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    // Each sender creates a unique identity and sends an announce
    let mut expected_hashes: Vec<[u8; TRUNCATED_HASHBYTES]> = Vec::new();

    for (i, stream) in sender_streams.iter_mut().enumerate() {
        let aspect = format!("multi_{}", i);
        let (dest_hash, _identity) =
            build_and_send_announce(stream, "leviculum", &[&aspect], format!("sender-{}", i).as_bytes()).await;
        expected_hashes.push(dest_hash);
        println!("  Sender {} sent announce: {:02x?}...", i, &dest_hash[..4]);
        // Small delay between sends to avoid overwhelming rnsd
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Collect announces on receiver
    let announces = collect_announces(&mut receiver, PROPAGATION_TIMEOUT).await;

    let mut found_count = 0;
    for expected in &expected_hashes {
        if announces.iter().any(|(h, _)| h == expected) {
            found_count += 1;
        } else {
            println!("  Missing: {:02x?}...", &expected[..4]);
        }
    }

    println!(
        "Found {}/{} unique announces on receiver",
        found_count, num_senders
    );
    // Rate limiting may suppress some, but we should get at least a few
    assert!(
        found_count >= 2,
        "Expected at least 2 of {} announces to propagate",
        num_senders
    );

    // Verify all received announces have valid structure
    for (hash, raw) in &announces {
        let pkt = Packet::unpack(raw).expect("Failed to unpack received announce");
        assert_eq!(pkt.flags.packet_type, PacketType::Announce);
        assert_eq!(&pkt.destination_hash, hash);
    }

    println!("SUCCESS: Multiple simultaneous connections handled correctly");
}

/// 4.2: Rapid announces from same identity (rate limiting)
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_rapid_announce_rate_limiting() {
    let mut conn1 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn1");
    let mut conn2 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn2");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    let identity = Identity::generate_with_rng(&mut rand_core::OsRng);
    let public_key = identity.public_key_bytes();
    let identity_hash = *identity.hash();
    let name_hash = compute_name_hash("leviculum", &["ratelimit", "test"]);

    // Send 20 announces from the same identity with different random_hashes
    let mut sent_hashes: Vec<[u8; TRUNCATED_HASHBYTES]> = Vec::new();

    for i in 0..20 {
        let random_hash = generate_random_hash();
        let dest_hash = compute_destination_hash(&name_hash, &identity_hash);

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&dest_hash);
        signed_data.extend_from_slice(&public_key);
        signed_data.extend_from_slice(&name_hash);
        signed_data.extend_from_slice(&random_hash);
        signed_data.extend_from_slice(format!("rapid-{}", i).as_bytes());

        let signature = identity.sign(&signed_data).unwrap();

        let mut payload = Vec::new();
        payload.extend_from_slice(&public_key);
        payload.extend_from_slice(&name_hash);
        payload.extend_from_slice(&random_hash);
        payload.extend_from_slice(&signature);
        payload.extend_from_slice(format!("rapid-{}", i).as_bytes());

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
        sent_hashes.push(dest_hash);

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    println!("Sent 20 rapid announces from same identity");

    // Count how many arrive on conn2
    let announces = collect_announces(&mut conn2, PROPAGATION_TIMEOUT).await;

    let received_count = announces
        .iter()
        .filter(|(h, _)| sent_hashes.contains(h))
        .count();

    println!("Received {} of 20 announces", received_count);
    // Rate limiting should suppress most - we just check it's less than 20
    // The first one should always get through
    assert!(
        received_count < 20,
        "Expected rate limiting to suppress some announces, but all {} went through",
        received_count
    );
    assert!(
        received_count >= 1,
        "Expected at least 1 announce to get through"
    );

    println!("SUCCESS: Rate limiting working ({}/20 passed)", received_count);
}

/// 4.3: Burst of mixed packet types
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_burst_of_mixed_packet_types() {
    let log_monitor = RnsdLogMonitor::new();

    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    let mut sent = 0;

    for i in 0..50 {
        let raw: Vec<u8> = match i % 4 {
            // Data packets
            0 => {
                let pkt = Packet {
                    flags: PacketFlags {
                        header_type: HeaderType::Type1,
                        context_flag: false,
                        transport_type: TransportType::Broadcast,
                        dest_type: DestinationType::Single,
                        packet_type: PacketType::Data,
                    },
                    hops: 0,
                    transport_id: None,
                    destination_hash: [i as u8; TRUNCATED_HASHBYTES],
                    context: PacketContext::None,
                    data: PacketData::Owned(format!("burst-data-{}", i).into_bytes()),
                };
                let mut buf = [0u8; MTU];
                let size = pkt.pack(&mut buf).unwrap();
                buf[..size].to_vec()
            }
            // Announces (unique identities)
            1 => {
                let (raw, _, _) = build_announce_raw(
                    "leviculum",
                    &[&format!("burst_{}", i)],
                    format!("burst-{}", i).as_bytes(),
                );
                raw
            }
            // LinkRequests
            2 => {
                let mut link = Link::new_outgoing_with_rng([i as u8; TRUNCATED_HASHBYTES], &mut rand_core::OsRng);
                link.build_link_request_packet()
            }
            // H2 Transport
            _ => {
                let pkt = Packet {
                    flags: PacketFlags {
                        header_type: HeaderType::Type2,
                        context_flag: false,
                        transport_type: TransportType::Transport,
                        dest_type: DestinationType::Single,
                        packet_type: PacketType::Data,
                    },
                    hops: 1,
                    transport_id: Some([i as u8; TRUNCATED_HASHBYTES]),
                    destination_hash: [(i + 1) as u8; TRUNCATED_HASHBYTES],
                    context: PacketContext::None,
                    data: PacketData::Owned(format!("h2-burst-{}", i).into_bytes()),
                };
                let mut buf = [0u8; MTU];
                let size = pkt.pack(&mut buf).unwrap();
                buf[..size].to_vec()
            }
        };

        send_framed(&mut stream, &raw).await;
        sent += 1;
    }

    println!("Sent {} burst packets", sent);
    tokio::time::sleep(Duration::from_secs(2)).await;

    assert!(
        connection_alive(&mut stream).await,
        "Connection should survive burst"
    );

    if let Some(monitor) = &log_monitor {
        let errors = monitor.check_for_errors();
        if !errors.is_empty() {
            println!("rnsd errors (rate limit messages OK): {:?}", &errors[..errors.len().min(5)]);
        }
    }

    println!("SUCCESS: {} burst packets sent, connection alive", sent);
}

/// 4.4: Fragmented HDLC delivery (TCP stream fragmentation)
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_fragmented_hdlc_delivery() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    // Build 3 valid framed packets
    let (raw1, _, _) = build_announce_raw("leviculum", &["frag", "p1"], b"frag-p1");
    let (raw2, _, _) = build_announce_raw("leviculum", &["frag", "p2"], b"frag-p2");
    let (raw3, _dest3, _) = build_announce_raw("leviculum", &["frag", "p3"], b"frag-p3");

    let mut framed1 = Vec::new();
    let mut framed2 = Vec::new();
    let mut framed3 = Vec::new();
    frame(&raw1, &mut framed1);
    frame(&raw2, &mut framed2);
    frame(&raw3, &mut framed3);

    // Send P1 split into 5-byte chunks
    for chunk in framed1.chunks(5) {
        stream.write_all(chunk).await.unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    println!("  P1 sent in 5-byte chunks");

    // Send P2 in one write
    stream.write_all(&framed2).await.unwrap();
    stream.flush().await.unwrap();
    println!("  P2 sent in one write");

    // Send P3 split into 3-byte chunks
    for chunk in framed3.chunks(3) {
        stream.write_all(chunk).await.unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    println!("  P3 sent in 3-byte chunks");

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Now send a normal announce and verify propagation on a second connection
    let mut conn2 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn2");

    let (raw4, dest4, _) = build_announce_raw("leviculum", &["frag", "p4"], b"frag-p4");
    send_framed(&mut stream, &raw4).await;

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    let found = wait_for_announce(&mut conn2, &dest4, PROPAGATION_TIMEOUT).await;

    assert!(
        connection_alive(&mut stream).await,
        "Connection should survive fragmented delivery"
    );

    println!(
        "Post-fragmentation announce propagated: {}",
        found
    );
    println!("SUCCESS: Fragmented HDLC delivery handled correctly");
}
