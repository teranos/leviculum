//! Error recovery, reconnection, and malformed packet tolerance tests

use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use reticulum_core::constants::{MTU, TRUNCATED_HASHBYTES};
use reticulum_core::destination::DestinationType;
use reticulum_core::packet::{
    HeaderType, Packet, PacketContext, PacketData, PacketFlags, PacketType, TransportType,
};
use reticulum_std::interfaces::hdlc::{frame, DeframeResult, Deframer, ESCAPE, FLAG};

use crate::common::*;

/// 1.4: HDLC worst-case escaping (all data bytes are 0x7E/0x7D)
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_hdlc_maximum_escaping() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect");

    // Build a packet where the payload is all FLAG and ESCAPE bytes
    // This creates worst-case expansion in HDLC framing
    let mut evil_payload = vec![0u8; 50];
    for i in 0..evil_payload.len() {
        evil_payload[i] = if i % 2 == 0 { FLAG } else { ESCAPE };
    }

    let packet = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: [0xEE; TRUNCATED_HASHBYTES],
        context: PacketContext::None,
        data: PacketData::Owned(evil_payload.clone()),
    };

    let mut raw = [0u8; MTU];
    let size = packet.pack(&mut raw).unwrap();

    // Frame it
    let mut framed = Vec::new();
    frame(&raw[..size], &mut framed);

    // The framed size should be larger due to escaping
    println!(
        "  Payload: {} bytes, raw: {} bytes, framed: {} bytes",
        evil_payload.len(),
        size,
        framed.len()
    );
    assert!(
        framed.len() > size + 2,
        "Framed should be larger due to escaping"
    );

    // Verify local roundtrip
    let mut deframer = Deframer::new();
    let results = deframer.process(&framed);
    assert_eq!(results.len(), 1, "Should get exactly one frame");
    match &results[0] {
        DeframeResult::Frame(data) => {
            assert_eq!(data.as_slice(), &raw[..size], "Deframed data should match original");
        }
        _ => panic!("Expected Frame result"),
    }

    // Send to rnsd
    stream.write_all(&framed).await.unwrap();
    stream.flush().await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        connection_alive(&mut stream).await,
        "Connection should survive worst-case escaping"
    );
    println!("SUCCESS: Worst-case HDLC escaping handled correctly");
}

/// 2.4: Truncated packet variants at boundary sizes
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_truncated_packet_variants() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let boundary_sizes = [0usize, 1, 18, 19, 34, 35];

    for &size in &boundary_sizes {
        let data: Vec<u8> = (0..size).map(|i| i as u8).collect();

        let mut framed = Vec::new();
        frame(&data, &mut framed);

        stream.write_all(&framed).await.unwrap();
        stream.flush().await.unwrap();

        println!("  Sent truncated packet ({} bytes)", size);

        // Small delay to let rnsd process
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        connection_alive(&mut stream).await,
        "Connection should survive all truncated packets"
    );
    println!("SUCCESS: All {} truncated packet sizes handled", boundary_sizes.len());
}

/// 2.5: Corrupt HDLC sequences
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_corrupt_hdlc_sequences() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test 1: [FLAG, ESCAPE, FLAG] - escape immediately before flag
    stream.write_all(&[FLAG, ESCAPE, FLAG]).await.unwrap();
    stream.flush().await.unwrap();
    println!("  Sent [FLAG, ESCAPE, FLAG]");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test 2: [FLAG, ESCAPE, ESCAPE, 0x42, FLAG] - double escape
    stream
        .write_all(&[FLAG, ESCAPE, ESCAPE, 0x42, FLAG])
        .await
        .unwrap();
    stream.flush().await.unwrap();
    println!("  Sent [FLAG, ESCAPE, ESCAPE, 0x42, FLAG]");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test 3: 256 bytes of random noise without any FLAG bytes
    let noise: Vec<u8> = (0..256)
        .map(|i| {
            let b = (i * 37 + 13) as u8;
            if b == FLAG { b.wrapping_add(1) } else { b }
        })
        .collect();
    stream.write_all(&noise).await.unwrap();
    stream.flush().await.unwrap();
    println!("  Sent 256 bytes of noise (no FLAGs)");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // After all corruption, send a valid framed packet
    let valid_pkt = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: [0xFF; TRUNCATED_HASHBYTES],
        context: PacketContext::None,
        data: PacketData::Owned(b"after-corruption".to_vec()),
    };

    let mut raw = [0u8; MTU];
    let size = valid_pkt.pack(&mut raw).unwrap();
    let mut framed = Vec::new();
    frame(&raw[..size], &mut framed);
    stream.write_all(&framed).await.unwrap();
    stream.flush().await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        connection_alive(&mut stream).await,
        "Connection should survive corrupt HDLC and process valid packets after"
    );
    println!("SUCCESS: HDLC deframer recovered from all corruption types");
}

/// 5.1: Reconnect after disconnect
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_reconnect_after_disconnect() {
    // First connection
    let mut stream1 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect");

    let mut conn2 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn2");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    // Send first announce
    let (dest1, _id1) =
        build_and_send_announce(&mut stream1, "leviculum", &["reconnect", "first"], b"first").await;
    println!("First announce sent: {:02x?}...", &dest1[..4]);

    let found1 = wait_for_announce(&mut conn2, &dest1, PROPAGATION_TIMEOUT).await;
    assert!(found1, "First announce should propagate");

    // Drop connection
    drop(stream1);
    drop(conn2);
    println!("First connections dropped");

    // Give rnsd time to clean up the closed connections
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Reconnect
    let mut stream2 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout on reconnect")
        .expect("Failed to reconnect");

    let mut conn3 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect conn3");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    // Send second announce (new identity)
    let (dest2, _id2) =
        build_and_send_announce(&mut stream2, "leviculum", &["reconnect", "second"], b"second").await;
    println!("Second announce sent: {:02x?}...", &dest2[..4]);

    let found2 = wait_for_announce(&mut conn3, &dest2, PROPAGATION_TIMEOUT).await;
    assert!(found2, "Second announce should propagate after reconnect");

    println!("SUCCESS: Clean disconnect/reconnect handling verified");
}

/// 5.2: Connection stays open after sequence of invalid packets
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_connection_stays_open_after_invalid_packets() {
    let log_monitor = RnsdLogMonitor::new();

    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("Failed to connect");

    let mut conn2 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("conn2");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    // Send a valid announce first
    let (dest_valid, _id) =
        build_and_send_announce(&mut stream, "leviculum", &["resilience", "pre"], b"pre-invalid").await;
    let found_pre = wait_for_announce(&mut conn2, &dest_valid, PROPAGATION_TIMEOUT).await;
    assert!(found_pre, "Pre-test announce should propagate");
    println!("  Pre-test announce propagated OK");

    // Now send 5 different types of malformed packets, each followed by a valid data packet

    // 1. Truncated packet (just a few bytes)
    let truncated = vec![0x01, 0x00, 0xAA, 0xBB];
    send_framed(&mut stream, &truncated).await;
    println!("  Sent truncated packet (4 bytes)");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 2. Announce with bad signature (from test above)
    let (mut bad_sig, _, _) =
        build_announce_raw("leviculum", &["resilience", "badsig"], b"bad-sig");
    bad_sig[103] ^= 0xFF; // corrupt signature
    send_framed(&mut stream, &bad_sig).await;
    println!("  Sent bad-signature announce");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 3. Announce with wrong hash
    let (mut bad_hash, _, _) =
        build_announce_raw("leviculum", &["resilience", "badhash"], b"bad-hash");
    bad_hash[2] ^= 0xFF; // corrupt dest hash in header
    send_framed(&mut stream, &bad_hash).await;
    println!("  Sent wrong-hash announce");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 4. Announce with zeroed signature
    let (mut zeroed, _, _) =
        build_announce_raw("leviculum", &["resilience", "zero"], b"zeroed");
    for i in 103..103 + 64 {
        zeroed[i] = 0;
    }
    send_framed(&mut stream, &zeroed).await;
    println!("  Sent zeroed-signature announce");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 5. Random garbage bytes
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                       0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                       0x99, 0xAA, 0xBB];
    send_framed(&mut stream, &garbage).await;
    println!("  Sent random garbage bytes");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify connection is still alive
    assert!(
        connection_alive(&mut stream).await,
        "Connection should survive all invalid packets"
    );

    // Now send a valid announce and verify propagation
    let mut conn3 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("conn3");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    let (dest_post, _id) =
        build_and_send_announce(&mut stream, "leviculum", &["resilience", "post"], b"post-invalid").await;
    let found_post = wait_for_announce(&mut conn3, &dest_post, PROPAGATION_TIMEOUT).await;

    if let Some(monitor) = &log_monitor {
        let errors = monitor.check_for_errors();
        if !errors.is_empty() {
            println!("  rnsd logged {} errors (expected for bad packets)", errors.len());
        }
    }

    assert!(
        found_post,
        "Post-invalid announce should propagate (connection should be functional)"
    );
    println!("SUCCESS: Connection survived 5 invalid packets and still works");
}
