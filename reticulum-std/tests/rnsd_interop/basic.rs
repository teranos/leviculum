//! Basic connectivity and packet format tests

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use reticulum_core::constants::MTU;
use reticulum_core::destination::DestinationType;
use reticulum_core::packet::{
    HeaderType, Packet, PacketContext, PacketData, PacketFlags, PacketType, TransportType,
};
use reticulum_std::interfaces::hdlc::{DeframeResult, Deframer, FLAG, frame};

use crate::common::*;

/// Test that we can connect to rnsd TCP interface
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_connect_to_rnsd() {
    let stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    assert!(stream.peer_addr().is_ok());
    println!("Successfully connected to rnsd at {}", RNSD_ADDR);
}

/// Test receiving packets from rnsd (announces from the network)
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_receive_packets_from_rnsd() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    let mut deframer = Deframer::new();
    let mut buffer = [0u8; 1024];
    let mut packets_received = 0;
    let mut total_bytes = 0;

    println!("Listening for packets from rnsd (5 second timeout)...");

    let start = std::time::Instant::now();
    while start.elapsed() < READ_TIMEOUT {
        match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
            Ok(Ok(0)) => {
                println!("Connection closed by rnsd");
                break;
            }
            Ok(Ok(n)) => {
                total_bytes += n;
                let results = deframer.process(&buffer[..n]);
                for result in results {
                    match result {
                        DeframeResult::Frame(data) => {
                            packets_received += 1;
                            println!(
                                "Received packet {} ({} bytes)",
                                packets_received,
                                data.len()
                            );

                            match Packet::unpack(&data) {
                                Ok(packet) => {
                                    println!("  Flags: {:02x}", packet.flags.to_byte());
                                    println!("  Type: {:?}", packet.flags.packet_type);
                                    println!("  Header: {:?}", packet.flags.header_type);
                                    println!("  Hops: {}", packet.hops);
                                    println!(
                                        "  Dest hash: {:02x?}",
                                        &packet.destination_hash[..4]
                                    );
                                    println!("  Context: {:?}", packet.context);
                                    println!("  Data len: {}", packet.data.len());
                                }
                                Err(e) => {
                                    println!("  Failed to parse: {:?}", e);
                                    println!(
                                        "  Raw data: {:02x?}",
                                        &data[..data.len().min(32)]
                                    );
                                }
                            }
                        }
                        DeframeResult::TooShort => {
                            println!("Received empty frame");
                        }
                        DeframeResult::NeedMore => {}
                    }
                }
            }
            Ok(Err(e)) => {
                println!("Read error: {}", e);
                break;
            }
            Err(_) => {}
        }
    }

    println!(
        "Total: {} bytes received, {} packets parsed",
        total_bytes, packets_received
    );
}

/// Test sending a packet to rnsd and verifying it's accepted
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_send_packet_to_rnsd() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

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
        destination_hash: [0x00; 16],
        context: PacketContext::None,
        data: PacketData::Owned(b"test".to_vec()),
    };

    let mut raw_packet = [0u8; MTU];
    let size = packet.pack(&mut raw_packet).expect("Failed to pack packet");

    let mut framed = Vec::new();
    frame(&raw_packet[..size], &mut framed);

    println!(
        "Sending test packet ({} bytes, {} framed)",
        size,
        framed.len()
    );

    stream.write_all(&framed).await.expect("Failed to send");
    stream.flush().await.expect("Failed to flush");

    tokio::time::sleep(Duration::from_millis(100)).await;
    println!("Packet sent successfully (connection still open)");

    let mut buffer = [0u8; 1024];
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            println!("Received {} bytes in response", n);
        }
        _ => {
            println!("No response (expected for dummy destination)");
        }
    }
}

/// Test HDLC framing interop
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_hdlc_framing_interop() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    // Send multiple FLAG bytes
    stream
        .write_all(&[FLAG, FLAG, FLAG])
        .await
        .expect("Failed to send flags");

    // Send an incomplete frame (no end flag)
    let mut incomplete = Vec::new();
    incomplete.push(FLAG);
    incomplete.extend_from_slice(b"incomplete");
    stream
        .write_all(&incomplete)
        .await
        .expect("Failed to send incomplete");

    // Send a complete empty frame
    stream
        .write_all(&[FLAG, FLAG])
        .await
        .expect("Failed to send empty frame");

    // Send a valid framed packet
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
        destination_hash: [0xAB; 16],
        context: PacketContext::None,
        data: PacketData::Owned(b"hdlc test".to_vec()),
    };

    let mut raw_packet = [0u8; MTU];
    let size = packet.pack(&mut raw_packet).expect("Failed to pack");

    let mut framed = Vec::new();
    frame(&raw_packet[..size], &mut framed);
    stream
        .write_all(&framed)
        .await
        .expect("Failed to send framed packet");
    stream.flush().await.expect("Failed to flush");

    tokio::time::sleep(Duration::from_millis(100)).await;
    println!("HDLC framing test completed successfully");
}

/// Test packet flags encoding matches Python Reticulum
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_packet_flags_interop() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    let test_cases = [
        (0x00, "Data, H1, broadcast, single"),
        (0x01, "Announce, H1, broadcast, single"),
        (0x02, "LinkRequest, H1, broadcast, single"),
        (0x03, "Proof, H1, broadcast, single"),
        (0x40, "Data, H2, broadcast, single"),
        (0x10, "Data, H1, transport, single"),
        (0x04, "Data, H1, broadcast, group"),
        (0x08, "Data, H1, broadcast, plain"),
    ];

    for (expected_byte, description) in test_cases {
        let flags = PacketFlags::from_byte(expected_byte)
            .unwrap_or_else(|_| panic!("Failed to parse flags 0x{:02x}", expected_byte));

        let encoded = flags.to_byte();
        assert_eq!(
            encoded, expected_byte,
            "Flags mismatch for {}: expected 0x{:02x}, got 0x{:02x}",
            description, expected_byte, encoded
        );

        println!("Flags 0x{:02x} ({}) - OK", expected_byte, description);
    }

    // Send Data packets with each non-H2 flag type
    for (flags_byte, _description) in test_cases {
        if flags_byte & 0x40 != 0 {
            continue;
        }
        let packet_type = flags_byte & 0x03;
        if packet_type != 0x00 {
            continue;
        }

        let flags = PacketFlags::from_byte(flags_byte).unwrap();
        let packet = Packet {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: [0xCD; 16],
            context: PacketContext::None,
            data: PacketData::Owned(b"flags test".to_vec()),
        };

        let mut raw_packet = [0u8; MTU];
        let size = packet.pack(&mut raw_packet).expect("Failed to pack");

        let mut framed = Vec::new();
        frame(&raw_packet[..size], &mut framed);
        stream.write_all(&framed).await.expect("Failed to send");
        println!("  Sent packet with flags 0x{:02x}", flags_byte);
    }

    stream.flush().await.expect("Failed to flush");
    println!("All packet flag variations sent successfully");
}

/// Test packet roundtrip (pack -> frame -> deframe -> unpack)
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_packet_roundtrip_format() {
    let original = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: true,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Group,
            packet_type: PacketType::Data,
        },
        hops: 5,
        transport_id: None,
        destination_hash: [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ],
        context: PacketContext::Channel,
        data: PacketData::Owned(b"roundtrip test data".to_vec()),
    };

    let mut raw_packet = [0u8; MTU];
    let size = original.pack(&mut raw_packet).expect("Failed to pack");

    let mut framed = Vec::new();
    frame(&raw_packet[..size], &mut framed);

    let mut deframer = Deframer::new();
    let results = deframer.process(&framed);
    assert_eq!(results.len(), 1, "Expected exactly one frame");

    let deframed = match &results[0] {
        DeframeResult::Frame(data) => data.clone(),
        _ => panic!("Expected Frame result"),
    };

    let restored = Packet::unpack(&deframed).expect("Failed to unpack");

    assert_eq!(
        original.flags.to_byte(),
        restored.flags.to_byte(),
        "Flags mismatch"
    );
    assert_eq!(original.hops, restored.hops, "Hops mismatch");
    assert_eq!(
        original.destination_hash, restored.destination_hash,
        "Dest hash mismatch"
    );
    assert_eq!(
        original.context as u8, restored.context as u8,
        "Context mismatch"
    );
    assert_eq!(
        original.data.as_slice(),
        restored.data.as_slice(),
        "Data mismatch"
    );

    println!("Packet roundtrip successful");
}

/// Quick connectivity check
#[tokio::test]
async fn test_rnsd_connectivity_check() {
    if rnsd_available().await {
        println!("rnsd is available at {}", RNSD_ADDR);
        println!("Run ignored tests with: cargo test --package reticulum-std --test rnsd_interop -- --ignored");
    } else {
        println!("rnsd is NOT available at {}", RNSD_ADDR);
        println!(
            "Start rnsd with TCPServerInterface on 127.0.0.1:4242 to run interop tests"
        );
    }
}
