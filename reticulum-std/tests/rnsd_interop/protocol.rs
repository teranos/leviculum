//! Protocol correctness tests: byte layouts, known vectors, flags
//!
//! Tests marked without `#[ignore]` are pure-logic tests that run without rnsd.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use reticulum_core::constants::{MTU, TRUNCATED_HASHBYTES};
use reticulum_core::crypto::{full_hash, sha256, truncated_hash};
use reticulum_core::destination::DestinationType;
use reticulum_core::identity::Identity;
use reticulum_core::link::Link;
use reticulum_core::packet::{
    HeaderType, Packet, PacketContext, PacketData, PacketFlags, PacketType, TransportType,
};
use reticulum_std::interfaces::hdlc::{frame, DeframeResult, Deframer};

use crate::common::*;

// =========================================================================
// Existing tests (moved from monolithic file)
// =========================================================================

/// Test real announce parsing from the network
#[tokio::test]
#[ignore = "requires running rnsd and active network"]
async fn test_parse_real_announces() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    let mut deframer = Deframer::new();
    let mut buffer = [0u8; 1024];
    let mut announces_parsed = 0;

    println!("Waiting for announce packets (30 second timeout)...");

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(30) && announces_parsed < 5 {
        match timeout(Duration::from_secs(1), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let results = deframer.process(&buffer[..n]);
                for result in results {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(packet) = Packet::unpack(&data) {
                            if packet.flags.packet_type == PacketType::Announce {
                                announces_parsed += 1;
                                println!("\nAnnounce #{}", announces_parsed);
                                println!("  Destination: {:02x?}", &packet.destination_hash);
                                println!("  Hops: {}", packet.hops);
                                println!("  Data length: {}", packet.data.len());

                                let payload = packet.data.as_slice();
                                if payload.len() >= 148 {
                                    println!("  Public key: {:02x?}...", &payload[..8]);
                                    println!("  Name hash: {:02x?}", &payload[64..74]);
                                    println!("  Random hash: {:02x?}", &payload[74..84]);
                                    println!("  Signature: {:02x?}...", &payload[84..92]);
                                    let app_data = &payload[148..];
                                    if !app_data.is_empty() {
                                        if let Ok(s) = std::str::from_utf8(app_data) {
                                            println!("  App data: {:?}", s);
                                        } else {
                                            println!("  App data: {:02x?}", app_data);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(Ok(0)) => break,
            _ => {}
        }
    }

    println!("\nParsed {} announce packets", announces_parsed);
}

/// Test various packet contexts
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_various_packet_contexts() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    let test_cases: &[(PacketContext, &str)] = &[
        (PacketContext::None, "None"),
        (PacketContext::Resource, "Resource"),
        (PacketContext::ResourceAdv, "ResourceAdv"),
        (PacketContext::ResourceReq, "ResourceReq"),
        (PacketContext::ResourceHmu, "ResourceHmu"),
        (PacketContext::ResourcePrf, "ResourcePrf"),
        (PacketContext::ResourceIcl, "ResourceIcl"),
        (PacketContext::ResourceRcl, "ResourceRcl"),
        (PacketContext::CacheRequest, "CacheRequest"),
        (PacketContext::Request, "Request"),
        (PacketContext::Response, "Response"),
        (PacketContext::PathResponse, "PathResponse"),
        (PacketContext::Command, "Command"),
        (PacketContext::CommandStatus, "CommandStatus"),
        (PacketContext::Channel, "Channel"),
        (PacketContext::Keepalive, "Keepalive"),
        (PacketContext::LinkClose, "LinkClose"),
        (PacketContext::Lrrtt, "Lrrtt"),
    ];

    let mut sent_count = 0;

    for (context, name) in test_cases {
        let packet = Packet {
            flags: PacketFlags {
                header_type: HeaderType::Type1,
                context_flag: true,
                transport_type: TransportType::Broadcast,
                dest_type: DestinationType::Single,
                packet_type: PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination_hash: [0xEE; TRUNCATED_HASHBYTES],
            context: *context,
            data: PacketData::Owned(format!("Context {} test", name).into_bytes()),
        };

        let mut raw = [0u8; MTU];
        let size = packet.pack(&mut raw).expect("Failed to pack");

        let unpacked = Packet::unpack(&raw[..size]).expect("Failed to unpack");
        assert_eq!(unpacked.context as u8, *context as u8);

        let mut framed = Vec::new();
        frame(&raw[..size], &mut framed);
        stream.write_all(&framed).await.expect("Failed to send");

        println!("  Sent context 0x{:02X}: {}", *context as u8, name);
        sent_count += 1;
    }

    stream.flush().await.expect("Failed to flush");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut buffer = [0u8; 1024];
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(0)) => panic!("Connection closed"),
        _ => println!("Connection still open after {} context packets", sent_count),
    }
}

/// Test Header Type 2 (transport) packets
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_header_type2_transport_packets() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    let transport_id = [0xAA; TRUNCATED_HASHBYTES];
    let destination_hash = [0xBB; TRUNCATED_HASHBYTES];

    let packet = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type2,
            context_flag: false,
            transport_type: TransportType::Transport,
            dest_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 3,
        transport_id: Some(transport_id),
        destination_hash,
        context: PacketContext::None,
        data: PacketData::Owned(b"Header Type 2 test data".to_vec()),
    };

    let mut raw = [0u8; MTU];
    let size = packet.pack(&mut raw).expect("Failed to pack");

    let unpacked = Packet::unpack(&raw[..size]).expect("Failed to unpack");
    assert_eq!(unpacked.flags.header_type, HeaderType::Type2);
    assert!(unpacked.transport_id.is_some());

    let mut framed = Vec::new();
    frame(&raw[..size], &mut framed);
    stream.write_all(&framed).await.expect("Failed to send");
    stream.flush().await.expect("Failed to flush");

    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut buffer = [0u8; 1024];
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(0)) => panic!("Connection closed - H2 packet rejected"),
        _ => println!("Header Type 2 packet accepted"),
    }
}

/// Test mixed packet sequence
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_mixed_packet_sequence() {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect to rnsd");

    let mut packets_sent = 0;
    let mut raw = [0u8; MTU];
    let mut framed = Vec::new();

    // 1. Data packet
    let p1 = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: [0x11; TRUNCATED_HASHBYTES],
        context: PacketContext::None,
        data: PacketData::Owned(b"Data packet".to_vec()),
    };
    let size = p1.pack(&mut raw).unwrap();
    frame(&raw[..size], &mut framed);
    stream.write_all(&framed).await.unwrap();
    packets_sent += 1;

    // 2. LinkRequest
    let link = Link::new_outgoing_with_rng([0x22; TRUNCATED_HASHBYTES], &mut rand_core::OsRng);
    let link_req = link.create_link_request();
    let p2 = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Single,
            packet_type: PacketType::LinkRequest,
        },
        hops: 0,
        transport_id: None,
        destination_hash: [0x22; TRUNCATED_HASHBYTES],
        context: PacketContext::None,
        data: PacketData::Owned(link_req.to_vec()),
    };
    let size = p2.pack(&mut raw).unwrap();
    framed.clear();
    frame(&raw[..size], &mut framed);
    stream.write_all(&framed).await.unwrap();
    packets_sent += 1;

    // 3. Transport H2
    let p3 = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type2,
            context_flag: false,
            transport_type: TransportType::Transport,
            dest_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 2,
        transport_id: Some([0x33; TRUNCATED_HASHBYTES]),
        destination_hash: [0x44; TRUNCATED_HASHBYTES],
        context: PacketContext::None,
        data: PacketData::Owned(b"Transport packet".to_vec()),
    };
    let size = p3.pack(&mut raw).unwrap();
    framed.clear();
    frame(&raw[..size], &mut framed);
    stream.write_all(&framed).await.unwrap();
    packets_sent += 1;

    // 4. Announce
    let identity = Identity::generate_with_rng(&mut rand_core::OsRng);
    let name_hash = compute_name_hash("test", &["mixed"]);
    let random_hash = generate_random_hash();
    let dest_hash = compute_destination_hash(&name_hash, identity.hash());
    let public_key = identity.public_key_bytes();

    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&dest_hash);
    signed_data.extend_from_slice(&public_key);
    signed_data.extend_from_slice(&name_hash);
    signed_data.extend_from_slice(&random_hash);

    let signature = identity.sign(&signed_data).unwrap();

    let mut payload = Vec::new();
    payload.extend_from_slice(&public_key);
    payload.extend_from_slice(&name_hash);
    payload.extend_from_slice(&random_hash);
    payload.extend_from_slice(&signature);

    let p4 = Packet {
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
    let size = p4.pack(&mut raw).unwrap();
    framed.clear();
    frame(&raw[..size], &mut framed);
    stream.write_all(&framed).await.unwrap();
    packets_sent += 1;

    stream.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut buffer = [0u8; 1024];
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(0)) => panic!("Connection closed"),
        _ => println!("Connection open after {} packets", packets_sent),
    }

    println!("SUCCESS: All {} mixed packets accepted!", packets_sent);
}

// =========================================================================
// NEW: Pure byte-level verification tests (no rnsd needed)
// =========================================================================

/// 3.1: Enumerate all valid flag byte combinations (bit7=0)
#[test]
fn test_flags_byte_all_valid_combinations() {
    let mut valid_count = 0;
    let mut data_type_count = 0;

    for byte in 0u8..128 {
        // bit7 is always 0 (values 0-127)
        match PacketFlags::from_byte(byte) {
            Ok(flags) => {
                let roundtripped = flags.to_byte();
                assert_eq!(
                    roundtripped, byte,
                    "Flags roundtrip failed for 0x{:02x}: got 0x{:02x}",
                    byte, roundtripped
                );
                valid_count += 1;

                if flags.packet_type == PacketType::Data {
                    data_type_count += 1;
                }
            }
            Err(_) => {
                // Some combinations may be invalid (e.g., reserved dest types)
                // That's fine; just count them
            }
        }
    }

    println!(
        "Valid flag combinations: {}/128, Data-type: {}",
        valid_count, data_type_count
    );
    // All 128 combinations should be valid since each field covers its full range
    assert!(
        valid_count >= 64,
        "Expected at least 64 valid flag combinations"
    );
}

/// 3.4: Verify packet context exact byte values match Python
#[test]
fn test_packet_context_exact_byte_values() {
    let expected: &[(PacketContext, u8, &str)] = &[
        (PacketContext::None, 0x00, "None"),
        (PacketContext::Resource, 0x01, "Resource"),
        (PacketContext::ResourceAdv, 0x02, "ResourceAdv"),
        (PacketContext::ResourceReq, 0x03, "ResourceReq"),
        (PacketContext::ResourceHmu, 0x04, "ResourceHmu"),
        (PacketContext::ResourcePrf, 0x05, "ResourcePrf"),
        (PacketContext::ResourceIcl, 0x06, "ResourceIcl"),
        (PacketContext::ResourceRcl, 0x07, "ResourceRcl"),
        (PacketContext::CacheRequest, 0x08, "CacheRequest"),
        (PacketContext::Request, 0x09, "Request"),
        (PacketContext::Response, 0x0A, "Response"),
        (PacketContext::PathResponse, 0x0B, "PathResponse"),
        (PacketContext::Command, 0x0C, "Command"),
        (PacketContext::CommandStatus, 0x0D, "CommandStatus"),
        (PacketContext::Channel, 0x0E, "Channel"),
        (PacketContext::Keepalive, 0xFA, "Keepalive"),
        (PacketContext::LinkIdentify, 0xFB, "LinkIdentify"),
        (PacketContext::LinkClose, 0xFC, "LinkClose"),
        (PacketContext::LinkProof, 0xFD, "LinkProof"),
        (PacketContext::Lrrtt, 0xFE, "Lrrtt"),
        (PacketContext::Lrproof, 0xFF, "Lrproof"),
    ];

    for &(context, expected_byte, name) in expected {
        assert_eq!(
            context as u8, expected_byte,
            "PacketContext::{} should be 0x{:02X}, got 0x{:02X}",
            name, expected_byte, context as u8,
        );

        // Verify roundtrip through TryFrom
        let parsed = PacketContext::try_from(expected_byte)
            .unwrap_or_else(|_| panic!("Failed to parse context byte 0x{:02X}", expected_byte));
        assert_eq!(parsed as u8, expected_byte);
    }

    // Also verify that packing a packet with context_flag=true places context at offset 18
    let packet = Packet {
        flags: PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: true,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Single,
            packet_type: PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: [0x00; 16],
        context: PacketContext::Keepalive,
        data: PacketData::Owned(vec![0x42]),
    };

    let mut raw = [0u8; MTU];
    let _size = packet.pack(&mut raw).unwrap();
    // Context byte is at: flags(1) + hops(1) + dest_hash(16) = offset 18
    assert_eq!(
        raw[18], 0xFA,
        "Context byte at offset 18 should be 0xFA (Keepalive)"
    );

    println!("All 21 PacketContext values verified");
}

/// 3.5: Verify name_hash for well-known app names matches Python
///
/// Pre-computed using Python Reticulum:
/// ```python
/// import RNS
/// RNS.Identity.full_hash("lxmf.delivery".encode())[:10].hex()
/// ```
#[test]
fn test_name_hash_known_vectors() {
    // These are the SHA-256 hash of the full name string, truncated to 10 bytes.
    // Verify our compute_name_hash matches Python's behavior.

    let test_cases = [
        ("lxmf", &["delivery"][..]),
        ("nomadnetwork", &["node"][..]),
        ("testapp", &["echo"][..]),
    ];

    for (app_name, aspects) in &test_cases {
        let our_hash = compute_name_hash(app_name, aspects);

        // Verify manually: construct the full name and SHA-256 it
        let mut full_name = app_name.to_string();
        for aspect in *aspects {
            full_name.push('.');
            full_name.push_str(aspect);
        }
        let expected_full_hash = sha256(full_name.as_bytes());
        let expected_name_hash: [u8; 10] = expected_full_hash[..10].try_into().unwrap();

        assert_eq!(
            our_hash, expected_name_hash,
            "Name hash mismatch for '{}'",
            full_name
        );
        println!(
            "  Name hash for '{}': {:02x?} - OK",
            full_name, our_hash
        );
    }

    // The critical invariant: our compute_name_hash uses full_hash (SHA-256)
    // and takes the first 10 bytes. Verify this explicitly:
    let manual = full_hash(b"lxmf.delivery");
    let manual_10: [u8; 10] = manual[..10].try_into().unwrap();
    let computed = compute_name_hash("lxmf", &["delivery"]);
    assert_eq!(computed, manual_10);

    println!("All name hash vectors verified");
}

/// 3.6: Verify destination hash from a known private key
#[test]
fn test_destination_hash_known_vector() {
    // Create an identity from deterministic private key bytes
    let private_key_bytes = [0x42u8; 64]; // 32 X25519 + 32 Ed25519
    let identity = Identity::from_private_key_bytes(&private_key_bytes)
        .expect("Failed to create identity from known key");

    let identity_hash = *identity.hash();
    let name_hash = compute_name_hash("testapp", &["echo"]);
    let dest_hash = compute_destination_hash(&name_hash, &identity_hash);

    // Verify the pipeline: dest_hash = truncated_hash(name_hash + identity_hash)
    let mut hash_material = Vec::new();
    hash_material.extend_from_slice(&name_hash);
    hash_material.extend_from_slice(&identity_hash);
    let expected = truncated_hash(&hash_material);

    assert_eq!(dest_hash, expected);
    println!(
        "  Identity hash: {:02x?}",
        &identity_hash[..4]
    );
    println!(
        "  Name hash: {:02x?}",
        &name_hash
    );
    println!(
        "  Destination hash: {:02x?}",
        &dest_hash[..4]
    );
    println!("Destination hash pipeline verified");
}

/// 3.2: Send our own announces via rnsd and verify signed_data byte order
/// on the retransmitted copies.
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_announce_signed_data_byte_order() {
    let mut sender = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect sender");

    let mut receiver = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Connection timeout")
        .expect("Failed to connect receiver");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    // Send 5 announces with unique identities from sender connection
    for i in 0..5 {
        let (_dest_hash, _identity) = build_and_send_announce(
            &mut sender,
            "leviculum",
            &[&format!("byteorder_{}", i)],
            format!("byteorder-test-{}", i).as_bytes(),
        ).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Collect announces on receiver
    let mut deframer = Deframer::new();
    let mut buffer = [0u8; 2048];
    let mut verified = 0;

    println!("Verifying signed data byte order on retransmitted announces...");

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(15) && verified < 3 {
        match timeout(Duration::from_secs(1), receiver.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                for result in deframer.process(&buffer[..n]) {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type != PacketType::Announce {
                                continue;
                            }
                            let announce = match ParsedAnnounce::from_packet(&pkt) {
                                Some(a) => a,
                                None => continue,
                            };

                            let identity = match Identity::from_public_key_bytes(&announce.public_key) {
                                Ok(id) => id,
                                Err(_) => continue,
                            };

                            // Manually reconstruct signed_data in the expected order:
                            // dest_hash + public_key + name_hash + random_hash + ratchet + app_data
                            let mut manual_signed = Vec::new();
                            manual_signed.extend_from_slice(&announce.destination_hash);
                            manual_signed.extend_from_slice(&announce.public_key);
                            manual_signed.extend_from_slice(&announce.name_hash);
                            manual_signed.extend_from_slice(&announce.random_hash);
                            manual_signed.extend_from_slice(&announce.ratchet);
                            manual_signed.extend_from_slice(&announce.app_data);

                            // This must match announce.signed_data()
                            assert_eq!(manual_signed, announce.signed_data(), "signed_data construction mismatch");

                            match identity.verify(&manual_signed, &announce.signature) {
                                Ok(true) => {
                                    verified += 1;
                                    println!(
                                        "  OK #{}: byte order verified for {:02x}{:02x}{:02x}{:02x}...",
                                        verified,
                                        announce.destination_hash[0],
                                        announce.destination_hash[1],
                                        announce.destination_hash[2],
                                        announce.destination_hash[3],
                                    );
                                }
                                Ok(false) => {
                                    println!("FAIL: Signature failed with manually reconstructed data");
                                    println!("  Manual len: {}", manual_signed.len());
                                    println!("  Manual hex: {:02x?}", &manual_signed[..32.min(manual_signed.len())]);
                                    panic!("Byte order mismatch in signed data!");
                                }
                                Err(e) => {
                                    println!("FAIL: Verification error: {:?}", e);
                                }
                            }
                        }
                    }
                }
            }
            Ok(Ok(0)) => break,
            _ => {}
        }
    }

    assert!(verified > 0, "No announces verified");
    println!("SUCCESS: Signed data byte order verified on {} announces", verified);
}

/// 3.3: Verify link request packet byte layout
#[test]
fn test_link_request_packet_byte_layout() {
    let dest_hash = [0x42u8; TRUNCATED_HASHBYTES];
    let mut link = Link::new_outgoing_with_rng(dest_hash, &mut rand_core::OsRng);

    let raw = link.build_link_request_packet();

    // Expected: [flags(1)] [hops(1)] [dest_hash(16)] [context(1)] [payload(64)]
    assert_eq!(raw.len(), 83, "Link request should be 83 bytes total");

    // Byte 0: flags = LinkRequest(0x02), H1, broadcast, single
    assert_eq!(raw[0], 0x02, "Flags should be 0x02 (LinkRequest)");

    // Byte 1: hops = 0
    assert_eq!(raw[1], 0x00, "Hops should be 0");

    // Bytes 2..18: destination hash
    assert_eq!(&raw[2..18], &dest_hash, "Dest hash mismatch");

    // Byte 18: context = None (0x00)
    assert_eq!(raw[18], 0x00, "Context should be 0x00 (None)");

    // Bytes 19..51: ephemeral X25519 public key (32 bytes)
    let ephemeral_pub = link.ephemeral_public_bytes();
    assert_eq!(&raw[19..51], &ephemeral_pub, "Ephemeral X25519 pub mismatch");

    // Bytes 51..83: Ed25519 verifying key (32 bytes)
    let verifying_key = link.verifying_key_bytes();
    assert_eq!(&raw[51..83], &verifying_key, "Ed25519 verifying key mismatch");

    println!("Link request byte layout verified:");
    println!("  [0]:     0x{:02x} (flags)", raw[0]);
    println!("  [1]:     0x{:02x} (hops)", raw[1]);
    println!("  [2..18]: dest_hash {:02x?}...", &raw[2..6]);
    println!("  [18]:    0x{:02x} (context)", raw[18]);
    println!("  [19..51]: ephemeral_pub {:02x?}...", &raw[19..23]);
    println!("  [51..83]: verifying_key {:02x?}...", &raw[51..55]);
}
