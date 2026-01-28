//! Cryptographic verification of real network announces

use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use reticulum_core::identity::Identity;
use reticulum_core::packet::{Packet, PacketType};
use reticulum_std::interfaces::hdlc::{DeframeResult, Deframer};

use crate::common::*;

/// Helper: send our own announce on conn1, collect announces on conn2 (including ours + network)
async fn send_and_collect_announces(
    target_count: usize,
    timeout_secs: u64,
) -> Vec<(Packet, ParsedAnnounce)> {
    let mut conn1 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("conn1");
    let mut conn2 = timeout(CONNECTION_TIMEOUT, TcpStream::connect(RNSD_ADDR))
        .await
        .expect("Timeout")
        .expect("conn2");

    tokio::time::sleep(INTERFACE_SETTLE_TIME).await;

    // Send our own announce so we're guaranteed at least one
    let (_dest_hash, _identity) = build_and_send_announce(
        &mut conn1,
        "leviculum",
        &["crypto", "verify"],
        b"crypto-verify-test",
    )
    .await;

    let mut deframer = Deframer::new();
    let mut buffer = [0u8; 2048];
    let mut collected = Vec::new();
    let start = std::time::Instant::now();

    while start.elapsed() < Duration::from_secs(timeout_secs) && collected.len() < target_count {
        match timeout(Duration::from_secs(1), conn2.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                for result in deframer.process(&buffer[..n]) {
                    if let DeframeResult::Frame(data) = result {
                        if let Ok(pkt) = Packet::unpack(&data) {
                            if pkt.flags.packet_type == PacketType::Announce {
                                if let Some(announce) = ParsedAnnounce::from_packet(&pkt) {
                                    collected.push((pkt, announce));
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

    collected
}

/// Verify announce signatures (our own + any network announces)
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_verify_real_announce_signatures() {
    let announces = send_and_collect_announces(10, 15).await;

    println!("Collected {} announces for signature verification", announces.len());
    assert!(!announces.is_empty(), "Should receive at least our own announce");

    let mut verified = 0;
    let mut failed = 0;

    for (_pkt, announce) in &announces {
        let identity = match Identity::from_public_key_bytes(&announce.public_key) {
            Ok(id) => id,
            Err(e) => {
                println!("FAIL: Could not create identity: {:?}", e);
                failed += 1;
                continue;
            }
        };

        let signed_data = announce.signed_data();
        match identity.verify(&signed_data, &announce.signature) {
            Ok(true) => {
                verified += 1;
                let ratchet_str = if announce.has_ratchet { " [ratcheted]" } else { "" };
                println!(
                    "  OK #{}: {:02x}{:02x}{:02x}{:02x}...{}",
                    verified,
                    announce.destination_hash[0],
                    announce.destination_hash[1],
                    announce.destination_hash[2],
                    announce.destination_hash[3],
                    ratchet_str,
                );
            }
            Ok(false) => {
                failed += 1;
                println!(
                    "  FAIL: Signature verification FAILED for {:02x?}",
                    &announce.destination_hash[..4]
                );
            }
            Err(e) => {
                failed += 1;
                println!("  FAIL: Verification error: {:?}", e);
            }
        }
    }

    println!("Verified: {}, Failed: {}", verified, failed);
    assert!(verified > 0, "Should verify at least 1 announce");
    assert_eq!(failed, 0, "No signature verifications should fail");
}

/// Verify destination hash calculation
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_verify_destination_hash_calculation() {
    let announces = send_and_collect_announces(10, 15).await;

    println!("Collected {} announces for dest hash verification", announces.len());
    assert!(!announces.is_empty(), "Should receive at least our own announce");

    let mut verified = 0;
    let mut failed = 0;

    for (_pkt, announce) in &announces {
        let computed = announce.computed_destination_hash();
        if computed == announce.destination_hash {
            verified += 1;
            println!(
                "  OK #{}: {:02x}{:02x}{:02x}{:02x}...",
                verified,
                announce.destination_hash[0],
                announce.destination_hash[1],
                announce.destination_hash[2],
                announce.destination_hash[3],
            );
        } else {
            failed += 1;
            println!("  FAIL: Destination hash mismatch!");
            println!("    Packet:   {:02x?}", announce.destination_hash);
            println!("    Computed: {:02x?}", computed);
        }
    }

    assert!(verified > 0, "Should verify at least 1 dest hash");
    assert_eq!(failed, 0, "No dest hash verifications should fail");
}

/// Verify identity hash from public key
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_verify_identity_hash_calculation() {
    let announces = send_and_collect_announces(10, 15).await;

    println!("Collected {} announces for identity hash verification", announces.len());
    assert!(!announces.is_empty(), "Should receive at least our own announce");

    let mut verified = 0;
    let mut failed = 0;

    for (_pkt, announce) in &announces {
        let identity = match Identity::from_public_key_bytes(&announce.public_key) {
            Ok(id) => id,
            Err(_) => {
                failed += 1;
                continue;
            }
        };

        let from_struct = identity.hash();
        let computed = announce.computed_identity_hash();

        if from_struct == &computed {
            verified += 1;
            println!(
                "  OK #{}: {:02x}{:02x}{:02x}{:02x}...",
                verified, computed[0], computed[1], computed[2], computed[3],
            );
        } else {
            failed += 1;
            println!("  FAIL: Identity hash mismatch!");
        }
    }

    assert!(verified > 0, "Should verify at least 1 identity hash");
    assert_eq!(failed, 0, "No identity hash verifications should fail");
}

/// Full cryptographic verification (all 3 checks combined)
#[tokio::test]
#[ignore = "requires running rnsd"]
async fn test_full_announce_crypto_verification() {
    let announces = send_and_collect_announces(10, 15).await;

    println!("=== FULL CRYPTOGRAPHIC VERIFICATION ===");
    println!("Collected {} announces\n", announces.len());
    assert!(!announces.is_empty(), "Should receive at least our own announce");

    let mut fully_verified = 0;
    let mut failures = 0;

    for (_pkt, announce) in &announces {
        let identity = match Identity::from_public_key_bytes(&announce.public_key) {
            Ok(id) => id,
            Err(_) => continue,
        };

        let signed_data = announce.signed_data();
        let sig_ok = identity
            .verify(&signed_data, &announce.signature)
            .unwrap_or(false);
        let dest_ok = announce.computed_destination_hash() == announce.destination_hash;
        let id_ok = identity.hash() == &announce.computed_identity_hash();

        if sig_ok && dest_ok && id_ok {
            fully_verified += 1;
            println!(
                "  OK #{}: {:02x}{:02x}{:02x}{:02x}...",
                fully_verified,
                announce.destination_hash[0],
                announce.destination_hash[1],
                announce.destination_hash[2],
                announce.destination_hash[3],
            );
        } else {
            failures += 1;
            if !sig_ok {
                println!("  FAIL: Signature");
            }
            if !dest_ok {
                println!("  FAIL: Dest hash");
            }
            if !id_ok {
                println!("  FAIL: Identity hash");
            }
        }
    }

    assert!(fully_verified > 0, "Should fully verify at least 1 announce");
    assert_eq!(failures, 0, "No verification failures");
    println!(
        "\nSUCCESS: {} announces passed full crypto verification",
        fully_verified
    );
}
