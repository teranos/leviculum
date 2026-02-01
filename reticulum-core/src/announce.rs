//! Announce message handling
//!
//! Announces are broadcast messages that inform the network about a destination.
//! They contain the destination's public key, name hash, and signature.
//!
//! # Announce Format (without ratchet)
//!
//! | Offset | Size | Field          |
//! |--------|------|----------------|
//! | 0      | 64   | public_key     | (32 bytes X25519 + 32 bytes Ed25519)
//! | 64     | 10   | name_hash      |
//! | 74     | 10   | random_hash    |
//! | 84     | 64   | signature      |
//! | 148    | var  | app_data       | (optional)
//!
//! # Announce Format (with ratchet)
//!
//! | Offset | Size | Field          |
//! |--------|------|----------------|
//! | 0      | 64   | public_key     |
//! | 64     | 10   | name_hash      |
//! | 74     | 10   | random_hash    |
//! | 84     | 32   | ratchet        |
//! | 116    | 64   | signature      |
//! | 180    | var  | app_data       | (optional)
//!
//! The signature covers: destination_hash + public_key + name_hash + random_hash + [ratchet] + app_data

use crate::constants::{
    slice_to_array, ED25519_SIGNATURE_SIZE, IDENTITY_KEY_SIZE, NAME_HASHBYTES, RANDOM_HASHBYTES,
    RANDOM_HASH_RANDOM_SIZE, RANDOM_HASH_TIMESTAMP_OFFSET, RANDOM_HASH_TIMESTAMP_SIZE,
    RATCHET_SIZE, TRUNCATED_HASHBYTES,
};

// ─── Announce Format Offsets ─────────────────────────────────────────────────
// These define the byte layout of announce payloads.

/// Offset of public key in announce payload
const OFFSET_PUBLIC_KEY: usize = 0;
/// Offset of name hash in announce payload
const OFFSET_NAME_HASH: usize = IDENTITY_KEY_SIZE; // 64
/// Offset of random hash in announce payload
const OFFSET_RANDOM_HASH: usize = OFFSET_NAME_HASH + NAME_HASHBYTES; // 74
/// Offset of ratchet in ratcheted announces (or signature in non-ratcheted)
const OFFSET_RATCHET_OR_SIG: usize = OFFSET_RANDOM_HASH + RANDOM_HASHBYTES; // 84
/// Offset of signature in ratcheted announces
const OFFSET_SIG_RATCHETED: usize = OFFSET_RATCHET_OR_SIG + RATCHET_SIZE; // 116
/// Offset of app_data in non-ratcheted announces
const OFFSET_APP_DATA: usize = OFFSET_RATCHET_OR_SIG + ED25519_SIGNATURE_SIZE; // 148
/// Offset of app_data in ratcheted announces
const OFFSET_APP_DATA_RATCHETED: usize = OFFSET_SIG_RATCHETED + ED25519_SIGNATURE_SIZE; // 180
use crate::crypto::truncated_hash;
use crate::identity::{Identity, IdentityError};
use crate::packet::{Packet, PacketType};
use crate::traits::{Clock, Context};

use alloc::vec::Vec;
use rand_core::RngCore;

/// Build the signed data for announce signature creation and verification.
///
/// The signature covers: `destination_hash + public_key + name_hash + random_hash + [ratchet] + app_data`
///
/// This is used both when creating announces (in `build_announce_payload`) and
/// when verifying them (in `ReceivedAnnounce::verify_signature`).
fn build_signed_data(
    destination_hash: &[u8; TRUNCATED_HASHBYTES],
    public_key: &[u8; IDENTITY_KEY_SIZE],
    name_hash: &[u8; NAME_HASHBYTES],
    random_hash: &[u8; RANDOM_HASHBYTES],
    ratchet: Option<&[u8; RATCHET_SIZE]>,
    app_data: &[u8],
) -> Vec<u8> {
    let ratchet_len = if ratchet.is_some() { RATCHET_SIZE } else { 0 };
    let mut data = Vec::with_capacity(
        TRUNCATED_HASHBYTES
            + IDENTITY_KEY_SIZE
            + NAME_HASHBYTES
            + RANDOM_HASHBYTES
            + ratchet_len
            + app_data.len(),
    );
    data.extend_from_slice(destination_hash);
    data.extend_from_slice(public_key);
    data.extend_from_slice(name_hash);
    data.extend_from_slice(random_hash);
    if let Some(r) = ratchet {
        data.extend_from_slice(r);
    }
    data.extend_from_slice(app_data);
    data
}

/// Minimum announce payload size (without ratchet, without app_data)
/// public_key(64) + name_hash(10) + random_hash(10) + signature(64) = 148
pub const ANNOUNCE_MIN_SIZE: usize =
    IDENTITY_KEY_SIZE + NAME_HASHBYTES + RANDOM_HASHBYTES + ED25519_SIGNATURE_SIZE;

/// Minimum announce payload size with ratchet (without app_data)
/// public_key(64) + name_hash(10) + random_hash(10) + ratchet(32) + signature(64) = 180
pub const ANNOUNCE_RATCHETED_MIN_SIZE: usize = ANNOUNCE_MIN_SIZE + RATCHET_SIZE;

/// Generate a random hash for announces (5 random + 5 timestamp bytes).
///
/// The random hash ensures announce uniqueness even for the same destination.
/// Format: 5 bytes from truncated_hash(random_16) + 5 bytes from timestamp_ms.
pub fn generate_random_hash(ctx: &mut impl Context) -> [u8; RANDOM_HASHBYTES] {
    let mut random_16 = [0u8; 16];
    ctx.rng().fill_bytes(&mut random_16);
    let random_part = truncated_hash(&random_16);

    let timestamp_ms = ctx.clock().now_ms();
    let timestamp_bytes = timestamp_ms.to_be_bytes();

    let mut result = [0u8; RANDOM_HASHBYTES]; // 10 bytes
    result[..RANDOM_HASH_RANDOM_SIZE].copy_from_slice(&random_part[..RANDOM_HASH_RANDOM_SIZE]);
    let ts_end = RANDOM_HASH_TIMESTAMP_OFFSET + RANDOM_HASH_TIMESTAMP_SIZE;
    result[RANDOM_HASH_RANDOM_SIZE..]
        .copy_from_slice(&timestamp_bytes[RANDOM_HASH_TIMESTAMP_OFFSET..ts_end]);
    result
}

/// Build an announce payload (internal helper for Destination::announce).
///
/// # Payload format (without ratchet)
/// `public_key(64) + name_hash(10) + random_hash(10) + signature(64) + app_data`
///
/// # Payload format (with ratchet)
/// `public_key(64) + name_hash(10) + random_hash(10) + ratchet(32) + signature(64) + app_data`
///
/// # Signature
/// The signature covers: `destination_hash + public_key + name_hash + random_hash + [ratchet] + app_data`
pub(crate) fn build_announce_payload(
    identity: &Identity,
    destination_hash: &[u8; TRUNCATED_HASHBYTES],
    name_hash: &[u8; NAME_HASHBYTES],
    ratchet: Option<&[u8; RATCHET_SIZE]>,
    app_data: Option<&[u8]>,
    ctx: &mut impl Context,
) -> Result<Vec<u8>, AnnounceError> {
    let public_key = identity.public_key_bytes();
    let random_hash = generate_random_hash(ctx);
    let app_data_bytes = app_data.unwrap_or(&[]);

    // Build signed data using helper
    let signed_data = build_signed_data(
        destination_hash,
        &public_key,
        name_hash,
        &random_hash,
        ratchet,
        app_data_bytes,
    );

    let signature = identity
        .sign(&signed_data)
        .map_err(|_| AnnounceError::SigningFailed)?;

    // Build payload: public_key + name_hash + random_hash + [ratchet] + signature + app_data
    let payload_size = if ratchet.is_some() {
        ANNOUNCE_RATCHETED_MIN_SIZE + app_data_bytes.len()
    } else {
        ANNOUNCE_MIN_SIZE + app_data_bytes.len()
    };
    let mut payload = Vec::with_capacity(payload_size);
    payload.extend_from_slice(&public_key);
    payload.extend_from_slice(name_hash);
    payload.extend_from_slice(&random_hash);
    if let Some(r) = ratchet {
        payload.extend_from_slice(r);
    }
    payload.extend_from_slice(&signature);
    payload.extend_from_slice(app_data_bytes);

    Ok(payload)
}

/// Error type for announce operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnounceError {
    /// Payload too short
    PayloadTooShort,
    /// Not an announce packet
    NotAnnounce,
    /// Invalid public key
    InvalidPublicKey,
    /// Signature verification failed
    InvalidSignature,
    /// Destination hash mismatch
    HashMismatch,
    /// Failed to sign announce (no private key)
    SigningFailed,
    /// Destination has no identity (PLAIN destination)
    NoIdentity,
    /// OUT destinations cannot announce (only IN)
    WrongDirection,
    /// Only SINGLE destinations can announce
    OnlySingleCanAnnounce,
}

impl core::fmt::Display for AnnounceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AnnounceError::PayloadTooShort => write!(f, "Announce payload too short"),
            AnnounceError::NotAnnounce => write!(f, "Not an announce packet"),
            AnnounceError::InvalidPublicKey => write!(f, "Invalid public key in announce"),
            AnnounceError::InvalidSignature => write!(f, "Signature verification failed"),
            AnnounceError::HashMismatch => write!(f, "Destination hash mismatch"),
            AnnounceError::SigningFailed => write!(f, "Failed to sign announce"),
            AnnounceError::NoIdentity => write!(f, "Destination has no identity"),
            AnnounceError::WrongDirection => write!(f, "OUT destinations cannot announce"),
            AnnounceError::OnlySingleCanAnnounce => {
                write!(f, "Only SINGLE destinations can announce")
            }
        }
    }
}

/// A received announce message parsed from a packet
///
/// This struct holds the parsed components of an announce and provides
/// methods to verify the signature and compute hashes.
pub struct ReceivedAnnounce {
    /// Destination hash from packet header
    destination_hash: [u8; TRUNCATED_HASHBYTES],
    /// Combined public key (32 bytes X25519 + 32 bytes Ed25519)
    public_key: [u8; IDENTITY_KEY_SIZE],
    /// Name hash (truncated hash of app_name.aspects)
    name_hash: [u8; NAME_HASHBYTES],
    /// Random hash (for announce uniqueness)
    random_hash: [u8; RANDOM_HASHBYTES],
    /// Ratchet key (if present)
    ratchet: Option<[u8; RATCHET_SIZE]>,
    /// Ed25519 signature
    signature: [u8; ED25519_SIGNATURE_SIZE],
    /// Application-specific data
    app_data: Vec<u8>,
}

impl ReceivedAnnounce {
    /// Parse an announce from a packet
    ///
    /// Returns an error if the packet is not an announce or the payload is malformed.
    ///
    /// # Ratchet Detection
    ///
    /// The `context_flag` in the packet header indicates whether a ratchet is present.
    /// This is the authoritative indicator per the Reticulum protocol specification.
    pub fn from_packet(packet: &Packet) -> Result<Self, AnnounceError> {
        if packet.flags.packet_type != PacketType::Announce {
            return Err(AnnounceError::NotAnnounce);
        }

        let payload = packet.data.as_slice();

        // Use context_flag as the authoritative indicator for ratchet presence
        let has_ratchet = packet.flags.context_flag;

        // Check minimum size based on announce type
        let min_size = if has_ratchet {
            ANNOUNCE_RATCHETED_MIN_SIZE
        } else {
            ANNOUNCE_MIN_SIZE
        };
        if payload.len() < min_size {
            return Err(AnnounceError::PayloadTooShort);
        }

        // Parse common fields (same offsets for both formats)
        let public_key = slice_to_array(payload, OFFSET_PUBLIC_KEY);
        let name_hash = slice_to_array(payload, OFFSET_NAME_HASH);
        let random_hash = slice_to_array(payload, OFFSET_RANDOM_HASH);

        // Parse ratchet, signature, and app_data based on format
        let (ratchet, signature, app_data_offset) = if has_ratchet {
            (
                Some(slice_to_array(payload, OFFSET_RATCHET_OR_SIG)),
                slice_to_array(payload, OFFSET_SIG_RATCHETED),
                OFFSET_APP_DATA_RATCHETED,
            )
        } else {
            (
                None,
                slice_to_array(payload, OFFSET_RATCHET_OR_SIG),
                OFFSET_APP_DATA,
            )
        };

        Ok(Self {
            destination_hash: packet.destination_hash,
            public_key,
            name_hash,
            random_hash,
            ratchet,
            signature,
            app_data: payload[app_data_offset..].to_vec(),
        })
    }

    /// Get the destination hash from the packet header
    pub fn destination_hash(&self) -> &[u8; TRUNCATED_HASHBYTES] {
        &self.destination_hash
    }

    /// Get the combined public key (X25519 + Ed25519)
    pub fn public_key(&self) -> &[u8; IDENTITY_KEY_SIZE] {
        &self.public_key
    }

    /// Get the name hash
    pub fn name_hash(&self) -> &[u8; NAME_HASHBYTES] {
        &self.name_hash
    }

    /// Get the random hash
    pub fn random_hash(&self) -> &[u8; RANDOM_HASHBYTES] {
        &self.random_hash
    }

    /// Get the ratchet key if present
    pub fn ratchet(&self) -> Option<&[u8; RATCHET_SIZE]> {
        self.ratchet.as_ref()
    }

    /// Check if this is a ratcheted announce
    pub fn has_ratchet(&self) -> bool {
        self.ratchet.is_some()
    }

    /// Get the signature
    pub fn signature(&self) -> &[u8; ED25519_SIGNATURE_SIZE] {
        &self.signature
    }

    /// Get the app_data
    pub fn app_data(&self) -> &[u8] {
        &self.app_data
    }

    /// Get app_data as a string if valid UTF-8
    pub fn app_data_string(&self) -> Option<&str> {
        core::str::from_utf8(&self.app_data).ok()
    }

    /// Compute the identity hash from the public key
    ///
    /// identity_hash = truncated_hash(public_key)
    pub fn computed_identity_hash(&self) -> [u8; TRUNCATED_HASHBYTES] {
        truncated_hash(&self.public_key)
    }

    /// Compute the destination hash from name_hash and identity_hash
    ///
    /// dest_hash = truncated_hash(name_hash + identity_hash)
    pub fn computed_destination_hash(&self) -> [u8; TRUNCATED_HASHBYTES] {
        let identity_hash = self.computed_identity_hash();
        let mut hash_material = [0u8; NAME_HASHBYTES + TRUNCATED_HASHBYTES];
        hash_material[..NAME_HASHBYTES].copy_from_slice(&self.name_hash);
        hash_material[NAME_HASHBYTES..].copy_from_slice(&identity_hash);
        truncated_hash(&hash_material)
    }

    /// Verify that the destination hash in the packet matches the computed hash
    pub fn verify_destination_hash(&self) -> bool {
        self.destination_hash == self.computed_destination_hash()
    }

    /// Compute the signed data for signature verification
    ///
    /// Python RNS signs: destination_hash + public_key + name_hash + random_hash + [ratchet] + app_data
    fn signed_data(&self) -> Vec<u8> {
        build_signed_data(
            &self.destination_hash,
            &self.public_key,
            &self.name_hash,
            &self.random_hash,
            self.ratchet.as_ref(),
            &self.app_data,
        )
    }

    /// Verify the announce signature
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid,
    /// or an error if the public key is malformed.
    pub fn verify_signature(&self) -> Result<bool, IdentityError> {
        let identity = Identity::from_public_key_bytes(&self.public_key)?;
        let signed_data = self.signed_data();
        identity.verify(&signed_data, &self.signature)
    }

    /// Create an Identity from the announce's public key
    ///
    /// This creates a public-only identity that can be used for encryption
    /// and signature verification, but not signing or decryption.
    pub fn to_identity(&self) -> Result<Identity, IdentityError> {
        Identity::from_public_key_bytes(&self.public_key)
    }

    /// Perform full validation of the announce
    ///
    /// This checks:
    /// 1. Destination hash matches computed hash
    /// 2. Signature is valid
    ///
    /// Returns `Ok(())` if valid, or an error describing what failed.
    pub fn validate(&self) -> Result<(), AnnounceError> {
        if !self.verify_destination_hash() {
            return Err(AnnounceError::HashMismatch);
        }

        match self.verify_signature() {
            Ok(true) => Ok(()),
            Ok(false) => Err(AnnounceError::InvalidSignature),
            Err(_) => Err(AnnounceError::InvalidPublicKey),
        }
    }
}

impl core::fmt::Debug for ReceivedAnnounce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReceivedAnnounce")
            .field(
                "destination_hash",
                &format_args!("{:02x?}", &self.destination_hash[..4]),
            )
            .field("has_ratchet", &self.has_ratchet())
            .field("app_data_len", &self.app_data.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::DestinationType;
    use crate::packet::{HeaderType, PacketContext, PacketData, PacketFlags, TransportType};
    use crate::traits::{NoStorage, PlatformContext};
    use alloc::vec;
    use rand_core::OsRng;

    // Mock clock for tests
    struct MockClock(u64);
    impl crate::traits::Clock for MockClock {
        fn now_ms(&self) -> u64 {
            self.0
        }
    }

    fn make_context() -> PlatformContext<OsRng, MockClock, NoStorage> {
        PlatformContext {
            rng: OsRng,
            clock: MockClock(1704067200000), // 2024-01-01 00:00:00 UTC
            storage: NoStorage,
        }
    }

    fn create_test_announce_payload(with_ratchet: bool) -> Vec<u8> {
        let mut payload = Vec::new();

        // Public key (64 bytes) - just test data
        payload.extend_from_slice(&[0x01; IDENTITY_KEY_SIZE]);

        // Name hash (10 bytes)
        payload.extend_from_slice(&[0x02; NAME_HASHBYTES]);

        // Random hash (10 bytes)
        payload.extend_from_slice(&[0x03; RANDOM_HASHBYTES]);

        if with_ratchet {
            // Ratchet (32 bytes)
            payload.extend_from_slice(&[0x04; RATCHET_SIZE]);
        }

        // Signature (64 bytes)
        payload.extend_from_slice(&[0x05; ED25519_SIGNATURE_SIZE]);

        // App data
        payload.extend_from_slice(b"test.app");

        payload
    }

    #[test]
    fn test_parse_announce_without_ratchet() {
        let payload = create_test_announce_payload(false);

        let packet = Packet {
            flags: PacketFlags {
                ifac_flag: false,
                header_type: HeaderType::Type1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                dest_type: DestinationType::Single,
                packet_type: PacketType::Announce,
            },
            hops: 0,
            transport_id: None,
            destination_hash: [0xaa; TRUNCATED_HASHBYTES],
            context: PacketContext::None,
            data: PacketData::Owned(payload),
        };

        let announce = ReceivedAnnounce::from_packet(&packet).unwrap();

        assert!(!announce.has_ratchet());
        assert_eq!(announce.public_key(), &[0x01; IDENTITY_KEY_SIZE]);
        assert_eq!(announce.name_hash(), &[0x02; NAME_HASHBYTES]);
        assert_eq!(announce.random_hash(), &[0x03; RANDOM_HASHBYTES]);
        assert_eq!(announce.signature(), &[0x05; ED25519_SIGNATURE_SIZE]);
        assert_eq!(announce.app_data(), b"test.app");
        assert_eq!(announce.app_data_string(), Some("test.app"));
    }

    #[test]
    fn test_parse_announce_with_ratchet() {
        let payload = create_test_announce_payload(true);

        let packet = Packet {
            flags: PacketFlags {
                ifac_flag: false,
                header_type: HeaderType::Type1,
                context_flag: true, // Indicates ratchet is present
                transport_type: TransportType::Broadcast,
                dest_type: DestinationType::Single,
                packet_type: PacketType::Announce,
            },
            hops: 0,
            transport_id: None,
            destination_hash: [0xaa; TRUNCATED_HASHBYTES],
            context: PacketContext::None,
            data: PacketData::Owned(payload),
        };

        let announce = ReceivedAnnounce::from_packet(&packet).unwrap();

        assert!(announce.has_ratchet());
        assert_eq!(announce.ratchet(), Some(&[0x04; RATCHET_SIZE]));
        assert_eq!(announce.app_data(), b"test.app");
    }

    #[test]
    fn test_not_announce_packet() {
        let packet = Packet {
            flags: PacketFlags {
                ifac_flag: false,
                header_type: HeaderType::Type1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                dest_type: DestinationType::Single,
                packet_type: PacketType::Data, // Not an announce
            },
            hops: 0,
            transport_id: None,
            destination_hash: [0xaa; TRUNCATED_HASHBYTES],
            context: PacketContext::None,
            data: PacketData::Owned(vec![0; 200]),
        };

        let result = ReceivedAnnounce::from_packet(&packet);
        assert!(matches!(result, Err(AnnounceError::NotAnnounce)));
    }

    #[test]
    fn test_payload_too_short() {
        let packet = Packet {
            flags: PacketFlags {
                ifac_flag: false,
                header_type: HeaderType::Type1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                dest_type: DestinationType::Single,
                packet_type: PacketType::Announce,
            },
            hops: 0,
            transport_id: None,
            destination_hash: [0xaa; TRUNCATED_HASHBYTES],
            context: PacketContext::None,
            data: PacketData::Owned(vec![0; 100]), // Too short
        };

        let result = ReceivedAnnounce::from_packet(&packet);
        assert!(matches!(result, Err(AnnounceError::PayloadTooShort)));
    }

    #[test]
    fn test_computed_hashes() {
        // Create a minimal valid announce with known test data
        let payload = create_test_announce_payload(false);

        let packet = Packet {
            flags: PacketFlags {
                ifac_flag: false,
                header_type: HeaderType::Type1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                dest_type: DestinationType::Single,
                packet_type: PacketType::Announce,
            },
            hops: 0,
            transport_id: None,
            destination_hash: [0xaa; TRUNCATED_HASHBYTES],
            context: PacketContext::None,
            data: PacketData::Owned(payload),
        };

        let announce = ReceivedAnnounce::from_packet(&packet).unwrap();

        // Identity hash is truncated_hash(public_key)
        let identity_hash = announce.computed_identity_hash();
        assert_eq!(identity_hash.len(), TRUNCATED_HASHBYTES);

        // Destination hash is truncated_hash(name_hash + identity_hash)
        let dest_hash = announce.computed_destination_hash();
        assert_eq!(dest_hash.len(), TRUNCATED_HASHBYTES);

        // These won't match because destination_hash in packet is fake
        assert!(!announce.verify_destination_hash());
    }

    #[test]
    fn test_real_announce_creation_and_verification() {
        use crate::destination::{Destination, Direction};
        use rand_core::OsRng;

        // Create a real identity and destination
        let identity = Identity::generate_with_rng(&mut OsRng);
        let dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["echo"],
        )
        .expect("Failed to create destination");

        // Get the identity from the destination for signing
        let identity = dest.identity().expect("destination should have identity");

        // Create random hash
        let random_hash = [0x42u8; RANDOM_HASHBYTES];

        // Build announce payload
        let mut payload = Vec::new();
        payload.extend_from_slice(&identity.public_key_bytes());
        payload.extend_from_slice(dest.name_hash());
        payload.extend_from_slice(&random_hash);

        // App data
        let app_data = b"testapp.echo";

        // Compute signed data
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(dest.hash());
        signed_data.extend_from_slice(&identity.public_key_bytes());
        signed_data.extend_from_slice(dest.name_hash());
        signed_data.extend_from_slice(&random_hash);
        signed_data.extend_from_slice(app_data);

        // Sign
        let signature = identity.sign(&signed_data).unwrap();
        payload.extend_from_slice(&signature);
        payload.extend_from_slice(app_data);

        // Create packet
        let packet = Packet {
            flags: PacketFlags {
                ifac_flag: false,
                header_type: HeaderType::Type1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                dest_type: DestinationType::Single,
                packet_type: PacketType::Announce,
            },
            hops: 0,
            transport_id: None,
            destination_hash: *dest.hash(),
            context: PacketContext::None,
            data: PacketData::Owned(payload),
        };

        // Parse and verify
        let announce = ReceivedAnnounce::from_packet(&packet).unwrap();

        assert!(announce.verify_destination_hash());
        assert!(announce.verify_signature().unwrap());
        assert!(announce.validate().is_ok());
    }

    #[test]
    fn test_generate_random_hash_format() {
        let mut ctx = make_context();
        let hash = generate_random_hash(&mut ctx);

        // Should be 10 bytes
        assert_eq!(hash.len(), RANDOM_HASHBYTES);

        // Last 5 bytes should be from timestamp (1704067200000 ms)
        // 1704067200000 = 0x18CC251F400
        // to_be_bytes() gives [0x00, 0x00, 0x01, 0x8C, 0xC2, 0x51, 0xF4, 0x00]
        // bytes 3..8 are [0x8C, 0xC2, 0x51, 0xF4, 0x00]
        assert_eq!(&hash[5..10], &[0x8C, 0xC2, 0x51, 0xF4, 0x00]);
    }

    #[test]
    fn test_generate_random_hash_different_each_call() {
        let mut ctx = make_context();
        let hash1 = generate_random_hash(&mut ctx);
        let hash2 = generate_random_hash(&mut ctx);

        // First 5 bytes (random) should be different
        // (with overwhelming probability)
        assert_ne!(&hash1[0..5], &hash2[0..5]);

        // Last 5 bytes (timestamp) should be the same (same mock clock)
        assert_eq!(&hash1[5..10], &hash2[5..10]);
    }
}
