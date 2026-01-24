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
    ED25519_SIGNATURE_SIZE, IDENTITY_KEY_SIZE, NAME_HASHBYTES, RANDOM_HASHBYTES, RATCHET_SIZE,
    TRUNCATED_HASHBYTES,
};
use crate::crypto::truncated_hash;
use crate::identity::{Identity, IdentityError};
use crate::packet::{Packet, PacketType};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Minimum announce payload size (without ratchet, without app_data)
/// public_key(64) + name_hash(10) + random_hash(10) + signature(64) = 148
pub const ANNOUNCE_MIN_SIZE: usize =
    IDENTITY_KEY_SIZE + NAME_HASHBYTES + RANDOM_HASHBYTES + ED25519_SIGNATURE_SIZE;

/// Minimum announce payload size with ratchet (without app_data)
/// public_key(64) + name_hash(10) + random_hash(10) + ratchet(32) + signature(64) = 180
pub const ANNOUNCE_RATCHETED_MIN_SIZE: usize = ANNOUNCE_MIN_SIZE + RATCHET_SIZE;

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
}

impl core::fmt::Display for AnnounceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AnnounceError::PayloadTooShort => write!(f, "Announce payload too short"),
            AnnounceError::NotAnnounce => write!(f, "Not an announce packet"),
            AnnounceError::InvalidPublicKey => write!(f, "Invalid public key in announce"),
            AnnounceError::InvalidSignature => write!(f, "Signature verification failed"),
            AnnounceError::HashMismatch => write!(f, "Destination hash mismatch"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AnnounceError {}

/// A received announce message parsed from a packet
///
/// This struct holds the parsed components of an announce and provides
/// methods to verify the signature and compute hashes.
#[cfg(feature = "alloc")]
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

#[cfg(feature = "alloc")]
impl ReceivedAnnounce {
    /// Parse an announce from a packet
    ///
    /// Returns an error if the packet is not an announce or the payload is malformed.
    ///
    /// Note: Ratchet detection is currently based on payload length heuristics.
    /// A payload >= 180 bytes is assumed to be ratcheted. This matches the
    /// Python Reticulum implementation behavior observed in interop testing.
    pub fn from_packet(packet: &Packet) -> Result<Self, AnnounceError> {
        if packet.flags.packet_type != PacketType::Announce {
            return Err(AnnounceError::NotAnnounce);
        }

        let payload = packet.data.as_slice();

        // Determine if this is a ratcheted announce based on payload length
        // TODO: Verify this detection method against the Python implementation
        let has_ratchet = payload.len() >= ANNOUNCE_RATCHETED_MIN_SIZE;

        if has_ratchet {
            if payload.len() < ANNOUNCE_RATCHETED_MIN_SIZE {
                return Err(AnnounceError::PayloadTooShort);
            }

            let mut public_key = [0u8; IDENTITY_KEY_SIZE];
            let mut name_hash = [0u8; NAME_HASHBYTES];
            let mut random_hash = [0u8; RANDOM_HASHBYTES];
            let mut ratchet = [0u8; RATCHET_SIZE];
            let mut signature = [0u8; ED25519_SIGNATURE_SIZE];

            public_key.copy_from_slice(&payload[0..64]);
            name_hash.copy_from_slice(&payload[64..74]);
            random_hash.copy_from_slice(&payload[74..84]);
            ratchet.copy_from_slice(&payload[84..116]);
            signature.copy_from_slice(&payload[116..180]);

            Ok(Self {
                destination_hash: packet.destination_hash,
                public_key,
                name_hash,
                random_hash,
                ratchet: Some(ratchet),
                signature,
                app_data: payload[180..].to_vec(),
            })
        } else {
            if payload.len() < ANNOUNCE_MIN_SIZE {
                return Err(AnnounceError::PayloadTooShort);
            }

            let mut public_key = [0u8; IDENTITY_KEY_SIZE];
            let mut name_hash = [0u8; NAME_HASHBYTES];
            let mut random_hash = [0u8; RANDOM_HASHBYTES];
            let mut signature = [0u8; ED25519_SIGNATURE_SIZE];

            public_key.copy_from_slice(&payload[0..64]);
            name_hash.copy_from_slice(&payload[64..74]);
            random_hash.copy_from_slice(&payload[74..84]);
            signature.copy_from_slice(&payload[84..148]);

            Ok(Self {
                destination_hash: packet.destination_hash,
                public_key,
                name_hash,
                random_hash,
                ratchet: None,
                signature,
                app_data: payload[148..].to_vec(),
            })
        }
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
    #[cfg(feature = "alloc")]
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
        let ratchet_len = if self.ratchet.is_some() {
            RATCHET_SIZE
        } else {
            0
        };
        let mut data = Vec::with_capacity(
            TRUNCATED_HASHBYTES
                + IDENTITY_KEY_SIZE
                + NAME_HASHBYTES
                + RANDOM_HASHBYTES
                + ratchet_len
                + self.app_data.len(),
        );
        data.extend_from_slice(&self.destination_hash);
        data.extend_from_slice(&self.public_key);
        data.extend_from_slice(&self.name_hash);
        data.extend_from_slice(&self.random_hash);
        if let Some(ratchet) = &self.ratchet {
            data.extend_from_slice(ratchet);
        }
        data.extend_from_slice(&self.app_data);
        data
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

#[cfg(feature = "alloc")]
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

    #[cfg(feature = "alloc")]
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

    #[cfg(feature = "alloc")]
    #[test]
    fn test_parse_announce_without_ratchet() {
        let payload = create_test_announce_payload(false);

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

    #[cfg(feature = "alloc")]
    #[test]
    fn test_parse_announce_with_ratchet() {
        let payload = create_test_announce_payload(true);

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
            destination_hash: [0xaa; TRUNCATED_HASHBYTES],
            context: PacketContext::None,
            data: PacketData::Owned(payload),
        };

        let announce = ReceivedAnnounce::from_packet(&packet).unwrap();

        assert!(announce.has_ratchet());
        assert_eq!(announce.ratchet(), Some(&[0x04; RATCHET_SIZE]));
        assert_eq!(announce.app_data(), b"test.app");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_not_announce_packet() {
        let packet = Packet {
            flags: PacketFlags {
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

    #[cfg(feature = "alloc")]
    #[test]
    fn test_payload_too_short() {
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
            destination_hash: [0xaa; TRUNCATED_HASHBYTES],
            context: PacketContext::None,
            data: PacketData::Owned(vec![0; 100]), // Too short
        };

        let result = ReceivedAnnounce::from_packet(&packet);
        assert!(matches!(result, Err(AnnounceError::PayloadTooShort)));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_computed_hashes() {
        // Create a minimal valid announce with known test data
        let payload = create_test_announce_payload(false);

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

    #[cfg(all(feature = "alloc", feature = "std"))]
    #[test]
    fn test_real_announce_creation_and_verification() {
        use crate::destination::{Destination, Direction};

        // Create a real identity and destination
        let identity = Identity::new();
        let dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["echo"],
        );

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
}
