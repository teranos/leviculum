//! Ratchet key management for forward secrecy
//!
//! Ratchets provide forward secrecy for packets sent to SINGLE destinations
//! without establishing a Link. Each destination periodically rotates X25519
//! key pairs and announces the current public key.
//!
//! # How it works
//!
//! 1. A destination enables ratchets and generates an initial keypair
//! 2. The destination announces with the ratchet public key
//! 3. Senders use the ratchet public key for encryption instead of identity key
//! 4. The destination rotates ratchets periodically (default: 30 minutes)
//! 5. Old ratchets are retained for decryption (default: 512 ratchets)
//!
//! # Forward Secrecy
//!
//! If a ratchet private key is compromised, only messages encrypted with
//! that specific ratchet can be decrypted. Past and future ratchets remain
//! secure because each ratchet is independently generated.

use crate::constants::{MS_PER_SECOND, RATCHET_EXPIRY_SECS, RATCHET_INTERVAL_SECS, RATCHET_SIZE};
use crate::crypto::sha256;
use rand_core::CryptoRngCore;

/// Ratchet ID size (first 10 bytes of SHA256(public_key))
pub(crate) const RATCHET_ID_SIZE: usize = 10;

/// Default number of ratchets to retain for decryption
pub(crate) const DEFAULT_RETAINED_RATCHETS: usize = 512;

/// Serialized ratchet size: 32 (private key) + 8 (timestamp)
pub(crate) const SERIALIZED_RATCHET_SIZE: usize = RATCHET_SIZE + 8;

/// Error types for ratchet operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RatchetError {
    /// Invalid serialized data length
    InvalidLength,
}

impl core::fmt::Display for RatchetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RatchetError::InvalidLength => write!(f, "Invalid ratchet data length"),
        }
    }
}

/// A ratchet key pair (X25519) for forward secrecy
///
/// Ratchets are ephemeral key pairs that are rotated periodically.
/// The private key is used for decryption, the public key is announced.
pub(crate) struct Ratchet {
    /// X25519 private key (32 bytes)
    private_key: x25519_dalek::StaticSecret,
    /// X25519 public key (32 bytes)
    public_key: x25519_dalek::PublicKey,
    /// Timestamp when this ratchet was created (milliseconds)
    created_at_ms: u64,
}

impl Ratchet {
    /// Generate a new ratchet key pair
    ///
    /// # Arguments
    /// * `rng` - Random number generator
    /// * `now_ms` - Current timestamp in milliseconds
    pub(crate) fn generate<R: CryptoRngCore>(rng: &mut R, now_ms: u64) -> Self {
        let private_key = x25519_dalek::StaticSecret::random_from_rng(rng);
        let public_key = x25519_dalek::PublicKey::from(&private_key);

        Self {
            private_key,
            public_key,
            created_at_ms: now_ms,
        }
    }

    /// Get the public key bytes (32 bytes)
    pub(crate) fn public_key_bytes(&self) -> [u8; RATCHET_SIZE] {
        *self.public_key.as_bytes()
    }

    /// Get the ratchet ID (first 10 bytes of SHA256(public_key))
    ///
    /// The ratchet ID is used to identify which ratchet was used for encryption.
    pub(crate) fn id(&self) -> [u8; RATCHET_ID_SIZE] {
        ratchet_id(&self.public_key_bytes())
    }

    /// Get the creation timestamp in milliseconds
    pub(crate) fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// Check if this ratchet has expired
    ///
    /// Ratchets expire after RATCHET_EXPIRY_SECS (30 days by default).
    pub(crate) fn is_expired(&self, current_time_ms: u64) -> bool {
        let age_ms = current_time_ms.saturating_sub(self.created_at_ms);
        let age_secs = age_ms / MS_PER_SECOND;
        age_secs > RATCHET_EXPIRY_SECS
    }

    /// Perform ECDH with a peer's ephemeral public key
    ///
    /// # Arguments
    /// * `peer_public` - The peer's X25519 public key (32 bytes)
    ///
    /// # Returns
    /// The shared secret (32 bytes)
    pub(crate) fn derive_shared_secret(&self, peer_public: &[u8; RATCHET_SIZE]) -> [u8; 32] {
        let peer_key = x25519_dalek::PublicKey::from(*peer_public);
        let shared = self.private_key.diffie_hellman(&peer_key);
        *shared.as_bytes()
    }

    /// Serialize this ratchet for storage
    ///
    /// Format: private_key (32 bytes) + created_at_ms (8 bytes big-endian)
    pub(crate) fn to_bytes(&self) -> [u8; SERIALIZED_RATCHET_SIZE] {
        let mut bytes = [0u8; SERIALIZED_RATCHET_SIZE];
        bytes[..RATCHET_SIZE].copy_from_slice(self.private_key.as_bytes());
        bytes[RATCHET_SIZE..].copy_from_slice(&self.created_at_ms.to_be_bytes());
        bytes
    }

    /// Deserialize a ratchet from storage
    ///
    /// # Arguments
    /// * `bytes` - Serialized ratchet data (40 bytes)
    ///
    /// # Returns
    /// The ratchet, or error if data is invalid
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, RatchetError> {
        if bytes.len() != SERIALIZED_RATCHET_SIZE {
            return Err(RatchetError::InvalidLength);
        }

        let mut private_bytes = [0u8; RATCHET_SIZE];
        private_bytes.copy_from_slice(&bytes[..RATCHET_SIZE]);

        let mut timestamp_bytes = [0u8; 8];
        timestamp_bytes.copy_from_slice(&bytes[RATCHET_SIZE..]);

        let private_key = x25519_dalek::StaticSecret::from(private_bytes);
        let public_key = x25519_dalek::PublicKey::from(&private_key);
        let created_at_ms = u64::from_be_bytes(timestamp_bytes);

        Ok(Self {
            private_key,
            public_key,
            created_at_ms,
        })
    }

    /// Get the X25519 private key reference (for ECDH operations)
    pub(crate) fn private_key(&self) -> &x25519_dalek::StaticSecret {
        &self.private_key
    }

    /// Get the raw X25519 private key bytes (32 bytes).
    ///
    /// Used for Python-compatible serialization which stores only private keys
    /// (public keys are derived on load).
    pub(crate) fn private_key_bytes(&self) -> [u8; RATCHET_SIZE] {
        *self.private_key.as_bytes()
    }

    /// Reconstruct a Ratchet from raw private key bytes.
    ///
    /// Derives the public key from the private key. Used when loading from
    /// Python-compatible format which stores only private keys, no timestamps.
    pub(crate) fn from_private_key_bytes(key: [u8; RATCHET_SIZE], created_at_ms: u64) -> Self {
        let private_key = x25519_dalek::StaticSecret::from(key);
        let public_key = x25519_dalek::PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
            created_at_ms,
        }
    }
}

impl core::fmt::Debug for Ratchet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ratchet")
            .field("id", &format_args!("{:02x?}", &self.id()[..4]))
            .field("created_at_ms", &self.created_at_ms)
            .finish()
    }
}

/// Compute ratchet ID from public key bytes
///
/// The ratchet ID is the first 10 bytes of SHA256(public_key).
/// This matches the Python Reticulum implementation.
pub(crate) fn ratchet_id(public_key: &[u8; RATCHET_SIZE]) -> [u8; RATCHET_ID_SIZE] {
    let hash = sha256(public_key);
    let mut id = [0u8; RATCHET_ID_SIZE];
    id.copy_from_slice(&hash[..RATCHET_ID_SIZE]);
    id
}

/// Check if a ratchet rotation is needed based on time
///
/// # Arguments
/// * `last_rotation_ms` - Timestamp of last rotation
/// * `current_time_ms` - Current timestamp
/// * `interval_ms` - Rotation interval (default: 30 minutes)
///
/// # Returns
/// True if rotation is needed
pub(crate) fn should_rotate(last_rotation_ms: u64, current_time_ms: u64, interval_ms: u64) -> bool {
    let elapsed = current_time_ms.saturating_sub(last_rotation_ms);
    elapsed >= interval_ms
}

/// Default rotation interval in milliseconds
pub(crate) const DEFAULT_INTERVAL_MS: u64 = RATCHET_INTERVAL_SECS * 1000;

/// Expiry time in milliseconds
pub(crate) const EXPIRY_MS: u64 = RATCHET_EXPIRY_SECS * 1000;

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    // ─── Ratchet Tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_ratchet_generation() {
        let ratchet = Ratchet::generate(&mut OsRng, 1704067200000);

        assert_eq!(ratchet.public_key_bytes().len(), RATCHET_SIZE);
        assert_eq!(ratchet.id().len(), RATCHET_ID_SIZE);
        assert_eq!(ratchet.created_at_ms(), 1704067200000);
    }

    #[test]
    fn test_ratchet_unique_keys() {
        let ratchet1 = Ratchet::generate(&mut OsRng, 1704067200000);
        let ratchet2 = Ratchet::generate(&mut OsRng, 1704067200000);

        // Each ratchet should have unique keys
        assert_ne!(ratchet1.public_key_bytes(), ratchet2.public_key_bytes());
        assert_ne!(ratchet1.id(), ratchet2.id());
    }

    #[test]
    fn test_ratchet_serialization() {
        let original = Ratchet::generate(&mut OsRng, 1704067200000);

        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), SERIALIZED_RATCHET_SIZE);

        let restored = Ratchet::from_bytes(&bytes).unwrap();

        assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
        assert_eq!(original.id(), restored.id());
        assert_eq!(original.created_at_ms(), restored.created_at_ms());
    }

    #[test]
    fn test_ratchet_from_bytes_invalid_length() {
        let short_bytes = [0u8; 20];
        let result = Ratchet::from_bytes(&short_bytes);
        assert!(matches!(result, Err(RatchetError::InvalidLength)));

        let long_bytes = [0u8; 50];
        let result = Ratchet::from_bytes(&long_bytes);
        assert!(matches!(result, Err(RatchetError::InvalidLength)));
    }

    #[test]
    fn test_ratchet_expiry() {
        let created_at = 1704067200000u64; // 2024-01-01 00:00:00 UTC
        let ratchet = Ratchet::generate(&mut OsRng, created_at);

        // Not expired immediately
        assert!(!ratchet.is_expired(created_at));

        // Not expired after 29 days
        let day_29 = created_at + (29 * 24 * 60 * 60 * 1000);
        assert!(!ratchet.is_expired(day_29));

        // Expired after 31 days
        let day_31 = created_at + (31 * 24 * 60 * 60 * 1000);
        assert!(ratchet.is_expired(day_31));
    }

    #[test]
    fn test_ratchet_ecdh() {
        // Test actual ECDH scenario: sender creates ephemeral, receiver uses ratchet
        let ratchet = Ratchet::generate(&mut OsRng, 1704067200000);

        let ephemeral_private = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_private);

        // Receiver uses their ratchet private key with sender's ephemeral public
        let receiver_shared = ratchet.derive_shared_secret(ephemeral_public.as_bytes());

        // Sender uses their ephemeral private with receiver's ratchet public
        let sender_shared = ephemeral_private
            .diffie_hellman(&x25519_dalek::PublicKey::from(ratchet.public_key_bytes()));
        let sender_shared_bytes = *sender_shared.as_bytes();

        // These should match - this is the core ECDH property
        assert_eq!(receiver_shared, sender_shared_bytes);

        // Test with different ephemeral produces different shared secret
        let ephemeral_private2 = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let ephemeral_public2 = x25519_dalek::PublicKey::from(&ephemeral_private2);

        let receiver_shared2 = ratchet.derive_shared_secret(ephemeral_public2.as_bytes());
        assert_ne!(receiver_shared, receiver_shared2);
    }

    #[test]
    fn test_ratchet_id_function() {
        let public_key = [0xab; RATCHET_SIZE];
        let id = ratchet_id(&public_key);

        assert_eq!(id.len(), RATCHET_ID_SIZE);

        // Same input should produce same ID
        let id2 = ratchet_id(&public_key);
        assert_eq!(id, id2);

        // Different input should produce different ID
        let other_key = [0xcd; RATCHET_SIZE];
        let other_id = ratchet_id(&other_key);
        assert_ne!(id, other_id);
    }

    #[test]
    fn test_private_key_bytes_roundtrip() {
        let original = Ratchet::generate(&mut OsRng, 1704067200000);
        let private_bytes = original.private_key_bytes();

        let restored = Ratchet::from_private_key_bytes(private_bytes, 5000);

        // Same public key (derived from private key)
        assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
        assert_eq!(original.id(), restored.id());
        // Timestamp is independently set
        assert_eq!(restored.created_at_ms(), 5000);
    }

    #[test]
    fn test_should_rotate() {
        let last_rotation = 1000000u64;
        let interval = 30 * 60 * 1000; // 30 minutes in ms

        // No rotation needed at start
        assert!(!should_rotate(last_rotation, last_rotation, interval));

        // No rotation needed after 29 minutes
        assert!(!should_rotate(
            last_rotation,
            last_rotation + 29 * 60 * 1000,
            interval
        ));

        // Rotation needed after 30 minutes
        assert!(should_rotate(
            last_rotation,
            last_rotation + 30 * 60 * 1000,
            interval
        ));

        // Rotation needed after 31 minutes
        assert!(should_rotate(
            last_rotation,
            last_rotation + 31 * 60 * 1000,
            interval
        ));
    }
}
