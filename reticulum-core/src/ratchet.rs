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

use crate::constants::{
    MS_PER_SECOND, RATCHET_EXPIRY_SECS, RATCHET_INTERVAL_SECS, RATCHET_SIZE, TRUNCATED_HASHBYTES,
};
use crate::crypto::sha256;
use crate::destination::DestinationHash;
use crate::traits::{Clock, Context, Storage, StorageError};

use alloc::collections::BTreeMap;

/// Ratchet ID size (first 10 bytes of SHA256(public_key))
pub const RATCHET_ID_SIZE: usize = 10;

/// Default number of ratchets to retain for decryption
pub const DEFAULT_RETAINED_RATCHETS: usize = 512;

/// Serialized ratchet size: 32 (private key) + 8 (timestamp)
const SERIALIZED_RATCHET_SIZE: usize = RATCHET_SIZE + 8;

/// Error types for ratchet operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatchetError {
    /// Invalid serialized data length
    InvalidLength,
    /// Ratchet has expired
    Expired,
    /// Decryption failed with all ratchets
    DecryptionFailed,
    /// Storage error
    StorageError(StorageError),
}

impl core::fmt::Display for RatchetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RatchetError::InvalidLength => write!(f, "Invalid ratchet data length"),
            RatchetError::Expired => write!(f, "Ratchet has expired"),
            RatchetError::DecryptionFailed => write!(f, "Decryption failed with all ratchets"),
            RatchetError::StorageError(e) => write!(f, "Storage error: {:?}", e),
        }
    }
}

impl From<StorageError> for RatchetError {
    fn from(e: StorageError) -> Self {
        RatchetError::StorageError(e)
    }
}

/// A ratchet key pair (X25519) for forward secrecy
///
/// Ratchets are ephemeral key pairs that are rotated periodically.
/// The private key is used for decryption, the public key is announced.
pub struct Ratchet {
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
    /// * `ctx` - Platform context providing RNG and clock
    ///
    /// # Example
    /// ```
    /// use reticulum_core::ratchet::Ratchet;
    /// use reticulum_core::traits::{PlatformContext, NoStorage, Clock};
    /// use rand_core::OsRng;
    ///
    /// struct SimpleClock;
    /// impl Clock for SimpleClock {
    ///     fn now_ms(&self) -> u64 { 1704067200000 }
    /// }
    ///
    /// let mut ctx = PlatformContext { rng: OsRng, clock: SimpleClock, storage: NoStorage };
    /// let ratchet = Ratchet::generate(&mut ctx);
    /// assert_eq!(ratchet.public_key_bytes().len(), 32);
    /// ```
    pub fn generate(ctx: &mut impl Context) -> Self {
        let private_key = x25519_dalek::StaticSecret::random_from_rng(ctx.rng());
        let public_key = x25519_dalek::PublicKey::from(&private_key);
        let created_at_ms = ctx.clock().now_ms();

        Self {
            private_key,
            public_key,
            created_at_ms,
        }
    }

    /// Generate a ratchet with a specific RNG (for testing)
    pub fn generate_with_rng<R: rand_core::CryptoRngCore>(rng: &mut R, created_at_ms: u64) -> Self {
        let private_key = x25519_dalek::StaticSecret::random_from_rng(rng);
        let public_key = x25519_dalek::PublicKey::from(&private_key);

        Self {
            private_key,
            public_key,
            created_at_ms,
        }
    }

    /// Get the public key bytes (32 bytes)
    pub fn public_key_bytes(&self) -> [u8; RATCHET_SIZE] {
        *self.public_key.as_bytes()
    }

    /// Get the ratchet ID (first 10 bytes of SHA256(public_key))
    ///
    /// The ratchet ID is used to identify which ratchet was used for encryption.
    pub fn id(&self) -> [u8; RATCHET_ID_SIZE] {
        ratchet_id(&self.public_key_bytes())
    }

    /// Get the creation timestamp in milliseconds
    pub fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// Check if this ratchet has expired
    ///
    /// Ratchets expire after RATCHET_EXPIRY_SECS (30 days by default).
    pub fn is_expired(&self, current_time_ms: u64) -> bool {
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
    pub fn derive_shared_secret(&self, peer_public: &[u8; RATCHET_SIZE]) -> [u8; 32] {
        let peer_key = x25519_dalek::PublicKey::from(*peer_public);
        let shared = self.private_key.diffie_hellman(&peer_key);
        *shared.as_bytes()
    }

    /// Serialize this ratchet for storage
    ///
    /// Format: private_key (32 bytes) + created_at_ms (8 bytes big-endian)
    pub fn to_bytes(&self) -> [u8; SERIALIZED_RATCHET_SIZE] {
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RatchetError> {
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
pub fn ratchet_id(public_key: &[u8; RATCHET_SIZE]) -> [u8; RATCHET_ID_SIZE] {
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
pub fn should_rotate(last_rotation_ms: u64, current_time_ms: u64, interval_ms: u64) -> bool {
    let elapsed = current_time_ms.saturating_sub(last_rotation_ms);
    elapsed >= interval_ms
}

/// Default rotation interval in milliseconds
pub const DEFAULT_INTERVAL_MS: u64 = RATCHET_INTERVAL_SECS * 1000;

/// Expiry time in milliseconds
pub const EXPIRY_MS: u64 = RATCHET_EXPIRY_SECS * 1000;

/// Manages ratchets received from other destinations (sender side)
///
/// When we receive an announce with a ratchet, we store it here so we can
/// use it when sending encrypted packets to that destination.
pub struct KnownRatchets {
    /// In-memory cache: destination_hash -> (ratchet_public, received_at_ms)
    cache: BTreeMap<DestinationHash, ([u8; RATCHET_SIZE], u64)>,
}

impl KnownRatchets {
    /// Create a new empty known ratchets manager
    pub fn new() -> Self {
        Self {
            cache: BTreeMap::new(),
        }
    }

    /// Remember a ratchet from a received announce
    ///
    /// # Arguments
    /// * `dest_hash` - Destination hash (16 bytes)
    /// * `ratchet` - Ratchet public key (32 bytes)
    /// * `timestamp_ms` - When the ratchet was received
    pub fn remember(
        &mut self,
        dest_hash: &DestinationHash,
        ratchet: &[u8; RATCHET_SIZE],
        timestamp_ms: u64,
    ) {
        self.cache.insert(*dest_hash, (*ratchet, timestamp_ms));
    }

    /// Get the ratchet for a destination
    ///
    /// Returns None if no ratchet is known for this destination.
    pub fn get(&self, dest_hash: &DestinationHash) -> Option<&[u8; RATCHET_SIZE]> {
        self.cache.get(dest_hash).map(|(ratchet, _)| ratchet)
    }

    /// Check if we have a ratchet for a destination
    pub fn has(&self, dest_hash: &DestinationHash) -> bool {
        self.cache.contains_key(dest_hash)
    }

    /// Remove a ratchet for a destination
    pub fn remove(&mut self, dest_hash: &DestinationHash) {
        self.cache.remove(dest_hash);
    }

    /// Remove expired ratchets (older than 30 days)
    ///
    /// # Arguments
    /// * `current_time_ms` - Current timestamp in milliseconds
    ///
    /// # Returns
    /// Number of ratchets removed
    pub fn clean_expired(&mut self, current_time_ms: u64) -> usize {
        let before_count = self.cache.len();

        self.cache.retain(|_, (_, received_at)| {
            let age_ms = current_time_ms.saturating_sub(*received_at);
            age_ms < EXPIRY_MS
        });

        before_count - self.cache.len()
    }

    /// Get the number of known ratchets
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Persist to storage
    ///
    /// Each ratchet is stored as a separate key-value pair:
    /// - Key: destination_hash (16 bytes)
    /// - Value: ratchet_public (32 bytes) + received_at (8 bytes)
    pub fn save(&self, storage: &mut impl Storage) -> Result<(), RatchetError> {
        use crate::traits::categories::RATCHETS;

        for (dest_hash, (ratchet, received_at)) in &self.cache {
            let mut value = [0u8; RATCHET_SIZE + 8];
            value[..RATCHET_SIZE].copy_from_slice(ratchet);
            value[RATCHET_SIZE..].copy_from_slice(&received_at.to_be_bytes());

            storage.store(RATCHETS, dest_hash.as_bytes(), &value)?;
        }

        Ok(())
    }

    /// Load from storage
    pub fn load(storage: &impl Storage) -> Self {
        use crate::traits::categories::RATCHETS;

        let mut cache = BTreeMap::new();

        for key in storage.list_keys(RATCHETS) {
            if key.len() != TRUNCATED_HASHBYTES {
                continue;
            }

            let mut dest_bytes = [0u8; TRUNCATED_HASHBYTES];
            dest_bytes.copy_from_slice(&key);
            let dest_hash = DestinationHash::new(dest_bytes);

            if let Some(value) = storage.load(RATCHETS, &key) {
                if value.len() == RATCHET_SIZE + 8 {
                    let mut ratchet = [0u8; RATCHET_SIZE];
                    ratchet.copy_from_slice(&value[..RATCHET_SIZE]);

                    let mut timestamp_bytes = [0u8; 8];
                    timestamp_bytes.copy_from_slice(&value[RATCHET_SIZE..]);
                    let received_at = u64::from_be_bytes(timestamp_bytes);

                    cache.insert(dest_hash, (ratchet, received_at));
                }
            }
        }

        Self { cache }
    }
}

impl Default for KnownRatchets {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for KnownRatchets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KnownRatchets")
            .field("count", &self.cache.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{NoStorage, PlatformContext};
    use rand_core::OsRng;

    // Mock clock for tests
    struct MockClock(u64);
    impl crate::traits::Clock for MockClock {
        fn now_ms(&self) -> u64 {
            self.0
        }
    }

    fn make_context(time_ms: u64) -> PlatformContext<OsRng, MockClock, NoStorage> {
        PlatformContext {
            rng: OsRng,
            clock: MockClock(time_ms),
            storage: NoStorage,
        }
    }

    // ─── Ratchet Tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_ratchet_generation() {
        let mut ctx = make_context(1704067200000);
        let ratchet = Ratchet::generate(&mut ctx);

        assert_eq!(ratchet.public_key_bytes().len(), RATCHET_SIZE);
        assert_eq!(ratchet.id().len(), RATCHET_ID_SIZE);
        assert_eq!(ratchet.created_at_ms(), 1704067200000);
    }

    #[test]
    fn test_ratchet_unique_keys() {
        let mut ctx = make_context(1704067200000);
        let ratchet1 = Ratchet::generate(&mut ctx);
        let ratchet2 = Ratchet::generate(&mut ctx);

        // Each ratchet should have unique keys
        assert_ne!(ratchet1.public_key_bytes(), ratchet2.public_key_bytes());
        assert_ne!(ratchet1.id(), ratchet2.id());
    }

    #[test]
    fn test_ratchet_serialization() {
        let mut ctx = make_context(1704067200000);
        let original = Ratchet::generate(&mut ctx);

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
        let mut ctx = make_context(created_at);
        let ratchet = Ratchet::generate(&mut ctx);

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
        let mut ctx = make_context(1704067200000);

        // Test actual ECDH scenario: sender creates ephemeral, receiver uses ratchet
        let ratchet = Ratchet::generate(&mut ctx);

        let ephemeral_private = x25519_dalek::StaticSecret::random_from_rng(ctx.rng());
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
        let ephemeral_private2 = x25519_dalek::StaticSecret::random_from_rng(ctx.rng());
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

    // ─── KnownRatchets Tests ───────────────────────────────────────────────────

    #[test]
    fn test_known_ratchets_remember_get() {
        let mut known = KnownRatchets::new();

        let dest_hash = DestinationHash::new([0xaa; TRUNCATED_HASHBYTES]);
        let ratchet = [0xbb; RATCHET_SIZE];
        let timestamp = 1704067200000u64;

        // Initially empty
        assert!(known.get(&dest_hash).is_none());
        assert!(!known.has(&dest_hash));

        // Remember ratchet
        known.remember(&dest_hash, &ratchet, timestamp);

        // Now should be found
        assert!(known.has(&dest_hash));
        assert_eq!(known.get(&dest_hash), Some(&ratchet));
        assert_eq!(known.len(), 1);
    }

    #[test]
    fn test_known_ratchets_update() {
        let mut known = KnownRatchets::new();

        let dest_hash = DestinationHash::new([0xaa; TRUNCATED_HASHBYTES]);
        let ratchet1 = [0xbb; RATCHET_SIZE];
        let ratchet2 = [0xcc; RATCHET_SIZE];

        // Remember first ratchet
        known.remember(&dest_hash, &ratchet1, 1000);
        assert_eq!(known.get(&dest_hash), Some(&ratchet1));

        // Update with second ratchet
        known.remember(&dest_hash, &ratchet2, 2000);
        assert_eq!(known.get(&dest_hash), Some(&ratchet2));

        // Still only one entry
        assert_eq!(known.len(), 1);
    }

    #[test]
    fn test_known_ratchets_remove() {
        let mut known = KnownRatchets::new();

        let dest_hash = DestinationHash::new([0xaa; TRUNCATED_HASHBYTES]);
        let ratchet = [0xbb; RATCHET_SIZE];

        known.remember(&dest_hash, &ratchet, 1000);
        assert_eq!(known.len(), 1);

        known.remove(&dest_hash);
        assert_eq!(known.len(), 0);
        assert!(known.get(&dest_hash).is_none());
    }

    #[test]
    fn test_known_ratchets_clean_expired() {
        let mut known = KnownRatchets::new();

        let dest1 = DestinationHash::new([0x01; TRUNCATED_HASHBYTES]);
        let dest2 = DestinationHash::new([0x02; TRUNCATED_HASHBYTES]);
        let dest3 = DestinationHash::new([0x03; TRUNCATED_HASHBYTES]);
        let ratchet = [0xaa; RATCHET_SIZE];

        // Add ratchets at different times
        let base_time = 1704067200000u64; // 2024-01-01

        // Old ratchet (35 days ago)
        known.remember(&dest1, &ratchet, base_time - 35 * 24 * 60 * 60 * 1000);

        // Recent ratchet (5 days ago)
        known.remember(&dest2, &ratchet, base_time - 5 * 24 * 60 * 60 * 1000);

        // Very recent ratchet (1 hour ago)
        known.remember(&dest3, &ratchet, base_time - 60 * 60 * 1000);

        assert_eq!(known.len(), 3);

        // Clean expired
        let removed = known.clean_expired(base_time);
        assert_eq!(removed, 1);
        assert_eq!(known.len(), 2);

        // Old one should be gone
        assert!(known.get(&dest1).is_none());
        assert!(known.get(&dest2).is_some());
        assert!(known.get(&dest3).is_some());
    }

    #[test]
    fn test_known_ratchets_multiple_destinations() {
        let mut known = KnownRatchets::new();

        for i in 0..10 {
            let mut dest_bytes = [0u8; TRUNCATED_HASHBYTES];
            dest_bytes[0] = i;
            let dest_hash = DestinationHash::new(dest_bytes);

            let mut ratchet = [0u8; RATCHET_SIZE];
            ratchet[0] = i + 100;

            known.remember(&dest_hash, &ratchet, (i as u64) * 1000);
        }

        assert_eq!(known.len(), 10);

        // Verify each one
        for i in 0..10 {
            let mut dest_bytes = [0u8; TRUNCATED_HASHBYTES];
            dest_bytes[0] = i;
            let dest_hash = DestinationHash::new(dest_bytes);

            let mut expected_ratchet = [0u8; RATCHET_SIZE];
            expected_ratchet[0] = i + 100;

            assert_eq!(known.get(&dest_hash), Some(&expected_ratchet));
        }
    }

    #[test]
    fn test_known_ratchets_empty() {
        let known = KnownRatchets::new();
        assert!(known.is_empty());
        assert_eq!(known.len(), 0);
    }

    #[test]
    fn test_known_ratchets_default() {
        let known = KnownRatchets::default();
        assert!(known.is_empty());
    }
}
