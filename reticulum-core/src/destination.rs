//! Network endpoint addressing
//!
//! A Destination represents an addressable endpoint in the Reticulum network.
//! Destinations have:
//! - A unique hash derived from application name, aspects, and identity
//! - A type (SINGLE, GROUP, PLAIN, LINK) determining encryption behavior
//! - A direction (IN, OUT) determining receive/send capability
//!
//! # Ratchet Support
//!
//! Destinations can enable ratchets for forward secrecy. When enabled:
//! - The destination rotates X25519 key pairs periodically
//! - Announces include the current ratchet public key
//! - Incoming packets are decrypted by trying retained ratchets
//!
//! See [`Destination::enable_ratchets`] for more details.

use crate::announce::{build_announce_payload, AnnounceError};
use crate::constants::{IDENTITY_HASHBYTES, NAME_HASHBYTES, RATCHET_SIZE, TRUNCATED_HASHBYTES};
use crate::crypto::{sha256, truncated_hash};
use crate::identity::{Identity, IdentityError};
use crate::packet::{
    HeaderType, Packet, PacketContext, PacketData, PacketFlags, PacketType, TransportType,
};
use crate::ratchet::{Ratchet, DEFAULT_INTERVAL_MS, DEFAULT_RETAINED_RATCHETS};
use crate::traits::{Clock, Context};

use alloc::string::String;
use alloc::vec::Vec;

/// Error type for destination operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationError {
    /// PLAIN destination type cannot have an identity
    PlainCannotHaveIdentity,
    /// Outbound SINGLE/GROUP destinations require an identity
    OutboundRequiresIdentity,
    /// Operation requires an identity
    NoIdentity,
    /// Ratchets are required but no ratchet was used
    RatchetRequired,
    /// Decryption failed
    DecryptionFailed,
    /// Cannot enable ratchets on OUT destination
    CannotEnableRatchetsOnOut,
}

impl core::fmt::Display for DestinationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DestinationError::PlainCannotHaveIdentity => {
                write!(f, "PLAIN destination type cannot hold an identity")
            }
            DestinationError::OutboundRequiresIdentity => {
                write!(f, "Outbound SINGLE/GROUP destinations require an identity")
            }
            DestinationError::NoIdentity => {
                write!(f, "Operation requires an identity")
            }
            DestinationError::RatchetRequired => {
                write!(f, "Ratchets are required but no ratchet was used")
            }
            DestinationError::DecryptionFailed => {
                write!(f, "Decryption failed")
            }
            DestinationError::CannotEnableRatchetsOnOut => {
                write!(f, "Cannot enable ratchets on OUT destination")
            }
        }
    }
}

impl From<IdentityError> for DestinationError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::NoPrivateKey => DestinationError::NoIdentity,
            IdentityError::DecryptionFailed => DestinationError::DecryptionFailed,
            _ => DestinationError::DecryptionFailed,
        }
    }
}

/// Destination type determining encryption behavior
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DestinationType {
    /// Point-to-point with ephemeral encryption per packet
    Single = 0x00,
    /// Broadcast with pre-shared key
    Group = 0x01,
    /// Unencrypted
    Plain = 0x02,
    /// Link-based encryption (internal use)
    Link = 0x03,
}

impl TryFrom<u8> for DestinationType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(DestinationType::Single),
            0x01 => Ok(DestinationType::Group),
            0x02 => Ok(DestinationType::Plain),
            0x03 => Ok(DestinationType::Link),
            _ => Err(()),
        }
    }
}

/// Destination direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    /// Incoming - can receive announces and accept links
    In = 0x11,
    /// Outgoing - source address for packets
    Out = 0x12,
}

/// Proof generation strategy for incoming packets
///
/// Controls how the destination responds to requests for delivery proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ProofStrategy {
    /// Never generate proofs (default)
    #[default]
    None = 0x21,
    /// Ask application via ProofRequested event to decide
    App = 0x22,
    /// Automatically prove every packet
    All = 0x23,
}

/// A 16-byte destination hash (truncated hash of name_hash + identity_hash)
///
/// In the Reticulum protocol, destination hashes identify network endpoints.
/// They are computed as `truncated_hash(name_hash + identity_hash)` and
/// appear in packet headers and routing tables.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DestinationHash([u8; TRUNCATED_HASHBYTES]);

impl DestinationHash {
    /// Create a DestinationHash from raw bytes
    pub const fn new(bytes: [u8; TRUNCATED_HASHBYTES]) -> Self {
        Self(bytes)
    }

    /// Get the underlying bytes
    pub const fn as_bytes(&self) -> &[u8; TRUNCATED_HASHBYTES] {
        &self.0
    }

    /// Convert to the raw byte array
    pub const fn into_bytes(self) -> [u8; TRUNCATED_HASHBYTES] {
        self.0
    }
}

impl From<[u8; TRUNCATED_HASHBYTES]> for DestinationHash {
    fn from(bytes: [u8; TRUNCATED_HASHBYTES]) -> Self {
        Self(bytes)
    }
}

impl From<DestinationHash> for [u8; TRUNCATED_HASHBYTES] {
    fn from(hash: DestinationHash) -> Self {
        hash.0
    }
}

impl AsRef<[u8]> for DestinationHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; TRUNCATED_HASHBYTES]> for DestinationHash {
    fn as_ref(&self) -> &[u8; TRUNCATED_HASHBYTES] {
        &self.0
    }
}

impl core::borrow::Borrow<[u8; TRUNCATED_HASHBYTES]> for DestinationHash {
    fn borrow(&self) -> &[u8; TRUNCATED_HASHBYTES] {
        &self.0
    }
}

impl PartialEq<[u8; TRUNCATED_HASHBYTES]> for DestinationHash {
    fn eq(&self, other: &[u8; TRUNCATED_HASHBYTES]) -> bool {
        self.0 == *other
    }
}

impl PartialEq<DestinationHash> for [u8; TRUNCATED_HASHBYTES] {
    fn eq(&self, other: &DestinationHash) -> bool {
        *self == other.0
    }
}

impl core::fmt::Debug for DestinationHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DestinationHash(")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}

impl core::fmt::Display for DestinationHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// A network destination (endpoint)
pub struct Destination {
    /// The destination hash (address)
    hash: DestinationHash,
    /// Name hash (truncated hash of app_name.aspects)
    name_hash: [u8; NAME_HASHBYTES],
    /// Associated identity (optional for PLAIN destinations)
    identity: Option<Identity>,
    /// Destination type
    dest_type: DestinationType,
    /// Direction
    direction: Direction,
    /// Whether to accept incoming links
    accepts_links: bool,
    /// Proof generation strategy for incoming packets
    proof_strategy: ProofStrategy,

    // ─── Ratchet State (for IN destinations) ─────────────────────────────────
    /// Retained ratchets for decryption (newest first)
    ratchets: Vec<Ratchet>,
    /// Ratchet rotation interval in milliseconds
    ratchet_interval_ms: u64,
    /// Maximum number of ratchets to retain
    retained_ratchet_count: usize,
    /// Timestamp of last ratchet rotation
    last_ratchet_time_ms: u64,
    /// If true, reject packets not encrypted with a ratchet
    enforce_ratchets: bool,
    /// If true, ratchets are enabled for this destination
    ratchets_enabled: bool,
}

impl Destination {
    /// Create a new destination
    ///
    /// # Arguments
    /// * `identity` - The identity for this destination (required except for PLAIN)
    /// * `direction` - IN for receiving, OUT for sending
    /// * `dest_type` - The encryption type
    /// * `app_name` - Application name
    /// * `aspects` - Additional name components
    ///
    /// # Errors
    /// * `PlainCannotHaveIdentity` - PLAIN destinations cannot have an identity
    /// * `OutboundRequiresIdentity` - SINGLE/GROUP OUT destinations require an identity
    pub fn new(
        identity: Option<Identity>,
        direction: Direction,
        dest_type: DestinationType,
        app_name: &str,
        aspects: &[&str],
    ) -> Result<Self, DestinationError> {
        // PLAIN destinations cannot have an identity (per Python Reticulum spec)
        if dest_type == DestinationType::Plain && identity.is_some() {
            return Err(DestinationError::PlainCannotHaveIdentity);
        }

        // SINGLE/GROUP OUT destinations require an identity for encryption
        if direction == Direction::Out && dest_type != DestinationType::Plain && identity.is_none()
        {
            return Err(DestinationError::OutboundRequiresIdentity);
        }

        let name_hash = Self::compute_name_hash(app_name, aspects);

        let hash = match &identity {
            Some(id) => Self::compute_destination_hash(&name_hash, id.hash()),
            None => {
                // For PLAIN destinations without identity: hash = full_hash(name_hash)[:16]
                // This matches Python: RNS.Identity.full_hash(name_hash)[:TRUNCATED_HASHLENGTH//8]
                DestinationHash::new(truncated_hash(&name_hash))
            }
        };

        Ok(Self {
            hash,
            name_hash,
            identity,
            dest_type,
            direction,
            accepts_links: false,
            proof_strategy: ProofStrategy::None,
            // Ratchet fields - not enabled by default
            ratchets: Vec::new(),
            ratchet_interval_ms: DEFAULT_INTERVAL_MS,
            retained_ratchet_count: DEFAULT_RETAINED_RATCHETS,
            last_ratchet_time_ms: 0,
            enforce_ratchets: false,
            ratchets_enabled: false,
        })
    }

    /// Get the destination hash
    pub fn hash(&self) -> &DestinationHash {
        &self.hash
    }

    /// Get the name hash
    pub fn name_hash(&self) -> &[u8; NAME_HASHBYTES] {
        &self.name_hash
    }

    /// Get the destination type
    pub fn dest_type(&self) -> DestinationType {
        self.dest_type
    }

    /// Get the direction
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Get the associated identity
    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    /// Check if this destination accepts incoming links
    pub fn accepts_links(&self) -> bool {
        self.accepts_links
    }

    /// Set whether to accept incoming links
    pub fn set_accepts_links(&mut self, accept: bool) {
        self.accepts_links = accept;
    }

    /// Get the proof generation strategy
    pub fn proof_strategy(&self) -> ProofStrategy {
        self.proof_strategy
    }

    /// Set the proof generation strategy for incoming packets
    ///
    /// # Arguments
    /// * `strategy` - The proof strategy to use:
    ///   - `ProofStrategy::None` - Never generate proofs (default)
    ///   - `ProofStrategy::App` - Emit ProofRequested event for app to decide
    ///   - `ProofStrategy::All` - Automatically prove every packet
    pub fn set_proof_strategy(&mut self, strategy: ProofStrategy) {
        self.proof_strategy = strategy;
    }

    // ─── Ratchet Management ──────────────────────────────────────────────────

    /// Enable ratchets for forward secrecy on this destination
    ///
    /// Ratchets provide forward secrecy by rotating X25519 key pairs
    /// periodically. When enabled, announces will include the current
    /// ratchet public key, and packets must be encrypted with that ratchet.
    ///
    /// # Arguments
    /// * `ctx` - Platform context providing RNG and clock
    ///
    /// # Errors
    /// Returns error if called on an OUT destination.
    ///
    /// # Example
    /// ```
    /// use reticulum_core::destination::{Destination, DestinationType, Direction};
    /// use reticulum_core::identity::Identity;
    /// use reticulum_core::traits::{PlatformContext, NoStorage, Clock};
    /// use rand_core::OsRng;
    ///
    /// struct SimpleClock;
    /// impl Clock for SimpleClock {
    ///     fn now_ms(&self) -> u64 { 1704067200000 }
    /// }
    ///
    /// let identity = Identity::generate_with_rng(&mut OsRng);
    /// let mut dest = Destination::new(
    ///     Some(identity),
    ///     Direction::In,
    ///     DestinationType::Single,
    ///     "app",
    ///     &["echo"],
    /// ).unwrap();
    ///
    /// let mut ctx = PlatformContext { rng: OsRng, clock: SimpleClock, storage: NoStorage };
    /// dest.enable_ratchets(&mut ctx).unwrap();
    /// assert!(dest.ratchets_enabled());
    /// ```
    pub fn enable_ratchets(&mut self, ctx: &mut impl Context) -> Result<(), DestinationError> {
        if self.direction == Direction::Out {
            return Err(DestinationError::CannotEnableRatchetsOnOut);
        }

        // Generate initial ratchet
        let ratchet = Ratchet::generate(ctx);
        self.last_ratchet_time_ms = ctx.clock().now_ms();
        self.ratchets.insert(0, ratchet);
        self.ratchets_enabled = true;

        Ok(())
    }

    /// Check if ratchets are enabled for this destination
    pub fn ratchets_enabled(&self) -> bool {
        self.ratchets_enabled
    }

    /// Get the current ratchet public key (for announces)
    ///
    /// Returns None if ratchets are not enabled.
    pub fn current_ratchet_public(&self) -> Option<[u8; RATCHET_SIZE]> {
        if !self.ratchets_enabled {
            return None;
        }
        self.ratchets.first().map(|r| r.public_key_bytes())
    }

    /// Rotate ratchet if the interval has passed
    ///
    /// Call this before creating an announce to ensure the ratchet is current.
    ///
    /// # Returns
    /// True if a new ratchet was generated.
    pub fn rotate_ratchet_if_needed(&mut self, ctx: &mut impl Context) -> bool {
        if !self.ratchets_enabled {
            return false;
        }

        let current_time = ctx.clock().now_ms();
        let elapsed = current_time.saturating_sub(self.last_ratchet_time_ms);

        if elapsed < self.ratchet_interval_ms {
            return false;
        }

        // Generate new ratchet and add to front
        let ratchet = Ratchet::generate(ctx);
        self.ratchets.insert(0, ratchet);
        self.last_ratchet_time_ms = current_time;

        // Trim old ratchets if exceeding limit
        if self.ratchets.len() > self.retained_ratchet_count {
            self.ratchets.truncate(self.retained_ratchet_count);
        }

        true
    }

    /// Minimum ratchet interval in milliseconds (1 second)
    const MIN_RATCHET_INTERVAL_MS: u64 = 1000;

    /// Set the ratchet rotation interval
    ///
    /// # Arguments
    /// * `interval_ms` - Rotation interval in milliseconds (default: 30 minutes, minimum: 1 second)
    pub fn set_ratchet_interval(&mut self, interval_ms: u64) {
        self.ratchet_interval_ms = interval_ms.max(Self::MIN_RATCHET_INTERVAL_MS);
    }

    /// Get the current ratchet rotation interval in milliseconds
    pub fn ratchet_interval(&self) -> u64 {
        self.ratchet_interval_ms
    }

    /// Set the maximum number of ratchets to retain
    ///
    /// # Arguments
    /// * `count` - Maximum retained ratchets (default: 512, minimum: 1)
    pub fn set_retained_ratchets(&mut self, count: usize) {
        // Ensure at least 1 ratchet is retained
        self.retained_ratchet_count = count.max(1);

        // Trim if needed
        if self.ratchets.len() > self.retained_ratchet_count {
            self.ratchets.truncate(self.retained_ratchet_count);
        }
    }

    /// Get the number of retained ratchets
    pub fn retained_ratchet_count(&self) -> usize {
        self.retained_ratchet_count
    }

    /// Get the current number of ratchets stored
    pub fn ratchet_count(&self) -> usize {
        self.ratchets.len()
    }

    /// Enforce ratchet-only decryption
    ///
    /// When enabled, packets not encrypted with a ratchet will be rejected
    /// even if they could be decrypted with the identity key.
    pub fn set_enforce_ratchets(&mut self, enforce: bool) {
        self.enforce_ratchets = enforce;
    }

    /// Check if ratchet enforcement is enabled
    pub fn enforces_ratchets(&self) -> bool {
        self.enforce_ratchets
    }

    // ─── Encryption/Decryption ───────────────────────────────────────────────

    /// Decrypt data received at this destination
    ///
    /// Tries decryption with each retained ratchet, then falls back to
    /// the identity key (unless ratchets are enforced).
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data from an incoming packet
    ///
    /// # Returns
    /// Decrypted plaintext on success.
    ///
    /// # Errors
    /// * `NoIdentity` - Destination has no identity
    /// * `DecryptionFailed` - No ratchet or identity key could decrypt
    /// * `RatchetRequired` - Ratchets enforced but decrypted with identity key
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DestinationError> {
        let identity = self.identity.as_ref().ok_or(DestinationError::NoIdentity)?;

        // Always try with identity fallback to know if ratchet was used
        let (plaintext, ratchet_id) =
            identity.decrypt_with_ratchets(ciphertext, &self.ratchets, true)?;

        // If ratchets are enforced and we decrypted without a ratchet, reject
        if self.enforce_ratchets && ratchet_id.is_none() {
            return Err(DestinationError::RatchetRequired);
        }

        Ok(plaintext)
    }

    /// Encrypt data for sending to another destination
    ///
    /// For OUT destinations, encrypts using the target identity and
    /// optionally a known ratchet public key.
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `ratchet_public` - Optional ratchet public key from target's announce
    /// * `ctx` - Platform context providing RNG
    ///
    /// # Returns
    /// Ciphertext that can be decrypted by the target destination.
    ///
    /// # Errors
    /// * `NoIdentity` - Destination has no identity to encrypt for
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        ratchet_public: Option<&[u8; RATCHET_SIZE]>,
        ctx: &mut impl Context,
    ) -> Result<Vec<u8>, DestinationError> {
        let identity = self.identity.as_ref().ok_or(DestinationError::NoIdentity)?;

        Ok(identity.encrypt_for_destination(plaintext, ratchet_public, ctx))
    }

    /// Compute the name hash from app_name and aspects.
    ///
    /// The name hash is the first 10 bytes of SHA256(app_name.aspect1.aspect2...).
    pub fn compute_name_hash(app_name: &str, aspects: &[&str]) -> [u8; NAME_HASHBYTES] {
        let mut full_name = String::from(app_name);
        for aspect in aspects {
            full_name.push('.');
            full_name.push_str(aspect);
        }

        let hash = sha256(full_name.as_bytes());
        let mut name_hash = [0u8; NAME_HASHBYTES];
        name_hash.copy_from_slice(&hash[..NAME_HASHBYTES]);
        name_hash
    }

    /// Compute the destination hash from name_hash and identity_hash.
    ///
    /// destination_hash = truncated_hash(name_hash + identity_hash)
    pub fn compute_destination_hash(
        name_hash: &[u8; NAME_HASHBYTES],
        identity_hash: &[u8; IDENTITY_HASHBYTES],
    ) -> DestinationHash {
        let mut combined = [0u8; NAME_HASHBYTES + IDENTITY_HASHBYTES];
        combined[..NAME_HASHBYTES].copy_from_slice(name_hash);
        combined[NAME_HASHBYTES..].copy_from_slice(identity_hash);
        DestinationHash::new(truncated_hash(&combined))
    }

    /// Create a signed announce packet for this destination.
    ///
    /// Announces inform the network about this destination's presence.
    /// Only IN destinations can announce (they receive traffic).
    ///
    /// If ratchets are enabled, the announce will include the current ratchet
    /// public key and the context_flag will be set. The ratchet will be rotated
    /// if the rotation interval has passed.
    ///
    /// # Arguments
    /// * `app_data` - Optional application-specific data (max ~350 bytes)
    /// * `ctx` - Platform context for RNG and clock
    ///
    /// # Errors
    /// * `OnlySingleCanAnnounce` - Only SINGLE destinations can announce
    /// * `WrongDirection` - OUT destinations cannot announce
    /// * `NoIdentity` - Destination has no identity
    /// * `SigningFailed` - Signature could not be created
    ///
    /// # Example
    /// ```
    /// use reticulum_core::destination::{Destination, DestinationType, Direction};
    /// use reticulum_core::identity::Identity;
    /// use reticulum_core::traits::{PlatformContext, NoStorage};
    /// use rand_core::OsRng;
    ///
    /// struct SimpleClock;
    /// impl reticulum_core::traits::Clock for SimpleClock {
    ///     fn now_ms(&self) -> u64 { 1704067200000 }
    /// }
    ///
    /// let identity = Identity::generate_with_rng(&mut OsRng);
    /// let mut dest = Destination::new(
    ///     Some(identity),
    ///     Direction::In,
    ///     DestinationType::Single,
    ///     "app",
    ///     &["echo"],
    /// ).unwrap();
    ///
    /// let mut ctx = PlatformContext { rng: OsRng, clock: SimpleClock, storage: NoStorage };
    /// let packet = dest.announce(Some(b"my-data"), &mut ctx).unwrap();
    /// assert_eq!(packet.destination_hash, *dest.hash());
    /// ```
    pub fn announce(
        &mut self,
        app_data: Option<&[u8]>,
        ctx: &mut impl Context,
    ) -> Result<Packet, AnnounceError> {
        // Only SINGLE destinations can announce (per Python Reticulum spec)
        if self.dest_type != DestinationType::Single {
            return Err(AnnounceError::OnlySingleCanAnnounce);
        }

        // Only IN destinations can announce
        if self.direction != Direction::In {
            return Err(AnnounceError::WrongDirection);
        }

        // Check identity exists early
        if self.identity.is_none() {
            return Err(AnnounceError::NoIdentity);
        }

        // Rotate ratchet if needed
        self.rotate_ratchet_if_needed(ctx);

        // Get current ratchet (if enabled)
        let ratchet = self.current_ratchet_public();
        let has_ratchet = ratchet.is_some();

        // Get identity (safe because we checked above)
        let identity = self.identity.as_ref().unwrap();

        // Build the signed payload with optional ratchet
        let payload = build_announce_payload(
            identity,
            self.hash.as_bytes(),
            &self.name_hash,
            ratchet.as_ref(),
            app_data,
            ctx,
        )?;

        // Create the packet
        let packet = Packet {
            flags: PacketFlags {
                ifac_flag: false,
                header_type: HeaderType::Type1,
                context_flag: has_ratchet, // Set if ratchet is present
                transport_type: TransportType::Broadcast,
                dest_type: self.dest_type,
                packet_type: PacketType::Announce,
            },
            hops: 0,
            transport_id: None,
            destination_hash: self.hash.into_bytes(),
            context: PacketContext::None,
            data: PacketData::Owned(payload),
        };

        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::announce::ReceivedAnnounce;
    use crate::traits::{NoStorage, PlatformContext};
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

    #[test]
    fn test_destination_creation() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "test",
            &["echo"],
        )
        .unwrap();

        assert_eq!(dest.dest_type(), DestinationType::Single);
        assert_eq!(dest.direction(), Direction::In);
        assert_eq!(dest.hash().as_bytes().len(), TRUNCATED_HASHBYTES);
    }

    #[test]
    fn test_name_hash() {
        let hash1 = Destination::compute_name_hash("app", &["aspect1"]);
        let hash2 = Destination::compute_name_hash("app", &["aspect2"]);
        let hash3 = Destination::compute_name_hash("app", &["aspect1"]);

        assert_ne!(hash1, hash2);
        assert_eq!(hash1, hash3);
    }

    #[test]
    fn test_destination_type_conversion() {
        assert_eq!(DestinationType::try_from(0x00), Ok(DestinationType::Single));
        assert_eq!(DestinationType::try_from(0x01), Ok(DestinationType::Group));
        assert_eq!(DestinationType::try_from(0x02), Ok(DestinationType::Plain));
        assert_eq!(DestinationType::try_from(0x03), Ok(DestinationType::Link));
        assert_eq!(DestinationType::try_from(0x04), Err(()));
    }

    #[test]
    fn test_destination_announce_creates_valid_packet() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["echo"],
        )
        .unwrap();

        let mut ctx = make_context();
        let packet = dest.announce(Some(b"hello"), &mut ctx).unwrap();

        // Verify packet structure
        assert_eq!(packet.flags.packet_type, PacketType::Announce);
        assert_eq!(packet.flags.transport_type, TransportType::Broadcast);
        assert_eq!(packet.flags.dest_type, DestinationType::Single);
        assert_eq!(packet.flags.header_type, HeaderType::Type1);
        assert!(!packet.flags.context_flag); // No ratchet
        assert_eq!(packet.hops, 0);
        assert_eq!(packet.destination_hash, *dest.hash());

        // Parse and verify the announce
        let announce = ReceivedAnnounce::from_packet(&packet).unwrap();
        assert!(announce.verify_destination_hash());
        assert!(announce.verify_signature().unwrap());
        assert_eq!(announce.app_data(), b"hello");
    }

    #[test]
    fn test_destination_announce_out_direction_fails() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::Out, // OUT cannot announce
            DestinationType::Single,
            "testapp",
            &["echo"],
        )
        .unwrap();

        let mut ctx = make_context();
        let result = dest.announce(None, &mut ctx);

        assert!(matches!(result, Err(AnnounceError::WrongDirection)));
    }

    #[test]
    fn test_destination_announce_plain_type_fails() {
        // PLAIN destinations cannot announce (only SINGLE can)
        let mut dest = Destination::new(
            None, // No identity (valid for PLAIN)
            Direction::In,
            DestinationType::Plain,
            "testapp",
            &["echo"],
        )
        .unwrap();

        let mut ctx = make_context();
        let result = dest.announce(None, &mut ctx);

        // PLAIN destinations can't announce - OnlySingleCanAnnounce takes priority
        assert!(matches!(result, Err(AnnounceError::OnlySingleCanAnnounce)));
    }

    #[test]
    fn test_destination_announce_without_app_data() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["echo"],
        )
        .unwrap();

        let mut ctx = make_context();
        let packet = dest.announce(None, &mut ctx).unwrap();

        let announce = ReceivedAnnounce::from_packet(&packet).unwrap();
        assert!(announce.app_data().is_empty());
        assert!(announce.validate().is_ok());
    }

    #[test]
    fn test_destination_announce_validates_correctly() {
        // Create destination and announce
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "myapp",
            &["service", "v1"],
        )
        .unwrap();

        let mut ctx = make_context();
        let packet = dest.announce(Some(b"app-data"), &mut ctx).unwrap();

        // Full validation should pass
        let announce = ReceivedAnnounce::from_packet(&packet).unwrap();
        assert!(announce.validate().is_ok());

        // Computed hashes should match
        assert_eq!(announce.computed_destination_hash(), *dest.hash());
    }

    // ─── Spec Compliance Tests ─────────────────────────────────────────────────

    #[test]
    fn test_plain_destination_cannot_have_identity() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let result = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Plain,
            "test",
            &["echo"],
        );
        assert!(matches!(
            result,
            Err(DestinationError::PlainCannotHaveIdentity)
        ));
    }

    #[test]
    fn test_plain_destination_without_identity_succeeds() {
        let result = Destination::new(
            None,
            Direction::In,
            DestinationType::Plain,
            "test",
            &["echo"],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_single_out_requires_identity() {
        let result = Destination::new(
            None,
            Direction::Out,
            DestinationType::Single,
            "test",
            &["echo"],
        );
        assert!(matches!(
            result,
            Err(DestinationError::OutboundRequiresIdentity)
        ));
    }

    #[test]
    fn test_group_out_requires_identity() {
        let result = Destination::new(
            None,
            Direction::Out,
            DestinationType::Group,
            "test",
            &["echo"],
        );
        assert!(matches!(
            result,
            Err(DestinationError::OutboundRequiresIdentity)
        ));
    }

    #[test]
    fn test_only_single_can_announce() {
        let identity = Identity::generate_with_rng(&mut OsRng);

        // GROUP destination cannot announce
        let mut group_dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Group,
            "test",
            &["echo"],
        )
        .unwrap();

        let mut ctx = make_context();
        let result = group_dest.announce(None, &mut ctx);
        assert!(matches!(result, Err(AnnounceError::OnlySingleCanAnnounce)));
    }

    #[test]
    fn test_single_in_can_announce() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "test",
            &["echo"],
        )
        .unwrap();

        let mut ctx = make_context();
        let result = dest.announce(None, &mut ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_plain_out_allowed_without_identity() {
        // PLAIN OUT is valid without identity (for local broadcast)
        let result = Destination::new(
            None,
            Direction::Out,
            DestinationType::Plain,
            "test",
            &["broadcast"],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_single_in_without_identity_allowed() {
        // SINGLE IN can exist without identity initially
        // (auto-creation would happen in a full implementation)
        let result = Destination::new(
            None,
            Direction::In,
            DestinationType::Single,
            "test",
            &["echo"],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_group_in_allowed_with_identity() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let result = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Group,
            "test",
            &["broadcast"],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_link_type_allowed_without_identity() {
        // LINK type is internal use, allowing various configs
        let result = Destination::new(
            None,
            Direction::In,
            DestinationType::Link,
            "test",
            &["link"],
        );
        assert!(result.is_ok());
    }

    // ─── Ratchet Tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_enable_ratchets() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "test",
            &["ratchet"],
        )
        .unwrap();

        assert!(!dest.ratchets_enabled());
        assert!(dest.current_ratchet_public().is_none());
        assert_eq!(dest.ratchet_count(), 0);

        let mut ctx = make_context();
        dest.enable_ratchets(&mut ctx).unwrap();

        assert!(dest.ratchets_enabled());
        assert!(dest.current_ratchet_public().is_some());
        assert_eq!(dest.ratchet_count(), 1);
    }

    #[test]
    fn test_enable_ratchets_on_out_fails() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::Out,
            DestinationType::Single,
            "test",
            &["ratchet"],
        )
        .unwrap();

        let mut ctx = make_context();
        let result = dest.enable_ratchets(&mut ctx);

        assert!(matches!(
            result,
            Err(DestinationError::CannotEnableRatchetsOnOut)
        ));
    }

    #[test]
    fn test_ratchet_rotation() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "test",
            &["ratchet"],
        )
        .unwrap();

        // Use a shorter interval for testing
        dest.set_ratchet_interval(1000); // 1 second

        let mut ctx = make_context();
        dest.enable_ratchets(&mut ctx).unwrap();

        let first_ratchet = dest.current_ratchet_public().unwrap();

        // No rotation needed yet
        assert!(!dest.rotate_ratchet_if_needed(&mut ctx));
        assert_eq!(dest.current_ratchet_public().unwrap(), first_ratchet);

        // Advance time past interval
        ctx.clock.0 += 2000; // 2 seconds later

        // Rotation should happen
        assert!(dest.rotate_ratchet_if_needed(&mut ctx));
        let second_ratchet = dest.current_ratchet_public().unwrap();
        assert_ne!(first_ratchet, second_ratchet);

        // Old ratchet should still be retained
        assert_eq!(dest.ratchet_count(), 2);
    }

    #[test]
    fn test_retained_ratchet_limit() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "test",
            &["ratchet"],
        )
        .unwrap();

        // Set small limit for testing
        dest.set_retained_ratchets(3);
        dest.set_ratchet_interval(1000);

        let mut ctx = make_context();
        dest.enable_ratchets(&mut ctx).unwrap();
        assert_eq!(dest.ratchet_count(), 1);

        // Rotate 5 times
        for _ in 1..=5 {
            ctx.clock.0 += 2000;
            dest.rotate_ratchet_if_needed(&mut ctx);
        }

        // Should only have 3 ratchets (limit enforced)
        assert_eq!(dest.ratchet_count(), 3);
    }

    #[test]
    fn test_encrypt_decrypt_with_ratchet() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "test",
            &["ratchet"],
        )
        .unwrap();

        let mut ctx = make_context();
        dest.enable_ratchets(&mut ctx).unwrap();

        // Get ratchet public key (simulating what a sender would get from announce)
        let ratchet_pub = dest.current_ratchet_public().unwrap();

        // Encrypt using the destination's identity and ratchet
        let plaintext = b"Hello with forward secrecy!";
        let ciphertext = dest
            .encrypt(plaintext, Some(&ratchet_pub), &mut ctx)
            .unwrap();

        // Decrypt
        let decrypted = dest.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_decrypt_with_old_ratchet() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "test",
            &["ratchet"],
        )
        .unwrap();

        dest.set_ratchet_interval(1000);

        let mut ctx = make_context();
        dest.enable_ratchets(&mut ctx).unwrap();

        // Encrypt with current ratchet
        let first_ratchet = dest.current_ratchet_public().unwrap();
        let plaintext = b"Message encrypted with first ratchet";
        let ciphertext = dest
            .encrypt(plaintext, Some(&first_ratchet), &mut ctx)
            .unwrap();

        // Rotate ratchet
        ctx.clock.0 += 2000;
        dest.rotate_ratchet_if_needed(&mut ctx);

        // Should still be able to decrypt with old ratchet
        let decrypted = dest.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_enforce_ratchets() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "test",
            &["ratchet"],
        )
        .unwrap();

        let mut ctx = make_context();
        dest.enable_ratchets(&mut ctx).unwrap();
        dest.set_enforce_ratchets(true);

        // Encrypt WITHOUT ratchet (using identity key)
        let plaintext = b"No ratchet used";
        let ciphertext = dest.encrypt(plaintext, None, &mut ctx).unwrap();

        // Should fail because ratchets are enforced
        let result = dest.decrypt(&ciphertext);
        assert!(matches!(result, Err(DestinationError::RatchetRequired)));
    }

    #[test]
    fn test_decrypt_without_ratchet_when_not_enforced() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "test",
            &["ratchet"],
        )
        .unwrap();

        let mut ctx = make_context();
        dest.enable_ratchets(&mut ctx).unwrap();

        // Encrypt WITHOUT ratchet (using identity key)
        let plaintext = b"No ratchet used";
        let ciphertext = dest.encrypt(plaintext, None, &mut ctx).unwrap();

        // Should succeed because ratchets are not enforced
        let decrypted = dest.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_ratchet_settings() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "test",
            &["ratchet"],
        )
        .unwrap();

        // Test default settings
        assert_eq!(dest.ratchet_interval(), DEFAULT_INTERVAL_MS);
        assert_eq!(dest.retained_ratchet_count(), DEFAULT_RETAINED_RATCHETS);
        assert!(!dest.enforces_ratchets());

        // Change settings
        dest.set_ratchet_interval(60000);
        dest.set_retained_ratchets(100);
        dest.set_enforce_ratchets(true);

        assert_eq!(dest.ratchet_interval(), 60000);
        assert_eq!(dest.retained_ratchet_count(), 100);
        assert!(dest.enforces_ratchets());
    }

    #[test]
    fn test_no_rotation_when_ratchets_disabled() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "test",
            &["ratchet"],
        )
        .unwrap();

        let mut ctx = make_context();

        // Don't enable ratchets
        ctx.clock.0 += 100000000; // Far in future
        assert!(!dest.rotate_ratchet_if_needed(&mut ctx));
    }

    // ─── Ratcheted Announce Tests ──────────────────────────────────────────────

    #[test]
    fn test_announce_with_ratchet() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "test",
            &["ratchet"],
        )
        .unwrap();

        let mut ctx = make_context();
        dest.enable_ratchets(&mut ctx).unwrap();

        let packet = dest.announce(Some(b"test-data"), &mut ctx).unwrap();

        // context_flag should be set
        assert!(packet.flags.context_flag);

        // Parse and verify
        let announce = ReceivedAnnounce::from_packet(&packet).unwrap();
        assert!(announce.has_ratchet());
        assert!(announce.validate().is_ok());
        assert_eq!(announce.app_data(), b"test-data");

        // Ratchet in announce should match destination's current ratchet
        assert_eq!(
            announce.ratchet().unwrap(),
            &dest.current_ratchet_public().unwrap()
        );
    }

    #[test]
    fn test_announce_without_ratchet_when_disabled() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "test",
            &["noratchet"],
        )
        .unwrap();

        let mut ctx = make_context();
        // Don't enable ratchets

        let packet = dest.announce(Some(b"test-data"), &mut ctx).unwrap();

        // context_flag should NOT be set
        assert!(!packet.flags.context_flag);

        // Parse and verify
        let announce = ReceivedAnnounce::from_packet(&packet).unwrap();
        assert!(!announce.has_ratchet());
        assert!(announce.ratchet().is_none());
        assert!(announce.validate().is_ok());
    }

    #[test]
    fn test_announce_rotates_ratchet() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "test",
            &["ratchet"],
        )
        .unwrap();

        dest.set_ratchet_interval(1000);

        let mut ctx = make_context();
        dest.enable_ratchets(&mut ctx).unwrap();

        let first_ratchet = dest.current_ratchet_public().unwrap();

        // First announce - uses first ratchet
        let packet1 = dest.announce(None, &mut ctx).unwrap();
        let announce1 = ReceivedAnnounce::from_packet(&packet1).unwrap();
        assert_eq!(announce1.ratchet().unwrap(), &first_ratchet);

        // Advance time to trigger rotation
        ctx.clock.0 += 2000;

        // Second announce - should rotate and use new ratchet
        let packet2 = dest.announce(None, &mut ctx).unwrap();
        let announce2 = ReceivedAnnounce::from_packet(&packet2).unwrap();

        let second_ratchet = dest.current_ratchet_public().unwrap();
        assert_ne!(first_ratchet, second_ratchet);
        assert_eq!(announce2.ratchet().unwrap(), &second_ratchet);
    }

    // ─── Proof Strategy Tests ────────────────────────────────────────────────────

    #[test]
    fn test_proof_strategy_default() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "test",
            &["proof"],
        )
        .unwrap();

        assert_eq!(dest.proof_strategy(), ProofStrategy::None);
    }

    #[test]
    fn test_proof_strategy_setter() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "test",
            &["proof"],
        )
        .unwrap();

        dest.set_proof_strategy(ProofStrategy::All);
        assert_eq!(dest.proof_strategy(), ProofStrategy::All);

        dest.set_proof_strategy(ProofStrategy::App);
        assert_eq!(dest.proof_strategy(), ProofStrategy::App);

        dest.set_proof_strategy(ProofStrategy::None);
        assert_eq!(dest.proof_strategy(), ProofStrategy::None);
    }

    #[test]
    fn test_proof_strategy_enum_values() {
        // Verify the enum values match the protocol constants
        assert_eq!(ProofStrategy::None as u8, 0x21);
        assert_eq!(ProofStrategy::App as u8, 0x22);
        assert_eq!(ProofStrategy::All as u8, 0x23);
    }

    // ─── DestinationHash Tests ────────────────────────────────────────────────

    #[test]
    fn test_destination_hash_construction() {
        let bytes = [0x42u8; 16];
        let hash = DestinationHash::new(bytes);
        assert_eq!(*hash.as_bytes(), bytes);
    }

    #[test]
    fn test_destination_hash_into_bytes_roundtrip() {
        let bytes = [0xAB; 16];
        let hash = DestinationHash::new(bytes);
        assert_eq!(hash.into_bytes(), bytes);
    }

    #[test]
    fn test_destination_hash_from_array() {
        let bytes = [0x01; 16];
        let hash: DestinationHash = bytes.into();
        assert_eq!(*hash.as_bytes(), bytes);

        let back: [u8; 16] = hash.into();
        assert_eq!(back, bytes);
    }

    #[test]
    fn test_destination_hash_display() {
        let hash = DestinationHash::new([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ]);
        let display = alloc::format!("{}", hash);
        assert_eq!(display, "0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn test_destination_hash_debug() {
        let hash = DestinationHash::new([0xAA; 16]);
        let debug = alloc::format!("{:?}", hash);
        assert!(debug.starts_with("DestinationHash("));
        assert!(debug.contains("aa"));
    }

    #[test]
    fn test_destination_hash_equality_with_raw() {
        let bytes = [0x42; 16];
        let hash = DestinationHash::new(bytes);
        assert_eq!(hash, bytes);
        assert_eq!(bytes, hash);
    }

    #[test]
    fn test_destination_hash_inequality() {
        let hash1 = DestinationHash::new([0x01; 16]);
        let hash2 = DestinationHash::new([0x02; 16]);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_destination_hash_as_ref() {
        let hash = DestinationHash::new([0x42; 16]);
        let slice: &[u8] = hash.as_ref();
        assert_eq!(slice.len(), 16);
        assert_eq!(slice[0], 0x42);

        let arr_ref: &[u8; 16] = hash.as_ref();
        assert_eq!(*arr_ref, [0x42; 16]);
    }

    #[test]
    fn test_destination_hash_borrow() {
        use core::borrow::Borrow;
        let hash = DestinationHash::new([0x42; 16]);
        let borrowed: &[u8; 16] = hash.borrow();
        assert_eq!(*borrowed, [0x42; 16]);
    }

    #[test]
    fn test_destination_hash_ord() {
        let hash1 = DestinationHash::new([0x01; 16]);
        let hash2 = DestinationHash::new([0x02; 16]);
        assert!(hash1 < hash2);
    }

    #[test]
    fn test_destination_hash_copy() {
        let hash1 = DestinationHash::new([0x42; 16]);
        let hash2 = hash1; // Copy
        assert_eq!(hash1, hash2); // Original still usable
    }

    #[test]
    fn test_destination_hash_is_different_type_from_link_id() {
        use crate::link::LinkId;
        let bytes = [0x42; 16];
        let _dest_hash = DestinationHash::new(bytes);
        let _link_id = LinkId::new(bytes);
        // These are different types - compiler prevents mixing them
        // (No PartialEq<LinkId> for DestinationHash or vice versa)
    }

    #[test]
    fn test_destination_hash_btreemap_key() {
        use alloc::collections::BTreeMap;
        let mut map = BTreeMap::new();
        let hash = DestinationHash::new([0x42; 16]);
        map.insert(hash, "test");
        assert_eq!(map.get(&hash), Some(&"test"));
        // Lookup via raw bytes via Borrow
        assert_eq!(map.get(&[0x42u8; 16]), Some(&"test"));
    }
}
