//! Network endpoint addressing
//!
//! A Destination represents an addressable endpoint in the Reticulum network.
//! Destinations have:
//! - A unique hash derived from application name, aspects, and identity
//! - A type (SINGLE, GROUP, PLAIN, LINK) determining encryption behavior
//! - A direction (IN, OUT) determining receive/send capability

use crate::announce::{build_announce_payload, AnnounceError};
use crate::constants::{IDENTITY_HASHBYTES, NAME_HASHBYTES, TRUNCATED_HASHBYTES};
use crate::crypto::{sha256, truncated_hash};
use crate::identity::Identity;
use crate::packet::{
    HeaderType, Packet, PacketContext, PacketData, PacketFlags, PacketType, TransportType,
};
use crate::traits::Context;

use alloc::string::String;

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

/// A network destination (endpoint)
pub struct Destination {
    /// The destination hash (address)
    hash: [u8; TRUNCATED_HASHBYTES],
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
    // TODO: Add callback handlers
    // TODO: Add ratchet support
    // TODO: Add request handlers
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
    pub fn new(
        identity: Option<Identity>,
        direction: Direction,
        dest_type: DestinationType,
        app_name: &str,
        aspects: &[&str],
    ) -> Self {
        let name_hash = Self::compute_name_hash(app_name, aspects);

        let hash = match &identity {
            Some(id) => Self::compute_destination_hash(&name_hash, id.hash()),
            None => {
                // For PLAIN destinations without identity, hash is just name_hash padded
                let mut h = [0u8; TRUNCATED_HASHBYTES];
                h[..NAME_HASHBYTES].copy_from_slice(&name_hash);
                h
            }
        };

        Self {
            hash,
            name_hash,
            identity,
            dest_type,
            direction,
            accepts_links: false,
        }
    }

    /// Get the destination hash
    pub fn hash(&self) -> &[u8; TRUNCATED_HASHBYTES] {
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
    ) -> [u8; TRUNCATED_HASHBYTES] {
        let mut combined = [0u8; NAME_HASHBYTES + IDENTITY_HASHBYTES];
        combined[..NAME_HASHBYTES].copy_from_slice(name_hash);
        combined[NAME_HASHBYTES..].copy_from_slice(identity_hash);
        truncated_hash(&combined)
    }

    /// Create a signed announce packet for this destination.
    ///
    /// Announces inform the network about this destination's presence.
    /// Only IN destinations can announce (they receive traffic).
    ///
    /// # Arguments
    /// * `app_data` - Optional application-specific data (max ~350 bytes)
    /// * `ctx` - Platform context for RNG and clock
    ///
    /// # Errors
    /// * `NoIdentity` - Destination has no identity (PLAIN type)
    /// * `WrongDirection` - OUT destinations cannot announce
    /// * `SigningFailed` - Signature could not be created
    ///
    /// # Example
    /// ```ignore
    /// let dest = Destination::new(Some(identity), Direction::In,
    ///                             DestinationType::Single, "app", &["echo"]);
    /// let packet = dest.announce(Some(b"my-data"), &mut ctx)?;
    /// transport.send_packet(packet)?;
    /// ```
    pub fn announce(
        &self,
        app_data: Option<&[u8]>,
        ctx: &mut impl Context,
    ) -> Result<Packet, AnnounceError> {
        // Only IN destinations can announce
        if self.direction != Direction::In {
            return Err(AnnounceError::WrongDirection);
        }

        // Must have an identity to sign the announce
        let identity = self.identity.as_ref().ok_or(AnnounceError::NoIdentity)?;

        // Build the signed payload
        let payload = build_announce_payload(identity, &self.hash, &self.name_hash, app_data, ctx)?;

        // Create the packet
        let packet = Packet {
            flags: PacketFlags {
                header_type: HeaderType::Type1,
                context_flag: false, // No ratchet (for now)
                transport_type: TransportType::Broadcast,
                dest_type: self.dest_type,
                packet_type: PacketType::Announce,
            },
            hops: 0,
            transport_id: None,
            destination_hash: self.hash,
            context: PacketContext::None,
            data: PacketData::Owned(payload),
        };

        Ok(packet)
    }

    // TODO: Implement encrypt/decrypt methods
    // TODO: Implement callback registration
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
        );

        assert_eq!(dest.dest_type(), DestinationType::Single);
        assert_eq!(dest.direction(), Direction::In);
        assert_eq!(dest.hash().len(), TRUNCATED_HASHBYTES);
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
        let dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["echo"],
        );

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
        let dest = Destination::new(
            Some(identity),
            Direction::Out, // OUT cannot announce
            DestinationType::Single,
            "testapp",
            &["echo"],
        );

        let mut ctx = make_context();
        let result = dest.announce(None, &mut ctx);

        assert!(matches!(result, Err(AnnounceError::WrongDirection)));
    }

    #[test]
    fn test_destination_announce_no_identity_fails() {
        let dest = Destination::new(
            None, // No identity
            Direction::In,
            DestinationType::Plain,
            "testapp",
            &["echo"],
        );

        let mut ctx = make_context();
        let result = dest.announce(None, &mut ctx);

        assert!(matches!(result, Err(AnnounceError::NoIdentity)));
    }

    #[test]
    fn test_destination_announce_without_app_data() {
        let identity = Identity::generate_with_rng(&mut OsRng);
        let dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["echo"],
        );

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
        let dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "myapp",
            &["service", "v1"],
        );

        let mut ctx = make_context();
        let packet = dest.announce(Some(b"app-data"), &mut ctx).unwrap();

        // Full validation should pass
        let announce = ReceivedAnnounce::from_packet(&packet).unwrap();
        assert!(announce.validate().is_ok());

        // Computed hashes should match
        assert_eq!(announce.computed_destination_hash(), *dest.hash());
    }
}
