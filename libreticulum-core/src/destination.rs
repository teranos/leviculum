//! Network endpoint addressing
//!
//! A Destination represents an addressable endpoint in the Reticulum network.
//! Destinations have:
//! - A unique hash derived from application name, aspects, and identity
//! - A type (SINGLE, GROUP, PLAIN, LINK) determining encryption behavior
//! - A direction (IN, OUT) determining receive/send capability

use crate::constants::{IDENTITY_HASHBYTES, NAME_HASHBYTES, TRUNCATED_HASHBYTES};
use crate::crypto::{sha256, truncated_hash};
use crate::identity::Identity;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

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
    #[cfg(feature = "alloc")]
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

    /// Compute the name hash from app_name and aspects
    #[cfg(feature = "alloc")]
    fn compute_name_hash(app_name: &str, aspects: &[&str]) -> [u8; NAME_HASHBYTES] {
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

    /// Compute the destination hash from name_hash and identity_hash
    fn compute_destination_hash(
        name_hash: &[u8; NAME_HASHBYTES],
        identity_hash: &[u8; IDENTITY_HASHBYTES],
    ) -> [u8; TRUNCATED_HASHBYTES] {
        let mut combined = [0u8; NAME_HASHBYTES + IDENTITY_HASHBYTES];
        combined[..NAME_HASHBYTES].copy_from_slice(name_hash);
        combined[NAME_HASHBYTES..].copy_from_slice(identity_hash);
        truncated_hash(&combined)
    }

    // TODO: Implement encrypt/decrypt methods
    // TODO: Implement announce method
    // TODO: Implement callback registration
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "std", feature = "alloc"))]
    #[test]
    fn test_destination_creation() {
        let identity = Identity::new();
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

    #[cfg(feature = "alloc")]
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
}
