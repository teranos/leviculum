//! Point-to-point verified connections
//!
//! Links provide:
//! - Verified, encrypted communication channels
//! - Perfect forward secrecy via ephemeral keys
//! - Bidirectional data transfer
//! - Keepalive and timeout management

use crate::constants::{
    IDENTITY_KEY_SIZE, LINK_KEEPALIVE_SECS, LINK_STALE_TIME_SECS, TRUNCATED_HASHBYTES,
    X25519_KEY_SIZE,
};

/// Link state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// Link request sent, waiting for proof
    Pending,
    /// Handshake in progress
    Handshake,
    /// Link established and active
    Active,
    /// Link inactive for too long
    Stale,
    /// Link closed
    Closed,
}

/// Link establishment error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    /// Invalid state for operation
    InvalidState,
    /// Timeout waiting for response
    Timeout,
    /// Invalid proof received
    InvalidProof,
    /// Key exchange failed
    KeyExchangeFailed,
    /// No destination
    NoDestination,
}

/// Link identifier (8 bytes)
pub type LinkId = [u8; 8];

/// A verified point-to-point link
pub struct Link {
    /// Link identifier
    id: LinkId,
    /// Current state
    state: LinkState,
    /// Our ephemeral X25519 private key
    ephemeral_private: Option<x25519_dalek::StaticSecret>,
    /// Our ephemeral X25519 public key
    ephemeral_public: x25519_dalek::PublicKey,
    /// Our ephemeral Ed25519 signing key
    signing_key: Option<ed25519_dalek::SigningKey>,
    /// Our ephemeral Ed25519 verifying key
    verifying_key: ed25519_dalek::VerifyingKey,
    /// Peer's ephemeral public key (after handshake)
    peer_ephemeral_public: Option<x25519_dalek::PublicKey>,
    /// Peer's verifying key (after handshake)
    peer_verifying_key: Option<ed25519_dalek::VerifyingKey>,
    /// Derived link encryption key (64 bytes: 32 encrypt + 32 HMAC)
    link_key: Option<[u8; 64]>,
    /// Destination hash this link connects to
    destination_hash: [u8; TRUNCATED_HASHBYTES],
    /// Whether we initiated this link
    initiator: bool,
    /// Hop count to destination
    hops: u8,
    /// Round-trip time estimate (microseconds)
    rtt_us: Option<u64>,
    /// Keepalive interval in seconds
    keepalive_secs: u64,
    /// Time of last inbound packet (timestamp)
    last_inbound: u64,
    /// Time of last outbound packet (timestamp)
    last_outbound: u64,
    /// When the link was established (timestamp)
    established_at: Option<u64>,
    // TODO: Add MTU discovery
    // TODO: Add callbacks
}

impl Link {
    /// Create a new outgoing link (initiator side)
    #[cfg(feature = "std")]
    pub fn new_outgoing(destination_hash: [u8; TRUNCATED_HASHBYTES]) -> Self {
        use rand_core::OsRng;
        Self::new_outgoing_with_rng(destination_hash, &mut OsRng)
    }

    /// Create a new outgoing link with a provided RNG
    pub fn new_outgoing_with_rng<R: rand_core::CryptoRngCore>(
        destination_hash: [u8; TRUNCATED_HASHBYTES],
        rng: &mut R,
    ) -> Self {
        use rand_core::RngCore;

        let ephemeral_private = x25519_dalek::StaticSecret::random_from_rng(&mut *rng);
        let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_private);

        // Generate Ed25519 key from random bytes
        let mut ed25519_seed = [0u8; 32];
        rng.fill_bytes(&mut ed25519_seed);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&ed25519_seed);
        let verifying_key = signing_key.verifying_key();

        // Temporary link ID (will be finalized after handshake)
        let mut id = [0u8; 8];
        rng.fill_bytes(&mut id);

        Self {
            id,
            state: LinkState::Pending,
            ephemeral_private: Some(ephemeral_private),
            ephemeral_public,
            signing_key: Some(signing_key),
            verifying_key,
            peer_ephemeral_public: None,
            peer_verifying_key: None,
            link_key: None,
            destination_hash,
            initiator: true,
            hops: 0,
            rtt_us: None,
            keepalive_secs: LINK_KEEPALIVE_SECS,
            last_inbound: 0,
            last_outbound: 0,
            established_at: None,
        }
    }

    /// Get the link ID
    pub fn id(&self) -> &LinkId {
        &self.id
    }

    /// Get the current state
    pub fn state(&self) -> LinkState {
        self.state
    }

    /// Get the destination hash
    pub fn destination_hash(&self) -> &[u8; TRUNCATED_HASHBYTES] {
        &self.destination_hash
    }

    /// Check if we initiated this link
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    /// Get the hop count
    pub fn hops(&self) -> u8 {
        self.hops
    }

    /// Get the RTT estimate in microseconds
    pub fn rtt_us(&self) -> Option<u64> {
        self.rtt_us
    }

    /// Get the RTT estimate in seconds
    pub fn rtt_secs(&self) -> Option<f64> {
        self.rtt_us.map(|us| us as f64 / 1_000_000.0)
    }

    /// Get our ephemeral public key bytes for the link request
    pub fn ephemeral_public_bytes(&self) -> [u8; X25519_KEY_SIZE] {
        *self.ephemeral_public.as_bytes()
    }

    /// Get our signing verifying key bytes for the link request
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Create the link request data
    /// Format: [ephemeral_pub (32)] [sig_pub (32)] [mtu_signaling (3)]
    pub fn create_link_request(&self) -> [u8; 67] {
        let mut data = [0u8; 67];
        data[..32].copy_from_slice(self.ephemeral_public.as_bytes());
        data[32..64].copy_from_slice(&self.verifying_key.to_bytes());
        // MTU signaling bytes (reserved for future use)
        data[64] = 0;
        data[65] = 0;
        data[66] = 0;
        data
    }

    /// Check if the link is active
    pub fn is_active(&self) -> bool {
        self.state == LinkState::Active
    }

    /// Check if the link should be considered stale
    pub fn is_stale(&self, current_time: u64) -> bool {
        if self.state != LinkState::Active {
            return false;
        }
        let elapsed = current_time.saturating_sub(self.last_inbound);
        elapsed > LINK_STALE_TIME_SECS
    }

    // TODO: Implement process_link_proof
    // TODO: Implement key derivation
    // TODO: Implement encrypt/decrypt
    // TODO: Implement keepalive sending
    // TODO: Implement timeout checking
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "std")]
    #[test]
    fn test_link_creation() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let link = Link::new_outgoing(dest_hash);

        assert_eq!(link.state(), LinkState::Pending);
        assert!(link.is_initiator());
        assert_eq!(link.destination_hash(), &dest_hash);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_link_request_data() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let link = Link::new_outgoing(dest_hash);

        let request = link.create_link_request();
        assert_eq!(request.len(), 67);

        // Check that keys are embedded
        assert_eq!(&request[..32], link.ephemeral_public.as_bytes());
        assert_eq!(&request[32..64], &link.verifying_key.to_bytes());
    }
}
