//! Point-to-point verified connections
//!
//! Links provide:
//! - Verified, encrypted communication channels
//! - Perfect forward secrecy via ephemeral keys
//! - Bidirectional data transfer
//! - Keepalive and timeout management

use crate::constants::{
    ED25519_SIGNATURE_SIZE, LINK_KEEPALIVE_SECS, LINK_STALE_TIME_SECS, TRUNCATED_HASHBYTES,
    X25519_KEY_SIZE,
};
use crate::crypto::{derive_key, truncated_hash};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

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

/// Link identifier (16 bytes - truncated hash)
pub type LinkId = [u8; TRUNCATED_HASHBYTES];

/// A verified point-to-point link
#[allow(dead_code)] // Fields for future link management features
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
        let ephemeral_private = x25519_dalek::StaticSecret::random_from_rng(&mut *rng);
        let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_private);

        // Generate Ed25519 key from random bytes
        let mut ed25519_seed = [0u8; 32];
        rng.fill_bytes(&mut ed25519_seed);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&ed25519_seed);
        let verifying_key = signing_key.verifying_key();

        // Temporary link ID (will be set properly after receiving proof)
        let id = [0u8; TRUNCATED_HASHBYTES];

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

    /// Create the link request data without MTU signaling
    /// Format: [ephemeral_pub (32)] [sig_pub (32)]
    pub fn create_link_request(&self) -> [u8; 64] {
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(self.ephemeral_public.as_bytes());
        data[32..64].copy_from_slice(&self.verifying_key.to_bytes());
        data
    }

    /// Create the link request data with MTU signaling
    /// Format: [ephemeral_pub (32)] [sig_pub (32)] [mtu_signaling (3)]
    pub fn create_link_request_with_mtu(&self, mtu: u32, mode: u8) -> [u8; 67] {
        let mut data = [0u8; 67];
        data[..32].copy_from_slice(self.ephemeral_public.as_bytes());
        data[32..64].copy_from_slice(&self.verifying_key.to_bytes());
        // MTU signaling: 21-bit MTU + 3-bit mode
        let signaling = (mtu & 0x1FFFFF) | ((mode as u32 & 0x07) << 21);
        let bytes = signaling.to_be_bytes();
        data[64] = bytes[1];
        data[65] = bytes[2];
        data[66] = bytes[3];
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

    /// Calculate link ID from the raw packet bytes
    ///
    /// Python RNS calculates link_id as:
    /// ```python
    /// hashable_part = bytes([raw[0] & 0x0F]) + raw[2:]
    /// # Remove signalling bytes if present (payload > 64 bytes)
    /// link_id = truncated_hash(hashable_part)
    /// ```
    ///
    /// The raw_packet is: [flags (1)] [hops (1)] [dest_hash (16)] [context (1)] [payload (64-67)]
    pub fn calculate_link_id(raw_packet: &[u8]) -> LinkId {
        // Build hashable part: (flags & 0x0F) + raw[2:]
        let mut hashable = Vec::with_capacity(raw_packet.len() - 1);
        hashable.push(raw_packet[0] & 0x0F);
        hashable.extend_from_slice(&raw_packet[2..]);

        // If payload has signalling bytes (packet > 83 bytes), remove them
        // Packet structure: flags(1) + hops(1) + dest_hash(16) + context(1) + payload(64+)
        // Minimum packet size with 64-byte payload = 83 bytes
        let payload_offset = 1 + 1 + TRUNCATED_HASHBYTES + 1; // 19 bytes
        let payload_len = raw_packet.len() - payload_offset;
        if payload_len > 64 {
            let diff = payload_len - 64;
            hashable.truncate(hashable.len() - diff);
        }

        truncated_hash(&hashable)
    }

    /// Set the link ID (called after calculating it from the sent packet)
    pub fn set_link_id(&mut self, link_id: LinkId) {
        self.id = link_id;
    }

    /// Process a link proof from the destination
    ///
    /// PROOF format: [signature (64)] [peer_ephemeral_pub (32)] [signaling (0-3)]
    ///
    /// Returns Ok(()) if proof is valid and keys are derived
    pub fn process_proof(&mut self, proof_data: &[u8]) -> Result<(), LinkError> {
        use ed25519_dalek::Verifier;

        if self.state != LinkState::Pending {
            return Err(LinkError::InvalidState);
        }

        // Proof format: signature (64) + X25519_pub (32) + signalling (3) = 99 bytes
        if proof_data.len() < 99 {
            return Err(LinkError::InvalidProof);
        }

        // Extract signature (first 64 bytes)
        let signature_bytes: [u8; ED25519_SIGNATURE_SIZE] = proof_data[..64]
            .try_into()
            .map_err(|_| LinkError::InvalidProof)?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

        // Extract peer's ephemeral X25519 public key (next 32 bytes)
        let peer_pub_bytes: [u8; X25519_KEY_SIZE] = proof_data[64..96]
            .try_into()
            .map_err(|_| LinkError::InvalidProof)?;
        let peer_ephemeral_public = x25519_dalek::PublicKey::from(peer_pub_bytes);

        // Extract signalling bytes (last 3 bytes)
        let signalling_bytes: [u8; 3] = proof_data[96..99]
            .try_into()
            .map_err(|_| LinkError::InvalidProof)?;

        // Python RNS signs: link_id (16) + pub_bytes (32) + sig_pub_bytes (32) + signalling (3)
        // Where (from responder's perspective in prove()):
        //   pub_bytes = responder's X25519 ephemeral public key (in proof bytes 64-96)
        //   sig_pub_bytes = responder's Ed25519 signing public key (destination's verifying key)
        //   signalling = MTU and mode bytes from the proof
        //
        // Total signed data = 83 bytes
        if let Some(ref peer_verifying_key) = self.peer_verifying_key {
            let mut signed_data = [0u8; 83];
            signed_data[..TRUNCATED_HASHBYTES].copy_from_slice(&self.id);
            signed_data[TRUNCATED_HASHBYTES..TRUNCATED_HASHBYTES + 32]
                .copy_from_slice(&peer_pub_bytes); // Responder's X25519 pub from proof
            signed_data[TRUNCATED_HASHBYTES + 32..TRUNCATED_HASHBYTES + 64]
                .copy_from_slice(&peer_verifying_key.to_bytes()); // Responder's Ed25519 pub
            signed_data[TRUNCATED_HASHBYTES + 64..].copy_from_slice(&signalling_bytes);

            // Verify the signature
            peer_verifying_key
                .verify(&signed_data, &signature)
                .map_err(|_| LinkError::InvalidProof)?;
        } else {
            // If we don't have the destination's signing key, we can't verify
            // This means set_destination_keys() must be called before process_proof()
            return Err(LinkError::NoDestination);
        }

        // Perform X25519 key exchange
        let ephemeral_private = self
            .ephemeral_private
            .take()
            .ok_or(LinkError::KeyExchangeFailed)?;
        let shared_secret = ephemeral_private.diffie_hellman(&peer_ephemeral_public);

        // Derive link key using HKDF
        let link_key = Self::derive_link_key(shared_secret.as_bytes(), &self.id);

        // Update state
        self.peer_ephemeral_public = Some(peer_ephemeral_public);
        self.link_key = Some(link_key);
        self.state = LinkState::Active;

        Ok(())
    }

    /// Set the destination's signing key (from announce)
    ///
    /// This must be called before process_proof() so we can verify the signature
    pub fn set_destination_keys(
        &mut self,
        verifying_key_bytes: &[u8; 32],
    ) -> Result<(), LinkError> {
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(verifying_key_bytes)
            .map_err(|_| LinkError::KeyExchangeFailed)?;
        self.peer_verifying_key = Some(verifying_key);
        Ok(())
    }

    /// Derive the 64-byte link key from shared secret and link ID
    ///
    /// Format: [encryption_key (32)] [hmac_key (32)]
    fn derive_link_key(shared_secret: &[u8; 32], link_id: &LinkId) -> [u8; 64] {
        let mut key = [0u8; 64];
        derive_key(shared_secret, Some(link_id), None, &mut key);
        key
    }

    /// Get the derived encryption key (first 32 bytes of link_key)
    pub fn encryption_key(&self) -> Option<&[u8]> {
        self.link_key.as_ref().map(|k| &k[..32])
    }

    /// Get the derived HMAC key (last 32 bytes of link_key)
    pub fn hmac_key(&self) -> Option<&[u8]> {
        self.link_key.as_ref().map(|k| &k[32..])
    }

    /// Get the full link key (for token encryption)
    pub fn link_key(&self) -> Option<&[u8; 64]> {
        self.link_key.as_ref()
    }

    /// Build the complete link request packet data
    ///
    /// Returns the raw packet bytes ready for framing/transmission.
    /// Also sets the link_id on this Link.
    #[cfg(feature = "alloc")]
    pub fn build_link_request_packet(&mut self) -> alloc::vec::Vec<u8> {
        use crate::destination::DestinationType;
        use crate::packet::{HeaderType, PacketContext, PacketFlags, PacketType, TransportType};

        let request_data = self.create_link_request();

        // Build flags
        let flags = PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Single,
            packet_type: PacketType::LinkRequest,
        };

        // Packet format: [flags (1)] [hops (1)] [dest_hash (16)] [context (1)] [data (64)]
        let mut packet = alloc::vec::Vec::with_capacity(1 + 1 + TRUNCATED_HASHBYTES + 1 + 64);
        packet.push(flags.to_byte());
        packet.push(0); // hops = 0
        packet.extend_from_slice(&self.destination_hash);
        packet.push(PacketContext::None as u8);
        packet.extend_from_slice(&request_data);

        // Calculate and set link ID from the complete packet
        let link_id = Self::calculate_link_id(&packet);
        self.set_link_id(link_id);

        packet
    }

    // TODO: Implement encrypt/decrypt for link data
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
        // ID starts as zeros before handshake completes
        assert_eq!(link.id(), &[0u8; TRUNCATED_HASHBYTES]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_link_request_data() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let link = Link::new_outgoing(dest_hash);

        let request = link.create_link_request();
        assert_eq!(request.len(), 64);

        // Check that keys are embedded
        assert_eq!(&request[..32], link.ephemeral_public.as_bytes());
        assert_eq!(&request[32..64], &link.verifying_key.to_bytes());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_link_request_with_mtu() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let link = Link::new_outgoing(dest_hash);

        let request = link.create_link_request_with_mtu(500, 1);
        assert_eq!(request.len(), 67);

        // Check that keys are embedded
        assert_eq!(&request[..32], link.ephemeral_public.as_bytes());
        assert_eq!(&request[32..64], &link.verifying_key.to_bytes());

        // Check MTU signaling bytes encode MTU and mode
        // MTU 500 = 0x1F4, mode 1 -> signaling = 0x1F4 | (1 << 21) = 0x2001F4
        // Big-endian bytes [1:] = [0x20, 0x01, 0xF4]
        assert_eq!(request[64], 0x20);
        assert_eq!(request[65], 0x01);
        assert_eq!(request[66], 0xF4);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_link_id_calculation() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let link = Link::new_outgoing(dest_hash);

        // Construct raw packet: [flags][hops][dest_hash][context][request_data]
        let request = link.create_link_request();
        let mut raw_packet = Vec::new();
        raw_packet.push(0x02); // flags
        raw_packet.push(0x00); // hops
        raw_packet.extend_from_slice(&dest_hash);
        raw_packet.push(0x00); // context
        raw_packet.extend_from_slice(&request);

        let link_id = Link::calculate_link_id(&raw_packet);

        // Link ID should be 16 bytes
        assert_eq!(link_id.len(), TRUNCATED_HASHBYTES);
        // Should be deterministic
        assert_eq!(link_id, Link::calculate_link_id(&raw_packet));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_set_link_id() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let mut link = Link::new_outgoing(dest_hash);

        let new_id = [0xAB; TRUNCATED_HASHBYTES];
        link.set_link_id(new_id);

        assert_eq!(link.id(), &new_id);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_process_proof_invalid_state() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let mut link = Link::new_outgoing(dest_hash);

        // Manually set state to Active
        link.state = LinkState::Active;

        let fake_proof = [0u8; 96];
        let result = link.process_proof(&fake_proof);
        assert!(matches!(result, Err(LinkError::InvalidState)));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_process_proof_too_short() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let mut link = Link::new_outgoing(dest_hash);

        let short_proof = [0u8; 98]; // One byte short of required 99
        let result = link.process_proof(&short_proof);
        assert!(matches!(result, Err(LinkError::InvalidProof)));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_process_proof_no_destination_key() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let mut link = Link::new_outgoing(dest_hash);

        let fake_proof = [0u8; 99]; // 64 sig + 32 X25519 + 3 signalling
        let result = link.process_proof(&fake_proof);
        // Should fail because we haven't set the destination's verifying key
        assert!(matches!(result, Err(LinkError::NoDestination)));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_set_destination_keys() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let mut link = Link::new_outgoing(dest_hash);

        // Create a valid Ed25519 verifying key
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let verifying_key = signing_key.verifying_key();

        let result = link.set_destination_keys(&verifying_key.to_bytes());
        assert!(result.is_ok());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_key_derivation() {
        // Test that key derivation produces consistent results
        let shared_secret = [0x42; 32];
        let link_id = [0x13; TRUNCATED_HASHBYTES];

        let key1 = Link::derive_link_key(&shared_secret, &link_id);
        let key2 = Link::derive_link_key(&shared_secret, &link_id);

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 64);

        // Different link_id should produce different key
        let link_id2 = [0x14; TRUNCATED_HASHBYTES];
        let key3 = Link::derive_link_key(&shared_secret, &link_id2);
        assert_ne!(key1, key3);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_full_handshake_simulation() {
        use ed25519_dalek::Signer;

        // Simulate a full handshake between initiator and destination
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];

        // --- Initiator side ---
        let mut link = Link::new_outgoing(dest_hash);
        let request = link.create_link_request();

        // Build raw packet: [flags][hops][dest_hash][context][request]
        let mut raw_packet = Vec::new();
        raw_packet.push(0x02); // flags
        raw_packet.push(0x00); // hops
        raw_packet.extend_from_slice(&dest_hash);
        raw_packet.push(0x00); // context
        raw_packet.extend_from_slice(&request);

        // Calculate and set link ID from raw packet
        let link_id = Link::calculate_link_id(&raw_packet);
        link.set_link_id(link_id);

        // --- Destination side (simulated) ---
        // Destination has its own identity with signing key
        let dest_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x33; 32]);
        let dest_verifying_key = dest_signing_key.verifying_key();

        // Destination generates ephemeral X25519 key
        let dest_ephemeral_private =
            x25519_dalek::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let dest_ephemeral_public = x25519_dalek::PublicKey::from(&dest_ephemeral_private);

        // Python RNS signs: link_id (16) + pub_bytes (32) + sig_pub_bytes (32) + signalling (3)
        // Where (from responder's perspective):
        //   pub_bytes = responder's X25519 ephemeral public key
        //   sig_pub_bytes = responder's Ed25519 signing public key
        //   signalling = MTU and mode bytes
        let signalling_bytes: [u8; 3] = [0x43, 0x0f, 0x38]; // Example signalling bytes
        let mut signed_data = [0u8; 83];
        signed_data[..TRUNCATED_HASHBYTES].copy_from_slice(&link_id);
        signed_data[TRUNCATED_HASHBYTES..TRUNCATED_HASHBYTES + 32]
            .copy_from_slice(dest_ephemeral_public.as_bytes()); // Responder's X25519 pub
        signed_data[TRUNCATED_HASHBYTES + 32..TRUNCATED_HASHBYTES + 64]
            .copy_from_slice(&dest_verifying_key.to_bytes()); // Responder's Ed25519 pub
        signed_data[TRUNCATED_HASHBYTES + 64..].copy_from_slice(&signalling_bytes);
        let signature = dest_signing_key.sign(&signed_data);

        // Create proof: [signature (64)] [ephemeral_pub (32)] [signalling (3)]
        let mut proof = [0u8; 99];
        proof[..64].copy_from_slice(&signature.to_bytes());
        proof[64..96].copy_from_slice(dest_ephemeral_public.as_bytes());
        proof[96..99].copy_from_slice(&signalling_bytes);

        // --- Back to initiator ---
        // Set destination's verifying key (would come from announce)
        link.set_destination_keys(&dest_verifying_key.to_bytes()).unwrap();

        // Process the proof
        let result = link.process_proof(&proof);
        assert!(result.is_ok());

        // Link should now be active
        assert_eq!(link.state(), LinkState::Active);
        assert!(link.link_key().is_some());
        assert!(link.encryption_key().is_some());
        assert!(link.hmac_key().is_some());
    }
}
