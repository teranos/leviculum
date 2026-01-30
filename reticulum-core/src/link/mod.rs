//! Point-to-point verified connections
//!
//! Links provide:
//! - Verified, encrypted communication channels
//! - Perfect forward secrecy via ephemeral keys
//! - Bidirectional data transfer
//! - Keepalive and timeout management
//!
//! ## Link Establishment
//!
//! Links can be established in two directions:
//!
//! ### Initiator (client) side:
//! 1. Create link with `Link::new_outgoing()`
//! 2. Send LINK_REQUEST packet via `build_link_request_packet()`
//! 3. Receive PROOF from destination
//! 4. Verify proof with `process_proof()`
//! 5. Send RTT packet via `build_rtt_packet()` to finalize
//!
//! ### Responder (server) side:
//! 1. Receive LINK_REQUEST packet
//! 2. Create link with `Link::new_incoming()`
//! 3. Send PROOF via `build_proof_packet()`
//! 4. Receive RTT packet
//! 5. Finalize with `process_rtt()`
//!
//! ## High-Level API
//!
//! For easier link management, use the [`LinkManager`] which handles:
//! - Tracking pending and active links
//! - Processing incoming link packets
//! - Emitting [`LinkEvent`]s for state changes
//!
//! [`LinkManager`]: manager::LinkManager

mod manager;

pub use manager::LinkManager;

use crate::constants::{
    ED25519_SIGNATURE_SIZE, LINK_KEEPALIVE_SECS, LINK_STALE_TIME_SECS, TRUNCATED_HASHBYTES,
    X25519_KEY_SIZE,
};
use crate::crypto::{derive_key, truncated_hash};
use crate::identity::Identity;
use crate::traits::Context;
use alloc::vec::Vec;
use rand_core::RngCore;

// Link request/proof size constants
/// Size of link request payload without signaling (X25519 pub + Ed25519 pub)
const LINK_REQUEST_BASE_SIZE: usize = 64;
/// Size of link request payload with MTU signaling
const LINK_REQUEST_SIGNALING_SIZE: usize = 67;
/// Size of signed data in proof (link_id + X25519 pub + Ed25519 pub + signaling)
const PROOF_SIGNED_DATA_SIZE: usize = 83; // 16 + 32 + 32 + 3
/// Size of proof data (signature + X25519 pub + signaling)
const PROOF_DATA_SIZE: usize = 99; // 64 + 32 + 3
/// Size of signaling bytes (21-bit MTU + 3-bit mode)
const SIGNALING_SIZE: usize = 3;

/// Encode MTU and mode into 3-byte signaling format
///
/// Format: 21-bit MTU (bits 0-20) + 3-bit mode (bits 21-23)
/// Returns the lower 3 bytes of the big-endian representation.
fn encode_signaling_bytes(mtu: u32, mode: u8) -> [u8; SIGNALING_SIZE] {
    let signaling = (mtu & 0x1FFFFF) | ((mode as u32 & 0x07) << 21);
    let bytes = signaling.to_be_bytes();
    [bytes[1], bytes[2], bytes[3]]
}

/// Build the signed data for proof verification/generation
///
/// Format: [link_id (16)] [x25519_pub (32)] [ed25519_pub (32)] [signaling (3)]
fn build_proof_signed_data(
    link_id: &LinkId,
    x25519_pub: &[u8; X25519_KEY_SIZE],
    ed25519_pub: &[u8; X25519_KEY_SIZE],
    signaling: &[u8; SIGNALING_SIZE],
) -> [u8; PROOF_SIGNED_DATA_SIZE] {
    let mut signed_data = [0u8; PROOF_SIGNED_DATA_SIZE];
    signed_data[..TRUNCATED_HASHBYTES].copy_from_slice(link_id);
    signed_data[TRUNCATED_HASHBYTES..TRUNCATED_HASHBYTES + X25519_KEY_SIZE]
        .copy_from_slice(x25519_pub);
    signed_data[TRUNCATED_HASHBYTES + X25519_KEY_SIZE..TRUNCATED_HASHBYTES + 2 * X25519_KEY_SIZE]
        .copy_from_slice(ed25519_pub);
    signed_data[TRUNCATED_HASHBYTES + 2 * X25519_KEY_SIZE..].copy_from_slice(signaling);
    signed_data
}

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
    /// Invalid link request data
    InvalidRequest,
    /// No identity to sign with
    NoIdentity,
    /// Invalid RTT packet
    InvalidRtt,
    /// Link not found
    NotFound,
}

/// Reason why a link was closed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkCloseReason {
    /// Normal close requested
    Normal,
    /// Handshake timed out
    Timeout,
    /// Invalid proof received
    InvalidProof,
    /// Peer closed the link
    PeerClosed,
    /// Link became stale (no activity)
    Stale,
}

/// Peer's public keys from a link request
#[derive(Debug, Clone)]
pub struct PeerKeys {
    /// Peer's ephemeral X25519 public key (32 bytes)
    pub x25519_public: [u8; 32],
    /// Peer's ephemeral Ed25519 verifying key (32 bytes)
    pub ed25519_verifying: [u8; 32],
}

/// Events emitted by LinkManager
#[derive(Debug)]
pub enum LinkEvent {
    /// Incoming link request received (responder should accept/reject)
    LinkRequestReceived {
        /// The link ID for this request
        link_id: LinkId,
        /// Destination hash the request was sent to
        dest_hash: [u8; 16],
        /// Peer's public keys
        peer_keys: PeerKeys,
    },
    /// Link handshake completed
    LinkEstablished {
        /// The link ID
        link_id: LinkId,
        /// Whether we initiated this link
        is_initiator: bool,
    },
    /// Data received on a link
    DataReceived {
        /// The link ID
        link_id: LinkId,
        /// The decrypted data
        data: Vec<u8>,
    },
    /// Link closed or failed
    LinkClosed {
        /// The link ID
        link_id: LinkId,
        /// Why the link was closed
        reason: LinkCloseReason,
    },
}

/// Link identifier (16 bytes - truncated hash)
pub type LinkId = [u8; TRUNCATED_HASHBYTES];

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
    /// Our ephemeral Ed25519 signing key (for future link authentication)
    _signing_key: Option<ed25519_dalek::SigningKey>,
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
    /// Keepalive interval in seconds (for future keepalive management)
    _keepalive_secs: u64,
    /// Time of last inbound packet (timestamp)
    last_inbound: u64,
    /// Time of last outbound packet (timestamp, for future keepalive management)
    _last_outbound: u64,
    /// When the link was established (timestamp, for future timeout management)
    _established_at: Option<u64>,
}

impl Link {
    /// Create a new outgoing link (initiator side) using a Context
    pub fn new_outgoing(
        destination_hash: [u8; TRUNCATED_HASHBYTES],
        ctx: &mut impl Context,
    ) -> Self {
        Self::new_outgoing_with_rng(destination_hash, ctx.rng())
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
            _signing_key: Some(signing_key),
            verifying_key,
            peer_ephemeral_public: None,
            peer_verifying_key: None,
            link_key: None,
            destination_hash,
            initiator: true,
            hops: 0,
            rtt_us: None,
            _keepalive_secs: LINK_KEEPALIVE_SECS,
            last_inbound: 0,
            _last_outbound: 0,
            _established_at: None,
        }
    }

    /// Create a new incoming link (responder/server side) from a LINK_REQUEST packet.
    ///
    /// This is called when a destination receives a LINK_REQUEST packet.
    /// The destination's identity is used for signing the proof.
    ///
    /// # Arguments
    /// * `request_data` - The 64-byte payload from the LINK_REQUEST packet
    ///   (32 bytes X25519 pub + 32 bytes Ed25519 pub)
    /// * `link_id` - The pre-computed link ID (from `calculate_link_id()`)
    /// * `destination_hash` - The hash of the destination receiving this request
    /// * `ctx` - Platform context for RNG
    ///
    /// # Returns
    /// A new Link in Pending state, ready for `build_proof_packet()` to be called.
    pub fn new_incoming(
        request_data: &[u8],
        link_id: LinkId,
        destination_hash: [u8; TRUNCATED_HASHBYTES],
        ctx: &mut impl Context,
    ) -> Result<Self, LinkError> {
        Self::new_incoming_with_rng(request_data, link_id, destination_hash, ctx.rng())
    }

    /// Create a new incoming link with a provided RNG.
    pub fn new_incoming_with_rng<R: rand_core::CryptoRngCore>(
        request_data: &[u8],
        link_id: LinkId,
        destination_hash: [u8; TRUNCATED_HASHBYTES],
        rng: &mut R,
    ) -> Result<Self, LinkError> {
        // LINK_REQUEST payload: [peer_x25519_pub (32)] [peer_ed25519_pub (32)]
        // May have additional MTU signaling bytes but we only need first LINK_REQUEST_BASE_SIZE
        if request_data.len() < LINK_REQUEST_BASE_SIZE {
            return Err(LinkError::InvalidRequest);
        }

        // Extract peer's public keys
        let peer_x25519_bytes: [u8; 32] = request_data[..32]
            .try_into()
            .map_err(|_| LinkError::InvalidRequest)?;
        let peer_ed25519_bytes: [u8; 32] = request_data[32..64]
            .try_into()
            .map_err(|_| LinkError::InvalidRequest)?;

        let peer_ephemeral_public = x25519_dalek::PublicKey::from(peer_x25519_bytes);
        let peer_verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&peer_ed25519_bytes)
            .map_err(|_| LinkError::InvalidRequest)?;

        // Generate our ephemeral X25519 key pair
        let ephemeral_private = x25519_dalek::StaticSecret::random_from_rng(&mut *rng);
        let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_private);

        // Generate Ed25519 key for future link authentication (not used for proof signing)
        let mut ed25519_seed = [0u8; 32];
        rng.fill_bytes(&mut ed25519_seed);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&ed25519_seed);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            id: link_id,
            state: LinkState::Pending,
            ephemeral_private: Some(ephemeral_private),
            ephemeral_public,
            _signing_key: Some(signing_key),
            verifying_key,
            peer_ephemeral_public: Some(peer_ephemeral_public),
            peer_verifying_key: Some(peer_verifying_key),
            link_key: None,
            destination_hash,
            initiator: false, // We are the responder
            hops: 0,
            rtt_us: None,
            _keepalive_secs: LINK_KEEPALIVE_SECS,
            last_inbound: 0,
            _last_outbound: 0,
            _established_at: None,
        })
    }

    /// Build the PROOF packet for responding to a LINK_REQUEST.
    ///
    /// This performs the DH key exchange and derives the link key.
    /// Must be called on an incoming link in Pending state.
    ///
    /// # Arguments
    /// * `identity` - The destination's identity (for signing the proof)
    /// * `mtu` - The MTU value for signaling (typically 500)
    /// * `mode` - The mode for signaling (typically 1 for AES-256-CBC)
    ///
    /// # Returns
    /// The raw PROOF packet bytes ready for framing/transmission.
    /// Link state transitions to Handshake.
    pub fn build_proof_packet(
        &mut self,
        identity: &Identity,
        mtu: u32,
        mode: u8,
    ) -> Result<alloc::vec::Vec<u8>, LinkError> {
        use crate::destination::DestinationType;
        use crate::packet::{HeaderType, PacketContext, PacketFlags, PacketType, TransportType};

        self.require_state(LinkState::Pending)?;
        self.require_responder()?;

        // Get peer's public key (from the LINK_REQUEST)
        let peer_ephemeral_public = self
            .peer_ephemeral_public
            .ok_or(LinkError::KeyExchangeFailed)?;

        // Perform X25519 key exchange
        let ephemeral_private = self
            .ephemeral_private
            .as_ref()
            .ok_or(LinkError::KeyExchangeFailed)?;
        let shared_secret = ephemeral_private.diffie_hellman(&peer_ephemeral_public);

        // Derive link key using HKDF
        let link_key = Self::derive_link_key(shared_secret.as_bytes(), &self.id);
        self.link_key = Some(link_key);

        // Build signaling bytes: 21-bit MTU + 3-bit mode
        let signaling_bytes = encode_signaling_bytes(mtu, mode);

        // Build signed data: link_id (16) + our_x25519_pub (32) + dest_ed25519_pub (32) + signaling (3)
        // Note: Python RNS uses the destination's Ed25519 signing key (not the link's ephemeral one)
        let signed_data = build_proof_signed_data(
            &self.id,
            self.ephemeral_public.as_bytes(),
            &identity.ed25519_verifying().to_bytes(),
            &signaling_bytes,
        );

        // Sign with destination's identity
        let signature = identity
            .sign(&signed_data)
            .map_err(|_| LinkError::NoIdentity)?;

        // Build proof data: [signature (64)] [our_x25519_pub (32)] [signaling (3)]
        let mut proof_data = alloc::vec![0u8; PROOF_DATA_SIZE];
        proof_data[..ED25519_SIGNATURE_SIZE].copy_from_slice(&signature);
        proof_data[ED25519_SIGNATURE_SIZE..ED25519_SIGNATURE_SIZE + X25519_KEY_SIZE]
            .copy_from_slice(self.ephemeral_public.as_bytes());
        proof_data[ED25519_SIGNATURE_SIZE + X25519_KEY_SIZE..].copy_from_slice(&signaling_bytes);

        // Build packet: PROOF packet addressed to the link_id
        let flags = PacketFlags {
            ifac_flag: false,
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Link,
            packet_type: PacketType::Proof,
        };

        let mut packet =
            alloc::vec::Vec::with_capacity(1 + 1 + TRUNCATED_HASHBYTES + 1 + PROOF_DATA_SIZE);
        packet.push(flags.to_byte());
        packet.push(0); // hops = 0
        packet.extend_from_slice(&self.id); // destination = link_id
        packet.push(PacketContext::Lrproof as u8);
        packet.extend_from_slice(&proof_data);

        // Transition to Handshake state (waiting for RTT from initiator)
        self.state = LinkState::Handshake;

        Ok(packet)
    }

    /// Process the RTT packet from the initiator to finalize link establishment.
    ///
    /// This is called on the responder side after sending the PROOF.
    /// The RTT packet contains an encrypted msgpack float64 value.
    ///
    /// # Arguments
    /// * `encrypted_data` - The encrypted payload from the RTT packet
    ///
    /// # Returns
    /// Ok(rtt_seconds) if the link is now active, Err otherwise.
    pub fn process_rtt(&mut self, encrypted_data: &[u8]) -> Result<f64, LinkError> {
        self.require_state(LinkState::Handshake)?;
        self.require_responder()?;

        // Decrypt the RTT data
        let mut plaintext = alloc::vec![0u8; encrypted_data.len()];
        let plaintext_len = self.decrypt(encrypted_data, &mut plaintext)?;

        // RTT is msgpack-encoded float64: 0xCB + 8 bytes big-endian IEEE 754
        if plaintext_len < 9 || plaintext[0] != 0xCB {
            return Err(LinkError::InvalidRtt);
        }

        let rtt_bytes: [u8; 8] = plaintext[1..9]
            .try_into()
            .map_err(|_| LinkError::InvalidRtt)?;
        let rtt_seconds = f64::from_be_bytes(rtt_bytes);

        // Store RTT (convert to microseconds for internal storage)
        self.rtt_us = Some((rtt_seconds * 1_000_000.0) as u64);

        // Link is now active
        self.state = LinkState::Active;

        Ok(rtt_seconds)
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
    pub fn create_link_request(&self) -> [u8; LINK_REQUEST_BASE_SIZE] {
        let mut data = [0u8; LINK_REQUEST_BASE_SIZE];
        data[..X25519_KEY_SIZE].copy_from_slice(self.ephemeral_public.as_bytes());
        data[X25519_KEY_SIZE..].copy_from_slice(&self.verifying_key.to_bytes());
        data
    }

    /// Create the link request data with MTU signaling
    /// Format: [ephemeral_pub (32)] [sig_pub (32)] [mtu_signaling (3)]
    pub fn create_link_request_with_mtu(
        &self,
        mtu: u32,
        mode: u8,
    ) -> [u8; LINK_REQUEST_SIGNALING_SIZE] {
        let mut data = [0u8; LINK_REQUEST_SIGNALING_SIZE];
        data[..X25519_KEY_SIZE].copy_from_slice(self.ephemeral_public.as_bytes());
        data[X25519_KEY_SIZE..LINK_REQUEST_BASE_SIZE]
            .copy_from_slice(&self.verifying_key.to_bytes());
        // MTU signaling: 21-bit MTU + 3-bit mode
        let signaling_bytes = encode_signaling_bytes(mtu, mode);
        data[LINK_REQUEST_BASE_SIZE..].copy_from_slice(&signaling_bytes);
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

    /// Require link to be in a specific state
    fn require_state(&self, expected: LinkState) -> Result<(), LinkError> {
        if self.state == expected {
            Ok(())
        } else {
            Err(LinkError::InvalidState)
        }
    }

    /// Require that we are the initiator (client side)
    #[allow(dead_code)]
    fn require_initiator(&self) -> Result<(), LinkError> {
        if self.initiator {
            Ok(())
        } else {
            Err(LinkError::InvalidState)
        }
    }

    /// Require that we are the responder (server side)
    fn require_responder(&self) -> Result<(), LinkError> {
        if !self.initiator {
            Ok(())
        } else {
            Err(LinkError::InvalidState)
        }
    }

    /// Calculate link ID from the raw packet bytes
    ///
    /// Python RNS calculates link_id as:
    /// ```python
    /// hashable_part = bytes([raw[0] & 0x0F])
    /// if header_type == HEADER_2:
    ///     hashable_part += raw[(TRUNCATED_HASHBYTES//8)+2:]  # Skip transport_id
    /// else:
    ///     hashable_part += raw[2:]
    /// # Remove signalling bytes if present (payload > 64 bytes)
    /// link_id = truncated_hash(hashable_part)
    /// ```
    ///
    /// For HEADER_1: [flags (1)] [hops (1)] [dest_hash (16)] [context (1)] [payload (64-67)]
    /// For HEADER_2: [flags (1)] [hops (1)] [transport_id (16)] [dest_hash (16)] [context (1)] [payload (64-67)]
    ///
    /// The hashable part always includes: (flags & 0x0F) + dest_hash + context + payload
    /// This ensures the link_id is the same regardless of whether transport headers are present.
    pub fn calculate_link_id(raw_packet: &[u8]) -> LinkId {
        use crate::packet::HeaderType;

        let flags = raw_packet[0];
        let header_type = if flags & 0x40 != 0 {
            HeaderType::Type2
        } else {
            HeaderType::Type1
        };

        // Build hashable part: (flags & 0x0F) + [dest_hash + context + payload]
        // For HEADER_2, skip the transport_id (16 bytes after flags+hops)
        let mut hashable = alloc::vec::Vec::with_capacity(raw_packet.len() - 1);
        hashable.push(flags & 0x0F);

        let data_start = match header_type {
            HeaderType::Type2 => 2 + TRUNCATED_HASHBYTES, // Skip flags, hops, transport_id
            HeaderType::Type1 => 2,                       // Skip flags, hops only
        };
        hashable.extend_from_slice(&raw_packet[data_start..]);

        // If payload has signalling bytes (payload > LINK_REQUEST_BASE_SIZE), remove them
        // After stripping header: dest_hash(16) + context(1) + payload(64+) = 81+ bytes
        // Minimum hashable with 64-byte payload = 1 + 16 + 1 + 64 = 82 bytes
        let payload_offset = 1 + TRUNCATED_HASHBYTES + 1; // (flags&0x0F) + dest_hash + context = 18 bytes
        if hashable.len() > payload_offset + LINK_REQUEST_BASE_SIZE {
            let diff = hashable.len() - (payload_offset + LINK_REQUEST_BASE_SIZE);
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

        self.require_state(LinkState::Pending)?;

        // Proof format: signature (64) + X25519_pub (32) + signalling (3) = PROOF_DATA_SIZE bytes
        if proof_data.len() < PROOF_DATA_SIZE {
            return Err(LinkError::InvalidProof);
        }

        // Extract signature (first ED25519_SIGNATURE_SIZE bytes)
        let signature_bytes: [u8; ED25519_SIGNATURE_SIZE] = proof_data[..ED25519_SIGNATURE_SIZE]
            .try_into()
            .map_err(|_| LinkError::InvalidProof)?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

        // Extract peer's ephemeral X25519 public key (next X25519_KEY_SIZE bytes)
        let peer_pub_bytes: [u8; X25519_KEY_SIZE] = proof_data
            [ED25519_SIGNATURE_SIZE..ED25519_SIGNATURE_SIZE + X25519_KEY_SIZE]
            .try_into()
            .map_err(|_| LinkError::InvalidProof)?;
        let peer_ephemeral_public = x25519_dalek::PublicKey::from(peer_pub_bytes);

        // Extract signalling bytes (last SIGNALING_SIZE bytes)
        let signalling_bytes: [u8; SIGNALING_SIZE] = proof_data
            [ED25519_SIGNATURE_SIZE + X25519_KEY_SIZE..PROOF_DATA_SIZE]
            .try_into()
            .map_err(|_| LinkError::InvalidProof)?;

        // Python RNS signs: link_id (16) + pub_bytes (32) + sig_pub_bytes (32) + signalling (3)
        // Where (from responder's perspective in prove()):
        //   pub_bytes = responder's X25519 ephemeral public key (in proof bytes 64-96)
        //   sig_pub_bytes = responder's Ed25519 signing public key (destination's verifying key)
        //   signalling = MTU and mode bytes from the proof
        let peer_verifying_key = self
            .peer_verifying_key
            .as_ref()
            .ok_or(LinkError::NoDestination)?;

        let signed_data = build_proof_signed_data(
            &self.id,
            &peer_pub_bytes,
            &peer_verifying_key.to_bytes(),
            &signalling_bytes,
        );

        // Verify the signature
        peer_verifying_key
            .verify(&signed_data, &signature)
            .map_err(|_| LinkError::InvalidProof)?;

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
    /// Format: [signing/hmac_key (32)] [encryption_key (32)]
    /// This matches Python Reticulum's Token class which expects:
    /// - key[:32] = signing_key (for HMAC)
    /// - key[32:] = encryption_key (for AES)
    fn derive_link_key(shared_secret: &[u8; 32], link_id: &LinkId) -> [u8; 64] {
        let mut key = [0u8; 64];
        derive_key(shared_secret, Some(link_id), None, &mut key);
        key
    }

    /// Get the derived HMAC/signing key (first 32 bytes of link_key)
    pub fn hmac_key(&self) -> Option<&[u8]> {
        self.link_key.as_ref().map(|k| &k[..32])
    }

    /// Get the derived encryption key (last 32 bytes of link_key)
    pub fn encryption_key(&self) -> Option<&[u8]> {
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
    pub fn build_link_request_packet(&mut self) -> alloc::vec::Vec<u8> {
        use crate::destination::DestinationType;
        use crate::packet::{HeaderType, PacketContext, PacketFlags, PacketType, TransportType};

        let request_data = self.create_link_request();

        // Build flags
        let flags = PacketFlags {
            ifac_flag: false,
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Single,
            packet_type: PacketType::LinkRequest,
        };

        // Packet format: [flags (1)] [hops (1)] [dest_hash (16)] [context (1)] [data (64)]
        let mut packet = alloc::vec::Vec::with_capacity(
            1 + 1 + TRUNCATED_HASHBYTES + 1 + LINK_REQUEST_BASE_SIZE,
        );
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

    /// Build link request packet with transport headers for multi-hop routing.
    ///
    /// When the packet needs to be routed through a transport node (indicated by
    /// having a transport_id from an announce), we use HEADER_2 format with the
    /// transport_id so intermediate nodes can route the packet.
    ///
    /// # Arguments
    /// * `next_hop` - The transport_id (identity hash of the next hop node that will forward this packet)
    /// * `hops_to_dest` - Number of hops to the destination (from path info, stored for reference)
    ///
    /// # Returns
    /// The raw packet bytes ready for framing/transmission.
    /// Also sets the link_id on this Link.
    ///
    /// # Note
    /// If `next_hop` is None, falls back to HEADER_1 (direct/broadcast).
    /// If `next_hop` is Some, uses HEADER_2 with transport routing regardless of hop count,
    /// because the presence of transport_id in an announce indicates the packet must be
    /// routed through that transport node.
    pub fn build_link_request_packet_with_transport(
        &mut self,
        next_hop: Option<[u8; TRUNCATED_HASHBYTES]>,
        hops_to_dest: u8,
    ) -> alloc::vec::Vec<u8> {
        use crate::destination::DestinationType;
        use crate::packet::{HeaderType, PacketContext, PacketFlags, PacketType, TransportType};

        // If no transport_id provided, use HEADER_1 (direct/broadcast)
        if next_hop.is_none() {
            return self.build_link_request_packet();
        }

        let transport_id = next_hop.unwrap();
        let request_data = self.create_link_request();

        // Build flags for HEADER_2 with transport routing
        // Type2=1 (bit 6), Transport=1 (bit 4), Single=1 (bits 3-2), LinkReq=2 (bits 1-0)
        let flags = PacketFlags {
            ifac_flag: false,
            header_type: HeaderType::Type2,
            context_flag: false,
            transport_type: TransportType::Transport,
            dest_type: DestinationType::Single,
            packet_type: PacketType::LinkRequest,
        };

        // Packet format: [flags (1)] [hops (1)] [transport_id (16)] [dest_hash (16)] [context (1)] [data (64)]
        let mut packet = alloc::vec::Vec::with_capacity(
            1 + 1 + TRUNCATED_HASHBYTES + TRUNCATED_HASHBYTES + 1 + LINK_REQUEST_BASE_SIZE,
        );
        packet.push(flags.to_byte());
        packet.push(0); // hops = 0 (we're originating)
        packet.extend_from_slice(&transport_id);
        packet.extend_from_slice(&self.destination_hash);
        packet.push(PacketContext::None as u8);
        packet.extend_from_slice(&request_data);

        // Calculate and set link ID from the complete packet
        // Note: Link ID calculation uses the same algorithm regardless of header type
        let link_id = Self::calculate_link_id(&packet);
        self.set_link_id(link_id);

        // Store hop count
        self.hops = hops_to_dest;

        packet
    }

    /// Get the token key (same as link key, no conversion needed)
    ///
    /// Link key format matches Token format: [hmac/signing (32)][encryption (32)]
    /// This matches Python Reticulum's Token class expectations.
    fn token_key(&self) -> Option<[u8; 64]> {
        self.link_key
    }

    /// Encrypt data for transmission over this link (with provided RNG)
    ///
    /// Returns the encrypted token: [IV (16)][ciphertext][HMAC (32)]
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        output: &mut [u8],
        ctx: &mut impl Context,
    ) -> Result<usize, LinkError> {
        use crate::crypto::encrypt_token;

        let token_key = self.token_key().ok_or(LinkError::InvalidState)?;
        let mut iv = [0u8; 16];
        ctx.rng().fill_bytes(&mut iv);

        encrypt_token(&token_key, &iv, plaintext, output).map_err(|_| LinkError::KeyExchangeFailed)
    }

    /// Decrypt data received over this link
    ///
    /// The token format is: [IV (16)][ciphertext][HMAC (32)]
    ///
    /// Returns the plaintext length written to output.
    pub fn decrypt(&self, token: &[u8], output: &mut [u8]) -> Result<usize, LinkError> {
        use crate::crypto::decrypt_token;

        let token_key = self.token_key().ok_or(LinkError::InvalidState)?;

        decrypt_token(&token_key, token, output).map_err(|e| {
            use crate::crypto::TokenError;
            match e {
                TokenError::HmacVerificationFailed => LinkError::InvalidProof,
                _ => LinkError::KeyExchangeFailed,
            }
        })
    }

    /// Calculate the required output buffer size for encrypting data
    ///
    /// Returns the size needed for: IV (16) + padded ciphertext + HMAC (32)
    pub fn encrypted_size(plaintext_len: usize) -> usize {
        let padded = ((plaintext_len / 16) + 1) * 16;
        16 + padded + 32
    }

    /// Build a data packet for transmission over this link
    ///
    /// The plaintext is encrypted and wrapped in a proper packet format.
    /// Returns the raw packet bytes ready for framing/transmission.
    pub fn build_data_packet(
        &self,
        plaintext: &[u8],
        ctx: &mut impl Context,
    ) -> Result<alloc::vec::Vec<u8>, LinkError> {
        use crate::destination::DestinationType;
        use crate::packet::{HeaderType, PacketContext, PacketFlags, PacketType, TransportType};

        self.require_state(LinkState::Active)?;

        // Encrypt the data
        let encrypted_len = Self::encrypted_size(plaintext.len());
        let mut encrypted = alloc::vec![0u8; encrypted_len];
        let enc_len = self.encrypt(plaintext, &mut encrypted, ctx)?;

        // Build flags for link data packet
        let flags = PacketFlags {
            ifac_flag: false,
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Link,
            packet_type: PacketType::Data,
        };

        // Packet format: [flags (1)] [hops (1)] [link_id (16)] [context (1)] [encrypted_data]
        let mut packet = alloc::vec::Vec::with_capacity(1 + 1 + TRUNCATED_HASHBYTES + 1 + enc_len);
        packet.push(flags.to_byte());
        packet.push(0); // hops = 0
        packet.extend_from_slice(&self.id);
        packet.push(PacketContext::None as u8);
        packet.extend_from_slice(&encrypted[..enc_len]);

        Ok(packet)
    }

    /// Build the RTT (Round-Trip Time) packet that finalizes link establishment
    ///
    /// This packet must be sent by the initiator after processing the proof.
    /// The destination only considers the link "established" after receiving this.
    ///
    /// The RTT value is msgpack-encoded (float64 format).
    pub fn build_rtt_packet(
        &self,
        rtt_seconds: f64,
        ctx: &mut impl Context,
    ) -> Result<alloc::vec::Vec<u8>, LinkError> {
        use crate::destination::DestinationType;
        use crate::packet::{HeaderType, PacketContext, PacketFlags, PacketType, TransportType};

        self.require_state(LinkState::Active)?;

        // Encode RTT as msgpack float64: 0xCB + 8 bytes big-endian IEEE 754
        let mut rtt_data = [0u8; 9];
        rtt_data[0] = 0xCB; // msgpack float64 marker
        rtt_data[1..9].copy_from_slice(&rtt_seconds.to_be_bytes());

        // Encrypt the RTT data
        let encrypted_len = Self::encrypted_size(rtt_data.len());
        let mut encrypted = alloc::vec![0u8; encrypted_len];
        let enc_len = self.encrypt(&rtt_data, &mut encrypted, ctx)?;

        // Build flags for link RTT packet
        let flags = PacketFlags {
            ifac_flag: false,
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Link,
            packet_type: PacketType::Data,
        };

        // Packet format: [flags (1)] [hops (1)] [link_id (16)] [context (1)] [encrypted_data]
        let mut packet = alloc::vec::Vec::with_capacity(1 + 1 + TRUNCATED_HASHBYTES + 1 + enc_len);
        packet.push(flags.to_byte());
        packet.push(0); // hops = 0
        packet.extend_from_slice(&self.id);
        packet.push(PacketContext::Lrrtt as u8);
        packet.extend_from_slice(&encrypted[..enc_len]);

        Ok(packet)
    }

    // TODO: Implement keepalive sending
    // TODO: Implement timeout checking
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Clock, NoStorage, PlatformContext};
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::Cell;
    use rand_core::OsRng;

    struct TestClock(Cell<u64>);
    impl TestClock {
        fn new(start_ms: u64) -> Self {
            Self(Cell::new(start_ms))
        }
    }
    impl Default for TestClock {
        fn default() -> Self {
            // Use a fixed timestamp for deterministic tests
            Self::new(1_700_000_000_000) // ~2023-11-14
        }
    }
    impl Clock for TestClock {
        fn now_ms(&self) -> u64 {
            self.0.get()
        }
    }

    #[test]
    fn test_link_creation() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let link = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);

        assert_eq!(link.state(), LinkState::Pending);
        assert!(link.is_initiator());
        assert_eq!(link.destination_hash(), &dest_hash);
        // ID starts as zeros before handshake completes
        assert_eq!(link.id(), &[0u8; TRUNCATED_HASHBYTES]);
    }

    #[test]
    fn test_link_request_data() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let link = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);

        let request = link.create_link_request();
        assert_eq!(request.len(), 64);

        // Check that keys are embedded
        assert_eq!(&request[..32], link.ephemeral_public.as_bytes());
        assert_eq!(&request[32..64], &link.verifying_key.to_bytes());
    }

    #[test]
    fn test_link_request_with_mtu() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let link = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);

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

    #[test]
    fn test_link_id_calculation() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let link = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);

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

    #[test]
    fn test_set_link_id() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let mut link = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);

        let new_id = [0xAB; TRUNCATED_HASHBYTES];
        link.set_link_id(new_id);

        assert_eq!(link.id(), &new_id);
    }

    #[test]
    fn test_process_proof_invalid_state() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let mut link = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);

        // Manually set state to Active
        link.state = LinkState::Active;

        let fake_proof = [0u8; 96];
        let result = link.process_proof(&fake_proof);
        assert!(matches!(result, Err(LinkError::InvalidState)));
    }

    #[test]
    fn test_process_proof_too_short() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let mut link = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);

        let short_proof = [0u8; 98]; // One byte short of required 99
        let result = link.process_proof(&short_proof);
        assert!(matches!(result, Err(LinkError::InvalidProof)));
    }

    #[test]
    fn test_process_proof_no_destination_key() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let mut link = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);

        let fake_proof = [0u8; 99]; // 64 sig + 32 X25519 + 3 signalling
        let result = link.process_proof(&fake_proof);
        // Should fail because we haven't set the destination's verifying key
        assert!(matches!(result, Err(LinkError::NoDestination)));
    }

    #[test]
    fn test_set_destination_keys() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let mut link = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);

        // Create a valid Ed25519 verifying key
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let verifying_key = signing_key.verifying_key();

        let result = link.set_destination_keys(&verifying_key.to_bytes());
        assert!(result.is_ok());
    }

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

    #[test]
    fn test_full_handshake_simulation() {
        use ed25519_dalek::Signer;

        // Simulate a full handshake between initiator and destination
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];

        // --- Initiator side ---
        let mut link = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);
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
        link.set_destination_keys(&dest_verifying_key.to_bytes())
            .unwrap();

        // Process the proof
        let result = link.process_proof(&proof);
        assert!(result.is_ok());

        // Link should now be active
        assert_eq!(link.state(), LinkState::Active);
        assert!(link.link_key().is_some());
        assert!(link.encryption_key().is_some());
        assert!(link.hmac_key().is_some());
    }

    #[test]
    fn test_link_encrypt_decrypt() {
        use ed25519_dalek::Signer;

        // Set up a link with completed handshake (reuse handshake simulation)
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let mut link = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);
        let request = link.create_link_request();

        // Build raw packet
        let mut raw_packet = Vec::new();
        raw_packet.push(0x02);
        raw_packet.push(0x00);
        raw_packet.extend_from_slice(&dest_hash);
        raw_packet.push(0x00);
        raw_packet.extend_from_slice(&request);

        let link_id = Link::calculate_link_id(&raw_packet);
        link.set_link_id(link_id);

        // Simulate destination side
        let dest_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x33; 32]);
        let dest_verifying_key = dest_signing_key.verifying_key();
        let dest_ephemeral_private =
            x25519_dalek::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let dest_ephemeral_public = x25519_dalek::PublicKey::from(&dest_ephemeral_private);

        let signalling_bytes: [u8; 3] = [0x43, 0x0f, 0x38];
        let mut signed_data = [0u8; 83];
        signed_data[..TRUNCATED_HASHBYTES].copy_from_slice(&link_id);
        signed_data[TRUNCATED_HASHBYTES..TRUNCATED_HASHBYTES + 32]
            .copy_from_slice(dest_ephemeral_public.as_bytes());
        signed_data[TRUNCATED_HASHBYTES + 32..TRUNCATED_HASHBYTES + 64]
            .copy_from_slice(&dest_verifying_key.to_bytes());
        signed_data[TRUNCATED_HASHBYTES + 64..].copy_from_slice(&signalling_bytes);
        let signature = dest_signing_key.sign(&signed_data);

        let mut proof = [0u8; 99];
        proof[..64].copy_from_slice(&signature.to_bytes());
        proof[64..96].copy_from_slice(dest_ephemeral_public.as_bytes());
        proof[96..99].copy_from_slice(&signalling_bytes);

        link.set_destination_keys(&dest_verifying_key.to_bytes())
            .unwrap();
        link.process_proof(&proof).unwrap();

        // Now test encrypt/decrypt
        let plaintext = b"Hello, encrypted link!";
        let encrypted_len = Link::encrypted_size(plaintext.len());
        let mut encrypted = vec![0u8; encrypted_len];

        let mut ctx = PlatformContext {
            rng: OsRng,
            clock: TestClock::default(),
            storage: NoStorage,
        };
        let enc_len = link.encrypt(plaintext, &mut encrypted, &mut ctx).unwrap();
        assert!(enc_len > plaintext.len()); // Should be larger due to IV + padding + HMAC

        let mut decrypted = vec![0u8; plaintext.len() + 16]; // Allow for padding
        let dec_len = link.decrypt(&encrypted[..enc_len], &mut decrypted).unwrap();

        assert_eq!(dec_len, plaintext.len());
        assert_eq!(&decrypted[..dec_len], plaintext);
    }

    #[test]
    fn test_link_decrypt_tampered() {
        use ed25519_dalek::Signer;

        // Set up a link with completed handshake
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let mut link = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);
        let request = link.create_link_request();

        let mut raw_packet = Vec::new();
        raw_packet.push(0x02);
        raw_packet.push(0x00);
        raw_packet.extend_from_slice(&dest_hash);
        raw_packet.push(0x00);
        raw_packet.extend_from_slice(&request);

        let link_id = Link::calculate_link_id(&raw_packet);
        link.set_link_id(link_id);

        let dest_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x33; 32]);
        let dest_verifying_key = dest_signing_key.verifying_key();
        let dest_ephemeral_private =
            x25519_dalek::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let dest_ephemeral_public = x25519_dalek::PublicKey::from(&dest_ephemeral_private);

        let signalling_bytes: [u8; 3] = [0x43, 0x0f, 0x38];
        let mut signed_data = [0u8; 83];
        signed_data[..TRUNCATED_HASHBYTES].copy_from_slice(&link_id);
        signed_data[TRUNCATED_HASHBYTES..TRUNCATED_HASHBYTES + 32]
            .copy_from_slice(dest_ephemeral_public.as_bytes());
        signed_data[TRUNCATED_HASHBYTES + 32..TRUNCATED_HASHBYTES + 64]
            .copy_from_slice(&dest_verifying_key.to_bytes());
        signed_data[TRUNCATED_HASHBYTES + 64..].copy_from_slice(&signalling_bytes);
        let signature = dest_signing_key.sign(&signed_data);

        let mut proof = [0u8; 99];
        proof[..64].copy_from_slice(&signature.to_bytes());
        proof[64..96].copy_from_slice(dest_ephemeral_public.as_bytes());
        proof[96..99].copy_from_slice(&signalling_bytes);

        link.set_destination_keys(&dest_verifying_key.to_bytes())
            .unwrap();
        link.process_proof(&proof).unwrap();

        // Encrypt some data
        let plaintext = b"Secret message";
        let mut encrypted = vec![0u8; Link::encrypted_size(plaintext.len())];
        let mut ctx = PlatformContext {
            rng: OsRng,
            clock: TestClock::default(),
            storage: NoStorage,
        };
        let enc_len = link.encrypt(plaintext, &mut encrypted, &mut ctx).unwrap();

        // Tamper with the ciphertext
        encrypted[20] ^= 0xFF;

        // Decrypt should fail due to HMAC verification
        let mut decrypted = vec![0u8; 64];
        let result = link.decrypt(&encrypted[..enc_len], &mut decrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_size() {
        // 0 bytes -> 16 bytes padded -> 16 + 16 IV + 32 HMAC = 64
        assert_eq!(Link::encrypted_size(0), 64);

        // 1 byte -> 16 bytes padded -> 64
        assert_eq!(Link::encrypted_size(1), 64);

        // 15 bytes -> 16 bytes padded -> 64
        assert_eq!(Link::encrypted_size(15), 64);

        // 16 bytes -> 32 bytes padded -> 16 + 32 + 32 = 80
        assert_eq!(Link::encrypted_size(16), 80);

        // 100 bytes -> 112 bytes padded -> 16 + 112 + 32 = 160
        assert_eq!(Link::encrypted_size(100), 160);
    }

    #[test]
    fn test_build_data_packet() {
        use ed25519_dalek::Signer;

        // Set up a link with completed handshake
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let mut link = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);
        let request = link.create_link_request();

        let mut raw_packet = Vec::new();
        raw_packet.push(0x02);
        raw_packet.push(0x00);
        raw_packet.extend_from_slice(&dest_hash);
        raw_packet.push(0x00);
        raw_packet.extend_from_slice(&request);

        let link_id = Link::calculate_link_id(&raw_packet);
        link.set_link_id(link_id);

        let dest_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x33; 32]);
        let dest_verifying_key = dest_signing_key.verifying_key();
        let dest_ephemeral_private =
            x25519_dalek::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let dest_ephemeral_public = x25519_dalek::PublicKey::from(&dest_ephemeral_private);

        let signalling_bytes: [u8; 3] = [0x43, 0x0f, 0x38];
        let mut signed_data = [0u8; 83];
        signed_data[..TRUNCATED_HASHBYTES].copy_from_slice(&link_id);
        signed_data[TRUNCATED_HASHBYTES..TRUNCATED_HASHBYTES + 32]
            .copy_from_slice(dest_ephemeral_public.as_bytes());
        signed_data[TRUNCATED_HASHBYTES + 32..TRUNCATED_HASHBYTES + 64]
            .copy_from_slice(&dest_verifying_key.to_bytes());
        signed_data[TRUNCATED_HASHBYTES + 64..].copy_from_slice(&signalling_bytes);
        let signature = dest_signing_key.sign(&signed_data);

        let mut proof = [0u8; 99];
        proof[..64].copy_from_slice(&signature.to_bytes());
        proof[64..96].copy_from_slice(dest_ephemeral_public.as_bytes());
        proof[96..99].copy_from_slice(&signalling_bytes);

        link.set_destination_keys(&dest_verifying_key.to_bytes())
            .unwrap();
        link.process_proof(&proof).unwrap();

        // Now test build_data_packet
        let message = b"Hello, link!";
        let mut ctx = PlatformContext {
            rng: OsRng,
            clock: TestClock::default(),
            storage: NoStorage,
        };
        let packet = link.build_data_packet(message, &mut ctx).unwrap();

        // Verify packet structure:
        // [flags (1)] [hops (1)] [link_id (16)] [context (1)] [encrypted_data]
        assert!(packet.len() >= 19 + 48); // header + min encrypted size

        // Flags should be: Type1, no context, broadcast, Link dest type, Data packet type
        // dest_type=Link=0b11, packet_type=Data=0b00 -> bits 3-0 = 0b1100 = 0x0C
        assert_eq!(packet[0] & 0x0F, 0x0C);

        // Hops should be 0
        assert_eq!(packet[1], 0x00);

        // Link ID should be in bytes 2-17
        assert_eq!(&packet[2..18], &link_id);

        // Context should be None (0x00)
        assert_eq!(packet[18], 0x00);

        // Encrypted data starts at byte 19
        // We can decrypt it to verify
        let encrypted_data = &packet[19..];
        let mut decrypted = vec![0u8; message.len() + 16];
        let dec_len = link.decrypt(encrypted_data, &mut decrypted).unwrap();
        assert_eq!(dec_len, message.len());
        assert_eq!(&decrypted[..dec_len], message);
    }

    #[test]
    fn test_build_data_packet_not_active() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let link = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);

        let mut ctx = PlatformContext {
            rng: OsRng,
            clock: TestClock::default(),
            storage: NoStorage,
        };
        // Link is in Pending state, not Active
        let result = link.build_data_packet(b"Hello", &mut ctx);
        assert!(matches!(result, Err(LinkError::InvalidState)));
    }

    // ==================== RESPONDER-SIDE TESTS ====================

    #[test]
    fn test_new_incoming_link() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];

        // Create initiator's link request
        let initiator = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);
        let request_data = initiator.create_link_request();

        // Calculate link ID (as if from raw packet)
        let mut raw_packet = Vec::new();
        raw_packet.push(0x02); // flags
        raw_packet.push(0x00); // hops
        raw_packet.extend_from_slice(&dest_hash);
        raw_packet.push(0x00); // context
        raw_packet.extend_from_slice(&request_data);
        let link_id = Link::calculate_link_id(&raw_packet);

        // Create responder's link
        let responder =
            Link::new_incoming_with_rng(&request_data, link_id, dest_hash, &mut OsRng).unwrap();

        assert_eq!(responder.state(), LinkState::Pending);
        assert!(!responder.is_initiator());
        assert_eq!(responder.id(), &link_id);
        assert_eq!(responder.destination_hash(), &dest_hash);
        // Responder should have peer's public keys set
        assert!(responder.peer_ephemeral_public.is_some());
        assert!(responder.peer_verifying_key.is_some());
    }

    #[test]
    fn test_new_incoming_link_invalid_request() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let link_id = [0xAB; TRUNCATED_HASHBYTES];

        // Too short request data
        let short_data = [0u8; 63];
        let result = Link::new_incoming_with_rng(&short_data, link_id, dest_hash, &mut OsRng);
        assert!(matches!(result, Err(LinkError::InvalidRequest)));
    }

    #[test]
    fn test_build_proof_packet() {
        use crate::identity::Identity;

        let dest_hash = [0x42; TRUNCATED_HASHBYTES];

        // Create destination identity
        let identity = Identity::generate_with_rng(&mut OsRng);

        // Create initiator's link request
        let initiator = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);
        let request_data = initiator.create_link_request();

        // Calculate link ID
        let mut raw_packet = Vec::new();
        raw_packet.push(0x02);
        raw_packet.push(0x00);
        raw_packet.extend_from_slice(&dest_hash);
        raw_packet.push(0x00);
        raw_packet.extend_from_slice(&request_data);
        let link_id = Link::calculate_link_id(&raw_packet);

        // Create responder's link
        let mut responder =
            Link::new_incoming_with_rng(&request_data, link_id, dest_hash, &mut OsRng).unwrap();

        // Build proof packet
        let proof_packet = responder.build_proof_packet(&identity, 500, 1).unwrap();

        // Verify responder state
        assert_eq!(responder.state(), LinkState::Handshake);
        assert!(responder.link_key().is_some());

        // Verify packet structure
        // [flags (1)] [hops (1)] [link_id (16)] [context (1)] [proof_data (99)]
        assert_eq!(proof_packet.len(), 1 + 1 + TRUNCATED_HASHBYTES + 1 + 99);

        // Context should be LRPROOF
        use crate::packet::PacketContext;
        assert_eq!(proof_packet[18], PacketContext::Lrproof as u8);

        // Link ID in packet should match
        assert_eq!(&proof_packet[2..18], &link_id);
    }

    #[test]
    fn test_build_proof_packet_wrong_state() {
        use crate::identity::Identity;

        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let identity = Identity::generate_with_rng(&mut OsRng);

        let initiator = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);
        let request_data = initiator.create_link_request();
        let link_id = [0xAB; TRUNCATED_HASHBYTES];

        let mut responder =
            Link::new_incoming_with_rng(&request_data, link_id, dest_hash, &mut OsRng).unwrap();

        // Build proof once (transitions to Handshake)
        responder.build_proof_packet(&identity, 500, 1).unwrap();

        // Second call should fail (wrong state)
        let result = responder.build_proof_packet(&identity, 500, 1);
        assert!(matches!(result, Err(LinkError::InvalidState)));
    }

    #[test]
    fn test_build_proof_packet_from_initiator() {
        use crate::identity::Identity;

        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let identity = Identity::generate_with_rng(&mut OsRng);

        // Initiator should not be able to build proof
        let mut initiator = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);

        let result = initiator.build_proof_packet(&identity, 500, 1);
        assert!(matches!(result, Err(LinkError::InvalidState)));
    }

    #[test]
    fn test_full_handshake_responder_side() {
        use crate::identity::Identity;

        let dest_hash = [0x42; TRUNCATED_HASHBYTES];

        // --- Destination setup ---
        let dest_identity = Identity::generate_with_rng(&mut OsRng);

        // --- Initiator side ---
        let mut initiator = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);
        let request_data = initiator.create_link_request();

        // Calculate link ID from raw packet
        let mut raw_packet = Vec::new();
        raw_packet.push(0x02);
        raw_packet.push(0x00);
        raw_packet.extend_from_slice(&dest_hash);
        raw_packet.push(0x00);
        raw_packet.extend_from_slice(&request_data);
        let link_id = Link::calculate_link_id(&raw_packet);
        initiator.set_link_id(link_id);

        // --- Responder side ---
        let mut responder =
            Link::new_incoming_with_rng(&request_data, link_id, dest_hash, &mut OsRng).unwrap();

        // Build proof packet
        let proof_packet = responder
            .build_proof_packet(&dest_identity, 500, 1)
            .unwrap();

        // --- Back to initiator ---
        // Set destination's verifying key
        initiator
            .set_destination_keys(dest_identity.ed25519_verifying().as_bytes())
            .unwrap();

        // Extract proof data from packet (skip header)
        let proof_data = &proof_packet[19..]; // Skip flags(1) + hops(1) + link_id(16) + context(1)

        // Process proof
        initiator.process_proof(proof_data).unwrap();
        assert_eq!(initiator.state(), LinkState::Active);

        // Both links should have the same derived key
        assert_eq!(initiator.link_key().unwrap(), responder.link_key().unwrap());
    }

    #[test]
    fn test_process_rtt() {
        use crate::identity::Identity;

        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let dest_identity = Identity::generate_with_rng(&mut OsRng);

        // Set up links
        let mut initiator = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);
        let request_data = initiator.create_link_request();

        let mut raw_packet = Vec::new();
        raw_packet.push(0x02);
        raw_packet.push(0x00);
        raw_packet.extend_from_slice(&dest_hash);
        raw_packet.push(0x00);
        raw_packet.extend_from_slice(&request_data);
        let link_id = Link::calculate_link_id(&raw_packet);
        initiator.set_link_id(link_id);

        let mut responder =
            Link::new_incoming_with_rng(&request_data, link_id, dest_hash, &mut OsRng).unwrap();

        // Build and process proof
        let proof_packet = responder
            .build_proof_packet(&dest_identity, 500, 1)
            .unwrap();
        initiator
            .set_destination_keys(dest_identity.ed25519_verifying().as_bytes())
            .unwrap();
        initiator.process_proof(&proof_packet[19..]).unwrap();

        // Initiator builds RTT packet
        let mut ctx = PlatformContext {
            rng: OsRng,
            clock: TestClock::default(),
            storage: NoStorage,
        };
        let rtt_seconds = 0.05; // 50ms
        let rtt_packet = initiator.build_rtt_packet(rtt_seconds, &mut ctx).unwrap();

        // Extract encrypted data from RTT packet
        let encrypted_data = &rtt_packet[19..];

        // Responder processes RTT
        let received_rtt = responder.process_rtt(encrypted_data).unwrap();

        // Responder should now be active
        assert_eq!(responder.state(), LinkState::Active);
        assert!((received_rtt - rtt_seconds).abs() < 0.001);
        assert!(responder.rtt_us().is_some());
    }

    #[test]
    fn test_process_rtt_wrong_state() {
        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let link_id = [0xAB; TRUNCATED_HASHBYTES];

        let initiator = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);
        let request_data = initiator.create_link_request();

        let mut responder =
            Link::new_incoming_with_rng(&request_data, link_id, dest_hash, &mut OsRng).unwrap();

        // Responder is still in Pending state (no proof built yet)
        let fake_data = [0u8; 64];
        let result = responder.process_rtt(&fake_data);
        assert!(matches!(result, Err(LinkError::InvalidState)));
    }

    #[test]
    fn test_bidirectional_data_after_handshake() {
        use crate::identity::Identity;

        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let dest_identity = Identity::generate_with_rng(&mut OsRng);

        // Full handshake
        let mut initiator = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);
        let request_data = initiator.create_link_request();

        let mut raw_packet = Vec::new();
        raw_packet.push(0x02);
        raw_packet.push(0x00);
        raw_packet.extend_from_slice(&dest_hash);
        raw_packet.push(0x00);
        raw_packet.extend_from_slice(&request_data);
        let link_id = Link::calculate_link_id(&raw_packet);
        initiator.set_link_id(link_id);

        let mut responder =
            Link::new_incoming_with_rng(&request_data, link_id, dest_hash, &mut OsRng).unwrap();

        let proof_packet = responder
            .build_proof_packet(&dest_identity, 500, 1)
            .unwrap();
        initiator
            .set_destination_keys(dest_identity.ed25519_verifying().as_bytes())
            .unwrap();
        initiator.process_proof(&proof_packet[19..]).unwrap();

        let mut ctx = PlatformContext {
            rng: OsRng,
            clock: TestClock::default(),
            storage: NoStorage,
        };
        let rtt_packet = initiator.build_rtt_packet(0.05, &mut ctx).unwrap();
        responder.process_rtt(&rtt_packet[19..]).unwrap();

        // Both sides active
        assert_eq!(initiator.state(), LinkState::Active);
        assert_eq!(responder.state(), LinkState::Active);

        // Test initiator -> responder
        let message1 = b"Hello from initiator!";
        let mut encrypted1 = vec![0u8; Link::encrypted_size(message1.len())];
        let enc_len1 = initiator
            .encrypt(message1, &mut encrypted1, &mut ctx)
            .unwrap();

        let mut decrypted1 = vec![0u8; message1.len() + 16];
        let dec_len1 = responder
            .decrypt(&encrypted1[..enc_len1], &mut decrypted1)
            .unwrap();
        assert_eq!(&decrypted1[..dec_len1], message1);

        // Test responder -> initiator
        let message2 = b"Hello from responder!";
        let mut encrypted2 = vec![0u8; Link::encrypted_size(message2.len())];
        let enc_len2 = responder
            .encrypt(message2, &mut encrypted2, &mut ctx)
            .unwrap();

        let mut decrypted2 = vec![0u8; message2.len() + 16];
        let dec_len2 = initiator
            .decrypt(&encrypted2[..enc_len2], &mut decrypted2)
            .unwrap();
        assert_eq!(&decrypted2[..dec_len2], message2);
    }

    #[test]
    fn test_build_link_request_with_transport() {
        use crate::packet::{HeaderType, Packet, TransportType};

        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let transport_id = [0xAB; TRUNCATED_HASHBYTES];

        // Test with transport_id and hops=1 (should still use HEADER_2 because transport_id is set)
        let mut link1 = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);
        let packet1 = link1.build_link_request_packet_with_transport(Some(transport_id), 1);

        // Should be HEADER_2 (transport_id is set, even with hops=1)
        let parsed1 = Packet::unpack(&packet1).unwrap();
        assert_eq!(parsed1.flags.header_type, HeaderType::Type2);
        assert_eq!(parsed1.flags.transport_type, TransportType::Transport);
        assert_eq!(parsed1.transport_id, Some(transport_id));
        assert_eq!(parsed1.destination_hash, dest_hash);
        assert_eq!(link1.hops(), 1);

        // Test with hops > 1 and transport_id (should use HEADER_2)
        let mut link2 = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);
        let packet2 = link2.build_link_request_packet_with_transport(Some(transport_id), 2);

        // Should be HEADER_2 with transport_id
        let parsed2 = Packet::unpack(&packet2).unwrap();
        assert_eq!(parsed2.flags.header_type, HeaderType::Type2);
        assert_eq!(parsed2.flags.transport_type, TransportType::Transport);
        assert_eq!(parsed2.transport_id, Some(transport_id));
        assert_eq!(parsed2.destination_hash, dest_hash);
        assert_eq!(link2.hops(), 2);

        // Test with no transport_id (should use HEADER_1)
        let mut link3 = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);
        let packet3 = link3.build_link_request_packet_with_transport(None, 5);

        let parsed3 = Packet::unpack(&packet3).unwrap();
        assert_eq!(parsed3.flags.header_type, HeaderType::Type1);
        assert!(parsed3.transport_id.is_none());
    }

    #[test]
    fn test_build_link_request_with_transport_flags() {
        use crate::packet::Packet;

        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let transport_id = [0xCD; TRUNCATED_HASHBYTES];

        let mut link = Link::new_outgoing_with_rng(dest_hash, &mut OsRng);
        let packet = link.build_link_request_packet_with_transport(Some(transport_id), 3);

        // Parse and verify flags byte
        let parsed = Packet::unpack(&packet).unwrap();

        // Expected flags for HEADER_2 link request:
        // Bit 6: Header Type = 1 (Type2)
        // Bit 5: Context Flag = 0
        // Bit 4: Transport Type = 1 (Transport)
        // Bits 3-2: Dest Type = 00 (Single = 0x00)
        // Bits 1-0: Packet Type = 10 (LinkRequest)
        // = 0b01010010 = 0x52
        let expected_flags = 0x52;
        assert_eq!(
            packet[0], expected_flags,
            "Flags should be 0x52 for HEADER_2 transport link request"
        );

        // Hops should be 0 (we're originating)
        assert_eq!(packet[1], 0x00);

        // Transport ID should be at bytes 2-17
        assert_eq!(&packet[2..18], &transport_id);

        // Destination hash should be at bytes 18-33
        assert_eq!(&packet[18..34], &dest_hash);

        // Verify parsed packet matches
        assert_eq!(parsed.hops, 0);
        assert_eq!(parsed.transport_id, Some(transport_id));
        assert_eq!(parsed.destination_hash, dest_hash);
    }

    #[test]
    fn test_link_id_same_for_header1_and_header2() {
        // This test verifies that the link_id calculation is the same
        // regardless of whether HEADER_1 or HEADER_2 is used.
        // This is critical for transport routing to work correctly.

        let dest_hash = [0x42; TRUNCATED_HASHBYTES];
        let transport_id = [0xAB; TRUNCATED_HASHBYTES];

        // Create two links with the same ephemeral keys by using the same seed
        // We need to ensure the request data is identical for fair comparison
        let seed = [0x55; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let x25519_secret = x25519_dalek::StaticSecret::from([0x66; 32]);
        let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret);

        // Manually create the link request data (same for both)
        let mut request_data = [0u8; 64];
        request_data[..32].copy_from_slice(x25519_public.as_bytes());
        request_data[32..64].copy_from_slice(&verifying_key.to_bytes());

        // Build HEADER_1 packet manually
        let mut header1_packet = Vec::new();
        header1_packet.push(0x02); // flags: Type1, Broadcast, Single, LinkRequest
        header1_packet.push(0x00); // hops
        header1_packet.extend_from_slice(&dest_hash);
        header1_packet.push(0x00); // context
        header1_packet.extend_from_slice(&request_data);

        // Build HEADER_2 packet manually
        let mut header2_packet = Vec::new();
        header2_packet.push(0x52); // flags: Type2, Transport, Single, LinkRequest
        header2_packet.push(0x00); // hops
        header2_packet.extend_from_slice(&transport_id);
        header2_packet.extend_from_slice(&dest_hash);
        header2_packet.push(0x00); // context
        header2_packet.extend_from_slice(&request_data);

        // Calculate link_id for both
        let link_id_h1 = Link::calculate_link_id(&header1_packet);
        let link_id_h2 = Link::calculate_link_id(&header2_packet);

        // They should be identical
        assert_eq!(
            link_id_h1, link_id_h2,
            "Link ID should be the same for HEADER_1 and HEADER_2 packets with same content"
        );
    }
}
