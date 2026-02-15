//! High-level link management
//!
//! The [`LinkManager`] provides a high-level API for managing links.
//! It handles:
//! - Tracking pending and active links
//! - Processing incoming link packets (LINK_REQUEST, PROOF, RTT, DATA)
//! - Emitting events for state changes
//!
//! # Usage
//!
//! ```
//! use reticulum_core::link::{LinkManager, LinkEvent};
//! use rand_core::OsRng;
//!
//! use reticulum_core::destination::DestinationHash;
//!
//! let mut manager = LinkManager::new();
//!
//! // Register destination to accept incoming links
//! let my_dest_hash = DestinationHash::new([0x42u8; 16]);
//! manager.register_destination(my_dest_hash);
//!
//! // Initiate outgoing link
//! let dest_hash = DestinationHash::new([0x33u8; 16]);
//! let dest_signing_key = [0x11u8; 32];
//! let now_ms = 1_000_000u64;
//! let (link_id, packet) = manager.initiate(dest_hash, &dest_signing_key, &mut OsRng, now_ms);
//!
//! // Handle events
//! for event in manager.drain_events() {
//!     match event {
//!         LinkEvent::LinkEstablished { link_id, .. } => { /* ... */ }
//!         LinkEvent::DataReceived { link_id, data } => { /* ... */ }
//!         _ => {}
//!     }
//! }
//! ```

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::constants::{
    DATA_RECEIPT_TIMEOUT_MS, LINK_PENDING_TIMEOUT_MS, MODE_AES256_CBC, MS_PER_SECOND, MTU,
    PROOF_DATA_SIZE, TRUNCATED_HASHBYTES,
};
use crate::destination::ProofStrategy;
use crate::identity::Identity;
use crate::packet::{packet_hash, Packet, PacketContext, PacketType};
use rand_core::CryptoRngCore;

use super::channel::{Channel, ChannelError, Message};
use super::{
    Link, LinkCloseReason, LinkError, LinkEvent, LinkId, LinkPhase, LinkState, PeerKeys,
    PendingPacket,
};
use crate::destination::DestinationHash;
use crate::hex_fmt::HexFmt;

/// Extract packets matching a predicate from the unified queue, returning (link_id, data) pairs.
fn drain_packets_by_kind(
    packets: &mut Vec<PendingPacket>,
    pred: impl Fn(&PendingPacket) -> bool,
) -> Vec<(LinkId, Vec<u8>)> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < packets.len() {
        if pred(&packets[i]) {
            match packets.remove(i) {
                PendingPacket::Rtt { link_id, data }
                | PendingPacket::Keepalive { link_id, data }
                | PendingPacket::Close { link_id, data }
                | PendingPacket::Channel { link_id, data }
                | PendingPacket::Proof { link_id, data } => {
                    result.push((link_id, data));
                }
            }
        } else {
            i += 1;
        }
    }
    result
}

/// Manages all link state and handshakes
pub struct LinkManager {
    /// Active links by ID
    links: BTreeMap<LinkId, Link>,
    /// Destinations that accept incoming links
    accepted_destinations: BTreeSet<DestinationHash>,
    /// Pending events
    events: Vec<LinkEvent>,
    /// Unified queue for all outbound link packets
    pending_packets: Vec<PendingPacket>,
    /// Receipts for sent data packets awaiting proofs (truncated_hash -> receipt)
    data_receipts: BTreeMap<[u8; TRUNCATED_HASHBYTES], DataReceipt>,
    /// Maps (link_id, channel_sequence) → truncated receipt hash for cleanup on retransmit
    channel_receipt_keys: BTreeMap<(LinkId, u16), [u8; TRUNCATED_HASHBYTES]>,
    /// Count of rx_ring full drops since last log
    rx_ring_full_count: u64,
    /// Timestamp (ms) when last rx_ring full log was emitted
    rx_ring_full_last_log_ms: u64,
}

/// Receipt for a sent data packet awaiting proof (PROVE_ALL)
struct DataReceipt {
    /// Full SHA256 hash of the packet
    full_hash: [u8; 32],
    /// Link ID the packet was sent on
    link_id: LinkId,
    /// When the packet was sent (ms since epoch)
    sent_at_ms: u64,
}

impl LinkManager {
    /// Create a new LinkManager
    pub fn new() -> Self {
        Self {
            links: BTreeMap::new(),
            accepted_destinations: BTreeSet::new(),
            events: Vec::new(),
            pending_packets: Vec::new(),
            data_receipts: BTreeMap::new(),
            channel_receipt_keys: BTreeMap::new(),
            rx_ring_full_count: 0,
            rx_ring_full_last_log_ms: 0,
        }
    }

    // --- Initiator API ---

    /// Start establishing a link to a destination
    ///
    /// Returns (link_id, raw_packet) where raw_packet is the LINK_REQUEST
    /// packet that should be sent on the interface.
    ///
    /// The link will emit `LinkEstablished` or `LinkClosed` event when
    /// the handshake completes or times out.
    ///
    /// # Arguments
    /// * `dest_hash` - The destination hash to connect to
    /// * `dest_signing_key` - The destination's Ed25519 signing key (from announce)
    /// * `rng` - Random number generator
    /// * `now_ms` - Current time in milliseconds
    pub fn initiate(
        &mut self,
        dest_hash: DestinationHash,
        dest_signing_key: &[u8; 32],
        rng: &mut impl CryptoRngCore,
        now_ms: u64,
    ) -> (LinkId, Vec<u8>) {
        self.initiate_with_path(dest_hash, dest_signing_key, None, 1, rng, now_ms)
    }

    /// Start establishing a link to a destination with explicit path information.
    ///
    /// Use this method when the destination is reachable through an intermediate
    /// transport node (more than 1 hop away). The `next_hop` should be the identity
    /// hash of the transport node that will forward packets to the destination.
    ///
    /// Returns (link_id, raw_packet) where raw_packet is the LINK_REQUEST
    /// packet that should be sent on the interface.
    ///
    /// # Arguments
    /// * `dest_hash` - The destination hash to connect to
    /// * `dest_signing_key` - The destination's Ed25519 signing key (from announce)
    /// * `next_hop` - The transport_id (identity hash) of the next hop node, if routing through a relay
    /// * `hops` - Number of hops to the destination
    /// * `rng` - Random number generator
    /// * `now_ms` - Current time in milliseconds
    ///
    /// # Example
    /// ```
    /// use reticulum_core::link::LinkManager;
    /// use reticulum_core::destination::DestinationHash;
    /// use rand_core::OsRng;
    ///
    /// let mut manager = LinkManager::new();
    ///
    /// // For a destination 2+ hops away, use the transport_id from the announce
    /// let dest_hash = DestinationHash::new([0x42u8; 16]);
    /// let signing_key = [0x33u8; 32];
    /// let transport_id = [0x11u8; 16]; // relay node's identity hash
    /// let hops = 2;
    ///
    /// let (link_id, packet) = manager.initiate_with_path(
    ///     dest_hash,
    ///     &signing_key,
    ///     Some(transport_id),
    ///     hops,
    ///     &mut OsRng,
    ///     1_000_000,
    /// );
    /// assert!(!packet.is_empty());
    /// ```
    pub fn initiate_with_path(
        &mut self,
        dest_hash: DestinationHash,
        dest_signing_key: &[u8; 32],
        next_hop: Option<[u8; TRUNCATED_HASHBYTES]>,
        hops: u8,
        rng: &mut impl CryptoRngCore,
        now_ms: u64,
    ) -> (LinkId, Vec<u8>) {
        // Create new outgoing link
        let mut link = Link::new_outgoing(dest_hash, rng);

        // Build the LINK_REQUEST packet with transport headers if needed
        let packet = link.build_link_request_packet_with_transport(next_hop, hops);
        let link_id = *link.id();

        // Set the destination's signing key for proof verification
        let _ = link.set_destination_keys(dest_signing_key);

        // Track handshake phase on the link itself
        link.set_phase(LinkPhase::PendingOutgoing {
            created_at_ms: now_ms,
        });

        // Store the link
        self.links.insert(link_id, link);

        (link_id, packet)
    }

    // --- Responder API ---

    /// Register a destination to accept incoming links
    ///
    /// When a LINK_REQUEST arrives for this destination, a `LinkRequestReceived`
    /// event will be emitted. Call `accept_link()` or `reject_link()` to respond.
    ///
    /// # Arguments
    /// * `dest_hash` - The destination hash to register
    pub fn register_destination(&mut self, dest_hash: DestinationHash) {
        self.accepted_destinations.insert(dest_hash);
    }

    /// Unregister a destination from accepting links
    pub fn unregister_destination(&mut self, dest_hash: &DestinationHash) {
        self.accepted_destinations.remove(dest_hash);
    }

    /// Check if a destination accepts links
    pub fn accepts_links(&self, dest_hash: &DestinationHash) -> bool {
        self.accepted_destinations.contains(dest_hash)
    }

    /// Accept a pending incoming link (after `LinkRequestReceived` event)
    ///
    /// Returns the PROOF packet to send back to the initiator.
    ///
    /// # Arguments
    /// * `link_id` - The link ID from the `LinkRequestReceived` event
    /// * `identity` - The destination's identity (for signing the proof)
    /// * `proof_strategy` - The proof strategy for received data packets on this link
    /// * `now_ms` - Current time in milliseconds
    pub fn accept_link(
        &mut self,
        link_id: &LinkId,
        identity: &Identity,
        proof_strategy: ProofStrategy,
        now_ms: u64,
    ) -> Result<Vec<u8>, LinkError> {
        let link = self.links.get_mut(link_id).ok_or(LinkError::NotFound)?;

        if link.state() != LinkState::Pending {
            return Err(LinkError::InvalidState);
        }

        if link.is_initiator() {
            return Err(LinkError::InvalidState);
        }

        // Store proof strategy and signing key on the link itself.
        // Always store signing key — channel proofs are unconditional (Python Link.py:1173)
        // and need the key even when proof_strategy is None for regular data.
        link.set_proof_strategy(proof_strategy);
        if let Some(sk) = identity.ed25519_signing_key() {
            link.set_dest_signing_key(sk.clone());
        }

        // Build the proof packet (this also derives the link key)
        let proof_packet = link.build_proof_packet(identity, MTU as u32, MODE_AES256_CBC)?;

        // Track handshake phase on the link itself
        link.set_phase(LinkPhase::PendingIncoming {
            proof_sent_at_ms: now_ms,
        });

        Ok(proof_packet)
    }

    /// Reject a pending incoming link
    ///
    /// Removes the link without sending a response. The initiator will
    /// eventually time out.
    pub fn reject_link(&mut self, link_id: &LinkId) {
        self.links.remove(link_id);
    }

    // --- Data API ---

    /// Send data on an established link
    ///
    /// Returns the encrypted packet to send on the interface.
    ///
    /// # Arguments
    /// * `link_id` - The link to send on
    /// * `data` - The plaintext data to send
    /// * `rng` - Random number generator
    pub fn send(
        &mut self,
        link_id: &LinkId,
        data: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, LinkError> {
        let link = self.links.get(link_id).ok_or(LinkError::NotFound)?;

        if link.state() != LinkState::Active {
            return Err(LinkError::InvalidState);
        }

        link.build_data_packet(data, rng)
    }

    /// Send data on an established link with receipt tracking
    ///
    /// Returns the encrypted packet and the packet hash for tracking delivery.
    /// Use this when the peer has PROVE_ALL enabled and you want to receive
    /// confirmation of delivery via the `DataDelivered` event.
    ///
    /// # Arguments
    /// * `link_id` - The link to send on
    /// * `data` - The plaintext data to send
    /// * `now_ms` - Current time in milliseconds
    /// * `rng` - Random number generator
    ///
    /// # Returns
    /// On success, returns (packet_data, packet_hash) where:
    /// - `packet_data` is the encrypted packet to send
    /// - `packet_hash` is the full SHA256 hash used to match incoming proofs
    pub fn send_with_receipt(
        &mut self,
        link_id: &LinkId,
        data: &[u8],
        rng: &mut impl CryptoRngCore,
        now_ms: u64,
    ) -> Result<(Vec<u8>, [u8; 32]), LinkError> {
        let link = self.links.get(link_id).ok_or(LinkError::NotFound)?;

        if link.state() != LinkState::Active {
            return Err(LinkError::InvalidState);
        }

        let packet_data = link.build_data_packet(data, rng)?;
        let full_hash = packet_hash(&packet_data);

        // Compute truncated hash for receipt lookup
        let mut truncated = [0u8; TRUNCATED_HASHBYTES];
        truncated.copy_from_slice(&full_hash[..TRUNCATED_HASHBYTES]);

        // Track the receipt
        self.data_receipts.insert(
            truncated,
            DataReceipt {
                full_hash,
                link_id: *link_id,
                sent_at_ms: now_ms,
            },
        );

        Ok((packet_data, full_hash))
    }

    /// Send a data proof for a received packet (PROVE_APP callback)
    ///
    /// Call this after receiving a `ProofRequested` event when your application
    /// decides to prove delivery.
    ///
    /// # Arguments
    /// * `link_id` - The link the data was received on
    /// * `packet_hash` - The packet hash from the `ProofRequested` event
    ///
    /// # Returns
    /// On success, returns the proof packet to send. On error, returns `LinkError`.
    pub fn send_data_proof(
        &mut self,
        link_id: &LinkId,
        packet_hash: &[u8; 32],
    ) -> Result<Vec<u8>, LinkError> {
        let link = self.links.get(link_id).ok_or(LinkError::NotFound)?;

        if link.state() != LinkState::Active {
            return Err(LinkError::InvalidState);
        }

        let signing_key = link.proof_signing_key().ok_or(LinkError::NoIdentity)?;
        link.build_data_proof_packet_with_signing_key(packet_hash, signing_key)
    }

    /// Register a data receipt for a channel message, removing any previous receipt
    /// for the same (link_id, sequence).
    ///
    /// On retransmit, the re-encrypted packet has a different hash. This method
    /// removes the old receipt before inserting the new one, preventing leaks
    /// and ensuring proofs for retransmits match.
    ///
    /// # Arguments
    /// * `packet_data` - The serialized packet bytes (hashed for receipt matching)
    /// * `link_id` - The link this packet was sent on
    /// * `sequence` - Channel message sequence number
    /// * `now_ms` - Current time in milliseconds
    ///
    /// # Returns
    /// `(new_full_hash, old_full_hash)` where `old_full_hash` is `Some` if an
    /// old receipt was replaced.
    pub fn register_channel_receipt(
        &mut self,
        packet_data: &[u8],
        link_id: LinkId,
        sequence: u16,
        now_ms: u64,
    ) -> ([u8; 32], Option<[u8; 32]>) {
        // Remove old receipt for this (link_id, sequence) if present
        let old_full_hash = self
            .channel_receipt_keys
            .remove(&(link_id, sequence))
            .and_then(|old_truncated| self.data_receipts.remove(&old_truncated))
            .map(|old_receipt| old_receipt.full_hash);

        // Register new receipt
        let full_hash = packet_hash(packet_data);
        let mut truncated = [0u8; TRUNCATED_HASHBYTES];
        truncated.copy_from_slice(&full_hash[..TRUNCATED_HASHBYTES]);
        tracing::debug!(
            hash = %HexFmt(&full_hash),
            truncated = %HexFmt(&truncated),
            link = %HexFmt(link_id.as_bytes()),
            "link_mgr: registered channel receipt"
        );
        self.data_receipts.insert(
            truncated,
            DataReceipt {
                full_hash,
                link_id,
                sent_at_ms: now_ms,
            },
        );
        self.channel_receipt_keys
            .insert((link_id, sequence), truncated);

        (full_hash, old_full_hash)
    }

    /// Close a link gracefully
    ///
    /// This builds a LINKCLOSE packet that should be sent to the peer.
    /// Call `drain_pending_packets()` after this to get the packet to send.
    pub fn close(&mut self, link_id: &LinkId, rng: &mut impl CryptoRngCore) {
        if let Some(link) = self.links.get_mut(link_id) {
            // Capture metadata before closing
            let is_initiator = link.is_initiator();
            let destination_hash = *link.destination_hash();
            // Try to build and queue the close packet
            if let Ok(close_packet) = link.build_close_packet(rng) {
                self.pending_packets.push(PendingPacket::Close {
                    link_id: *link_id,
                    data: close_packet,
                });
            }
            // Mark the link as closed
            link.close();
            // Emit event
            self.events.push(LinkEvent::LinkClosed {
                link_id: *link_id,
                reason: LinkCloseReason::Normal,
                is_initiator,
                destination_hash,
            });
        }
        // Clean up all tracking (no-op if link_id not present)
        // Phase and channel are on Link — removing the link drops them automatically.
        self.links.remove(link_id);
        self.channel_receipt_keys
            .retain(|(lid, _), _| *lid != *link_id);
    }

    /// Close a link without sending a close packet (local only)
    ///
    /// Use this when the peer has already closed the link or when
    /// we don't want/can't send a close packet.
    pub fn close_local(&mut self, link_id: &LinkId, reason: LinkCloseReason) {
        // Capture metadata before removal
        let (is_initiator, destination_hash) = self
            .links
            .get(link_id)
            .map(|l| (l.is_initiator(), *l.destination_hash()))
            .unwrap_or((false, DestinationHash::new([0; 16])));
        if let Some(link) = self.links.get_mut(link_id) {
            link.close();
        }
        // Always remove from tracking regardless of link state
        // Phase and channel are on Link — removing the link drops them automatically.
        self.links.remove(link_id);
        self.channel_receipt_keys
            .retain(|(lid, _), _| *lid != *link_id);
        self.events.push(LinkEvent::LinkClosed {
            link_id: *link_id,
            reason,
            is_initiator,
            destination_hash,
        });
    }

    // --- Channel API ---

    /// Get or create a channel for a link
    ///
    /// Channels provide reliable, ordered message delivery over links.
    /// A channel is lazily created on first access.
    ///
    /// # Arguments
    /// * `link_id` - The link ID to get the channel for
    ///
    /// # Returns
    /// A mutable reference to the channel, or None if the link doesn't exist
    /// or is not active.
    pub fn get_channel(&mut self, link_id: &LinkId) -> Option<&mut Channel> {
        let link = self.links.get_mut(link_id)?;
        if link.state() != LinkState::Active {
            return None;
        }
        let rtt_ms = link.rtt_ms();
        Some(link.ensure_channel(rtt_ms))
    }

    /// Get an immutable reference to a channel (None if not yet created)
    pub fn channel(&self, link_id: &LinkId) -> Option<&Channel> {
        self.links.get(link_id)?.channel()
    }

    /// Check if a channel exists for a link
    pub fn has_channel(&self, link_id: &LinkId) -> bool {
        self.links
            .get(link_id)
            .map(|l| l.has_channel())
            .unwrap_or(false)
    }

    /// Mark a channel message as delivered (proof received)
    ///
    /// Returns true if the sequence was found in the channel's tx_ring.
    pub fn mark_channel_delivered(
        &mut self,
        link_id: &LinkId,
        sequence: u16,
        now_ms: u64,
        rtt_ms: u64,
    ) -> bool {
        self.links
            .get_mut(link_id)
            .and_then(|l| l.channel_mut())
            .map(|ch| ch.mark_delivered(sequence, now_ms, rtt_ms))
            .unwrap_or(false)
    }

    /// Get the last sent sequence number for a channel
    pub fn channel_last_sent_sequence(&self, link_id: &LinkId) -> Option<u16> {
        self.links
            .get(link_id)?
            .channel()
            .map(|ch| ch.last_sent_sequence())
    }

    /// Get the number of pending data receipts
    pub fn data_receipts_count(&self) -> usize {
        self.data_receipts.len()
    }

    /// Send a channel message on a link
    ///
    /// This creates an envelope, encrypts it, and returns the packet to send.
    ///
    /// # Arguments
    /// * `link_id` - The link to send on
    /// * `message` - The message to send
    /// * `now_ms` - Current time in milliseconds
    /// * `rng` - Random number generator
    ///
    /// # Errors
    /// - `NotFound` if the link doesn't exist or isn't active
    /// - Channel errors (TooLarge, WindowFull, etc.)
    pub fn channel_send<M: Message>(
        &mut self,
        link_id: &LinkId,
        message: &M,
        rng: &mut impl CryptoRngCore,
        now_ms: u64,
    ) -> Result<Vec<u8>, LinkError> {
        let link = self.links.get_mut(link_id).ok_or(LinkError::NotFound)?;
        if link.state() != LinkState::Active {
            return Err(LinkError::InvalidState);
        }

        // Extract values needed for channel.send() before taking &mut channel
        let link_mdu = link.mdu();
        let rtt_ms = link.rtt_ms();

        // Scope the &mut channel borrow so it's released before we call link methods again
        let envelope_data = {
            let channel = link.ensure_channel(rtt_ms);
            channel
                .send(message, link_mdu, now_ms, rtt_ms)
                .map_err(|e| match e {
                    ChannelError::WindowFull => LinkError::WindowFull,
                    ChannelError::PacingDelay { ready_at_ms } => {
                        LinkError::PacingDelay { ready_at_ms }
                    }
                    _ => LinkError::InvalidState,
                })?
        };
        // &mut channel borrow released by block scope — envelope_data is owned Vec<u8>
        link.build_data_packet_with_context(&envelope_data, PacketContext::Channel, rng)
    }

    /// Drain all pending outbound packets
    ///
    /// Returns all queued link-level packets (RTT, keepalive, close, channel, proof).
    /// NodeCore calls this to route each packet appropriately.
    pub(crate) fn drain_pending_packets(&mut self) -> alloc::vec::Drain<'_, PendingPacket> {
        self.pending_packets.drain(..)
    }

    // --- Packet Processing ---

    /// Process an incoming link-related packet
    ///
    /// Call this when Transport receives a packet with:
    /// - PacketType::LinkRequest (for destinations that accept links)
    /// - PacketType::Proof (for outgoing links awaiting proof)
    /// - PacketType::Data with context Lrrtt or None (for active links)
    ///
    /// # Arguments
    /// * `packet` - The parsed packet
    /// * `raw_packet` - The raw packet bytes (needed for link ID calculation)
    /// * `rng` - Random number generator
    /// * `now_ms` - Current time in milliseconds
    pub fn process_packet(
        &mut self,
        packet: &Packet,
        raw_packet: &[u8],
        rng: &mut impl CryptoRngCore,
        now_ms: u64,
        interface_index: usize,
    ) {
        match packet.flags.packet_type {
            PacketType::LinkRequest => {
                self.handle_link_request(packet, raw_packet, rng, interface_index);
            }
            PacketType::Proof => {
                self.handle_proof(packet, rng, now_ms, interface_index);
            }
            PacketType::Data => {
                self.handle_data(packet, raw_packet, now_ms);
            }
            PacketType::Announce => {
                // Announces are not link packets, ignore
            }
        }
    }

    // --- Polling ---

    /// Poll for timeouts, keepalives, and stale links
    ///
    /// Call this regularly (e.g. every 100ms). This method:
    /// - Checks for handshake timeouts on pending links
    /// - Checks if active links should send keepalives (initiator only)
    /// - Checks if active links have become stale
    /// - Checks if stale links should be closed
    ///
    /// # Arguments
    /// * `rng` - Random number generator (for building close packets)
    /// * `now_ms` - Current time in milliseconds
    pub fn poll(&mut self, rng: &mut impl CryptoRngCore, now_ms: u64) {
        self.check_timeouts(now_ms);
        let now_secs = now_ms / MS_PER_SECOND;
        self.check_keepalives(now_secs);
        self.check_stale_links(now_secs, rng);
        self.check_channel_timeouts(rng, now_ms);
    }

    /// Drain pending events
    pub fn drain_events(&mut self) -> alloc::vec::Drain<'_, LinkEvent> {
        self.events.drain(..)
    }

    // --- Queries ---

    /// Get a reference to a link
    pub fn link(&self, link_id: &LinkId) -> Option<&Link> {
        self.links.get(link_id)
    }

    /// Find an active link to a destination
    pub fn find_active_link_to(&self, dest_hash: &DestinationHash) -> Option<LinkId> {
        self.links
            .iter()
            .find(|(_, link)| {
                link.state() == LinkState::Active && link.destination_hash() == dest_hash
            })
            .map(|(id, _)| *id)
    }

    /// Check if a link is active
    pub fn is_active(&self, link_id: &LinkId) -> bool {
        self.links
            .get(link_id)
            .map(|l| l.state() == LinkState::Active)
            .unwrap_or(false)
    }

    /// Get the number of active links
    pub fn active_link_count(&self) -> usize {
        self.links
            .values()
            .filter(|l| l.state() == LinkState::Active)
            .count()
    }

    /// Get the number of pending links
    pub fn pending_link_count(&self) -> usize {
        self.links
            .values()
            .filter(|l| !matches!(l.phase(), LinkPhase::Established))
            .count()
    }

    /// Compute the earliest deadline across all link-layer timers
    ///
    /// Returns `None` if there are no pending deadlines (no links, no pending
    /// handshakes, no data receipts). The returned value is in milliseconds.
    pub fn next_deadline(&self, now_ms: u64) -> Option<u64> {
        let now_secs = now_ms / MS_PER_SECOND;
        let mut earliest: Option<u64> = None;

        let mut update = |deadline_ms: u64| {
            earliest = Some(match earliest {
                Some(e) => core::cmp::min(e, deadline_ms),
                None => deadline_ms,
            });
        };

        // Pending handshake timeouts (both outgoing and incoming)
        for link in self.links.values() {
            match link.phase() {
                LinkPhase::PendingOutgoing { created_at_ms } => {
                    update(created_at_ms.saturating_add(LINK_PENDING_TIMEOUT_MS));
                }
                LinkPhase::PendingIncoming { proof_sent_at_ms } => {
                    update(proof_sent_at_ms.saturating_add(LINK_PENDING_TIMEOUT_MS));
                }
                LinkPhase::Established => {}
            }
        }

        // Data receipt timeouts
        for receipt in self.data_receipts.values() {
            update(receipt.sent_at_ms.saturating_add(DATA_RECEIPT_TIMEOUT_MS));
        }

        // Active link keepalive and stale deadlines
        for link in self.links.values() {
            match link.state() {
                LinkState::Active => {
                    // Next keepalive (initiator only)
                    if link.is_initiator() {
                        let base = if link.last_keepalive_secs() > 0 {
                            link.last_keepalive_secs()
                        } else {
                            link.established_at_secs().unwrap_or(now_secs)
                        };
                        let next_keepalive_secs = base.saturating_add(link.keepalive_secs());
                        update(next_keepalive_secs.saturating_mul(MS_PER_SECOND));
                    }

                    // Next stale check
                    if link.last_inbound_secs() > 0 {
                        let stale_at_secs = link
                            .last_inbound_secs()
                            .saturating_add(link.stale_time_secs());
                        update(stale_at_secs.saturating_mul(MS_PER_SECOND));
                    }
                }
                LinkState::Stale => {
                    // Already stale — deadline is when it should be closed
                    // We can't compute this exactly without RTT, so use a short deadline
                    // to ensure check_stale_links runs soon
                    update(now_ms.saturating_add(MS_PER_SECOND));
                }
                _ => {}
            }
        }

        // Channel retransmit deadlines — channels track their own timeouts
        // but we don't have a direct accessor. Use a short deadline if channels exist.
        if self.links.values().any(|l| l.has_channel()) {
            // Ensure we poll channels at least every second
            update(now_ms.saturating_add(MS_PER_SECOND));
        }

        earliest
    }

    /// Take the pending RTT packet for a link (if any)
    ///
    /// After processing a PROOF packet, the initiator needs to send an RTT
    /// packet to complete the handshake. This method returns that packet.
    ///
    /// Returns None if there's no pending RTT packet for this link.
    pub fn take_pending_rtt_packet(&mut self, link_id: &LinkId) -> Option<Vec<u8>> {
        let pos = self.pending_packets.iter().position(|p| {
            matches!(
                p,
                PendingPacket::Rtt { link_id: id, .. } if id == link_id
            )
        })?;
        match self.pending_packets.remove(pos) {
            PendingPacket::Rtt { data, .. } => Some(data),
            _ => unreachable!(),
        }
    }

    /// Drain pending close packets to send
    ///
    /// Convenience method that extracts only Close packets from the unified queue.
    /// Returns (link_id, packet_data) pairs.
    pub fn drain_close_packets(&mut self) -> Vec<(LinkId, Vec<u8>)> {
        drain_packets_by_kind(&mut self.pending_packets, |p| {
            matches!(p, PendingPacket::Close { .. })
        })
    }

    /// Drain pending keepalive packets to send
    ///
    /// Convenience method that extracts only Keepalive packets from the unified queue.
    /// Returns (link_id, packet_data) pairs.
    pub fn drain_keepalive_packets(&mut self) -> Vec<(LinkId, Vec<u8>)> {
        drain_packets_by_kind(&mut self.pending_packets, |p| {
            matches!(p, PendingPacket::Keepalive { .. })
        })
    }

    /// Drain pending proof packets to send
    ///
    /// Convenience method that extracts only Proof packets from the unified queue.
    /// Returns (link_id, packet_data) pairs.
    pub fn drain_proof_packets(&mut self) -> Vec<(LinkId, Vec<u8>)> {
        drain_packets_by_kind(&mut self.pending_packets, |p| {
            matches!(p, PendingPacket::Proof { .. })
        })
    }

    /// Get a mutable reference to a link
    pub fn link_mut(&mut self, link_id: &LinkId) -> Option<&mut Link> {
        self.links.get_mut(link_id)
    }

    // --- Internal: Packet Handlers ---

    fn handle_link_request(
        &mut self,
        packet: &Packet,
        raw_packet: &[u8],
        rng: &mut impl CryptoRngCore,
        interface_index: usize,
    ) {
        let dest_hash = DestinationHash::new(packet.destination_hash);

        // Check if we accept links for this destination
        if !self.accepted_destinations.contains(&dest_hash) {
            return;
        }

        // Calculate link ID from raw packet
        let link_id = Link::calculate_link_id(raw_packet);

        // Check if we already have this link
        if self.links.contains_key(&link_id) {
            return;
        }

        // Extract request data from packet payload
        let request_data = packet.data.as_slice();

        // Create the incoming link
        let Ok(mut link) = Link::new_incoming(request_data, link_id, dest_hash, rng) else {
            return;
        };

        // Set attached interface from the receiving interface (mirrors Python's
        // link.attached_interface = packet.receiving_interface)
        link.set_attached_interface(interface_index);

        // Extract peer keys for the event
        let peer_keys = PeerKeys {
            x25519_public: request_data[..32].try_into().unwrap_or([0; 32]),
            ed25519_verifying: request_data[32..64].try_into().unwrap_or([0; 32]),
        };

        // Store the link
        self.links.insert(link_id, link);

        // Emit event for application to handle
        self.events.push(LinkEvent::LinkRequestReceived {
            link_id,
            dest_hash,
            peer_keys,
        });
    }

    fn handle_proof(
        &mut self,
        packet: &Packet,
        rng: &mut impl CryptoRngCore,
        now_ms: u64,
        interface_index: usize,
    ) {
        // PROOF packets are addressed to link_id (not destination hash)
        let link_id = LinkId::new(packet.destination_hash);

        // Extract proof data from packet payload
        let proof_data = packet.data.as_slice();

        // Check if this is a data proof (PROOF_DATA_SIZE bytes: 32-byte hash + 64-byte signature)
        // Data proofs have context = None, while link establishment proofs have context = Lrproof
        if proof_data.len() == PROOF_DATA_SIZE && packet.context == PacketContext::None {
            self.handle_data_proof(&link_id, proof_data);
            return;
        }

        let Some(link) = self.links.get_mut(&link_id) else {
            return;
        };

        // Check if we have a pending outgoing link (link establishment proof)
        if !matches!(link.phase(), LinkPhase::PendingOutgoing { .. }) {
            return;
        }

        if link.state() != LinkState::Pending || !link.is_initiator() {
            return;
        }

        // Set attached interface from the interface the proof arrived on
        // (mirrors Python: initiator learns attached_interface from proof)
        link.set_attached_interface(interface_index);

        // Process the proof
        if link.process_proof(proof_data).is_err() {
            // Invalid proof - capture metadata then close the link
            let is_initiator = link.is_initiator();
            let destination_hash = *link.destination_hash();
            self.links.remove(&link_id);
            self.events.push(LinkEvent::LinkClosed {
                link_id,
                reason: LinkCloseReason::InvalidProof,
                is_initiator,
                destination_hash,
            });
            return;
        }

        // Proof verified! Calculate RTT and build the RTT packet
        let now_secs = now_ms / MS_PER_SECOND;
        let rtt_ms = match link.phase() {
            LinkPhase::PendingOutgoing { created_at_ms } => now_ms.saturating_sub(created_at_ms),
            _ => 0,
        };
        link.set_phase(LinkPhase::Established);
        let rtt_seconds = rtt_ms as f64 / MS_PER_SECOND as f64;

        // Update keepalive timing based on RTT
        link.update_keepalive_from_rtt(rtt_seconds);
        link.mark_established(now_secs);

        // Build RTT packet - the caller retrieves it via take_pending_rtt_packet()
        if let Ok(rtt_packet) = link.build_rtt_packet(rtt_seconds, rng) {
            // Link is now active (from initiator's perspective)
            self.events.push(LinkEvent::LinkEstablished {
                link_id,
                is_initiator: true,
            });

            // Store RTT packet for caller to retrieve and send
            self.pending_packets.push(PendingPacket::Rtt {
                link_id,
                data: rtt_packet,
            });
        }
    }

    /// Handle a data proof packet (PROVE_ALL response)
    ///
    /// Data proofs are PROOF_DATA_SIZE bytes: 32-byte packet hash + 64-byte Ed25519 signature.
    /// We look up the receipt by truncated hash, then validate the full proof.
    fn handle_data_proof(&mut self, link_id: &LinkId, proof_data: &[u8]) {
        // Extract the packet hash from the proof (first 32 bytes)
        if proof_data.len() != PROOF_DATA_SIZE {
            tracing::debug!(
                len = proof_data.len(),
                expected = PROOF_DATA_SIZE,
                "link_mgr: data proof wrong size"
            );
            return;
        }
        let proof_hash: [u8; 32] = match proof_data[..32].try_into() {
            Ok(h) => h,
            Err(_) => return,
        };

        // Compute truncated hash to look up receipt
        let mut truncated = [0u8; TRUNCATED_HASHBYTES];
        truncated.copy_from_slice(&proof_hash[..TRUNCATED_HASHBYTES]);
        tracing::debug!(
            proof_hash = %HexFmt(&proof_hash),
            truncated = %HexFmt(&truncated),
            link = %HexFmt(link_id.as_bytes()),
            receipts = self.data_receipts.len(),
            "link_mgr: data proof received"
        );

        // Look up receipt by truncated hash
        let receipt = match self.data_receipts.get(&truncated) {
            Some(r) => r,
            None => {
                tracing::debug!(
                    receipts = self.data_receipts.len(),
                    "link_mgr: data proof — no matching receipt"
                );
                return;
            }
        };

        // Verify the receipt is for this link
        if &receipt.link_id != link_id {
            tracing::debug!("link_mgr: data proof — link_id mismatch");
            return;
        }

        // Get the link to validate the proof signature
        let link = match self.links.get(link_id) {
            Some(l) => l,
            None => return,
        };

        // Validate the proof (checks hash match and signature)
        if link.validate_data_proof(proof_data, &receipt.full_hash) {
            // Proof is valid - emit DataDelivered event
            let packet_hash = receipt.full_hash;
            self.data_receipts.remove(&truncated);
            tracing::debug!(
                receipts = self.data_receipts.len(),
                "link_mgr: data proof validated — delivered"
            );
            self.events.push(LinkEvent::DataDelivered {
                link_id: *link_id,
                packet_hash,
            });
        } else {
            tracing::debug!("link_mgr: data proof — signature validation failed");
        }
    }

    fn handle_data(&mut self, packet: &Packet, raw_packet: &[u8], now_ms: u64) {
        // DATA packets are addressed to link_id
        let link_id = LinkId::new(packet.destination_hash);
        let now_secs = now_ms / MS_PER_SECOND;

        // Recover stale links on any inbound traffic (Python Link.py:987-988).
        // Safe to call unconditionally: RTT only fires in Handshake state,
        // LinkClose transitions to Closed — neither will be Stale.
        self.try_recover_stale(&link_id, now_secs);

        let Some(link) = self.links.get_mut(&link_id) else {
            return;
        };

        // Check if this is an RTT packet (context = Lrrtt)
        if packet.context == PacketContext::Lrrtt {
            // This is an RTT packet for a responder-side link
            if link.state() != LinkState::Handshake || link.is_initiator() {
                return;
            }

            // Process RTT
            let encrypted_data = packet.data.as_slice();
            if let Ok(rtt_secs) = link.process_rtt(encrypted_data) {
                // Link is now active - update keepalive timing from RTT
                link.update_keepalive_from_rtt(rtt_secs);
                link.mark_established(now_secs);
                link.set_phase(LinkPhase::Established);
                self.events.push(LinkEvent::LinkEstablished {
                    link_id,
                    is_initiator: false,
                });
            }
            return;
        }

        // Handle KEEPALIVE packets
        if packet.context == PacketContext::Keepalive {
            // Record inbound activity
            link.record_inbound(now_secs);

            let data = packet.data.as_slice();
            match link.process_keepalive(data) {
                Ok(should_echo) => {
                    // If we're responder and received valid keepalive, echo back
                    if should_echo {
                        if let Ok(echo_packet) = link.build_keepalive_packet() {
                            self.pending_packets.push(PendingPacket::Keepalive {
                                link_id,
                                data: echo_packet,
                            });
                        }
                    }
                }
                Err(_) => {
                    // Invalid keepalive - ignore
                }
            }
            return;
        }

        // Handle LINKCLOSE packets
        if packet.context == PacketContext::LinkClose {
            let encrypted_data = packet.data.as_slice();
            if link.process_close(encrypted_data).is_ok() {
                // Link closed by peer
                self.events.push(LinkEvent::LinkClosed {
                    link_id,
                    reason: LinkCloseReason::PeerClosed,
                    is_initiator: link.is_initiator(),
                    destination_hash: *link.destination_hash(),
                });
            }
            return;
        }

        // Handle CHANNEL packets
        if packet.context == PacketContext::Channel {
            if link.state() != LinkState::Active {
                return;
            }

            // Record inbound activity
            link.record_inbound(now_secs);

            // Decrypt the envelope data
            let encrypted_data = packet.data.as_slice();
            let max_plaintext_len = encrypted_data.len();
            let mut plaintext = alloc::vec![0u8; max_plaintext_len];

            let decrypted_len = match link.decrypt(encrypted_data, &mut plaintext) {
                Ok(len) => len,
                Err(_) => return, // Decryption failed
            };
            plaintext.truncate(decrypted_len);

            // Get or create channel, process message, drain buffered.
            // self.events and self.rx_ring_full_* are different fields from self.links,
            // so split borrows allow accessing them while link (&mut) is held.
            let rtt_ms = link.rtt_ms();
            let channel = link.ensure_channel(rtt_ms);

            // Process through channel
            let message_accepted = match channel.receive(&plaintext) {
                Ok(Some(envelope)) => {
                    tracing::debug!(
                        seq = envelope.sequence,
                        msgtype = envelope.msgtype,
                        len = envelope.data.len(),
                        "link_mgr: channel message received (in-order)"
                    );
                    // In-order message received
                    self.events.push(LinkEvent::ChannelMessageReceived {
                        link_id,
                        msgtype: envelope.msgtype,
                        sequence: envelope.sequence,
                        data: envelope.data,
                    });
                    true
                }
                Ok(None) => {
                    tracing::debug!("link_mgr: channel message buffered (out-of-order)");
                    true // Buffered = accepted, prove it
                }
                Err(ChannelError::RxRingFull) => {
                    self.rx_ring_full_count += 1;
                    let elapsed = now_ms.saturating_sub(self.rx_ring_full_last_log_ms);
                    if self.rx_ring_full_last_log_ms == 0 || elapsed >= 5000 {
                        tracing::warn!(
                            "link_mgr: channel rx_ring full — {} messages dropped in last {}s (cap={})",
                            self.rx_ring_full_count,
                            elapsed / 1000,
                            crate::constants::CHANNEL_RX_RING_MAX
                        );
                        self.rx_ring_full_count = 0;
                        self.rx_ring_full_last_log_ms = now_ms;
                    }
                    false // Dropped = not accepted, don't prove
                }
                Err(e) => {
                    tracing::debug!(?e, "link_mgr: channel receive failed");
                    false // Parse/decode error = not accepted, don't prove
                }
            };

            // Drain any buffered messages that are now ready
            // (channel is still accessible through link)
            let drained: Vec<_> = link
                .channel_mut()
                .map(|ch| ch.drain_received())
                .unwrap_or_default();
            for envelope in drained {
                self.events.push(LinkEvent::ChannelMessageReceived {
                    link_id,
                    msgtype: envelope.msgtype,
                    sequence: envelope.sequence,
                    data: envelope.data,
                });
            }

            // Only prove if the message was accepted (in-order or buffered).
            // If the rx_ring was full or parsing failed, suppress the proof
            // so the sender retransmits instead of thinking it was delivered.
            if !message_accepted {
                return;
            }

            // Generate proof for CHANNEL packets (Python Link.py:1173).
            // Unlike regular data (which checks proof_strategy), Channel proofs are
            // always generated — matching Python's packet.prove() call.
            let full_packet_hash = packet_hash(raw_packet);
            if let Some(signing_key) = link.proof_signing_key() {
                match link.build_data_proof_packet_with_signing_key(&full_packet_hash, signing_key)
                {
                    Ok(proof_packet) => {
                        tracing::debug!(
                            hash = %HexFmt(&full_packet_hash),
                            link = %HexFmt(link_id.as_bytes()),
                            proof_len = proof_packet.len(),
                            "link_mgr: channel proof generated"
                        );
                        self.pending_packets.push(PendingPacket::Proof {
                            link_id,
                            data: proof_packet,
                        });
                    }
                    Err(e) => {
                        tracing::warn!(
                            hash = %HexFmt(&full_packet_hash),
                            link = %HexFmt(link_id.as_bytes()),
                            error = %e,
                            "link_mgr: channel proof build failed"
                        );
                    }
                }
            } else {
                tracing::warn!(
                    link = %HexFmt(link_id.as_bytes()),
                    "link_mgr: channel proof skipped — no signing key"
                );
            }

            return;
        }

        // Regular data packet
        if link.state() != LinkState::Active {
            return;
        }

        // Record inbound activity for any data packet
        link.record_inbound(now_secs);

        // Decrypt the data
        let encrypted_data = packet.data.as_slice();
        let max_plaintext_len = encrypted_data.len(); // Safe upper bound
        let mut plaintext = alloc::vec![0u8; max_plaintext_len];

        match link.decrypt(encrypted_data, &mut plaintext) {
            Ok(len) => {
                plaintext.truncate(len);

                // Handle proof strategy for received data (stored on the link)
                let full_packet_hash = packet_hash(raw_packet);

                match link.proof_strategy() {
                    ProofStrategy::All => {
                        // Automatically generate and queue proof using the link's signing key
                        if let Some(signing_key) = link.proof_signing_key() {
                            if let Ok(proof_packet) = link.build_data_proof_packet_with_signing_key(
                                &full_packet_hash,
                                signing_key,
                            ) {
                                self.pending_packets.push(PendingPacket::Proof {
                                    link_id,
                                    data: proof_packet,
                                });
                            }
                        }
                    }
                    ProofStrategy::App => {
                        // Emit event for application to decide
                        self.events.push(LinkEvent::ProofRequested {
                            link_id,
                            packet_hash: full_packet_hash,
                        });
                    }
                    ProofStrategy::None => {
                        // No proof needed
                    }
                }

                self.events.push(LinkEvent::DataReceived {
                    link_id,
                    data: plaintext,
                });
            }
            Err(_) => {
                // Decryption failed — drop the packet. This matches Python
                // Transport.py behavior: packets with invalid HMAC or failed
                // decryption indicate tampering, corruption, or misrouted
                // data and are silently discarded.
            }
        }
    }

    /// If the link is Stale and we receive any valid packet, recover to Active.
    /// Matches Python Link.py:987-988.
    fn try_recover_stale(&mut self, link_id: &LinkId, now_secs: u64) -> bool {
        let Some(link) = self.links.get_mut(link_id) else {
            return false;
        };
        if link.state() == LinkState::Stale {
            link.set_state(LinkState::Active);
            link.record_inbound(now_secs);
            self.events
                .push(LinkEvent::LinkRecovered { link_id: *link_id });
            tracing::debug!(link = %HexFmt(link_id.as_bytes()), "link_mgr: recovered from stale");
            true
        } else {
            false
        }
    }

    // --- Internal: Timeout Handling ---

    fn check_timeouts(&mut self, now_ms: u64) {
        // Collect timed-out pending links (both outgoing and incoming)
        let timed_out: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(_, link)| {
                let started_at = match link.phase() {
                    LinkPhase::PendingOutgoing { created_at_ms } => created_at_ms,
                    LinkPhase::PendingIncoming { proof_sent_at_ms } => proof_sent_at_ms,
                    LinkPhase::Established => return false,
                };
                now_ms.saturating_sub(started_at) > LINK_PENDING_TIMEOUT_MS
            })
            .map(|(id, _)| *id)
            .collect();

        for link_id in timed_out {
            let (is_initiator, destination_hash) = self
                .links
                .get(&link_id)
                .map(|l| (l.is_initiator(), *l.destination_hash()))
                .unwrap_or((false, DestinationHash::new([0; 16])));
            self.links.remove(&link_id);
            self.events.push(LinkEvent::LinkClosed {
                link_id,
                reason: LinkCloseReason::Timeout,
                is_initiator,
                destination_hash,
            });
        }

        // Clean up expired data receipts and their channel_receipt_keys
        self.data_receipts.retain(|_, receipt| {
            now_ms.saturating_sub(receipt.sent_at_ms) <= DATA_RECEIPT_TIMEOUT_MS
        });
        self.channel_receipt_keys
            .retain(|_, truncated| self.data_receipts.contains_key(truncated));
    }

    // --- Internal: Keepalive Handling ---

    /// Check if any active links need to send keepalives (initiator only)
    fn check_keepalives(&mut self, now_secs: u64) {
        // Collect link IDs that need keepalives (only initiators send proactive keepalives)
        let need_keepalive: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(_, link)| link.is_initiator() && link.should_send_keepalive(now_secs))
            .map(|(id, _)| *id)
            .collect();

        // Build and queue keepalive packets
        for link_id in need_keepalive {
            if let Some(link) = self.links.get_mut(&link_id) {
                if let Ok(packet) = link.build_keepalive_packet() {
                    link.record_keepalive_sent(now_secs);
                    self.pending_packets.push(PendingPacket::Keepalive {
                        link_id,
                        data: packet,
                    });
                }
            }
        }
    }

    // --- Internal: Stale Link Handling ---

    /// Check for stale links and close them if timeout expired
    fn check_stale_links(&mut self, now_secs: u64, rng: &mut impl CryptoRngCore) {
        // First pass: Find links that are active but should become stale
        let newly_stale: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(_, link)| link.state() == LinkState::Active && link.is_stale(now_secs))
            .map(|(id, _)| *id)
            .collect();

        // Transition newly stale links
        for link_id in newly_stale {
            if let Some(link) = self.links.get_mut(&link_id) {
                link.set_state(LinkState::Stale);
                self.events.push(LinkEvent::LinkStale { link_id });
            }
        }

        // Second pass: Find stale links that should be closed
        let should_close: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(_, link)| link.state() == LinkState::Stale && link.should_close(now_secs))
            .map(|(id, _)| *id)
            .collect();

        // Close stale links that have timed out
        for link_id in should_close {
            if let Some(link) = self.links.get_mut(&link_id) {
                let is_initiator = link.is_initiator();
                let destination_hash = *link.destination_hash();
                // Build close packet before closing
                if let Ok(close_packet) = link.build_close_packet(rng) {
                    self.pending_packets.push(PendingPacket::Close {
                        link_id,
                        data: close_packet,
                    });
                }
                link.close();
                self.channel_receipt_keys
                    .retain(|(lid, _), _| *lid != link_id);
                self.events.push(LinkEvent::LinkClosed {
                    link_id,
                    reason: LinkCloseReason::Stale,
                    is_initiator,
                    destination_hash,
                });
            }
        }
    }

    // --- Internal: Channel Timeout Handling ---

    /// Check for channel envelope timeouts and queue retransmissions
    fn check_channel_timeouts(&mut self, rng: &mut impl CryptoRngCore, now_ms: u64) {
        use super::channel::ChannelAction;

        // Collect link IDs that have channels
        let channel_link_ids: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(_, link)| link.has_channel())
            .map(|(id, _)| *id)
            .collect();

        for link_id in channel_link_ids {
            // Get link, extract RTT, poll channel — actions is owned Vec, releasing borrow
            let actions = match self.links.get_mut(&link_id) {
                Some(link) => {
                    let rtt_ms = link.rtt_ms();
                    match link.channel_mut() {
                        Some(ch) => ch.poll(now_ms, rtt_ms),
                        None => continue,
                    }
                }
                None => continue,
            };

            // Process actions (re-borrow link for each)
            for action in actions {
                match action {
                    ChannelAction::Retransmit {
                        sequence,
                        data,
                        tries,
                    } => {
                        tracing::debug!(seq = sequence, "link_mgr: queuing channel retransmit");
                        // Build and queue the retransmission packet
                        if let Some(link) = self.links.get(&link_id) {
                            if let Ok(packet) = link.build_data_packet_with_context(
                                &data,
                                PacketContext::Channel,
                                rng,
                            ) {
                                // Register receipt for the re-encrypted packet
                                // (Python Transport.py:965)
                                let (new_hash, old_hash) = self
                                    .register_channel_receipt(&packet, link_id, sequence, now_ms);
                                self.events.push(LinkEvent::ChannelReceiptUpdated {
                                    link_id,
                                    new_hash,
                                    old_hash,
                                    sequence,
                                });
                                self.events.push(LinkEvent::ChannelRetransmit {
                                    link_id,
                                    sequence,
                                    tries,
                                });

                                self.pending_packets.push(PendingPacket::Channel {
                                    link_id,
                                    data: packet,
                                });
                            }
                        }
                    }
                    ChannelAction::TearDownLink => {
                        tracing::debug!("link_mgr: channel teardown — closing link");
                        // Max retries exceeded - close the link
                        let (is_initiator, destination_hash) = self
                            .links
                            .get(&link_id)
                            .map(|l| (l.is_initiator(), *l.destination_hash()))
                            .unwrap_or((false, DestinationHash::new([0; 16])));
                        if let Some(link) = self.links.get_mut(&link_id) {
                            if let Ok(close_packet) = link.build_close_packet(rng) {
                                self.pending_packets.push(PendingPacket::Close {
                                    link_id,
                                    data: close_packet,
                                });
                            }
                            link.close();
                        }
                        self.channel_receipt_keys
                            .retain(|(lid, _), _| *lid != link_id);
                        self.events.push(LinkEvent::LinkClosed {
                            link_id,
                            reason: LinkCloseReason::Timeout,
                            is_initiator,
                            destination_hash,
                        });
                    }
                }
            }
        }
    }
}

impl Default for LinkManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use rand_core::OsRng;

    const INITIAL_TIME_MS: u64 = 1_000_000;

    #[test]
    fn test_new_manager() {
        let manager = LinkManager::new();
        assert_eq!(manager.active_link_count(), 0);
        assert_eq!(manager.pending_link_count(), 0);
    }

    #[test]
    fn test_register_destination() {
        let mut manager = LinkManager::new();
        let dest_hash = DestinationHash::new([0x42; 16]);

        manager.register_destination(dest_hash);
        assert!(manager.accepts_links(&dest_hash));

        manager.unregister_destination(&dest_hash);
        assert!(!manager.accepts_links(&dest_hash));
    }

    #[test]
    fn test_initiate_link() {
        let mut manager = LinkManager::new();
        let dest_hash = DestinationHash::new([0x42; 16]);
        let dest_signing_key = [0x33; 32];

        let (link_id, packet) =
            manager.initiate(dest_hash, &dest_signing_key, &mut OsRng, INITIAL_TIME_MS);

        // Should have created a pending link
        assert_eq!(manager.pending_link_count(), 1);
        assert!(manager.link(&link_id).is_some());
        assert!(!manager.is_active(&link_id));

        // Packet should be a valid LINK_REQUEST
        assert!(!packet.is_empty());
    }

    #[test]
    fn test_link_timeout() {
        let mut manager = LinkManager::new();
        let dest_hash = DestinationHash::new([0x42; 16]);
        let dest_signing_key = [0x33; 32];

        let (link_id, _) =
            manager.initiate(dest_hash, &dest_signing_key, &mut OsRng, INITIAL_TIME_MS);
        assert_eq!(manager.pending_link_count(), 1);

        // Advance time past timeout
        let now_ms = INITIAL_TIME_MS + LINK_PENDING_TIMEOUT_MS + 1;
        manager.poll(&mut OsRng, now_ms);

        // Link should be removed
        assert_eq!(manager.pending_link_count(), 0);
        assert!(manager.link(&link_id).is_none());

        // Should have emitted LinkClosed event
        let events: Vec<_> = manager.drain_events().collect();
        assert_eq!(events.len(), 1);
        match &events[0] {
            LinkEvent::LinkClosed {
                link_id: id,
                reason,
                ..
            } => {
                assert_eq!(id, &link_id);
                assert_eq!(*reason, LinkCloseReason::Timeout);
            }
            _ => panic!("Expected LinkClosed event"),
        }
    }

    #[test]
    fn test_close_link() {
        let mut manager = LinkManager::new();
        let dest_hash = DestinationHash::new([0x42; 16]);
        let dest_signing_key = [0x33; 32];

        let (link_id, _) =
            manager.initiate(dest_hash, &dest_signing_key, &mut OsRng, INITIAL_TIME_MS);

        // Use close_local for this test (graceful close requires active link with encryption key)
        manager.close_local(&link_id, LinkCloseReason::Normal);

        // Link should be removed
        assert!(manager.link(&link_id).is_none());

        let events: Vec<_> = manager.drain_events().collect();
        assert_eq!(events.len(), 1);
        match &events[0] {
            LinkEvent::LinkClosed { reason, .. } => {
                assert_eq!(*reason, LinkCloseReason::Normal);
            }
            _ => panic!("Expected LinkClosed event"),
        }
    }

    /// Established link pair returned by the test helper
    struct LinkPair {
        initiator: LinkManager,
        responder: LinkManager,
        now_ms: u64,
        initiator_link_id: LinkId,
        responder_link_id: LinkId,
    }

    /// Create two LinkManagers with an established link between them.
    ///
    /// The responder destination is registered with the given proof strategy.
    /// Both links will be Active after this returns.
    fn establish_link_pair(proof_strategy: ProofStrategy) -> LinkPair {
        let mut initiator_mgr = LinkManager::new();
        let mut responder_mgr = LinkManager::new();
        let now_ms = INITIAL_TIME_MS;

        let dest_identity = Identity::generate(&mut OsRng);
        let dest_hash = DestinationHash::new([0x42; 16]);
        let dest_signing_key = dest_identity.ed25519_verifying().to_bytes();

        // Register destination on responder
        responder_mgr.register_destination(dest_hash);

        // Initiator starts link
        let (link_id, link_request_packet) =
            initiator_mgr.initiate(dest_hash, &dest_signing_key, &mut OsRng, now_ms);

        // Deliver link request to responder
        let packet = Packet::unpack(&link_request_packet).unwrap();
        responder_mgr.process_packet(&packet, &link_request_packet, &mut OsRng, now_ms, 0);

        // Accept on responder
        let events: Vec<_> = responder_mgr.drain_events().collect();
        let responder_link_id = match &events[0] {
            LinkEvent::LinkRequestReceived { link_id, .. } => *link_id,
            _ => panic!("Expected LinkRequestReceived"),
        };

        let proof_packet = responder_mgr
            .accept_link(&responder_link_id, &dest_identity, proof_strategy, now_ms)
            .unwrap();

        // Deliver proof to initiator
        let proof = Packet::unpack(&proof_packet).unwrap();
        initiator_mgr.process_packet(&proof, &proof_packet, &mut OsRng, now_ms, 0);
        let _ = initiator_mgr.drain_events().collect::<Vec<_>>();

        // Deliver RTT packet to responder
        let rtt_packet = initiator_mgr.take_pending_rtt_packet(&link_id).unwrap();
        let rtt = Packet::unpack(&rtt_packet).unwrap();
        responder_mgr.process_packet(&rtt, &rtt_packet, &mut OsRng, now_ms, 0);
        let _ = responder_mgr.drain_events().collect::<Vec<_>>();

        assert!(initiator_mgr.is_active(&link_id));
        assert!(responder_mgr.is_active(&responder_link_id));

        LinkPair {
            initiator: initiator_mgr,
            responder: responder_mgr,
            now_ms,
            initiator_link_id: link_id,
            responder_link_id,
        }
    }

    #[test]
    fn test_full_handshake() {
        let pair = establish_link_pair(ProofStrategy::None);
        assert!(pair.initiator.is_active(&pair.initiator_link_id));
        assert!(pair.responder.is_active(&pair.responder_link_id));
    }

    #[test]
    fn test_proof_strategy_set_on_link_via_accept() {
        // Proof strategy is now set on the Link at accept_link() time,
        // not at destination registration time.
        let pair = establish_link_pair(ProofStrategy::All);
        let link = pair.responder.link(&pair.responder_link_id).unwrap();
        assert_eq!(link.proof_strategy(), ProofStrategy::All);
        assert!(link.dest_signing_key().is_some());

        let pair_app = establish_link_pair(ProofStrategy::App);
        let link_app = pair_app
            .responder
            .link(&pair_app.responder_link_id)
            .unwrap();
        assert_eq!(link_app.proof_strategy(), ProofStrategy::App);
        assert!(link_app.dest_signing_key().is_some());

        let pair_none = establish_link_pair(ProofStrategy::None);
        let link_none = pair_none
            .responder
            .link(&pair_none.responder_link_id)
            .unwrap();
        assert_eq!(link_none.proof_strategy(), ProofStrategy::None);
        // Signing key is always stored (needed for unconditional channel proofs)
        assert!(link_none.dest_signing_key().is_some());
    }

    #[test]
    fn test_prove_all_generates_proof_on_data_receive() {
        let mut pair = establish_link_pair(ProofStrategy::All);

        // Send data from initiator
        let data_packet = pair
            .initiator
            .send(&pair.initiator_link_id, b"hello", &mut OsRng)
            .unwrap();

        // Process data on responder
        let data = Packet::unpack(&data_packet).unwrap();
        pair.responder
            .process_packet(&data, &data_packet, &mut OsRng, pair.now_ms, 0);

        // Should have generated a proof packet
        let proof_packets: Vec<_> = pair.responder.drain_proof_packets();
        assert_eq!(proof_packets.len(), 1);
        assert_eq!(proof_packets[0].0, pair.responder_link_id);

        // Should have emitted DataReceived event
        let events: Vec<_> = pair.responder.drain_events().collect();
        let has_data_received = events
            .iter()
            .any(|e| matches!(e, LinkEvent::DataReceived { .. }));
        assert!(has_data_received, "Expected DataReceived event");
    }

    #[test]
    fn test_prove_app_emits_proof_requested_event() {
        let mut pair = establish_link_pair(ProofStrategy::App);

        // Send data from initiator
        let data_packet = pair
            .initiator
            .send(&pair.initiator_link_id, b"hello", &mut OsRng)
            .unwrap();

        // Process data on responder
        let data = Packet::unpack(&data_packet).unwrap();
        pair.responder
            .process_packet(&data, &data_packet, &mut OsRng, pair.now_ms, 0);

        // Should NOT have generated a proof packet (PROVE_APP waits for app decision)
        let proof_packets: Vec<_> = pair.responder.drain_proof_packets();
        assert!(
            proof_packets.is_empty(),
            "PROVE_APP should not auto-generate proofs"
        );

        // Should have emitted ProofRequested event
        let events: Vec<_> = pair.responder.drain_events().collect();
        let has_proof_requested = events
            .iter()
            .any(|e| matches!(e, LinkEvent::ProofRequested { .. }));
        assert!(has_proof_requested, "Expected ProofRequested event");
    }

    #[test]
    fn test_send_with_receipt_tracks_packet() {
        let mut pair = establish_link_pair(ProofStrategy::All);

        // Send data with receipt tracking
        let (data_packet, sent_hash) = pair
            .initiator
            .send_with_receipt(&pair.initiator_link_id, b"hello", &mut OsRng, pair.now_ms)
            .unwrap();

        // Should have created a receipt
        assert_eq!(pair.initiator.data_receipts.len(), 1);

        // Process data on responder - this generates the proof
        let data = Packet::unpack(&data_packet).unwrap();
        pair.responder
            .process_packet(&data, &data_packet, &mut OsRng, pair.now_ms, 0);

        // Get the proof packet
        let proof_packets: Vec<_> = pair.responder.drain_proof_packets();
        assert_eq!(proof_packets.len(), 1);
        let (_, data_proof_packet) = &proof_packets[0];

        // Process proof on initiator
        let data_proof = Packet::unpack(data_proof_packet).unwrap();

        assert_eq!(
            data_proof.flags.packet_type,
            crate::packet::PacketType::Proof,
            "Expected Proof packet type"
        );
        assert_eq!(
            data_proof.context,
            PacketContext::None,
            "Expected None context for data proof"
        );
        assert_eq!(
            data_proof.data.as_slice().len(),
            crate::constants::PROOF_DATA_SIZE,
            "Expected PROOF_DATA_SIZE-byte proof data"
        );

        pair.initiator
            .process_packet(&data_proof, data_proof_packet, &mut OsRng, pair.now_ms, 0);

        // Should have emitted DataDelivered event
        let events: Vec<_> = pair.initiator.drain_events().collect();
        let data_delivered = events.iter().find_map(|e| match e {
            LinkEvent::DataDelivered {
                link_id: lid,
                packet_hash,
            } => Some((*lid, *packet_hash)),
            _ => None,
        });

        assert!(data_delivered.is_some(), "Expected DataDelivered event");
        let (delivered_link_id, delivered_hash) = data_delivered.unwrap();
        assert_eq!(delivered_link_id, pair.initiator_link_id);
        assert_eq!(delivered_hash, sent_hash);

        // Receipt should have been removed
        assert_eq!(pair.initiator.data_receipts.len(), 0);
    }

    #[test]
    fn test_prove_app_responder_proof_verifiable_by_initiator() {
        // Tests that send_data_proof() creates proofs verifiable by the initiator.
        // The initiator verifies with the destination's identity key (from announce),
        // so the proof must be signed with that same key.
        let mut pair = establish_link_pair(ProofStrategy::App);

        // Send data with receipt tracking from initiator
        let (data_packet, sent_hash) = pair
            .initiator
            .send_with_receipt(
                &pair.initiator_link_id,
                b"prove_app_test",
                &mut OsRng,
                pair.now_ms,
            )
            .unwrap();

        // Process data on responder - should emit ProofRequested
        let data = Packet::unpack(&data_packet).unwrap();
        pair.responder
            .process_packet(&data, &data_packet, &mut OsRng, pair.now_ms, 0);

        // Find the ProofRequested event
        let events: Vec<_> = pair.responder.drain_events().collect();
        let proof_hash = events.iter().find_map(|e| match e {
            LinkEvent::ProofRequested { packet_hash, .. } => Some(*packet_hash),
            _ => None,
        });
        assert!(proof_hash.is_some(), "Expected ProofRequested event");
        let proof_hash = proof_hash.unwrap();

        // Application decides to prove - call send_data_proof
        let proof_packet = pair
            .responder
            .send_data_proof(&pair.responder_link_id, &proof_hash)
            .expect("send_data_proof should succeed");

        // Deliver proof to initiator
        let data_proof = Packet::unpack(&proof_packet).unwrap();
        pair.initiator
            .process_packet(&data_proof, &proof_packet, &mut OsRng, pair.now_ms, 0);

        // Initiator should receive DataDelivered event
        let events: Vec<_> = pair.initiator.drain_events().collect();
        let data_delivered = events.iter().find_map(|e| match e {
            LinkEvent::DataDelivered {
                link_id: lid,
                packet_hash,
            } => Some((*lid, *packet_hash)),
            _ => None,
        });
        assert!(
            data_delivered.is_some(),
            "Expected DataDelivered event - proof must be signed with destination identity key"
        );
        let (delivered_link_id, delivered_hash) = data_delivered.unwrap();
        assert_eq!(delivered_link_id, pair.initiator_link_id);
        assert_eq!(delivered_hash, sent_hash);

        // Receipt should have been removed
        assert_eq!(pair.initiator.data_receipts.len(), 0);
    }

    // ─── T7: LinkManager Lifecycle ─────────────────────────────────────────

    #[test]
    fn test_close_produces_close_packet() {
        let mut pair = establish_link_pair(ProofStrategy::None);

        pair.initiator.close(&pair.initiator_link_id, &mut OsRng);

        // Should have exactly 1 close packet
        let close_packets = pair.initiator.drain_close_packets();
        assert_eq!(close_packets.len(), 1);
        assert_eq!(close_packets[0].0, pair.initiator_link_id);

        // Should have emitted LinkClosed event
        let events: Vec<_> = pair.initiator.drain_events().collect();
        let has_close = events.iter().any(|e| {
            matches!(
                e,
                LinkEvent::LinkClosed {
                    reason: LinkCloseReason::Normal,
                    ..
                }
            )
        });
        assert!(has_close, "Expected LinkClosed event with Normal reason");

        // Link should be removed from map after close() (B1 fix)
        let link = pair.initiator.link(&pair.initiator_link_id);
        assert!(
            link.is_none(),
            "link should be removed from map after close()"
        );
    }

    #[test]
    fn test_check_stale_links_emits_stale_then_closed() {
        let mut pair = establish_link_pair(ProofStrategy::None);
        let link_id = pair.responder_link_id;

        // Get link timing
        let link = pair.responder.link(&link_id).unwrap();
        let stale_time_secs = link.stale_time_secs();
        let last_inbound = link.last_inbound_secs();

        // Phase 1: Advance past stale threshold
        let stale_secs = last_inbound + stale_time_secs + 1;
        let stale_ms = stale_secs * 1000;
        pair.responder.poll(&mut OsRng, stale_ms);

        let events: Vec<_> = pair.responder.drain_events().collect();
        let has_stale = events
            .iter()
            .any(|e| matches!(e, LinkEvent::LinkStale { .. }));
        assert!(has_stale, "Expected LinkStale event");

        let link = pair.responder.link(&link_id).unwrap();
        assert_eq!(link.state(), LinkState::Stale);

        // Phase 2: Advance past close threshold (stale_time + rtt*TIMEOUT_FACTOR + grace + 1)
        let rtt_secs = link.rtt_secs().unwrap_or(0.0);
        let close_timeout_secs = stale_time_secs
            + (rtt_secs * crate::constants::LINK_KEEPALIVE_TIMEOUT_FACTOR as f64) as u64
            + crate::constants::LINK_STALE_GRACE_SECS
            + 1;
        let close_secs = last_inbound + close_timeout_secs;
        let close_ms = close_secs * 1000;
        pair.responder.poll(&mut OsRng, close_ms);

        let events: Vec<_> = pair.responder.drain_events().collect();
        let has_closed = events.iter().any(|e| {
            matches!(
                e,
                LinkEvent::LinkClosed {
                    reason: LinkCloseReason::Stale,
                    ..
                }
            )
        });
        assert!(has_closed, "Expected LinkClosed with Stale reason");

        // Close packet should have been produced
        let close_packets = pair.responder.drain_close_packets();
        assert_eq!(close_packets.len(), 1);
    }

    #[test]
    fn test_check_keepalives_produces_keepalive_packet() {
        let mut pair = establish_link_pair(ProofStrategy::None);

        // Only the initiator sends keepalives proactively
        let link = pair.initiator.link(&pair.initiator_link_id).unwrap();
        let keepalive_secs = link.keepalive_secs();
        let established_at = link.established_at_secs().unwrap();

        // Advance past keepalive interval
        let keepalive_time_secs = established_at + keepalive_secs + 1;
        let keepalive_time_ms = keepalive_time_secs * 1000;
        pair.initiator.poll(&mut OsRng, keepalive_time_ms);

        let keepalive_packets = pair.initiator.drain_keepalive_packets();
        assert_eq!(
            keepalive_packets.len(),
            1,
            "initiator should produce 1 keepalive packet"
        );
        assert_eq!(keepalive_packets[0].0, pair.initiator_link_id);

        // Responder should NOT produce a keepalive (only echoes)
        let resp_link = pair.responder.link(&pair.responder_link_id).unwrap();
        let resp_established = resp_link.established_at_secs().unwrap();
        let resp_time_ms = (resp_established + keepalive_secs + 1) * 1000;
        pair.responder.poll(&mut OsRng, resp_time_ms);

        let resp_keepalive = pair.responder.drain_keepalive_packets();
        assert!(
            resp_keepalive.is_empty(),
            "responder should NOT produce keepalive proactively"
        );
    }

    #[test]
    fn test_check_channel_timeouts_produces_retransmit() {
        use crate::link::channel::ChannelError;

        struct TestMsg(Vec<u8>);
        impl Message for TestMsg {
            const MSGTYPE: u16 = 0x0001;
            fn pack(&self) -> Vec<u8> {
                self.0.clone()
            }
            fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
                Ok(Self(data.to_vec()))
            }
        }

        let mut pair = establish_link_pair(ProofStrategy::None);
        let link_id = pair.initiator_link_id;
        let now_ms = pair.now_ms;

        // Send a channel message (do NOT deliver proof)
        let _channel_packet = pair
            .initiator
            .channel_send(&link_id, &TestMsg(b"test".to_vec()), &mut OsRng, now_ms)
            .unwrap();
        let _ = pair.initiator.drain_pending_packets().collect::<Vec<_>>();

        // Advance time past the channel timeout
        let retransmit_time = now_ms + 10_000; // well past any timeout
        pair.initiator.poll(&mut OsRng, retransmit_time);

        // Should have ChannelRetransmit event
        let events: Vec<_> = pair.initiator.drain_events().collect();
        let has_retransmit = events
            .iter()
            .any(|e| matches!(e, LinkEvent::ChannelRetransmit { .. }));
        assert!(has_retransmit, "Expected ChannelRetransmit event");

        // Should have a Channel packet in pending
        let pending: Vec<_> = pair.initiator.drain_pending_packets().collect();
        let has_channel_packet = pending
            .iter()
            .any(|p| matches!(p, PendingPacket::Channel { .. }));
        assert!(has_channel_packet, "Expected Channel retransmit packet");
    }

    #[test]
    fn test_concurrent_links_independent() {
        use crate::link::channel::ChannelError;

        struct TestMsg(Vec<u8>);
        impl Message for TestMsg {
            const MSGTYPE: u16 = 0x0001;
            fn pack(&self) -> Vec<u8> {
                self.0.clone()
            }
            fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
                Ok(Self(data.to_vec()))
            }
        }

        // Establish two separate links
        let mut pair1 = establish_link_pair(ProofStrategy::None);
        let mut pair2 = establish_link_pair(ProofStrategy::None);

        // Send data on both
        let _p1 = pair1
            .initiator
            .channel_send(
                &pair1.initiator_link_id,
                &TestMsg(b"link1".to_vec()),
                &mut OsRng,
                pair1.now_ms,
            )
            .unwrap();
        let _p2 = pair2
            .initiator
            .channel_send(
                &pair2.initiator_link_id,
                &TestMsg(b"link2".to_vec()),
                &mut OsRng,
                pair2.now_ms,
            )
            .unwrap();

        // Close link1
        pair1.initiator.close(&pair1.initiator_link_id, &mut OsRng);

        // Link2 should still be active and functional
        assert!(pair2.initiator.is_active(&pair2.initiator_link_id));
    }

    #[test]
    fn test_memory_cleanup_on_close() {
        let mut pair = establish_link_pair(ProofStrategy::None);
        let link_id = pair.initiator_link_id;

        // Establish channel and send messages
        let _ = pair.initiator.get_channel(&link_id);

        // Close the link
        pair.initiator.close(&link_id, &mut OsRng);
        pair.initiator.poll(&mut OsRng, pair.now_ms);

        // Link should be removed from the map — FAILS: close() sets Closed but never removes
        assert!(
            pair.initiator.link(&link_id).is_none(),
            "closed link should be removed from links map"
        );
    }

    #[test]
    fn test_peer_close_processing() {
        let mut pair = establish_link_pair(ProofStrategy::None);

        // Build close packet on initiator
        pair.initiator.close(&pair.initiator_link_id, &mut OsRng);
        let close_packets = pair.initiator.drain_close_packets();
        assert_eq!(close_packets.len(), 1);
        let (_, close_data) = &close_packets[0];

        // Deliver close to responder
        let close_packet = Packet::unpack(close_data).unwrap();
        pair.responder
            .process_packet(&close_packet, close_data, &mut OsRng, pair.now_ms, 0);

        // Responder should emit LinkClosed with PeerClosed reason
        let events: Vec<_> = pair.responder.drain_events().collect();
        let has_peer_closed = events.iter().any(|e| {
            matches!(
                e,
                LinkEvent::LinkClosed {
                    reason: LinkCloseReason::PeerClosed,
                    ..
                }
            )
        });
        assert!(
            has_peer_closed,
            "Expected LinkClosed with PeerClosed reason, got: {:?}",
            events
        );
    }

    #[test]
    fn test_inbound_data_prevents_stale() {
        let mut pair = establish_link_pair(ProofStrategy::None);
        let link_id = pair.responder_link_id;

        let link = pair.responder.link(&link_id).unwrap();
        let stale_time_secs = link.stale_time_secs();
        let last_inbound = link.last_inbound_secs();

        // Advance time close to (but not past) stale threshold
        let almost_stale_secs = last_inbound + stale_time_secs - 2;
        let almost_stale_ms = almost_stale_secs * 1000;

        // Send data from initiator → process on responder (updates last_inbound)
        let data_packet = pair
            .initiator
            .send(&pair.initiator_link_id, b"keepalive data", &mut OsRng)
            .unwrap();
        let parsed = Packet::unpack(&data_packet).unwrap();
        pair.responder
            .process_packet(&parsed, &data_packet, &mut OsRng, almost_stale_ms, 0);
        let _ = pair.responder.drain_events().collect::<Vec<_>>();

        // Advance time past the ORIGINAL stale threshold, but within NEW stale time
        let past_original_stale_secs = last_inbound + stale_time_secs + 1;
        let past_original_stale_ms = past_original_stale_secs * 1000;
        pair.responder.poll(&mut OsRng, past_original_stale_ms);

        // Should NOT emit LinkStale (inbound data reset the timer)
        let events: Vec<_> = pair.responder.drain_events().collect();
        let has_stale = events
            .iter()
            .any(|e| matches!(e, LinkEvent::LinkStale { .. }));
        assert!(
            !has_stale,
            "should NOT become stale — inbound data reset the timer"
        );
    }

    #[test]
    fn test_channel_receipt_keys_cleaned_on_close() {
        use crate::link::channel::ChannelError;

        struct TestMsg(Vec<u8>);
        impl Message for TestMsg {
            const MSGTYPE: u16 = 0x0001;
            fn pack(&self) -> Vec<u8> {
                self.0.clone()
            }
            fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
                Ok(Self(data.to_vec()))
            }
        }

        let mut pair = establish_link_pair(ProofStrategy::All);
        let link_id = pair.initiator_link_id;

        // Send a channel message with receipt
        let channel_packet = pair
            .initiator
            .channel_send(
                &link_id,
                &TestMsg(b"track me".to_vec()),
                &mut OsRng,
                pair.now_ms,
            )
            .unwrap();
        let seq = pair
            .initiator
            .channel(&link_id)
            .unwrap()
            .last_sent_sequence();
        let _ = pair
            .initiator
            .register_channel_receipt(&channel_packet, link_id, seq, pair.now_ms);

        // Receipt should exist
        assert_eq!(pair.initiator.data_receipts_count(), 1);

        // Close the link
        pair.initiator.close(&link_id, &mut OsRng);

        // channel_receipt_keys for this link should be cleaned
        let has_keys_for_link = pair
            .initiator
            .channel_receipt_keys
            .keys()
            .any(|(lid, _)| *lid == link_id);
        assert!(
            !has_keys_for_link,
            "channel_receipt_keys should be cleaned on close"
        );
    }

    // ─── T10: Link Lifecycle ────────────────────────────────────────────────

    #[test]
    fn test_attached_interface_set_on_handshake() {
        let pair = establish_link_pair(ProofStrategy::None);

        // Responder: set from link request (interface_index=0)
        let resp_link = pair.responder.link(&pair.responder_link_id).unwrap();
        assert_eq!(
            resp_link.attached_interface(),
            Some(0),
            "responder should have attached_interface set from link request"
        );

        // Initiator: set from proof (interface_index=0)
        let init_link = pair.initiator.link(&pair.initiator_link_id).unwrap();
        assert_eq!(
            init_link.attached_interface(),
            Some(0),
            "initiator should have attached_interface set from proof"
        );
    }

    #[test]
    fn test_keepalive_timer_reset_on_inbound() {
        let mut pair = establish_link_pair(ProofStrategy::None);
        let link_id = pair.responder_link_id;

        // Note original last_inbound
        let link = pair.responder.link(&link_id).unwrap();
        let original_inbound = link.last_inbound_secs();
        let stale_time_secs = link.stale_time_secs();

        // Advance time partially
        let midpoint_secs = original_inbound + stale_time_secs / 2;
        let midpoint_ms = midpoint_secs * 1000;

        // Send data → updates last_inbound
        let data_packet = pair
            .initiator
            .send(&pair.initiator_link_id, b"ping", &mut OsRng)
            .unwrap();
        let parsed = Packet::unpack(&data_packet).unwrap();
        pair.responder
            .process_packet(&parsed, &data_packet, &mut OsRng, midpoint_ms, 0);
        let _ = pair.responder.drain_events().collect::<Vec<_>>();

        // Verify last_inbound was updated
        let link = pair.responder.link(&link_id).unwrap();
        assert_eq!(
            link.last_inbound_secs(),
            midpoint_secs,
            "last_inbound should be updated to midpoint"
        );

        // Advance past original stale threshold but not past new one
        let past_original = original_inbound + stale_time_secs + 1;
        let past_original_ms = past_original * 1000;
        pair.responder.poll(&mut OsRng, past_original_ms);

        let events: Vec<_> = pair.responder.drain_events().collect();
        let has_stale = events
            .iter()
            .any(|e| matches!(e, LinkEvent::LinkStale { .. }));
        assert!(
            !has_stale,
            "should NOT be stale — inbound data reset the timer"
        );
    }

    #[test]
    fn test_active_stale_closed_lifecycle() {
        let mut pair = establish_link_pair(ProofStrategy::None);
        let link_id = pair.responder_link_id;

        let link = pair.responder.link(&link_id).unwrap();
        let stale_time_secs = link.stale_time_secs();
        let last_inbound = link.last_inbound_secs();
        let rtt_secs = link.rtt_secs().unwrap_or(0.0);

        // Phase 1: Active → Stale
        let stale_secs = last_inbound + stale_time_secs + 1;
        pair.responder.poll(&mut OsRng, stale_secs * 1000);

        let events: Vec<_> = pair.responder.drain_events().collect();
        assert!(events
            .iter()
            .any(|e| matches!(e, LinkEvent::LinkStale { .. })));

        let link = pair.responder.link(&link_id).unwrap();
        assert_eq!(link.state(), LinkState::Stale);

        // Phase 2: Stale → Closed
        let close_timeout_secs = stale_time_secs
            + (rtt_secs * crate::constants::LINK_KEEPALIVE_TIMEOUT_FACTOR as f64) as u64
            + crate::constants::LINK_STALE_GRACE_SECS
            + 1;
        let close_secs = last_inbound + close_timeout_secs;
        pair.responder.poll(&mut OsRng, close_secs * 1000);

        let events: Vec<_> = pair.responder.drain_events().collect();
        assert!(events.iter().any(|e| matches!(
            e,
            LinkEvent::LinkClosed {
                reason: LinkCloseReason::Stale,
                ..
            }
        )));
    }

    #[test]
    fn test_stale_recovery_on_inbound() {
        let mut pair = establish_link_pair(ProofStrategy::None);
        let link_id = pair.responder_link_id;

        // Force link to Stale
        pair.responder
            .link_mut(&link_id)
            .unwrap()
            .set_state(LinkState::Stale);

        // Send data from initiator → process on responder (triggers try_recover_stale)
        let data_packet = pair
            .initiator
            .send(&pair.initiator_link_id, b"recover me", &mut OsRng)
            .unwrap();
        let parsed = Packet::unpack(&data_packet).unwrap();
        pair.responder
            .process_packet(&parsed, &data_packet, &mut OsRng, pair.now_ms + 1000, 0);

        // Should emit LinkRecovered
        let events: Vec<_> = pair.responder.drain_events().collect();
        let has_recovered = events
            .iter()
            .any(|e| matches!(e, LinkEvent::LinkRecovered { .. }));
        assert!(has_recovered, "Expected LinkRecovered event");

        // Link should be Active again
        let link = pair.responder.link(&link_id).unwrap();
        assert_eq!(link.state(), LinkState::Active);
    }

    // ─── T16: Regression Tests ──────────────────────────────────────────────

    #[test]
    fn test_b3_close_does_not_clean_channels_map() {
        use crate::link::channel::ChannelError;

        struct TestMsg(Vec<u8>);
        impl Message for TestMsg {
            const MSGTYPE: u16 = 0x0001;
            fn pack(&self) -> Vec<u8> {
                self.0.clone()
            }
            fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
                Ok(Self(data.to_vec()))
            }
        }

        let mut pair = establish_link_pair(ProofStrategy::None);
        let link_id = pair.initiator_link_id;

        // Create channel and send a message
        let _ = pair
            .initiator
            .channel_send(
                &link_id,
                &TestMsg(b"hello".to_vec()),
                &mut OsRng,
                pair.now_ms,
            )
            .unwrap();
        assert!(pair.initiator.has_channel(&link_id));

        // Close the link
        pair.initiator.close(&link_id, &mut OsRng);

        // Channel should be removed — dropping the link drops its channel
        assert!(
            !pair.initiator.has_channel(&link_id),
            "channel should be removed after close()"
        );
    }

    #[test]
    fn test_f4_mark_delivered_bogus_sequence() {
        let mut pair = establish_link_pair(ProofStrategy::None);
        let link_id = pair.initiator_link_id;

        // Create channel
        let _ = pair.initiator.get_channel(&link_id);

        // Call mark_channel_delivered with a sequence that was never sent
        let result = pair
            .initiator
            .mark_channel_delivered(&link_id, 9999, pair.now_ms, 500);
        assert!(
            !result,
            "mark_channel_delivered should return false for unknown sequence"
        );
    }

    #[test]
    fn test_d13_channel_exhaustion_produces_timeout_reason() {
        use crate::link::channel::ChannelError;

        struct TestMsg(Vec<u8>);
        impl Message for TestMsg {
            const MSGTYPE: u16 = 0x0001;
            fn pack(&self) -> Vec<u8> {
                self.0.clone()
            }
            fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
                Ok(Self(data.to_vec()))
            }
        }

        let mut pair = establish_link_pair(ProofStrategy::None);
        let link_id = pair.initiator_link_id;

        // Send a channel message
        let _ = pair
            .initiator
            .channel_send(
                &link_id,
                &TestMsg(b"exhaust".to_vec()),
                &mut OsRng,
                pair.now_ms,
            )
            .unwrap();
        let _ = pair.initiator.drain_pending_packets().collect::<Vec<_>>();
        let _ = pair.initiator.drain_events().collect::<Vec<_>>();

        // Reduce max_tries so we hit TearDownLink quickly
        pair.initiator
            .link_mut(&link_id)
            .unwrap()
            .channel_mut()
            .unwrap()
            .set_max_tries_for_test(2);

        // First retransmit (tries 1→2)
        let mut t = pair.now_ms + 50_000;
        pair.initiator.poll(&mut OsRng, t);
        let _ = pair.initiator.drain_events().collect::<Vec<_>>();
        let _ = pair.initiator.drain_pending_packets().collect::<Vec<_>>();

        // Second poll → tries=2 >= max_tries=2 → TearDownLink → LinkClosed with Timeout
        t += 100_000;
        pair.initiator.poll(&mut OsRng, t);

        let events: Vec<_> = pair.initiator.drain_events().collect();
        let has_timeout_close = events.iter().any(|e| {
            matches!(
                e,
                LinkEvent::LinkClosed {
                    reason: LinkCloseReason::Timeout,
                    ..
                }
            )
        });
        assert!(
            has_timeout_close,
            "channel exhaustion should produce LinkClosed with Timeout reason (limitation D13), got: {:?}",
            events
        );
    }

    // ─── T13: Split large tests ─────────────────────────────────────────────

    // Split of test_retransmit_registers_new_receipt_and_removes_old (137 LOC → 3 tests)

    // Helper to set up a retransmit scenario: send a channel message, advance past timeout
    fn setup_retransmit_scenario() -> (LinkPair, LinkId, u16, [u8; 32]) {
        use crate::link::channel::ChannelError;

        struct TestMsg(Vec<u8>);
        impl Message for TestMsg {
            const MSGTYPE: u16 = 0x0001;
            fn pack(&self) -> Vec<u8> {
                self.0.clone()
            }
            fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
                Ok(Self(data.to_vec()))
            }
        }

        let mut pair = establish_link_pair(ProofStrategy::None);
        let link_id = pair.initiator_link_id;
        let now_ms = pair.now_ms;

        // Send a channel message
        let channel_packet = pair
            .initiator
            .channel_send(&link_id, &TestMsg(b"hello".to_vec()), &mut OsRng, now_ms)
            .unwrap();
        let sequence = pair
            .initiator
            .channel(&link_id)
            .unwrap()
            .last_sent_sequence();
        let (hash_1, _) =
            pair.initiator
                .register_channel_receipt(&channel_packet, link_id, sequence, now_ms);
        let _ = pair.initiator.drain_pending_packets().collect::<Vec<_>>();

        // Trigger retransmit
        let retransmit_time = now_ms + 5000;
        pair.initiator.poll(&mut OsRng, retransmit_time);
        pair.now_ms = retransmit_time;

        (pair, link_id, sequence, hash_1)
    }

    #[test]
    fn test_retransmit_emits_receipt_updated_event() {
        let (mut pair, link_id, sequence, hash_1) = setup_retransmit_scenario();

        let events: Vec<_> = pair.initiator.drain_events().collect();
        let receipt_updated = events.iter().find_map(|e| match e {
            LinkEvent::ChannelReceiptUpdated {
                link_id: lid,
                new_hash,
                old_hash,
                sequence: seq,
            } => Some((*lid, *new_hash, *old_hash, *seq)),
            _ => None,
        });
        assert!(
            receipt_updated.is_some(),
            "Expected ChannelReceiptUpdated event"
        );
        let (evt_lid, hash_2, old_hash, evt_seq) = receipt_updated.unwrap();
        assert_eq!(evt_lid, link_id);
        assert_eq!(evt_seq, sequence);
        assert_eq!(old_hash, Some(hash_1));
        assert_ne!(
            hash_2, hash_1,
            "re-encrypted packet must have different hash"
        );
    }

    #[test]
    fn test_retransmit_removes_old_receipt() {
        let (pair, _link_id, _sequence, hash_1) = setup_retransmit_scenario();

        // Only one receipt should exist
        assert_eq!(pair.initiator.data_receipts.len(), 1);

        // Old hash should not be in data_receipts
        let mut old_truncated = [0u8; TRUNCATED_HASHBYTES];
        old_truncated.copy_from_slice(&hash_1[..TRUNCATED_HASHBYTES]);
        assert!(
            !pair.initiator.data_receipts.contains_key(&old_truncated),
            "old receipt should have been removed"
        );
    }

    #[test]
    fn test_retransmit_proof_matches_new_hash() {
        let (mut pair, link_id, _sequence, _hash_1) = setup_retransmit_scenario();

        let events: Vec<_> = pair.initiator.drain_events().collect();
        let hash_2 = events
            .iter()
            .find_map(|e| match e {
                LinkEvent::ChannelReceiptUpdated { new_hash, .. } => Some(*new_hash),
                _ => None,
            })
            .expect("need ChannelReceiptUpdated");

        // Get the retransmit packet and deliver to responder
        let retransmit_packets: Vec<_> = pair.initiator.drain_pending_packets().collect();
        let retransmit_data = retransmit_packets
            .iter()
            .find_map(|p| match p {
                PendingPacket::Channel { data, .. } => Some(data.clone()),
                _ => None,
            })
            .expect("should have retransmit packet");

        let packet = Packet::unpack(&retransmit_data).unwrap();
        pair.responder
            .process_packet(&packet, &retransmit_data, &mut OsRng, pair.now_ms, 0);
        let proofs = pair.responder.drain_proof_packets();
        assert_eq!(proofs.len(), 1);

        // Deliver proof to initiator
        let (_, proof_packet) = &proofs[0];
        let proof = Packet::unpack(proof_packet).unwrap();
        pair.initiator
            .process_packet(&proof, proof_packet, &mut OsRng, pair.now_ms, 0);

        let events: Vec<_> = pair.initiator.drain_events().collect();
        let delivered = events.iter().find_map(|e| match e {
            LinkEvent::DataDelivered {
                link_id: lid,
                packet_hash,
            } => Some((*lid, *packet_hash)),
            _ => None,
        });
        assert!(delivered.is_some(), "Expected DataDelivered event");
        let (dlid, dhash) = delivered.unwrap();
        assert_eq!(dlid, link_id);
        assert_eq!(dhash, hash_2, "proof should match retransmit hash");
    }

    // Split of test_multiple_retransmits_clean_up_receipts (109 LOC → 2 tests)

    #[test]
    fn test_multiple_retransmits_keep_single_receipt() {
        use crate::link::channel::ChannelError;

        struct TestMsg(Vec<u8>);
        impl Message for TestMsg {
            const MSGTYPE: u16 = 0x0001;
            fn pack(&self) -> Vec<u8> {
                self.0.clone()
            }
            fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
                Ok(Self(data.to_vec()))
            }
        }

        let mut pair = establish_link_pair(ProofStrategy::None);
        let link_id = pair.initiator_link_id;
        let mut now_ms = pair.now_ms;

        // Send a channel message
        let channel_packet = pair
            .initiator
            .channel_send(&link_id, &TestMsg(b"retry me".to_vec()), &mut OsRng, now_ms)
            .unwrap();
        let sequence = pair
            .initiator
            .channel(&link_id)
            .unwrap()
            .last_sent_sequence();
        let (hash_1, _) =
            pair.initiator
                .register_channel_receipt(&channel_packet, link_id, sequence, now_ms);
        let _ = pair.initiator.drain_pending_packets().collect::<Vec<_>>();

        // First retransmit
        now_ms += 5000;
        pair.initiator.poll(&mut OsRng, now_ms);
        let events: Vec<_> = pair.initiator.drain_events().collect();
        let hash_2 = events
            .iter()
            .find_map(|e| match e {
                LinkEvent::ChannelReceiptUpdated {
                    new_hash, old_hash, ..
                } => {
                    assert_eq!(*old_hash, Some(hash_1));
                    Some(*new_hash)
                }
                _ => None,
            })
            .expect("expected ChannelReceiptUpdated");
        assert_eq!(pair.initiator.data_receipts.len(), 1);
        let _ = pair.initiator.drain_pending_packets().collect::<Vec<_>>();

        // Second retransmit
        now_ms += 5000;
        pair.initiator.poll(&mut OsRng, now_ms);
        let events: Vec<_> = pair.initiator.drain_events().collect();
        let hash_3 = events
            .iter()
            .find_map(|e| match e {
                LinkEvent::ChannelReceiptUpdated {
                    new_hash, old_hash, ..
                } => {
                    assert_eq!(*old_hash, Some(hash_2));
                    Some(*new_hash)
                }
                _ => None,
            })
            .expect("expected ChannelReceiptUpdated");

        // Only 1 receipt should exist (no leaks)
        assert_eq!(pair.initiator.data_receipts.len(), 1);
        assert_ne!(hash_3, hash_2);
        assert_ne!(hash_3, hash_1);
    }

    #[test]
    fn test_proof_for_final_retransmit_delivers() {
        use crate::link::channel::ChannelError;

        struct TestMsg(Vec<u8>);
        impl Message for TestMsg {
            const MSGTYPE: u16 = 0x0001;
            fn pack(&self) -> Vec<u8> {
                self.0.clone()
            }
            fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
                Ok(Self(data.to_vec()))
            }
        }

        let mut pair = establish_link_pair(ProofStrategy::None);
        let link_id = pair.initiator_link_id;
        let mut now_ms = pair.now_ms;

        // Send and register receipt
        let channel_packet = pair
            .initiator
            .channel_send(&link_id, &TestMsg(b"multi".to_vec()), &mut OsRng, now_ms)
            .unwrap();
        let seq = pair
            .initiator
            .channel(&link_id)
            .unwrap()
            .last_sent_sequence();
        let _ = pair
            .initiator
            .register_channel_receipt(&channel_packet, link_id, seq, now_ms);
        let _ = pair.initiator.drain_pending_packets().collect::<Vec<_>>();

        // Three retransmits — keep the last retransmit packet for proof delivery
        let mut last_retransmit = None;
        for _ in 0..3 {
            now_ms += 10_000;
            pair.initiator.poll(&mut OsRng, now_ms);
            let _ = pair.initiator.drain_events().collect::<Vec<_>>();
            let packets: Vec<_> = pair.initiator.drain_pending_packets().collect();
            if let Some(data) = packets.iter().find_map(|p| match p {
                PendingPacket::Channel { data, .. } => Some(data.clone()),
                _ => None,
            }) {
                last_retransmit = Some(data);
            }
        }
        let retransmit_data = last_retransmit.expect("should have retransmit packet");

        let packet = Packet::unpack(&retransmit_data).unwrap();
        pair.responder
            .process_packet(&packet, &retransmit_data, &mut OsRng, now_ms, 0);
        let proofs = pair.responder.drain_proof_packets();
        assert!(!proofs.is_empty());

        let (_, proof_packet) = &proofs[0];
        let proof = Packet::unpack(proof_packet).unwrap();
        pair.initiator
            .process_packet(&proof, proof_packet, &mut OsRng, now_ms, 0);

        let events: Vec<_> = pair.initiator.drain_events().collect();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, LinkEvent::DataDelivered { .. })),
            "Expected DataDelivered after proof for latest retransmit"
        );
        assert_eq!(pair.initiator.data_receipts.len(), 0);
    }

    // Split of test_channel_proof_suppressed_on_rx_ring_full (84 LOC → 2 tests)

    #[test]
    fn test_channel_proof_generated_for_in_order_message() {
        use crate::link::channel::ChannelError;

        struct TestMsg(Vec<u8>);
        impl Message for TestMsg {
            const MSGTYPE: u16 = 0x0001;
            fn pack(&self) -> Vec<u8> {
                self.0.clone()
            }
            fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
                Ok(Self(data.to_vec()))
            }
        }

        let mut pair = establish_link_pair(ProofStrategy::None);

        let channel_packet = pair
            .initiator
            .channel_send(
                &pair.initiator_link_id,
                &TestMsg(b"normal message".to_vec()),
                &mut OsRng,
                pair.now_ms,
            )
            .unwrap();

        let packet = Packet::unpack(&channel_packet).unwrap();
        pair.responder
            .process_packet(&packet, &channel_packet, &mut OsRng, pair.now_ms, 0);

        let proofs = pair.responder.drain_proof_packets();
        assert_eq!(
            proofs.len(),
            1,
            "proof should be generated for normal in-order message"
        );
    }

    #[test]
    fn test_channel_proof_suppressed_when_rx_ring_full() {
        use crate::link::channel::ChannelError;

        struct TestMsg(Vec<u8>);
        impl Message for TestMsg {
            const MSGTYPE: u16 = 0x0001;
            fn pack(&self) -> Vec<u8> {
                self.0.clone()
            }
            fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
                Ok(Self(data.to_vec()))
            }
        }

        let mut pair = establish_link_pair(ProofStrategy::None);

        // First: send a normal message so responder's channel advances to expect seq 1
        let channel_packet = pair
            .initiator
            .channel_send(
                &pair.initiator_link_id,
                &TestMsg(b"first".to_vec()),
                &mut OsRng,
                pair.now_ms,
            )
            .unwrap();
        let packet = Packet::unpack(&channel_packet).unwrap();
        pair.responder
            .process_packet(&packet, &channel_packet, &mut OsRng, pair.now_ms, 0);
        let _ = pair.responder.drain_proof_packets(); // consume baseline proof
        let _ = pair.responder.drain_events().collect::<Vec<_>>();

        // Jump initiator's sequence far ahead to trigger rx_ring full
        let target_seq = 1 + crate::constants::CHANNEL_RX_RING_MAX as u16;
        pair.initiator
            .link_mut(&pair.initiator_link_id)
            .unwrap()
            .channel_mut()
            .unwrap()
            .force_next_tx_sequence_for_test(target_seq);

        let far_packet = pair
            .initiator
            .channel_send(
                &pair.initiator_link_id,
                &TestMsg(b"far future".to_vec()),
                &mut OsRng,
                pair.now_ms,
            )
            .unwrap();
        let packet = Packet::unpack(&far_packet).unwrap();
        pair.responder
            .process_packet(&packet, &far_packet, &mut OsRng, pair.now_ms, 0);

        let proofs = pair.responder.drain_proof_packets();
        assert_eq!(
            proofs.len(),
            0,
            "proof must be suppressed when rx_ring is full"
        );
    }

    #[test]
    fn test_channel_immutable_accessor() {
        let mut manager = LinkManager::new();
        let dest_hash = DestinationHash::new([0x42; 16]);
        let dest_signing_key = [0x33; 32];

        let (link_id, _) =
            manager.initiate(dest_hash, &dest_signing_key, &mut OsRng, INITIAL_TIME_MS);

        // No channel exists yet
        assert!(manager.channel(&link_id).is_none());

        // For a non-existent link, also returns None
        let fake_id = LinkId::new([0xFF; 16]);
        assert!(manager.channel(&fake_id).is_none());
    }

    #[test]
    fn test_data_receipts_count() {
        let mut pair = establish_link_pair(ProofStrategy::All);
        assert_eq!(pair.initiator.data_receipts_count(), 0);

        // Send data with receipt
        let _ = pair
            .initiator
            .send_with_receipt(&pair.initiator_link_id, b"test", &mut OsRng, pair.now_ms)
            .unwrap();
        assert_eq!(pair.initiator.data_receipts_count(), 1);

        // Send another
        let _ = pair
            .initiator
            .send_with_receipt(&pair.initiator_link_id, b"test2", &mut OsRng, pair.now_ms)
            .unwrap();
        assert_eq!(pair.initiator.data_receipts_count(), 2);
    }

    #[test]
    fn test_data_receipts_expire_after_timeout() {
        let mut pair = establish_link_pair(ProofStrategy::All);

        // Send data with receipt tracking (but don't deliver the proof)
        let (_data_packet, _sent_hash) = pair
            .initiator
            .send_with_receipt(
                &pair.initiator_link_id,
                b"will expire",
                &mut OsRng,
                pair.now_ms,
            )
            .unwrap();

        // Receipt should exist
        assert_eq!(pair.initiator.data_receipts.len(), 1);

        // Advance time past the receipt timeout
        let expired_ms = pair.now_ms + DATA_RECEIPT_TIMEOUT_MS + 1;
        pair.initiator.poll(&mut OsRng, expired_ms);

        // Receipt should have been cleaned up
        assert_eq!(
            pair.initiator.data_receipts.len(),
            0,
            "Expired receipts should be removed during poll"
        );
    }

    #[test]
    fn test_channel_proof_generated_with_proof_strategy_none() {
        use crate::link::channel::ChannelError;

        struct TestMsg(Vec<u8>);
        impl Message for TestMsg {
            const MSGTYPE: u16 = 0x0001;
            fn pack(&self) -> Vec<u8> {
                self.0.clone()
            }
            fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
                Ok(Self(data.to_vec()))
            }
        }

        // Establish with ProofStrategy::None — the default for destinations
        let mut pair = establish_link_pair(ProofStrategy::None);

        // Signing key must be present even with ProofStrategy::None
        let link = pair.responder.link(&pair.responder_link_id).unwrap();
        assert!(
            link.dest_signing_key().is_some(),
            "dest_signing_key must always be stored for channel proofs"
        );

        // Send a channel message from initiator
        let channel_packet = pair
            .initiator
            .channel_send(
                &pair.initiator_link_id,
                &TestMsg(b"hello channel".to_vec()),
                &mut OsRng,
                pair.now_ms,
            )
            .unwrap();

        // Process channel data on responder
        let packet = Packet::unpack(&channel_packet).unwrap();
        pair.responder
            .process_packet(&packet, &channel_packet, &mut OsRng, pair.now_ms, 0);

        // Responder must have generated a proof packet
        let proofs = pair.responder.drain_proof_packets();
        assert_eq!(
            proofs.len(),
            1,
            "Channel proof must be generated even with ProofStrategy::None"
        );
        assert_eq!(proofs[0].0, pair.responder_link_id);
    }

    #[test]
    fn test_channel_proof_generated_by_initiator() {
        use crate::link::channel::ChannelError;

        struct TestMsg(Vec<u8>);
        impl Message for TestMsg {
            const MSGTYPE: u16 = 0x0001;
            fn pack(&self) -> Vec<u8> {
                self.0.clone()
            }
            fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
                Ok(Self(data.to_vec()))
            }
        }

        let mut pair = establish_link_pair(ProofStrategy::None);

        // Initiator has no dest_signing_key but has ephemeral signing_key
        let link = pair.initiator.link(&pair.initiator_link_id).unwrap();
        assert!(
            link.dest_signing_key().is_none(),
            "initiator should not have dest_signing_key"
        );
        assert!(
            link.proof_signing_key().is_some(),
            "initiator must have proof_signing_key (ephemeral)"
        );

        // Send a channel message from responder to initiator
        let channel_packet = pair
            .responder
            .channel_send(
                &pair.responder_link_id,
                &TestMsg(b"hello from responder".to_vec()),
                &mut OsRng,
                pair.now_ms,
            )
            .unwrap();

        // Process channel data on initiator
        let packet = Packet::unpack(&channel_packet).unwrap();
        pair.initiator
            .process_packet(&packet, &channel_packet, &mut OsRng, pair.now_ms, 0);

        // Initiator must have generated a proof using its ephemeral signing key
        let proofs = pair.initiator.drain_proof_packets();
        assert_eq!(
            proofs.len(),
            1,
            "Initiator must generate channel proof using ephemeral signing key"
        );
        assert_eq!(proofs[0].0, pair.initiator_link_id);
    }
}
