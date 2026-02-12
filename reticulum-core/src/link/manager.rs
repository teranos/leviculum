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

use super::channel::{Channel, Message};
use super::{
    Link, LinkCloseReason, LinkError, LinkEvent, LinkId, LinkState, PeerKeys, PendingPacket,
};
use crate::destination::DestinationHash;

/// Display helper for hex-formatted byte slices in tracing output
struct HexFmt<'a>(&'a [u8]);
impl core::fmt::Display for HexFmt<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

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
    /// Channels by link ID
    channels: BTreeMap<LinkId, Channel>,
    /// Pending outgoing links (awaiting proof) - stores (link_id, created_at_ms)
    pending_outgoing: BTreeMap<LinkId, PendingOutgoing>,
    /// Pending incoming links (awaiting RTT) - stores (link_id, created_at_ms)
    pending_incoming: BTreeMap<LinkId, PendingIncoming>,
    /// Destinations that accept incoming links
    accepted_destinations: BTreeSet<DestinationHash>,
    /// Pending events
    events: Vec<LinkEvent>,
    /// Unified queue for all outbound link packets
    pending_packets: Vec<PendingPacket>,
    /// Receipts for sent data packets awaiting proofs (truncated_hash -> receipt)
    data_receipts: BTreeMap<[u8; TRUNCATED_HASHBYTES], DataReceipt>,
}

/// State for a pending outgoing link (initiator side, awaiting proof)
struct PendingOutgoing {
    /// When this link request was created
    created_at_ms: u64,
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

/// State for a pending incoming link (responder side, awaiting RTT)
struct PendingIncoming {
    /// When the proof was sent
    proof_sent_at_ms: u64,
}

impl LinkManager {
    /// Create a new LinkManager
    pub fn new() -> Self {
        Self {
            links: BTreeMap::new(),
            channels: BTreeMap::new(),
            pending_outgoing: BTreeMap::new(),
            pending_incoming: BTreeMap::new(),
            accepted_destinations: BTreeSet::new(),
            events: Vec::new(),
            pending_packets: Vec::new(),
            data_receipts: BTreeMap::new(),
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

        // Track as pending
        self.pending_outgoing.insert(
            link_id,
            PendingOutgoing {
                created_at_ms: now_ms,
            },
        );

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

        // Track as pending incoming (awaiting RTT)
        self.pending_incoming.insert(
            *link_id,
            PendingIncoming {
                proof_sent_at_ms: now_ms,
            },
        );

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

    /// Register a data receipt for tracking delivery via proofs
    ///
    /// Used by NodeCore to register receipts for channel messages, which are
    /// built by Connection (not LinkManager) but need proof matching here.
    ///
    /// # Arguments
    /// * `packet_data` - The serialized packet bytes (hashed for receipt matching)
    /// * `link_id` - The link this packet was sent on
    /// * `now_ms` - Current time in milliseconds
    ///
    /// # Returns
    /// The full SHA256 hash of the packet
    pub fn register_data_receipt(
        &mut self,
        packet_data: &[u8],
        link_id: LinkId,
        now_ms: u64,
    ) -> [u8; 32] {
        let full_hash = packet_hash(packet_data);
        let mut truncated = [0u8; TRUNCATED_HASHBYTES];
        truncated.copy_from_slice(&full_hash[..TRUNCATED_HASHBYTES]);
        tracing::debug!(
            hash = %HexFmt(&full_hash),
            truncated = %HexFmt(&truncated),
            link = %HexFmt(link_id.as_bytes()),
            "link_mgr: registered data receipt"
        );
        self.data_receipts.insert(
            truncated,
            DataReceipt {
                full_hash,
                link_id,
                sent_at_ms: now_ms,
            },
        );
        full_hash
    }

    /// Close a link gracefully
    ///
    /// This builds a LINKCLOSE packet that should be sent to the peer.
    /// Call `drain_pending_packets()` after this to get the packet to send.
    pub fn close(&mut self, link_id: &LinkId, rng: &mut impl CryptoRngCore) {
        if let Some(link) = self.links.get_mut(link_id) {
            // Try to build and queue the close packet
            if let Ok(close_packet) = link.build_close_packet(rng) {
                self.pending_packets.push(PendingPacket::Close {
                    link_id: *link_id,
                    data: close_packet,
                });
            }
            // Mark the link as closed
            link.close();
            // Remove from pending tracking
            self.pending_outgoing.remove(link_id);
            self.pending_incoming.remove(link_id);
            // Emit event
            self.events.push(LinkEvent::LinkClosed {
                link_id: *link_id,
                reason: LinkCloseReason::Normal,
            });
        }
    }

    /// Close a link without sending a close packet (local only)
    ///
    /// Use this when the peer has already closed the link or when
    /// we don't want/can't send a close packet.
    pub fn close_local(&mut self, link_id: &LinkId, reason: LinkCloseReason) {
        if let Some(link) = self.links.get_mut(link_id) {
            link.close();
        }
        // Always remove from tracking regardless of link state
        self.links.remove(link_id);
        self.channels.remove(link_id);
        self.pending_outgoing.remove(link_id);
        self.pending_incoming.remove(link_id);
        self.events.push(LinkEvent::LinkClosed {
            link_id: *link_id,
            reason,
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
        // Check if link exists and is active
        let link = self.links.get(link_id)?;
        if link.state() != LinkState::Active {
            return None;
        }

        // Get or create channel
        if !self.channels.contains_key(link_id) {
            let mut channel = Channel::new();
            // Update window based on link RTT
            channel.update_window_for_rtt(link.rtt_ms());
            self.channels.insert(*link_id, channel);
        }

        self.channels.get_mut(link_id)
    }

    /// Get an immutable reference to a channel (None if not yet created)
    pub fn channel(&self, link_id: &LinkId) -> Option<&Channel> {
        self.channels.get(link_id)
    }

    /// Check if a channel exists for a link
    pub fn has_channel(&self, link_id: &LinkId) -> bool {
        self.channels.contains_key(link_id)
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
        // First check if link exists and is active
        let link = self.links.get(link_id).ok_or(LinkError::NotFound)?;
        if link.state() != LinkState::Active {
            return Err(LinkError::InvalidState);
        }

        // Get link MDU and RTT for channel
        let link_mdu = link.mdu();
        let rtt_ms = link.rtt_ms();

        // Get or create channel
        if !self.channels.contains_key(link_id) {
            let mut channel = Channel::new();
            channel.update_window_for_rtt(rtt_ms);
            self.channels.insert(*link_id, channel);
        }

        let channel = self.channels.get_mut(link_id).ok_or(LinkError::NotFound)?;

        // Send through channel to get envelope data
        let envelope_data = channel
            .send(message, link_mdu, now_ms, rtt_ms)
            .map_err(|_| LinkError::InvalidState)?;

        // Build data packet with Channel context
        let link = self.links.get(link_id).ok_or(LinkError::NotFound)?;
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
        self.pending_outgoing.len() + self.pending_incoming.len()
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

        // Pending outgoing handshake timeouts
        for p in self.pending_outgoing.values() {
            update(p.created_at_ms.saturating_add(LINK_PENDING_TIMEOUT_MS));
        }

        // Pending incoming handshake timeouts
        for p in self.pending_incoming.values() {
            update(p.proof_sent_at_ms.saturating_add(LINK_PENDING_TIMEOUT_MS));
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
        if !self.channels.is_empty() {
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

        // Check if we have a pending outgoing link (link establishment proof)
        if !self.pending_outgoing.contains_key(&link_id) {
            return;
        }

        let Some(link) = self.links.get_mut(&link_id) else {
            return;
        };

        if link.state() != LinkState::Pending || !link.is_initiator() {
            return;
        }

        // Set attached interface from the interface the proof arrived on
        // (mirrors Python: initiator learns attached_interface from proof)
        link.set_attached_interface(interface_index);

        // Process the proof
        if link.process_proof(proof_data).is_err() {
            // Invalid proof - close the link
            self.links.remove(&link_id);
            self.pending_outgoing.remove(&link_id);
            self.events.push(LinkEvent::LinkClosed {
                link_id,
                reason: LinkCloseReason::InvalidProof,
            });
            return;
        }

        // Proof verified! Calculate RTT and build the RTT packet
        let now_secs = now_ms / MS_PER_SECOND;
        let pending = self.pending_outgoing.remove(&link_id);
        let rtt_ms = pending
            .map(|p| now_ms.saturating_sub(p.created_at_ms))
            .unwrap_or(0);
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
                self.pending_incoming.remove(&link_id);
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

            // Get or create channel for this link
            let rtt_ms = link.rtt_ms();
            let channel = self.channels.entry(link_id).or_insert_with(|| {
                let mut channel = Channel::new();
                channel.update_window_for_rtt(rtt_ms);
                channel
            });

            // Process through channel
            match channel.receive(&plaintext) {
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
                }
                Ok(None) => {
                    tracing::debug!("link_mgr: channel message buffered (out-of-order)");
                }
                Err(e) => {
                    tracing::debug!(?e, "link_mgr: channel receive failed");
                }
            }

            // Drain any buffered messages that are now ready
            let channel = match self.channels.get_mut(&link_id) {
                Some(c) => c,
                None => return,
            };
            for envelope in channel.drain_received() {
                self.events.push(LinkEvent::ChannelMessageReceived {
                    link_id,
                    msgtype: envelope.msgtype,
                    sequence: envelope.sequence,
                    data: envelope.data,
                });
            }

            // Generate proof unconditionally for CHANNEL packets (Python Link.py:1173).
            // Unlike regular data (which checks proof_strategy), Channel proofs are
            // always generated — matching Python's packet.prove() call.
            let link = match self.links.get(&link_id) {
                Some(l) => l,
                None => return,
            };
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
        // Check pending outgoing links
        let timed_out_outgoing =
            Self::collect_timed_out_ids(&self.pending_outgoing, |p| p.created_at_ms, now_ms);
        for link_id in timed_out_outgoing {
            self.links.remove(&link_id);
            self.pending_outgoing.remove(&link_id);
            self.events.push(LinkEvent::LinkClosed {
                link_id,
                reason: LinkCloseReason::Timeout,
            });
        }

        // Check pending incoming links
        let timed_out_incoming =
            Self::collect_timed_out_ids(&self.pending_incoming, |p| p.proof_sent_at_ms, now_ms);
        for link_id in timed_out_incoming {
            self.links.remove(&link_id);
            self.pending_incoming.remove(&link_id);
            self.events.push(LinkEvent::LinkClosed {
                link_id,
                reason: LinkCloseReason::Timeout,
            });
        }

        // Clean up expired data receipts
        self.data_receipts.retain(|_, receipt| {
            now_ms.saturating_sub(receipt.sent_at_ms) <= DATA_RECEIPT_TIMEOUT_MS
        });
    }

    /// Collect link IDs that have timed out from a pending map
    fn collect_timed_out_ids<T, F>(
        pending: &BTreeMap<LinkId, T>,
        get_timestamp: F,
        now_ms: u64,
    ) -> Vec<LinkId>
    where
        F: Fn(&T) -> u64,
    {
        pending
            .iter()
            .filter(|(_, entry)| {
                now_ms.saturating_sub(get_timestamp(entry)) > LINK_PENDING_TIMEOUT_MS
            })
            .map(|(id, _)| *id)
            .collect()
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
                // Build close packet before closing
                if let Ok(close_packet) = link.build_close_packet(rng) {
                    self.pending_packets.push(PendingPacket::Close {
                        link_id,
                        data: close_packet,
                    });
                }
                link.close();
                self.events.push(LinkEvent::LinkClosed {
                    link_id,
                    reason: LinkCloseReason::Stale,
                });
            }
        }
    }

    // --- Internal: Channel Timeout Handling ---

    /// Check for channel envelope timeouts and queue retransmissions
    fn check_channel_timeouts(&mut self, rng: &mut impl CryptoRngCore, now_ms: u64) {
        use super::channel::ChannelAction;

        // Collect link IDs that have channels
        let channel_link_ids: Vec<LinkId> = self.channels.keys().copied().collect();

        for link_id in channel_link_ids {
            // Get RTT for this link (use default if link not found)
            let rtt_ms = self
                .links
                .get(&link_id)
                .map(|link| link.rtt_ms())
                .unwrap_or(crate::constants::CHANNEL_DEFAULT_RTT_MS);

            // Get channel and poll for actions
            let actions = match self.channels.get_mut(&link_id) {
                Some(channel) => channel.poll(now_ms, rtt_ms),
                None => continue,
            };

            // Process actions
            for action in actions {
                match action {
                    ChannelAction::Retransmit { sequence, data } => {
                        tracing::debug!(seq = sequence, "link_mgr: queuing channel retransmit");
                        // Build and queue the retransmission packet
                        if let Some(link) = self.links.get(&link_id) {
                            if let Ok(packet) = link.build_data_packet_with_context(
                                &data,
                                PacketContext::Channel,
                                rng,
                            ) {
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
                        if let Some(link) = self.links.get_mut(&link_id) {
                            if let Ok(close_packet) = link.build_close_packet(rng) {
                                self.pending_packets.push(PendingPacket::Close {
                                    link_id,
                                    data: close_packet,
                                });
                            }
                            link.close();
                        }
                        self.channels.remove(&link_id);
                        self.events.push(LinkEvent::LinkClosed {
                            link_id,
                            reason: LinkCloseReason::Timeout,
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
