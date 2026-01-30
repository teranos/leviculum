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
//! use reticulum_core::traits::{PlatformContext, NoStorage};
//! use rand_core::OsRng;
//!
//! struct SimpleClock;
//! impl reticulum_core::traits::Clock for SimpleClock {
//!     fn now_ms(&self) -> u64 { 1000000 }
//! }
//!
//! let mut manager = LinkManager::new();
//!
//! // Register destination to accept incoming links
//! let my_dest_hash = [0x42u8; 16];
//! manager.register_destination(my_dest_hash);
//!
//! // Initiate outgoing link
//! let dest_hash = [0x33u8; 16];
//! let dest_signing_key = [0x11u8; 32];
//! let mut ctx = PlatformContext { rng: OsRng, clock: SimpleClock, storage: NoStorage };
//! let (link_id, packet) = manager.initiate(dest_hash, &dest_signing_key, &mut ctx);
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

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::constants::{MS_PER_SECOND, TRUNCATED_HASHBYTES};
use crate::identity::Identity;
use crate::packet::{Packet, PacketContext, PacketType};
use crate::traits::{Clock, Context};

use super::channel::{Channel, Message};
use super::{Link, LinkCloseReason, LinkError, LinkEvent, LinkId, LinkState, PeerKeys};

/// Default timeout for pending links (30 seconds)
const LINK_TIMEOUT_MS: u64 = 30_000;

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
    /// Destinations that accept links (dest_hash -> identity for signing proofs)
    accepting: BTreeSet<[u8; TRUNCATED_HASHBYTES]>,
    /// Pending events
    events: Vec<LinkEvent>,
    /// Pending RTT packets to send (generated after processing proof)
    pending_rtt_packets: BTreeMap<LinkId, Vec<u8>>,
    /// Pending keepalive packets to send
    pending_keepalive_packets: Vec<(LinkId, Vec<u8>)>,
    /// Pending close packets to send (with packet data)
    pending_close_packets: Vec<(LinkId, Vec<u8>)>,
    /// Pending channel packets to send (link_id, packet_data)
    pending_channel_packets: Vec<(LinkId, Vec<u8>)>,
}

/// State for a pending outgoing link (initiator side, awaiting proof)
struct PendingOutgoing {
    /// When this link request was created
    created_at_ms: u64,
    /// Destination's signing key (from announce) for proof verification
    #[allow(dead_code)]
    dest_signing_key: [u8; 32],
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
            accepting: BTreeSet::new(),
            events: Vec::new(),
            pending_rtt_packets: BTreeMap::new(),
            pending_keepalive_packets: Vec::new(),
            pending_close_packets: Vec::new(),
            pending_channel_packets: Vec::new(),
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
    /// * `ctx` - Platform context for RNG
    pub fn initiate(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASHBYTES],
        dest_signing_key: &[u8; 32],
        ctx: &mut impl Context,
    ) -> (LinkId, Vec<u8>) {
        self.initiate_with_path(dest_hash, dest_signing_key, None, 1, ctx)
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
    /// * `ctx` - Platform context for RNG
    ///
    /// # Example
    /// ```
    /// use reticulum_core::link::LinkManager;
    /// use reticulum_core::traits::{PlatformContext, NoStorage};
    /// use rand_core::OsRng;
    ///
    /// struct SimpleClock;
    /// impl reticulum_core::traits::Clock for SimpleClock {
    ///     fn now_ms(&self) -> u64 { 1000000 }
    /// }
    ///
    /// let mut manager = LinkManager::new();
    /// let mut ctx = PlatformContext { rng: OsRng, clock: SimpleClock, storage: NoStorage };
    ///
    /// // For a destination 2+ hops away, use the transport_id from the announce
    /// let dest_hash = [0x42u8; 16];
    /// let signing_key = [0x33u8; 32];
    /// let transport_id = [0x11u8; 16]; // relay node's identity hash
    /// let hops = 2;
    ///
    /// let (link_id, packet) = manager.initiate_with_path(
    ///     dest_hash,
    ///     &signing_key,
    ///     Some(transport_id),
    ///     hops,
    ///     &mut ctx,
    /// );
    /// assert!(!packet.is_empty());
    /// ```
    pub fn initiate_with_path(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASHBYTES],
        dest_signing_key: &[u8; 32],
        next_hop: Option<[u8; TRUNCATED_HASHBYTES]>,
        hops: u8,
        ctx: &mut impl Context,
    ) -> (LinkId, Vec<u8>) {
        // Create new outgoing link
        let mut link = Link::new_outgoing(dest_hash, ctx);

        // Build the LINK_REQUEST packet with transport headers if needed
        let packet = link.build_link_request_packet_with_transport(next_hop, hops);
        let link_id = *link.id();

        // Set the destination's signing key for proof verification
        let _ = link.set_destination_keys(dest_signing_key);

        // Track as pending
        let now = ctx.clock().now_ms();
        self.pending_outgoing.insert(
            link_id,
            PendingOutgoing {
                created_at_ms: now,
                dest_signing_key: *dest_signing_key,
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
    pub fn register_destination(&mut self, dest_hash: [u8; TRUNCATED_HASHBYTES]) {
        self.accepting.insert(dest_hash);
    }

    /// Unregister a destination from accepting links
    pub fn unregister_destination(&mut self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) {
        self.accepting.remove(dest_hash);
    }

    /// Check if a destination accepts links
    pub fn accepts_links(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> bool {
        self.accepting.contains(dest_hash)
    }

    /// Accept a pending incoming link (after `LinkRequestReceived` event)
    ///
    /// Returns the PROOF packet to send back to the initiator.
    ///
    /// # Arguments
    /// * `link_id` - The link ID from the `LinkRequestReceived` event
    /// * `identity` - The destination's identity (for signing the proof)
    /// * `ctx` - Platform context for clock
    pub fn accept_link(
        &mut self,
        link_id: &LinkId,
        identity: &Identity,
        ctx: &mut impl Context,
    ) -> Result<Vec<u8>, LinkError> {
        let link = self.links.get_mut(link_id).ok_or(LinkError::NotFound)?;

        if link.state() != LinkState::Pending {
            return Err(LinkError::InvalidState);
        }

        if link.is_initiator() {
            return Err(LinkError::InvalidState);
        }

        // Build the proof packet (this also derives the link key)
        let proof_packet = link.build_proof_packet(identity, 500, 1)?;

        // Track as pending incoming (awaiting RTT)
        let now = ctx.clock().now_ms();
        self.pending_incoming.insert(
            *link_id,
            PendingIncoming {
                proof_sent_at_ms: now,
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
    /// * `ctx` - Platform context for RNG
    pub fn send(
        &mut self,
        link_id: &LinkId,
        data: &[u8],
        ctx: &mut impl Context,
    ) -> Result<Vec<u8>, LinkError> {
        let link = self.links.get(link_id).ok_or(LinkError::NotFound)?;

        if link.state() != LinkState::Active {
            return Err(LinkError::InvalidState);
        }

        link.build_data_packet(data, ctx)
    }

    /// Close a link gracefully
    ///
    /// This builds a LINKCLOSE packet that should be sent to the peer.
    /// Call `drain_close_packets()` after this to get the packet to send.
    pub fn close(&mut self, link_id: &LinkId, ctx: &mut impl Context) {
        if let Some(link) = self.links.get_mut(link_id) {
            // Try to build and queue the close packet
            if let Ok(close_packet) = link.build_close_packet(ctx) {
                self.pending_close_packets.push((*link_id, close_packet));
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

    /// Check if a channel exists for a link
    pub fn has_channel(&self, link_id: &LinkId) -> bool {
        self.channels.contains_key(link_id)
    }

    /// Send a channel message on a link
    ///
    /// This creates an envelope, encrypts it, and returns the packet to send.
    ///
    /// # Arguments
    /// * `link_id` - The link to send on
    /// * `message` - The message to send
    /// * `ctx` - Platform context
    ///
    /// # Errors
    /// - `NotFound` if the link doesn't exist or isn't active
    /// - Channel errors (TooLarge, WindowFull, etc.)
    pub fn channel_send<M: Message>(
        &mut self,
        link_id: &LinkId,
        message: &M,
        ctx: &mut impl Context,
    ) -> Result<Vec<u8>, LinkError> {
        // First check if link exists and is active
        let link = self.links.get(link_id).ok_or(LinkError::NotFound)?;
        if link.state() != LinkState::Active {
            return Err(LinkError::InvalidState);
        }

        // Get link MDU and RTT for channel
        let link_mdu = link.mdu();
        let rtt_ms = link.rtt_ms();
        let now_ms = ctx.clock().now_ms();

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
        link.build_data_packet_with_context(&envelope_data, PacketContext::Channel, ctx)
    }

    /// Drain pending channel packets to send
    ///
    /// Returns an iterator over (link_id, packet_data) pairs.
    pub fn drain_channel_packets(&mut self) -> alloc::vec::Drain<'_, (LinkId, Vec<u8>)> {
        self.pending_channel_packets.drain(..)
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
    /// * `ctx` - Platform context
    pub fn process_packet(&mut self, packet: &Packet, raw_packet: &[u8], ctx: &mut impl Context) {
        match packet.flags.packet_type {
            PacketType::LinkRequest => {
                self.handle_link_request(packet, raw_packet, ctx);
            }
            PacketType::Proof => {
                self.handle_proof(packet, ctx);
            }
            PacketType::Data => {
                self.handle_data(packet, ctx);
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
    /// * `now_ms` - Current time in milliseconds
    /// * `ctx` - Context for building keepalive/close packets
    pub fn poll(&mut self, now_ms: u64, ctx: &mut impl Context) {
        self.check_timeouts(now_ms);
        let now_secs = now_ms / MS_PER_SECOND;
        self.check_keepalives(now_secs, ctx);
        self.check_stale_links(now_secs, ctx);
        self.check_channel_timeouts(now_ms, ctx);
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

    /// Take the pending RTT packet for a link (if any)
    ///
    /// After processing a PROOF packet, the initiator needs to send an RTT
    /// packet to complete the handshake. This method returns that packet.
    ///
    /// Returns None if there's no pending RTT packet for this link.
    pub fn take_pending_rtt_packet(&mut self, link_id: &LinkId) -> Option<Vec<u8>> {
        self.pending_rtt_packets.remove(link_id)
    }

    /// Check if there's a pending RTT packet for a link
    pub fn has_pending_rtt_packet(&self, link_id: &LinkId) -> bool {
        self.pending_rtt_packets.contains_key(link_id)
    }

    /// Drain pending keepalive packets to send
    ///
    /// Returns an iterator over (link_id, packet_data) pairs.
    /// Call this after poll() to get keepalive packets that need to be sent.
    pub fn drain_keepalive_packets(&mut self) -> alloc::vec::Drain<'_, (LinkId, Vec<u8>)> {
        self.pending_keepalive_packets.drain(..)
    }

    /// Drain pending close packets to send
    ///
    /// Returns an iterator over (link_id, packet_data) pairs.
    /// Call this after poll() to get close packets that need to be sent.
    pub fn drain_close_packets(&mut self) -> alloc::vec::Drain<'_, (LinkId, Vec<u8>)> {
        self.pending_close_packets.drain(..)
    }

    /// Get a mutable reference to a link
    pub fn link_mut(&mut self, link_id: &LinkId) -> Option<&mut Link> {
        self.links.get_mut(link_id)
    }

    // --- Internal: Packet Handlers ---

    fn handle_link_request(&mut self, packet: &Packet, raw_packet: &[u8], ctx: &mut impl Context) {
        let dest_hash = packet.destination_hash;

        // Check if we accept links for this destination
        if !self.accepting.contains(&dest_hash) {
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
        let Ok(link) = Link::new_incoming(request_data, link_id, dest_hash, ctx) else {
            return;
        };

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

    fn handle_proof(&mut self, packet: &Packet, ctx: &mut impl Context) {
        // PROOF packets are addressed to link_id (not destination hash)
        let link_id = packet.destination_hash;

        // Check if we have a pending outgoing link
        if !self.pending_outgoing.contains_key(&link_id) {
            return;
        }

        let Some(link) = self.links.get_mut(&link_id) else {
            return;
        };

        if link.state() != LinkState::Pending || !link.is_initiator() {
            return;
        }

        // Extract proof data from packet payload (skip context byte handling)
        let proof_data = packet.data.as_slice();

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
        let now_ms = ctx.clock().now_ms();
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
        if let Ok(rtt_packet) = link.build_rtt_packet(rtt_seconds, ctx) {
            // Link is now active (from initiator's perspective)
            self.events.push(LinkEvent::LinkEstablished {
                link_id,
                is_initiator: true,
            });

            // Store RTT packet for caller to retrieve and send
            self.pending_rtt_packets.insert(link_id, rtt_packet);
        }
    }

    fn handle_data(&mut self, packet: &Packet, ctx: &mut impl Context) {
        // DATA packets are addressed to link_id
        let link_id = packet.destination_hash;
        let now_secs = ctx.clock().now_ms() / MS_PER_SECOND;

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

            let encrypted_data = packet.data.as_slice();
            match link.process_keepalive(encrypted_data) {
                Ok(should_echo) => {
                    self.events
                        .push(LinkEvent::KeepaliveReceived { link_id });

                    // If we're responder and received valid keepalive, echo back
                    if should_echo {
                        if let Ok(echo_packet) = link.build_keepalive_packet(ctx) {
                            self.pending_keepalive_packets.push((link_id, echo_packet));
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
                    // In-order message received
                    self.events.push(LinkEvent::ChannelMessageReceived {
                        link_id,
                        msgtype: envelope.msgtype,
                        sequence: envelope.sequence,
                        data: envelope.data,
                    });
                }
                Ok(None) => {
                    // Out-of-order message buffered
                }
                Err(_) => {
                    // Invalid envelope
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
                self.events.push(LinkEvent::DataReceived {
                    link_id,
                    data: plaintext,
                });
            }
            Err(_) => {
                // Decryption failed - could be tampering or wrong link
                // Silently ignore for now
            }
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
            .filter(|(_, entry)| now_ms.saturating_sub(get_timestamp(entry)) > LINK_TIMEOUT_MS)
            .map(|(id, _)| *id)
            .collect()
    }

    // --- Internal: Keepalive Handling ---

    /// Check if any active links need to send keepalives (initiator only)
    fn check_keepalives(&mut self, now_secs: u64, ctx: &mut impl Context) {
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
                if let Ok(packet) = link.build_keepalive_packet(ctx) {
                    link.record_keepalive_sent(now_secs);
                    self.pending_keepalive_packets.push((link_id, packet));
                }
            }
        }
    }

    // --- Internal: Stale Link Handling ---

    /// Check for stale links and close them if timeout expired
    fn check_stale_links(&mut self, now_secs: u64, ctx: &mut impl Context) {
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
                if let Ok(close_packet) = link.build_close_packet(ctx) {
                    self.pending_close_packets.push((link_id, close_packet));
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
    fn check_channel_timeouts(&mut self, now_ms: u64, ctx: &mut impl Context) {
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
                    ChannelAction::Retransmit { sequence: _, data } => {
                        // Build and queue the retransmission packet
                        if let Some(link) = self.links.get(&link_id) {
                            if let Ok(packet) =
                                link.build_data_packet_with_context(&data, PacketContext::Channel, ctx)
                            {
                                self.pending_channel_packets.push((link_id, packet));
                            }
                        }
                    }
                    ChannelAction::TearDownLink => {
                        // Max retries exceeded - close the link
                        if let Some(link) = self.links.get_mut(&link_id) {
                            if let Ok(close_packet) = link.build_close_packet(ctx) {
                                self.pending_close_packets.push((link_id, close_packet));
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
    use crate::traits::{Clock, NoStorage, PlatformContext};
    use rand_core::OsRng;

    struct TestClock {
        time_ms: core::cell::Cell<u64>,
    }

    impl TestClock {
        fn new(time_ms: u64) -> Self {
            Self {
                time_ms: core::cell::Cell::new(time_ms),
            }
        }

        fn advance(&self, ms: u64) {
            self.time_ms.set(self.time_ms.get() + ms);
        }
    }

    impl Clock for TestClock {
        fn now_ms(&self) -> u64 {
            self.time_ms.get()
        }
    }

    fn make_ctx() -> PlatformContext<OsRng, TestClock, NoStorage> {
        PlatformContext {
            rng: OsRng,
            clock: TestClock::new(1_000_000),
            storage: NoStorage,
        }
    }

    #[test]
    fn test_new_manager() {
        let manager = LinkManager::new();
        assert_eq!(manager.active_link_count(), 0);
        assert_eq!(manager.pending_link_count(), 0);
    }

    #[test]
    fn test_register_destination() {
        let mut manager = LinkManager::new();
        let dest_hash = [0x42; 16];

        manager.register_destination(dest_hash);
        assert!(manager.accepts_links(&dest_hash));

        manager.unregister_destination(&dest_hash);
        assert!(!manager.accepts_links(&dest_hash));
    }

    #[test]
    fn test_initiate_link() {
        let mut manager = LinkManager::new();
        let mut ctx = make_ctx();
        let dest_hash = [0x42; 16];
        let dest_signing_key = [0x33; 32];

        let (link_id, packet) = manager.initiate(dest_hash, &dest_signing_key, &mut ctx);

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
        let mut ctx = make_ctx();
        let dest_hash = [0x42; 16];
        let dest_signing_key = [0x33; 32];

        let (link_id, _) = manager.initiate(dest_hash, &dest_signing_key, &mut ctx);
        assert_eq!(manager.pending_link_count(), 1);

        // Advance time past timeout
        ctx.clock.advance(LINK_TIMEOUT_MS + 1);
        manager.poll(ctx.clock.now_ms(), &mut ctx);

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
        let mut ctx = make_ctx();
        let dest_hash = [0x42; 16];
        let dest_signing_key = [0x33; 32];

        let (link_id, _) = manager.initiate(dest_hash, &dest_signing_key, &mut ctx);

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

    #[test]
    fn test_full_handshake() {
        // This test simulates a full handshake between initiator and responder
        let mut initiator_mgr = LinkManager::new();
        let mut responder_mgr = LinkManager::new();

        let mut initiator_ctx = make_ctx();
        let mut responder_ctx = make_ctx();

        let dest_identity = Identity::generate_with_rng(&mut OsRng);
        let dest_hash = [0x42; 16];
        let dest_signing_key = dest_identity.ed25519_verifying().to_bytes();

        // Register destination on responder
        responder_mgr.register_destination(dest_hash);

        // Initiator starts link
        let (link_id, link_request_packet) =
            initiator_mgr.initiate(dest_hash, &dest_signing_key, &mut initiator_ctx);

        // Parse the packet and deliver to responder
        let packet = Packet::unpack(&link_request_packet).unwrap();
        responder_mgr.process_packet(&packet, &link_request_packet, &mut responder_ctx);

        // Responder should have received LinkRequestReceived event
        let events: Vec<_> = responder_mgr.drain_events().collect();
        assert_eq!(events.len(), 1);
        let responder_link_id = match &events[0] {
            LinkEvent::LinkRequestReceived { link_id, .. } => *link_id,
            _ => panic!("Expected LinkRequestReceived event"),
        };

        assert_eq!(responder_link_id, link_id);

        // Responder accepts the link
        let proof_packet = responder_mgr
            .accept_link(&responder_link_id, &dest_identity, &mut responder_ctx)
            .unwrap();

        // Deliver proof to initiator
        let proof = Packet::unpack(&proof_packet).unwrap();
        initiator_mgr.process_packet(&proof, &proof_packet, &mut initiator_ctx);

        // Initiator should have received LinkEstablished event
        let events: Vec<_> = initiator_mgr.drain_events().collect();
        assert_eq!(events.len(), 1);
        match &events[0] {
            LinkEvent::LinkEstablished {
                link_id: id,
                is_initiator,
            } => {
                assert_eq!(id, &link_id);
                assert!(*is_initiator);
            }
            _ => panic!("Expected LinkEstablished event"),
        }

        // Get RTT packet and deliver to responder
        let rtt_packet = initiator_mgr.take_pending_rtt_packet(&link_id).unwrap();
        let rtt = Packet::unpack(&rtt_packet).unwrap();
        responder_mgr.process_packet(&rtt, &rtt_packet, &mut responder_ctx);

        // Responder should have received LinkEstablished event
        let events: Vec<_> = responder_mgr.drain_events().collect();
        assert_eq!(events.len(), 1);
        match &events[0] {
            LinkEvent::LinkEstablished {
                link_id: id,
                is_initiator,
            } => {
                assert_eq!(id, &responder_link_id);
                assert!(!*is_initiator);
            }
            _ => panic!("Expected LinkEstablished event"),
        }

        // Both sides should now be active
        assert!(initiator_mgr.is_active(&link_id));
        assert!(responder_mgr.is_active(&responder_link_id));
    }
}
