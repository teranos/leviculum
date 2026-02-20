//! Link management methods for NodeCore
//!
//! This module contains all link-related methods on [`NodeCore`]:
//! connection establishment, acceptance, data transfer, packet routing,
//! and internal link packet processing (handshake, data, timeouts).

use alloc::vec::Vec;

use crate::constants::{
    DATA_RECEIPT_TIMEOUT_MS, LINK_PENDING_TIMEOUT_MS, MODE_AES256_CBC, MS_PER_SECOND,
    PROOF_DATA_SIZE, TRUNCATED_HASHBYTES,
};
use crate::destination::{DestinationHash, ProofStrategy};
use crate::hex_fmt::{HexFmt, HexShort};
use crate::link::channel::{ChannelAction, ChannelError, Message};
use crate::link::{Link, LinkCloseReason, LinkError, LinkId, LinkPhase, LinkState, PeerKeys};
use crate::packet::{packet_hash, Packet, PacketContext, PacketType};
use crate::traits::{Clock, Storage};
use rand_core::CryptoRngCore;

use super::event::NodeEvent;
use super::send;
use super::{LinkStats, NodeCore};

/// Simple message type for sending raw bytes over a channel
struct RawBytesMessage<'a>(&'a [u8]);

impl Message for RawBytesMessage<'_> {
    const MSGTYPE: u16 = 0x0000;

    fn pack(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
        let _ = data;
        Err(ChannelError::EnvelopeTruncated)
    }
}

/// Tracks channel message receipts awaiting delivery proofs.
///
/// Each entry records a sent channel message: its packet hashes, link, sequence
/// number, and timestamp. A single `Vec<ReceiptEntry>` replaces the three
/// separate maps that previously encoded this relationship in different
/// directions (`data_receipts`, `channel_receipt_keys`, `channel_hash_to_seq`).
///
/// Every datum exists exactly once. Lookups are linear scans — n is bounded
/// by channel window size × active links (realistically < 100, typically < 20).
pub(super) struct ReceiptTracker {
    entries: Vec<ReceiptEntry>,
}

pub(super) struct ReceiptEntry {
    pub(super) truncated_hash: [u8; TRUNCATED_HASHBYTES],
    pub(super) full_hash: [u8; 32],
    pub(super) link_id: LinkId,
    pub(super) sequence: u16,
    pub(super) sent_at_ms: u64,
}

impl ReceiptTracker {
    pub(super) fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register a receipt for a channel message, replacing any existing entry
    /// for the same `(link_id, sequence)`.
    pub(super) fn register(
        &mut self,
        packet_data: &[u8],
        link_id: LinkId,
        sequence: u16,
        now_ms: u64,
    ) {
        self.entries
            .retain(|e| !(e.link_id == link_id && e.sequence == sequence));

        let full_hash = packet_hash(packet_data);
        let mut truncated_hash = [0u8; TRUNCATED_HASHBYTES];
        truncated_hash.copy_from_slice(&full_hash[..TRUNCATED_HASHBYTES]);

        tracing::debug!(
            hash = %HexFmt(&full_hash),
            truncated = %HexFmt(&truncated_hash),
            link = %HexFmt(link_id.as_bytes()),
            "link_mgr: registered channel receipt"
        );

        self.entries.push(ReceiptEntry {
            truncated_hash,
            full_hash,
            link_id,
            sequence,
            sent_at_ms: now_ms,
        });
    }

    /// Look up a receipt by truncated hash. Returns `(link_id, full_hash)`.
    pub(super) fn lookup_receipt(
        &self,
        truncated: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<(LinkId, [u8; 32])> {
        self.entries
            .iter()
            .find(|e| e.truncated_hash == *truncated)
            .map(|e| (e.link_id, e.full_hash))
    }

    /// Remove the entry matching `truncated_hash` and return its sequence number.
    pub(super) fn confirm_delivery(
        &mut self,
        truncated: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<u16> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.truncated_hash == *truncated)?;
        let entry = self.entries.swap_remove(idx);
        Some(entry.sequence)
    }

    /// Remove all entries for a given link.
    pub(super) fn remove_for_link(&mut self, link_id: &LinkId) {
        self.entries.retain(|e| e.link_id != *link_id);
    }

    /// Remove entries older than `DATA_RECEIPT_TIMEOUT_MS`.
    pub(super) fn expire(&mut self, now_ms: u64) {
        self.entries
            .retain(|e| now_ms.saturating_sub(e.sent_at_ms) <= DATA_RECEIPT_TIMEOUT_MS);
    }

    /// Number of tracked receipts.
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Earliest expiry deadline across all entries, if any.
    pub(super) fn earliest_expiry(&self) -> Option<u64> {
        self.entries
            .iter()
            .map(|e| e.sent_at_ms.saturating_add(DATA_RECEIPT_TIMEOUT_MS))
            .min()
    }

    #[cfg(test)]
    pub(crate) fn count_for_link(&self, link_id: &LinkId) -> usize {
        self.entries
            .iter()
            .filter(|e| e.link_id == *link_id)
            .count()
    }

    #[cfg(test)]
    pub(crate) fn contains_truncated(&self, truncated: &[u8; TRUNCATED_HASHBYTES]) -> bool {
        self.entries.iter().any(|e| e.truncated_hash == *truncated)
    }
}

impl<R: CryptoRngCore, C: Clock, S: Storage> NodeCore<R, C, S> {
    // ─── Link Management (Public API) ─────────────────────────────────────────

    /// Initiate a link to a destination
    ///
    /// # Arguments
    /// * `dest_hash` - The destination to connect to
    /// * `dest_signing_key` - The destination's signing key (from announce)
    ///
    /// # Returns
    /// A tuple of `(LinkId, was_routed, TickOutput)`:
    /// - `was_routed`: `true` if the link request was sent via a known path,
    ///   `false` if it was broadcast (no path existed).
    pub fn connect(
        &mut self,
        dest_hash: DestinationHash,
        dest_signing_key: &[u8; 32],
    ) -> (LinkId, bool, crate::transport::TickOutput) {
        // Check if we have path info for this destination
        let (next_hop, hops) = if let Some(path) = self.transport.path(dest_hash.as_bytes()) {
            if path.needs_relay() {
                (path.next_hop, path.hops)
            } else {
                (None, path.hops)
            }
        } else {
            (None, 1)
        };

        let now_ms = self.transport.clock().now_ms();

        // Look up HW_MTU for next-hop interface (for link MTU negotiation)
        let hw_mtu = self
            .transport
            .next_hop_interface_hw_mtu(dest_hash.as_bytes());

        // Create new outgoing link
        let mut link = Link::new_outgoing(dest_hash, &mut self.rng);
        let packet = link.build_link_request_packet_with_transport(next_hop, hops, hw_mtu);
        let link_id = *link.id();
        if let Err(e) = link.set_destination_keys(dest_signing_key) {
            tracing::debug!(%e, "set_destination_keys failed");
        }
        link.set_phase(LinkPhase::PendingOutgoing {
            created_at_ms: now_ms,
        });
        self.links.insert(link_id, link);

        // Route through transport: path lookup first, broadcast if no path
        let was_routed = self
            .transport
            .send_to_destination(dest_hash.as_bytes(), &packet)
            .is_ok();
        if !was_routed {
            self.transport.send_on_all_interfaces(&packet);
        }

        let output = self.process_events_and_actions();
        (link_id, was_routed, output)
    }

    /// Accept an incoming link request
    ///
    /// Looks up the destination's identity from the registered destination
    /// matching the link's destination hash.
    ///
    /// # Errors
    /// - `LinkError::NotFound` if the link does not exist
    /// - `LinkError::DestinationNotRegistered` if no identity available
    pub fn accept_link(
        &mut self,
        link_id: &LinkId,
    ) -> Result<crate::transport::TickOutput, LinkError> {
        let dest_hash = self
            .links
            .get(link_id)
            .map(|l| *l.destination_hash())
            .ok_or(LinkError::NotFound)?;

        let dest = self
            .destinations
            .get(&dest_hash)
            .ok_or(LinkError::DestinationNotRegistered)?;
        let identity = dest.identity().ok_or(LinkError::DestinationNotRegistered)?;
        let proof_strategy = dest.proof_strategy();

        let now_ms = self.transport.clock().now_ms();

        let link = self.links.get_mut(link_id).ok_or(LinkError::NotFound)?;
        if link.state() != LinkState::Pending {
            return Err(LinkError::InvalidState);
        }
        if link.is_initiator() {
            return Err(LinkError::InvalidState);
        }
        link.set_proof_strategy(proof_strategy);
        if let Some(sk) = identity.ed25519_signing_key() {
            link.set_dest_signing_key(sk.clone());
        }
        let proof_mtu = link.negotiated_mtu();
        let proof = link.build_proof_packet(identity, proof_mtu, MODE_AES256_CBC)?;
        link.set_phase(LinkPhase::PendingIncoming {
            proof_sent_at_ms: now_ms,
        });

        // Route proof on attached interface (matching Python Link.prove())
        let attached = self.links.get(link_id).and_then(|l| l.attached_interface());
        debug_assert!(
            attached.is_some(),
            "accept_link: link {:?} has no attached_interface",
            link_id
        );
        if let Some(iface_idx) = attached {
            if let Err(e) = self.transport.send_on_interface(iface_idx, &proof) {
                tracing::debug!(%e, "send_on_interface failed");
            }
        } else {
            self.transport.send_on_all_interfaces(&proof);
        }

        Ok(self.process_events_and_actions())
    }

    /// Reject an incoming link request
    pub fn reject_link(&mut self, link_id: &LinkId) {
        self.links.remove(link_id);
    }

    /// Close a link gracefully
    pub fn close_link(&mut self, link_id: &LinkId) -> crate::transport::TickOutput {
        if let Some(link) = self.links.get_mut(link_id) {
            let is_initiator = link.is_initiator();
            let destination_hash = *link.destination_hash();
            // Build and route close packet BEFORE removing the link
            if let Ok(close_packet) = link.build_close_packet(&mut self.rng) {
                link.close();
                // Route via attached interface while link is still in map
                self.route_link_packet(link_id, &close_packet);
            } else {
                link.close();
            }
            self.links.remove(link_id);
            self.emit_link_closed(
                *link_id,
                LinkCloseReason::Normal,
                is_initiator,
                destination_hash,
            );
        }
        self.process_events_and_actions()
    }

    /// Get a link by ID
    pub fn link(&self, link_id: &LinkId) -> Option<&crate::link::Link> {
        self.links.get(link_id)
    }

    /// Get a mutable reference to a link by ID
    pub fn link_mut(&mut self, link_id: &LinkId) -> Option<&mut crate::link::Link> {
        self.links.get_mut(link_id)
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

    // ─── Link Data Transfer ───────────────────────────────────────────────────

    /// Send data on an existing link via Channel (reliable, ordered)
    pub fn send_on_link(
        &mut self,
        link_id: &LinkId,
        data: &[u8],
    ) -> Result<crate::transport::TickOutput, send::SendError> {
        let link = self.links.get(link_id).ok_or(send::SendError::NoLink)?;

        let attached_iface = link.attached_interface();
        let dest_hash = *link.destination_hash();

        let now_ms = self.transport.clock().now_ms();

        let link = self.links.get_mut(link_id).ok_or(send::SendError::NoLink)?;
        if link.state() != LinkState::Active {
            return Err(send::SendError::LinkFailed);
        }
        let link_mdu = link.mdu();
        let rtt_ms = link.rtt_ms();
        let envelope_data = {
            let channel = link.ensure_channel(rtt_ms);
            channel
                .send(&RawBytesMessage(data), link_mdu, now_ms, rtt_ms)
                .map_err(|e| match e {
                    ChannelError::WindowFull => send::SendError::WindowFull,
                    ChannelError::PacingDelay { ready_at_ms } => {
                        send::SendError::PacingDelay { ready_at_ms }
                    }
                    _ => send::SendError::LinkFailed,
                })?
        };
        let packet_bytes = link
            .build_data_packet_with_context(&envelope_data, PacketContext::Channel, &mut self.rng)
            .map_err(|_| send::SendError::LinkFailed)?;

        // Register receipt for channel delivery tracking (Python Channel.py:606)
        if let Some(seq) = self
            .links
            .get(link_id)
            .and_then(|l| l.channel())
            .map(|ch| ch.last_sent_sequence())
        {
            self.receipt_tracker
                .register(&packet_bytes, *link_id, seq, now_ms);
        }

        // Route via attached interface
        if let Some(iface_idx) = attached_iface {
            if let Err(e) = self.transport.send_on_interface(iface_idx, &packet_bytes) {
                tracing::debug!(%e, "send_on_interface failed");
            }
        } else if let Err(e) = self
            .transport
            .send_to_destination(dest_hash.as_bytes(), &packet_bytes)
        {
            tracing::warn!(%e, "send_to_destination failed — packet lost");
        }

        Ok(self.process_events_and_actions())
    }

    /// Find an existing active link to a destination
    #[cfg(test)]
    pub(crate) fn find_link_to(&self, dest_hash: &DestinationHash) -> Option<LinkId> {
        self.links
            .iter()
            .find(|(_, link)| {
                link.state() == LinkState::Active && link.destination_hash() == dest_hash
            })
            .map(|(id, _)| *id)
    }

    /// Get link statistics
    pub fn link_stats(&self, link_id: &LinkId) -> Option<LinkStats> {
        self.links.get(link_id)?;
        let ch = self.links.get(link_id).and_then(|l| l.channel());
        Some(LinkStats::new(
            ch.map(|c| c.outstanding()).unwrap_or(0),
            ch.map(|c| c.window()).unwrap_or(0),
            ch.map(|c| c.window_max()).unwrap_or(0),
            ch.map(|c| c.pacing_interval_ms()).unwrap_or(0),
        ))
    }

    // ─── Internal: Link Packet Processing ─────────────────────────────────────

    /// Process an incoming link-related packet
    pub(super) fn process_link_packet(
        &mut self,
        packet: &Packet,
        raw_packet: &[u8],
        now_ms: u64,
        interface_index: usize,
    ) {
        match packet.flags.packet_type {
            PacketType::LinkRequest => {
                self.handle_link_request(packet, raw_packet, interface_index);
            }
            PacketType::Proof => {
                self.handle_link_proof(packet, now_ms, interface_index);
            }
            PacketType::Data => {
                self.handle_link_data(packet, raw_packet, now_ms);
            }
            PacketType::Announce => {
                // Announces are not link packets, ignore
            }
        }
    }

    /// Handle an incoming LINK_REQUEST packet
    fn handle_link_request(&mut self, packet: &Packet, raw_packet: &[u8], interface_index: usize) {
        let dest_hash = DestinationHash::new(packet.destination_hash);

        // Check if we accept links for this destination (consolidated with self.destinations)
        let accepts = self
            .destinations
            .get(&dest_hash)
            .map(|d| d.accepts_links())
            .unwrap_or(false);
        if !accepts {
            tracing::trace!(
                dest = %HexShort(dest_hash.as_bytes()),
                "Link request ignored, destination does not accept links"
            );
            return;
        }

        // Calculate link ID from raw packet
        let link_id = Link::calculate_link_id(raw_packet);

        // Check if we already have this link
        if self.links.contains_key(&link_id) {
            tracing::trace!(
                link = %HexShort(link_id.as_bytes()),
                "Link request ignored, link already exists"
            );
            return;
        }

        // Extract request data from packet payload
        let request_data = packet.data.as_slice();

        // Create the incoming link
        let iface_hw_mtu = self.transport.interface_hw_mtu(interface_index);
        let Ok(mut link) = Link::new_incoming(
            request_data,
            link_id,
            dest_hash,
            &mut self.rng,
            iface_hw_mtu,
        ) else {
            tracing::warn!(
                link = %HexShort(link_id.as_bytes()),
                "Dropped malformed link request, failed to parse"
            );
            return;
        };

        // Set attached interface from the receiving interface
        link.set_attached_interface(interface_index);

        // Extract peer keys for the event
        let peer_keys = PeerKeys {
            x25519_public: request_data[..32].try_into().unwrap_or([0; 32]),
            ed25519_verifying: request_data[32..64].try_into().unwrap_or([0; 32]),
        };

        // Store the link
        self.links.insert(link_id, link);

        tracing::debug!(
            "Incoming link request <{}> for <{}> accepted on {}",
            HexShort(link_id.as_bytes()),
            HexShort(dest_hash.as_bytes()),
            self.transport.iface_name(interface_index)
        );

        // Emit event directly as NodeEvent
        self.events.push(NodeEvent::LinkRequest {
            link_id,
            destination_hash: dest_hash,
            peer_keys,
        });
    }

    /// Handle an incoming PROOF packet (link establishment or data proof)
    fn handle_link_proof(&mut self, packet: &Packet, now_ms: u64, interface_index: usize) {
        let link_id = LinkId::new(packet.destination_hash);
        let proof_data = packet.data.as_slice();

        // Check if this is a data proof (not a link establishment proof)
        if proof_data.len() == PROOF_DATA_SIZE && packet.context == PacketContext::None {
            self.handle_data_proof(&link_id, proof_data);
            return;
        }

        let Some(link) = self.links.get_mut(&link_id) else {
            tracing::trace!(
                link = %HexShort(link_id.as_bytes()),
                "Link proof for unknown link, ignoring"
            );
            return;
        };

        // Must be a pending outgoing link
        if !matches!(link.phase(), LinkPhase::PendingOutgoing { .. }) {
            tracing::trace!(
                link = %HexShort(link_id.as_bytes()),
                "Link proof for non-pending link, ignoring"
            );
            return;
        }
        if link.state() != LinkState::Pending || !link.is_initiator() {
            return;
        }

        // Set attached interface from the interface the proof arrived on
        link.set_attached_interface(interface_index);

        // Process the proof
        if link.process_proof(proof_data).is_err() {
            tracing::debug!(
                "Link proof for <{}> is invalid, closing link",
                HexShort(link_id.as_bytes())
            );
            let is_initiator = link.is_initiator();
            let destination_hash = *link.destination_hash();
            self.links.remove(&link_id);
            self.emit_link_closed(
                link_id,
                LinkCloseReason::InvalidProof,
                is_initiator,
                destination_hash,
            );
            return;
        }

        // Proof verified! Calculate RTT and transition to established
        let now_secs = now_ms / MS_PER_SECOND;
        let rtt_ms = match link.phase() {
            LinkPhase::PendingOutgoing { created_at_ms } => now_ms.saturating_sub(created_at_ms),
            _ => 0,
        };
        link.set_phase(LinkPhase::Established);
        let rtt_seconds = rtt_ms as f64 / MS_PER_SECOND as f64;

        link.update_keepalive_from_rtt(rtt_seconds);
        link.mark_established(now_secs);

        tracing::debug!(
            "Link <{}> established with RTT {}ms",
            HexShort(link_id.as_bytes()),
            rtt_ms
        );

        // Build RTT packet and route via attached interface
        if let Ok(rtt_packet) = link.build_rtt_packet(rtt_seconds, &mut self.rng) {
            self.events.push(NodeEvent::LinkEstablished {
                link_id,
                is_initiator: true,
            });

            // Route RTT packet via attached interface
            self.route_link_packet(&link_id, &rtt_packet);
        }
    }

    /// Handle a data proof packet (PROVE_ALL response)
    fn handle_data_proof(&mut self, link_id: &LinkId, proof_data: &[u8]) {
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

        let mut truncated = [0u8; TRUNCATED_HASHBYTES];
        truncated.copy_from_slice(&proof_hash[..TRUNCATED_HASHBYTES]);
        tracing::debug!(
            proof_hash = %HexFmt(&proof_hash),
            truncated = %HexFmt(&truncated),
            link = %HexFmt(link_id.as_bytes()),
            receipts = self.receipt_tracker.len(),
            "link_mgr: data proof received"
        );

        // Look up receipt
        let Some((receipt_link_id, receipt_full_hash)) =
            self.receipt_tracker.lookup_receipt(&truncated)
        else {
            tracing::debug!(
                receipts = self.receipt_tracker.len(),
                "link_mgr: data proof — no matching receipt"
            );
            return;
        };

        if receipt_link_id != *link_id {
            tracing::debug!("link_mgr: data proof — link_id mismatch");
            return;
        }

        // Validate the proof using the link
        let is_valid = self
            .links
            .get(link_id)
            .map(|l| l.validate_data_proof(proof_data, &receipt_full_hash))
            .unwrap_or(false);

        if is_valid {
            // confirm_delivery removes the entry entirely (fixes orphan path #1).
            // Event only fires when the receipt still exists — a valid proof for
            // an already-expired/removed receipt is silently dropped.
            if let Some(sequence) = self.receipt_tracker.confirm_delivery(&truncated) {
                tracing::debug!(
                    receipts = self.receipt_tracker.len(),
                    "link_mgr: data proof validated — delivered"
                );

                let now_ms = self.transport.clock().now_ms();
                let rtt_ms = self.links.get(link_id).map(|l| l.rtt_ms()).unwrap_or(500);
                if let Some(link) = self.links.get_mut(link_id) {
                    if let Some(ch) = link.channel_mut() {
                        ch.mark_delivered(sequence, now_ms, rtt_ms);
                    }
                }

                self.events.push(NodeEvent::LinkDeliveryConfirmed {
                    link_id: *link_id,
                    packet_hash: receipt_full_hash,
                });
            }
        } else {
            tracing::debug!("link_mgr: data proof — signature validation failed");
        }
    }

    /// Handle an incoming DATA packet on a link.
    ///
    /// Dispatches to per-context handlers after stale-link recovery.
    fn handle_link_data(&mut self, packet: &Packet, raw_packet: &[u8], now_ms: u64) {
        let link_id = LinkId::new(packet.destination_hash);
        let now_secs = now_ms / MS_PER_SECOND;

        // Recover stale links on any inbound traffic (Python Link.py:987-988)
        self.try_recover_stale(&link_id, now_secs);

        if !self.links.contains_key(&link_id) {
            tracing::trace!(
                link = %HexShort(link_id.as_bytes()),
                "Link data packet for unknown link, ignoring"
            );
            return;
        }

        match packet.context {
            PacketContext::Lrrtt => self.handle_rtt_packet(link_id, packet, now_secs),
            PacketContext::Keepalive => self.handle_keepalive_packet(link_id, packet, now_secs),
            PacketContext::LinkClose => self.handle_close_packet(link_id, packet),
            PacketContext::Channel => {
                self.handle_channel_packet(link_id, packet, raw_packet, now_ms, now_secs)
            }
            _ => self.handle_plain_data_packet(link_id, packet, raw_packet, now_secs),
        }
    }

    /// RTT packet (context = Lrrtt) — responder side
    fn handle_rtt_packet(&mut self, link_id: LinkId, packet: &Packet, now_secs: u64) {
        let Some(link) = self.links.get_mut(&link_id) else {
            return;
        };
        if link.state() != LinkState::Handshake || link.is_initiator() {
            return;
        }
        let encrypted_data = packet.data.as_slice();
        if let Ok(rtt_secs) = link.process_rtt(encrypted_data) {
            link.update_keepalive_from_rtt(rtt_secs);
            link.mark_established(now_secs);
            link.set_phase(LinkPhase::Established);
            tracing::debug!(
                "Link <{}> established (responder), RTT {:.3}s",
                HexShort(link_id.as_bytes()),
                rtt_secs
            );
            self.events.push(NodeEvent::LinkEstablished {
                link_id,
                is_initiator: false,
            });
        }
    }

    /// Keepalive packet — record activity and echo if requested
    fn handle_keepalive_packet(&mut self, link_id: LinkId, packet: &Packet, now_secs: u64) {
        let Some(link) = self.links.get_mut(&link_id) else {
            return;
        };
        link.record_inbound(now_secs);
        let data = packet.data.as_slice();
        if let Ok(should_echo) = link.process_keepalive(data) {
            if should_echo {
                if let Ok(echo_packet) = link.build_keepalive_packet() {
                    self.route_link_packet(&link_id, &echo_packet);
                }
            }
        }
    }

    /// Link close packet — verify and tear down the link
    fn handle_close_packet(&mut self, link_id: LinkId, packet: &Packet) {
        let Some(link) = self.links.get_mut(&link_id) else {
            return;
        };
        let encrypted_data = packet.data.as_slice();
        if link.process_close(encrypted_data).is_ok() {
            tracing::debug!("Link <{}> closed by peer", HexShort(link_id.as_bytes()));
            let is_initiator = link.is_initiator();
            let destination_hash = *link.destination_hash();
            self.links.remove(&link_id);
            self.emit_link_closed(
                link_id,
                LinkCloseReason::PeerClosed,
                is_initiator,
                destination_hash,
            );
        }
    }

    /// Channel packet — decrypt, process through channel, build proof
    fn handle_channel_packet(
        &mut self,
        link_id: LinkId,
        packet: &Packet,
        raw_packet: &[u8],
        now_ms: u64,
        now_secs: u64,
    ) {
        let Some(link) = self.links.get_mut(&link_id) else {
            tracing::trace!(
                link = %HexShort(link_id.as_bytes()),
                "Channel packet for unknown link, ignoring"
            );
            return;
        };
        if link.state() != LinkState::Active {
            tracing::trace!(
                link = %HexShort(link_id.as_bytes()),
                "Channel packet for non-active link, ignoring"
            );
            return;
        }

        link.record_inbound(now_secs);

        // 1. Decrypt the envelope data
        let encrypted_data = packet.data.as_slice();
        let max_plaintext_len = encrypted_data.len();
        let mut plaintext = alloc::vec![0u8; max_plaintext_len];
        let decrypted_len = match link.decrypt(encrypted_data, &mut plaintext) {
            Ok(len) => len,
            Err(_) => {
                tracing::debug!(
                    link = %HexShort(link_id.as_bytes()),
                    "Channel packet decryption failed"
                );
                return;
            }
        };
        plaintext.truncate(decrypted_len);

        // 2. Channel receive + drain + proof — link borrow scoped in this block
        // so that route_link_packet (which needs &mut self) can run afterward.
        let mut rx_ring_full = false;
        let proof_packet = {
            let rtt_ms = link.rtt_ms();
            let channel = link.ensure_channel(rtt_ms);

            let message_accepted = match channel.receive(&plaintext) {
                Ok(Some(envelope)) => {
                    tracing::debug!(
                        seq = envelope.sequence,
                        msgtype = envelope.msgtype,
                        len = envelope.data.len(),
                        "link_mgr: channel message received (in-order)"
                    );
                    self.events.push(NodeEvent::MessageReceived {
                        link_id,
                        msgtype: envelope.msgtype,
                        sequence: envelope.sequence,
                        data: envelope.data,
                    });
                    true
                }
                Ok(None) => {
                    tracing::debug!("link_mgr: channel message buffered (out-of-order)");
                    true
                }
                Err(ChannelError::RxRingFull) => {
                    rx_ring_full = true;
                    false
                }
                Err(e) => {
                    tracing::debug!(?e, "link_mgr: channel receive failed");
                    false
                }
            };

            // Drain any buffered messages that are now ready
            let drained: Vec<_> = link
                .channel_mut()
                .map(|ch| ch.drain_received())
                .unwrap_or_default();
            for envelope in drained {
                self.events.push(NodeEvent::MessageReceived {
                    link_id,
                    msgtype: envelope.msgtype,
                    sequence: envelope.sequence,
                    data: envelope.data,
                });
            }

            // 3. Build proof while link borrow is still held
            if message_accepted {
                Self::build_channel_proof(link, &link_id, raw_packet)
            } else {
                None
            }
        };

        // 4. Post-processing (link borrow released)
        if rx_ring_full {
            self.update_rx_ring_full(now_ms);
        }
        if let Some(proof) = proof_packet {
            self.route_link_packet(&link_id, &proof);
        }
    }

    /// Build a data proof for an accepted channel message.
    ///
    /// This is an associated function (not `&self`) to avoid borrow conflicts —
    /// the caller holds `link` via `self.links.get_mut()`.
    fn build_channel_proof(link: &Link, link_id: &LinkId, raw_packet: &[u8]) -> Option<Vec<u8>> {
        let full_packet_hash = packet_hash(raw_packet);
        if let Some(signing_key) = link.proof_signing_key() {
            match link.build_data_proof_packet_with_signing_key(&full_packet_hash, signing_key) {
                Ok(proof) => {
                    tracing::debug!(
                        hash = %HexFmt(&full_packet_hash),
                        link = %HexFmt(link_id.as_bytes()),
                        proof_len = proof.len(),
                        "link_mgr: channel proof generated"
                    );
                    Some(proof)
                }
                Err(e) => {
                    tracing::warn!(
                        hash = %HexFmt(&full_packet_hash),
                        link = %HexFmt(link_id.as_bytes()),
                        error = %e,
                        "link_mgr: channel proof build failed"
                    );
                    None
                }
            }
        } else {
            tracing::warn!(
                link = %HexFmt(link_id.as_bytes()),
                "link_mgr: channel proof skipped — no signing key"
            );
            None
        }
    }

    /// Update rx_ring overflow counter with rate-limited warning.
    fn update_rx_ring_full(&mut self, now_ms: u64) {
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
    }

    /// Regular data packet — decrypt, handle proof strategy, emit data event
    fn handle_plain_data_packet(
        &mut self,
        link_id: LinkId,
        packet: &Packet,
        raw_packet: &[u8],
        now_secs: u64,
    ) {
        let Some(link) = self.links.get_mut(&link_id) else {
            tracing::trace!(
                link = %HexShort(link_id.as_bytes()),
                "Data packet for unknown link, ignoring"
            );
            return;
        };
        if link.state() != LinkState::Active {
            tracing::trace!(
                link = %HexShort(link_id.as_bytes()),
                "Data packet for non-active link, ignoring"
            );
            return;
        }

        link.record_inbound(now_secs);

        let encrypted_data = packet.data.as_slice();
        let max_plaintext_len = encrypted_data.len();
        let mut plaintext = alloc::vec![0u8; max_plaintext_len];

        match link.decrypt(encrypted_data, &mut plaintext) {
            Ok(len) => {
                plaintext.truncate(len);

                let full_packet_hash = packet_hash(raw_packet);

                match link.proof_strategy() {
                    ProofStrategy::All => {
                        if let Some(signing_key) = link.proof_signing_key() {
                            if let Ok(proof_packet) = link.build_data_proof_packet_with_signing_key(
                                &full_packet_hash,
                                signing_key,
                            ) {
                                self.route_link_packet(&link_id, &proof_packet);
                            }
                        }
                    }
                    ProofStrategy::App => {
                        self.events.push(NodeEvent::LinkProofRequested {
                            link_id,
                            packet_hash: full_packet_hash,
                        });
                    }
                    ProofStrategy::None => {}
                }

                self.events.push(NodeEvent::LinkDataReceived {
                    link_id,
                    data: plaintext,
                });
            }
            Err(_) => {
                tracing::debug!(
                    link = %HexShort(link_id.as_bytes()),
                    "Plain data packet decryption failed"
                );
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
                .push(NodeEvent::LinkRecovered { link_id: *link_id });
            tracing::debug!(link = %HexFmt(link_id.as_bytes()), "link_mgr: recovered from stale");
            true
        } else {
            false
        }
    }

    // ─── Internal: Timeout / Polling ──────────────────────────────────────────

    /// Check for handshake timeouts on pending links
    pub(super) fn check_timeouts(&mut self, now_ms: u64) {
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
            tracing::debug!(
                "Link <{}> establishment timed out",
                HexShort(link_id.as_bytes())
            );
            let (is_initiator, destination_hash) = self
                .links
                .get(&link_id)
                .map(|l| (l.is_initiator(), *l.destination_hash()))
                .unwrap_or((false, DestinationHash::new([0; 16])));
            self.links.remove(&link_id);
            self.emit_link_closed(
                link_id,
                LinkCloseReason::Timeout,
                is_initiator,
                destination_hash,
            );
        }

        // Clean up expired receipts
        self.receipt_tracker.expire(now_ms);
    }

    /// Check if any active links need to send keepalives (initiator only)
    pub(super) fn check_keepalives(&mut self, now_secs: u64) {
        let need_keepalive: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(_, link)| link.is_initiator() && link.should_send_keepalive(now_secs))
            .map(|(id, _)| *id)
            .collect();

        for link_id in need_keepalive {
            if let Some(link) = self.links.get_mut(&link_id) {
                if let Ok(packet) = link.build_keepalive_packet() {
                    tracing::trace!("Sent keepalive on link <{}>", HexShort(link_id.as_bytes()));
                    link.record_keepalive_sent(now_secs);
                    self.route_link_packet(&link_id, &packet);
                }
            }
        }
    }

    /// Check for stale links and close them if timeout expired
    pub(super) fn check_stale_links(&mut self, now_secs: u64) {
        // First pass: Find links that are active but should become stale
        let newly_stale: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(_, link)| link.state() == LinkState::Active && link.is_stale(now_secs))
            .map(|(id, _)| *id)
            .collect();

        for link_id in newly_stale {
            if let Some(link) = self.links.get_mut(&link_id) {
                tracing::debug!(
                    "Link <{}> marked stale, no activity",
                    HexShort(link_id.as_bytes())
                );
                link.set_state(LinkState::Stale);
                self.events.push(NodeEvent::LinkStale { link_id });
            }
        }

        // Second pass: Find stale links that should be closed
        let should_close: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(_, link)| link.state() == LinkState::Stale && link.should_close(now_secs))
            .map(|(id, _)| *id)
            .collect();

        for link_id in should_close {
            // Extract all data from link, build close packet, then drop borrow
            let close_info = if let Some(link) = self.links.get_mut(&link_id) {
                let is_initiator = link.is_initiator();
                let destination_hash = *link.destination_hash();
                let close_packet = link.build_close_packet(&mut self.rng).ok();
                link.close();
                Some((is_initiator, destination_hash, close_packet))
            } else {
                None
            };
            // link borrow dropped here

            if let Some((is_initiator, destination_hash, close_packet)) = close_info {
                tracing::debug!("Closing stale link <{}>", HexShort(link_id.as_bytes()));
                // Route close packet BEFORE removing link from map
                if let Some(ref pkt) = close_packet {
                    self.route_link_packet(&link_id, pkt);
                }
                self.links.remove(&link_id);
                self.emit_link_closed(
                    link_id,
                    LinkCloseReason::Stale,
                    is_initiator,
                    destination_hash,
                );
            }
        }
    }

    /// Check for channel envelope timeouts and queue retransmissions
    pub(super) fn check_channel_timeouts(&mut self, now_ms: u64) {
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
                        // Build retransmission packet
                        let packet = if let Some(link) = self.links.get(&link_id) {
                            link.build_data_packet_with_context(
                                &data,
                                PacketContext::Channel,
                                &mut self.rng,
                            )
                            .ok()
                        } else {
                            None
                        };
                        // link borrow released here

                        if let Some(packet) = packet {
                            // Register receipt for the re-encrypted packet
                            self.receipt_tracker
                                .register(&packet, link_id, sequence, now_ms);

                            self.events.push(NodeEvent::ChannelRetransmit {
                                link_id,
                                sequence,
                                tries,
                            });

                            // Route directly via transport
                            self.route_link_packet(&link_id, &packet);
                        }
                    }
                    ChannelAction::TearDownLink => {
                        tracing::debug!("link_mgr: channel teardown — closing link");
                        let (is_initiator, destination_hash) = self
                            .links
                            .get(&link_id)
                            .map(|l| (l.is_initiator(), *l.destination_hash()))
                            .unwrap_or((false, DestinationHash::new([0; 16])));

                        // Build and route close packet BEFORE removing link
                        let close_packet = if let Some(link) = self.links.get_mut(&link_id) {
                            let pkt = link.build_close_packet(&mut self.rng).ok();
                            link.close();
                            pkt
                        } else {
                            None
                        };
                        if let Some(ref pkt) = close_packet {
                            self.route_link_packet(&link_id, pkt);
                        }

                        self.links.remove(&link_id);
                        self.emit_link_closed(
                            link_id,
                            LinkCloseReason::ChannelExhausted,
                            is_initiator,
                            destination_hash,
                        );
                    }
                }
            }
        }
    }

    /// Compute the earliest deadline across all link-layer timers
    pub(super) fn link_next_deadline(&self, now_ms: u64) -> Option<u64> {
        let now_secs = now_ms / MS_PER_SECOND;
        let mut earliest: Option<u64> = None;

        let mut update = |deadline_ms: u64| {
            earliest = Some(match earliest {
                Some(e) => core::cmp::min(e, deadline_ms),
                None => deadline_ms,
            });
        };

        // Pending handshake timeouts
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
        if let Some(deadline) = self.receipt_tracker.earliest_expiry() {
            update(deadline);
        }

        // Active link keepalive and stale deadlines
        for link in self.links.values() {
            match link.state() {
                LinkState::Active => {
                    if link.is_initiator() {
                        let base = if link.last_keepalive_secs() > 0 {
                            link.last_keepalive_secs()
                        } else {
                            link.established_at_secs().unwrap_or(now_secs)
                        };
                        let next_keepalive_secs = base.saturating_add(link.keepalive_secs());
                        update(next_keepalive_secs.saturating_mul(MS_PER_SECOND));
                    }
                    if link.last_inbound_secs() > 0 {
                        let stale_at_secs = link
                            .last_inbound_secs()
                            .saturating_add(link.stale_time_secs());
                        update(stale_at_secs.saturating_mul(MS_PER_SECOND));
                    }
                }
                LinkState::Stale => {
                    update(now_ms.saturating_add(MS_PER_SECOND));
                }
                _ => {}
            }
        }

        // Channel retransmit deadlines
        if self.links.values().any(|l| l.has_channel()) {
            update(now_ms.saturating_add(MS_PER_SECOND));
        }

        earliest
    }

    // ─── Internal: Helpers ────────────────────────────────────────────────────

    /// Route a link packet via attached interface, with path lookup fallback.
    fn route_link_packet(&mut self, link_id: &LinkId, data: &[u8]) {
        if let Some(link) = self.links.get(link_id) {
            if let Some(iface_idx) = link.attached_interface() {
                if let Err(e) = self.transport.send_on_interface(iface_idx, data) {
                    tracing::debug!(%e, "send_on_interface failed");
                }
            } else {
                let dest_hash = *link.destination_hash();
                if let Err(e) = self
                    .transport
                    .send_to_destination(dest_hash.as_bytes(), data)
                {
                    tracing::warn!(%e, "send_to_destination failed — packet lost");
                }
            }
        }
    }

    /// Emit LinkClosed event and run path recovery.
    ///
    /// INVARIANT: The link has already been removed from self.links
    /// at all call sites. This method must not access the link.
    fn emit_link_closed(
        &mut self,
        link_id: LinkId,
        reason: LinkCloseReason,
        is_initiator: bool,
        destination_hash: DestinationHash,
    ) {
        // Clean up all receipt entries for this link
        self.receipt_tracker.remove_for_link(&link_id);

        // Path recovery for locally-initiated links that never activated
        // (Python Transport.py:472-494)
        if reason == LinkCloseReason::Timeout
            && is_initiator
            && !self.transport.config().enable_transport
        {
            let dest_hash = destination_hash.into_bytes();
            self.transport.expire_path(&dest_hash);
            let now = self.transport.clock().now_ms();
            let mut tag = [0u8; TRUNCATED_HASHBYTES];
            tag[..8].copy_from_slice(&now.to_be_bytes());
            tag[8..16].copy_from_slice(&dest_hash[..8]);
            if let Err(e) = self.transport.request_path(&dest_hash, None, &tag) {
                tracing::debug!(%e, "path request failed (best-effort)");
            }
        }

        self.events.push(NodeEvent::LinkClosed {
            link_id,
            reason,
            is_initiator,
            destination_hash,
        });
    }

    pub(super) fn repack_packet(&self, packet: &Packet) -> Vec<u8> {
        let mut buf = [0u8; crate::constants::MTU];
        let len = packet.pack(&mut buf).unwrap_or(0);
        buf[..len].to_vec()
    }
}

#[cfg(test)]
mod receipt_tracker_tests {
    use super::*;

    fn make_link_id(b: u8) -> LinkId {
        LinkId::new([b; 16])
    }

    #[test]
    fn test_register_retransmit_replaces_entry() {
        let mut tracker = ReceiptTracker::new();
        let link = make_link_id(0xAA);

        // Use data with distinct hashable parts (packet_hash strips first 2 bytes)
        let data_v1 = [0x00u8; 64];
        let data_v2 = [0xFFu8; 64];

        tracker.register(&data_v1, link, 1, 1000);
        assert_eq!(tracker.len(), 1);

        // Re-register same (link, seq) with different data
        tracker.register(&data_v2, link, 1, 2000);
        assert_eq!(tracker.len(), 1);

        // Entry should have the new hashes
        let new_hash = packet_hash(&data_v2);
        let mut new_truncated = [0u8; TRUNCATED_HASHBYTES];
        new_truncated.copy_from_slice(&new_hash[..TRUNCATED_HASHBYTES]);
        assert!(tracker.contains_truncated(&new_truncated));

        // Old entry should be gone
        let old_hash = packet_hash(&data_v1);
        let mut old_truncated = [0u8; TRUNCATED_HASHBYTES];
        old_truncated.copy_from_slice(&old_hash[..TRUNCATED_HASHBYTES]);
        assert!(!tracker.contains_truncated(&old_truncated));
    }

    #[test]
    fn test_confirm_delivery_unknown_hash_returns_none() {
        let mut tracker = ReceiptTracker::new();
        let link = make_link_id(0xBB);

        tracker.register(b"some_packet", link, 5, 1000);
        assert_eq!(tracker.len(), 1);

        let unknown = [0xFFu8; TRUNCATED_HASHBYTES];
        assert!(tracker.confirm_delivery(&unknown).is_none());
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn test_remove_for_link_only_affects_target() {
        let mut tracker = ReceiptTracker::new();
        let link_a = make_link_id(0xAA);
        let link_b = make_link_id(0xBB);

        tracker.register(b"a1", link_a, 1, 1000);
        tracker.register(b"a2", link_a, 2, 1000);
        tracker.register(b"b1", link_b, 1, 1000);
        assert_eq!(tracker.count_for_link(&link_a), 2);
        assert_eq!(tracker.count_for_link(&link_b), 1);

        tracker.remove_for_link(&link_a);
        assert_eq!(tracker.count_for_link(&link_a), 0);
        assert_eq!(tracker.count_for_link(&link_b), 1);
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn test_expire_partial() {
        let mut tracker = ReceiptTracker::new();
        let link = make_link_id(0xCC);

        tracker.register(b"old_packet", link, 1, 1000);
        tracker.register(b"new_packet", link, 2, 1000 + DATA_RECEIPT_TIMEOUT_MS);

        // Advance time so only the first has expired
        let now = 1000 + DATA_RECEIPT_TIMEOUT_MS + 1;
        tracker.expire(now);

        assert_eq!(tracker.len(), 1);
        // The surviving entry should be the newer one (seq=2)
        let new_hash = packet_hash(b"new_packet");
        let mut new_truncated = [0u8; TRUNCATED_HASHBYTES];
        new_truncated.copy_from_slice(&new_hash[..TRUNCATED_HASHBYTES]);
        assert!(tracker.contains_truncated(&new_truncated));
    }

    #[test]
    fn test_register_then_confirm_then_register_same_seq() {
        let mut tracker = ReceiptTracker::new();
        let link = make_link_id(0xDD);

        // Register, confirm delivery, register again with same sequence
        tracker.register(b"msg_v1", link, 1, 1000);
        let hash1 = packet_hash(b"msg_v1");
        let mut trunc1 = [0u8; TRUNCATED_HASHBYTES];
        trunc1.copy_from_slice(&hash1[..TRUNCATED_HASHBYTES]);

        let seq = tracker.confirm_delivery(&trunc1);
        assert_eq!(seq, Some(1));
        assert_eq!(tracker.len(), 0);

        // Re-register same sequence (after wraparound or new message)
        tracker.register(b"msg_v2", link, 1, 2000);
        assert_eq!(tracker.len(), 1);

        let hash2 = packet_hash(b"msg_v2");
        let mut trunc2 = [0u8; TRUNCATED_HASHBYTES];
        trunc2.copy_from_slice(&hash2[..TRUNCATED_HASHBYTES]);
        assert!(tracker.contains_truncated(&trunc2));
    }
}
