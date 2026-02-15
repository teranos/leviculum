//! Link management methods for NodeCore
//!
//! This module contains all link-related methods on [`NodeCore`]:
//! connection establishment, acceptance, data transfer, packet routing,
//! and internal link packet processing (handshake, data, timeouts).

use alloc::vec::Vec;

use crate::constants::{
    DATA_RECEIPT_TIMEOUT_MS, LINK_PENDING_TIMEOUT_MS, MODE_AES256_CBC, MS_PER_SECOND, MTU,
    PROOF_DATA_SIZE, TRUNCATED_HASHBYTES,
};
use crate::destination::{DestinationHash, ProofStrategy};
use crate::hex_fmt::HexFmt;
use crate::link::channel::{ChannelAction, ChannelError};
use crate::link::{
    DataReceipt, Link, LinkCloseReason, LinkError, LinkId, LinkPhase, LinkState, PeerKeys,
};
use crate::packet::{packet_hash, Packet, PacketContext, PacketType};
use crate::traits::{Clock, Storage};
use rand_core::CryptoRngCore;

use super::event::NodeEvent;
use super::send;
use super::{LinkStats, NodeCore, RawBytesMessage};

impl<R: CryptoRngCore, C: Clock, S: Storage> NodeCore<R, C, S> {
    // ─── Link Management (Public API) ─────────────────────────────────────────

    /// Initiate a link to a destination
    ///
    /// # Arguments
    /// * `dest_hash` - The destination to connect to
    /// * `dest_signing_key` - The destination's signing key (from announce)
    ///
    /// # Returns
    /// The `LinkId` for the new connection and a `TickOutput` containing the
    /// link request action.
    pub fn connect(
        &mut self,
        dest_hash: DestinationHash,
        dest_signing_key: &[u8; 32],
    ) -> (LinkId, crate::transport::TickOutput) {
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

        // Create new outgoing link
        let mut link = Link::new_outgoing(dest_hash, &mut self.rng);
        let packet = link.build_link_request_packet_with_transport(next_hop, hops);
        let link_id = *link.id();
        let _ = link.set_destination_keys(dest_signing_key);
        link.set_phase(LinkPhase::PendingOutgoing {
            created_at_ms: now_ms,
        });
        self.links.insert(link_id, link);

        // Route through transport: path lookup first, broadcast if no path
        if self
            .transport
            .send_to_destination(dest_hash.as_bytes(), &packet)
            .is_err()
        {
            self.transport.send_on_all_interfaces(&packet);
        }

        let output = self.process_events_and_actions();
        (link_id, output)
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
        let proof = link.build_proof_packet(identity, MTU as u32, MODE_AES256_CBC)?;
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
            let _ = self.transport.send_on_interface(iface_idx, &proof);
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
            self.channel_receipt_keys
                .retain(|(lid, _), _| *lid != *link_id);
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
            let (full_hash, _old) =
                self.register_channel_receipt(&packet_bytes, *link_id, seq, now_ms);
            self.channel_hash_to_seq.insert(full_hash, (*link_id, seq));
        }

        // Route via attached interface
        if let Some(iface_idx) = attached_iface {
            let _ = self.transport.send_on_interface(iface_idx, &packet_bytes);
        } else {
            let _ = self
                .transport
                .send_to_destination(dest_hash.as_bytes(), &packet_bytes);
        }

        Ok(self.process_events_and_actions())
    }

    /// Find an existing active link to a destination
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
        Some(LinkStats {
            tx_ring_size: ch.map(|c| c.outstanding()).unwrap_or(0),
            window: ch.map(|c| c.window()).unwrap_or(0),
            window_max: ch.map(|c| c.window_max()).unwrap_or(0),
            pacing_interval_ms: ch.map(|c| c.pacing_interval_ms()).unwrap_or(0),
        })
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
        let Ok(mut link) = Link::new_incoming(request_data, link_id, dest_hash, &mut self.rng)
        else {
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
            return;
        };

        // Must be a pending outgoing link
        if !matches!(link.phase(), LinkPhase::PendingOutgoing { .. }) {
            return;
        }
        if link.state() != LinkState::Pending || !link.is_initiator() {
            return;
        }

        // Set attached interface from the interface the proof arrived on
        link.set_attached_interface(interface_index);

        // Process the proof
        if link.process_proof(proof_data).is_err() {
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
            receipts = self.data_receipts.len(),
            "link_mgr: data proof received"
        );

        // Look up receipt — extract needed data before any mutable borrow
        let receipt_info = self
            .data_receipts
            .get(&truncated)
            .map(|r| (r.full_hash, r.link_id));
        let Some((receipt_full_hash, receipt_link_id)) = receipt_info else {
            tracing::debug!(
                receipts = self.data_receipts.len(),
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
            self.data_receipts.remove(&truncated);
            tracing::debug!(
                receipts = self.data_receipts.len(),
                "link_mgr: data proof validated — delivered"
            );

            // Inline delivery tracking
            if let Some((_, sequence)) = self.channel_hash_to_seq.remove(&receipt_full_hash) {
                let now_ms = self.transport.clock().now_ms();
                let rtt_ms = self.links.get(link_id).map(|l| l.rtt_ms()).unwrap_or(500);
                if let Some(link) = self.links.get_mut(link_id) {
                    if let Some(ch) = link.channel_mut() {
                        ch.mark_delivered(sequence, now_ms, rtt_ms);
                    }
                }
            }

            self.events.push(NodeEvent::LinkDeliveryConfirmed {
                link_id: *link_id,
                packet_hash: receipt_full_hash,
            });
        } else {
            tracing::debug!("link_mgr: data proof — signature validation failed");
        }
    }

    /// Handle an incoming DATA packet on a link
    fn handle_link_data(&mut self, packet: &Packet, raw_packet: &[u8], now_ms: u64) {
        let link_id = LinkId::new(packet.destination_hash);
        let now_secs = now_ms / MS_PER_SECOND;

        // Recover stale links on any inbound traffic (Python Link.py:987-988)
        self.try_recover_stale(&link_id, now_secs);

        let Some(link) = self.links.get_mut(&link_id) else {
            return;
        };

        // RTT packet (context = Lrrtt) — responder side
        if packet.context == PacketContext::Lrrtt {
            if link.state() != LinkState::Handshake || link.is_initiator() {
                return;
            }
            let encrypted_data = packet.data.as_slice();
            if let Ok(rtt_secs) = link.process_rtt(encrypted_data) {
                link.update_keepalive_from_rtt(rtt_secs);
                link.mark_established(now_secs);
                link.set_phase(LinkPhase::Established);
                self.events.push(NodeEvent::LinkEstablished {
                    link_id,
                    is_initiator: false,
                });
            }
            return;
        }

        // KEEPALIVE packet
        if packet.context == PacketContext::Keepalive {
            link.record_inbound(now_secs);
            let data = packet.data.as_slice();
            if let Ok(should_echo) = link.process_keepalive(data) {
                if should_echo {
                    if let Ok(echo_packet) = link.build_keepalive_packet() {
                        self.route_link_packet(&link_id, &echo_packet);
                    }
                }
            }
            return;
        }

        // LINKCLOSE packet
        if packet.context == PacketContext::LinkClose {
            let encrypted_data = packet.data.as_slice();
            if link.process_close(encrypted_data).is_ok() {
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
            return;
        }

        // CHANNEL packet
        if packet.context == PacketContext::Channel {
            if link.state() != LinkState::Active {
                return;
            }

            link.record_inbound(now_secs);

            // Decrypt the envelope data
            let encrypted_data = packet.data.as_slice();
            let max_plaintext_len = encrypted_data.len();
            let mut plaintext = alloc::vec![0u8; max_plaintext_len];
            let decrypted_len = match link.decrypt(encrypted_data, &mut plaintext) {
                Ok(len) => len,
                Err(_) => return,
            };
            plaintext.truncate(decrypted_len);

            // Process through channel — all link operations happen in this block
            // to allow the link borrow to be dropped before accessing other
            // fields (rx_ring_full counters, route_link_packet).
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

                // Build proof while link borrow is still held (if message accepted)
                if message_accepted {
                    let full_packet_hash = packet_hash(raw_packet);
                    if let Some(signing_key) = link.proof_signing_key() {
                        match link.build_data_proof_packet_with_signing_key(
                            &full_packet_hash,
                            signing_key,
                        ) {
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
                } else {
                    None
                }
            };
            // link borrow released here (NLL: last use was inside the block)

            // Deferred rx_ring_full counter update (safe now — link borrow dropped)
            if rx_ring_full {
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

            // Route proof via transport (safe now — link borrow dropped)
            if let Some(proof) = proof_packet {
                self.route_link_packet(&link_id, &proof);
            }

            return;
        }

        // Regular data packet
        if link.state() != LinkState::Active {
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

                self.events.push(NodeEvent::DataReceived {
                    link_id,
                    data: plaintext,
                });
            }
            Err(_) => {
                // Decryption failed — silently discard
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

        // Clean up expired data receipts and their channel_receipt_keys
        self.data_receipts.retain(|_, receipt| {
            now_ms.saturating_sub(receipt.sent_at_ms) <= DATA_RECEIPT_TIMEOUT_MS
        });
        self.channel_receipt_keys
            .retain(|_, truncated| self.data_receipts.contains_key(truncated));
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
                // Route close packet BEFORE removing link from map
                if let Some(ref pkt) = close_packet {
                    self.route_link_packet(&link_id, pkt);
                }
                self.channel_receipt_keys
                    .retain(|(lid, _), _| *lid != link_id);
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
                            let (new_hash, old_hash) =
                                self.register_channel_receipt(&packet, link_id, sequence, now_ms);

                            // Update channel_hash_to_seq inline
                            if let Some(old) = old_hash {
                                self.channel_hash_to_seq.remove(&old);
                            }
                            self.channel_hash_to_seq
                                .insert(new_hash, (link_id, sequence));

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
                        self.channel_receipt_keys
                            .retain(|(lid, _), _| *lid != link_id);
                        self.emit_link_closed(
                            link_id,
                            LinkCloseReason::Timeout,
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
        for receipt in self.data_receipts.values() {
            update(receipt.sent_at_ms.saturating_add(DATA_RECEIPT_TIMEOUT_MS));
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

    /// Register a data receipt for a channel message, removing any previous receipt
    /// for the same (link_id, sequence).
    fn register_channel_receipt(
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

    // ─── Internal: Helpers ────────────────────────────────────────────────────

    /// Route a link packet via attached interface, with path lookup fallback.
    fn route_link_packet(&mut self, link_id: &LinkId, data: &[u8]) {
        if let Some(link) = self.links.get(link_id) {
            if let Some(iface_idx) = link.attached_interface() {
                let _ = self.transport.send_on_interface(iface_idx, data);
            } else {
                let dest_hash = *link.destination_hash();
                let _ = self
                    .transport
                    .send_to_destination(dest_hash.as_bytes(), data);
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
        // Clean up channel hash→seq entries for this link
        self.channel_hash_to_seq
            .retain(|_, (lid, _)| *lid != link_id);

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
            let _ = self.transport.request_path(&dest_hash, None, &tag);
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
