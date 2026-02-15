//! Link management methods for NodeCore
//!
//! This module contains all link-related methods on [`NodeCore`]:
//! connection establishment, acceptance, data transfer, packet routing,
//! and the LinkEvent → NodeEvent translation layer.

use alloc::vec::Vec;

use crate::destination::DestinationHash;
use crate::link::{LinkCloseReason, LinkError, LinkEvent, LinkId, PendingPacket};
use crate::packet::Packet;
use crate::traits::{Clock, Storage};
use rand_core::CryptoRngCore;

use super::event::NodeEvent;
use super::send;
use super::{LinkStats, NodeCore, RawBytesMessage};

impl<R: CryptoRngCore, C: Clock, S: Storage> NodeCore<R, C, S> {
    // ─── Link Management ──────────────────────────────────────────────────────

    /// Initiate a link to a destination
    ///
    /// # Arguments
    /// * `dest_hash` - The destination to connect to
    /// * `dest_signing_key` - The destination's signing key (from announce)
    ///
    /// # Returns
    /// The `LinkId` for the new connection and a `TickOutput` containing the
    /// link request action. The driver must dispatch this output the same way
    /// it handles output from `handle_packet()` / `handle_timeout()`.
    pub fn connect(
        &mut self,
        dest_hash: DestinationHash,
        dest_signing_key: &[u8; 32],
    ) -> (LinkId, crate::transport::TickOutput) {
        // Check if we have path info for this destination
        let (next_hop, hops) = if let Some(path) = self.transport.path(dest_hash.as_bytes()) {
            if path.needs_relay() {
                // Multi-hop: use HEADER_2 with the relay's transport_id
                (path.next_hop, path.hops)
            } else {
                // Direct neighbor: use HEADER_1
                (None, path.hops)
            }
        } else {
            (None, 1)
        };

        let now_ms = self.transport.clock().now_ms();
        let (link_id, packet) = self.link_manager.initiate_with_path(
            dest_hash,
            dest_signing_key,
            next_hop,
            hops,
            &mut self.rng,
            now_ms,
        );

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
    /// matching the link's destination hash. The identity is used to sign
    /// the link proof.
    ///
    /// # Arguments
    /// * `link_id` - The link ID from the LinkRequest event
    ///
    /// # Returns
    /// A `TickOutput` containing the link proof action. The driver must
    /// dispatch this output the same way it handles output from
    /// `handle_packet()` / `handle_timeout()`.
    ///
    /// # Errors
    /// - `LinkError::NotFound` if the link does not exist
    /// - `LinkError::DestinationNotRegistered` if the destination is not
    ///   registered or has no identity
    pub fn accept_link(
        &mut self,
        link_id: &LinkId,
    ) -> Result<crate::transport::TickOutput, LinkError> {
        // Look up the destination hash from the link
        let dest_hash = self
            .link_manager
            .link(link_id)
            .map(|l| *l.destination_hash())
            .ok_or(LinkError::NotFound)?;

        // Look up identity and proof strategy from the registered destination
        let dest = self
            .destinations
            .get(&dest_hash)
            .ok_or(LinkError::DestinationNotRegistered)?;
        let identity = dest.identity().ok_or(LinkError::DestinationNotRegistered)?;
        let proof_strategy = dest.proof_strategy();

        let now_ms = self.transport.clock().now_ms();
        let proof = self
            .link_manager
            .accept_link(link_id, identity, proof_strategy, now_ms)?;

        // Route proof on attached interface (matching Python Link.prove())
        let attached = self
            .link_manager
            .link(link_id)
            .and_then(|l| l.attached_interface());
        debug_assert!(
            attached.is_some(),
            "accept_link: link {:?} has no attached_interface — \
             process_packet() should have set this",
            link_id
        );
        if let Some(iface_idx) = attached {
            let _ = self.transport.send_on_interface(iface_idx, &proof);
        } else {
            // Fallback: broadcast if attached_interface was not set
            self.transport.send_on_all_interfaces(&proof);
        }

        Ok(self.process_events_and_actions())
    }

    /// Reject an incoming link request
    pub fn reject_link(&mut self, link_id: &LinkId) {
        self.link_manager.reject_link(link_id);
    }

    /// Close a link gracefully
    ///
    /// # Returns
    /// A `TickOutput` containing the close packet action. The driver must
    /// dispatch this output the same way it handles output from
    /// `handle_packet()` / `handle_timeout()`.
    pub fn close_link(&mut self, link_id: &LinkId) -> crate::transport::TickOutput {
        self.link_manager.close(link_id, &mut self.rng);
        self.process_events_and_actions()
    }

    /// Get a link by ID
    pub fn link(&self, link_id: &LinkId) -> Option<&crate::link::Link> {
        self.link_manager.link(link_id)
    }

    /// Get a mutable reference to a link by ID
    pub fn link_mut(&mut self, link_id: &LinkId) -> Option<&mut crate::link::Link> {
        self.link_manager.link_mut(link_id)
    }

    /// Get the number of active links
    pub fn active_link_count(&self) -> usize {
        self.link_manager.active_link_count()
    }

    /// Get the number of pending links
    pub fn pending_link_count(&self) -> usize {
        self.link_manager.pending_link_count()
    }

    // ─── Link Data Transfer ───────────────────────────────────────────────────

    /// Send data on an existing link
    ///
    /// This sends data via the Channel on an established link,
    /// providing reliable, ordered delivery.
    ///
    /// # Arguments
    /// * `link_id` - The link to send on
    /// * `data` - The data to send
    ///
    /// # Returns
    /// A `TickOutput` containing the send action. The driver must dispatch
    /// this output the same way it handles output from `handle_packet()` /
    /// `handle_timeout()`.
    pub fn send_on_link(
        &mut self,
        link_id: &LinkId,
        data: &[u8],
    ) -> Result<crate::transport::TickOutput, send::SendError> {
        let link = self
            .link_manager
            .link(link_id)
            .ok_or(send::SendError::NoLink)?;

        let attached_iface = link.attached_interface();
        let dest_hash = *link.destination_hash();

        // Send through LinkManager's Channel (unified tx_ring + rx_ring)
        let now_ms = self.transport.clock().now_ms();
        let packet_bytes = self
            .link_manager
            .channel_send(link_id, &RawBytesMessage(data), &mut self.rng, now_ms)
            .map_err(|e| match e {
                crate::link::LinkError::WindowFull => send::SendError::WindowFull,
                crate::link::LinkError::PacingDelay { ready_at_ms } => {
                    send::SendError::PacingDelay { ready_at_ms }
                }
                crate::link::LinkError::NotFound => send::SendError::NoLink,
                _ => send::SendError::LinkFailed,
            })?;

        // Register receipt for channel delivery tracking (Python Channel.py:606)
        if let Some(seq) = self.link_manager.channel_last_sent_sequence(link_id) {
            let (full_hash, _old) =
                self.link_manager
                    .register_channel_receipt(&packet_bytes, *link_id, seq, now_ms);
            self.channel_hash_to_seq.insert(full_hash, (*link_id, seq));
        }

        // Route via attached interface (matching Python's LINK routing)
        if let Some(iface_idx) = attached_iface {
            let _ = self.transport.send_on_interface(iface_idx, &packet_bytes);
        } else {
            // Fallback: path lookup
            let _ = self
                .transport
                .send_to_destination(dest_hash.as_bytes(), &packet_bytes);
        }

        Ok(self.process_events_and_actions())
    }

    /// Find an existing active link to a destination
    pub(crate) fn find_link_to(&self, dest_hash: &DestinationHash) -> Option<LinkId> {
        self.link_manager.find_active_link_to(dest_hash)
    }

    /// Get link statistics
    ///
    /// Returns channel and receipt stats useful for monitoring link health.
    pub fn link_stats(&self, link_id: &LinkId) -> Option<LinkStats> {
        // Verify link exists
        self.link_manager.link(link_id)?;
        let ch = self.link_manager.channel(link_id);
        Some(LinkStats {
            tx_ring_size: ch.map(|c| c.outstanding()).unwrap_or(0),
            window: ch.map(|c| c.window()).unwrap_or(0),
            window_max: ch.map(|c| c.window_max()).unwrap_or(0),
            pacing_interval_ms: ch.map(|c| c.pacing_interval_ms()).unwrap_or(0),
        })
    }

    // ─── Internal: Link Event Handling ────────────────────────────────────────

    pub(super) fn handle_link_event(&mut self, event: LinkEvent) {
        match event {
            LinkEvent::LinkRequestReceived {
                link_id,
                dest_hash,
                peer_keys,
            } => {
                self.events.push(NodeEvent::LinkRequest {
                    link_id,
                    destination_hash: dest_hash,
                    peer_keys,
                });
            }

            LinkEvent::LinkEstablished {
                link_id,
                is_initiator,
            } => {
                self.events.push(NodeEvent::LinkEstablished {
                    link_id,
                    is_initiator,
                });
            }

            LinkEvent::DataReceived { link_id, data } => {
                self.events.push(NodeEvent::DataReceived { link_id, data });
            }

            LinkEvent::ChannelMessageReceived {
                link_id,
                msgtype,
                sequence,
                data,
            } => {
                self.events.push(NodeEvent::MessageReceived {
                    link_id,
                    msgtype,
                    sequence,
                    data,
                });
            }

            LinkEvent::LinkStale { link_id } => {
                self.events.push(NodeEvent::LinkStale { link_id });
            }

            LinkEvent::LinkRecovered { link_id } => {
                self.events.push(NodeEvent::LinkRecovered { link_id });
            }

            LinkEvent::LinkClosed {
                link_id,
                reason,
                is_initiator,
                destination_hash,
            } => {
                // Clean up channel hash→seq entries for this link
                self.channel_hash_to_seq
                    .retain(|_, (lid, _)| *lid != link_id);

                // Path recovery for locally-initiated links that never activated
                // (Python Transport.py:472-494). When an initiator link times out
                // on a non-transport node, expire the stale path and request a
                // fresh one so the application can retry.
                if reason == LinkCloseReason::Timeout
                    && is_initiator
                    && !self.transport.config().enable_transport
                {
                    let dest_hash = destination_hash.into_bytes();
                    self.transport.expire_path(&dest_hash);

                    // Tag = [now_ms (8 bytes)] [dest_hash prefix (8 bytes)]
                    // Same pattern as clean_link_table() for dedup.
                    let now = self.transport.clock().now_ms();
                    let mut tag = [0u8; crate::constants::TRUNCATED_HASHBYTES];
                    let now_bytes = now.to_be_bytes();
                    tag[..8].copy_from_slice(&now_bytes);
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

            LinkEvent::DataDelivered {
                link_id,
                packet_hash,
            } => {
                // Check if this was a channel message and call mark_delivered
                // on the LinkManager's Channel (unified tx_ring + rx_ring)
                if let Some((_, sequence)) = self.channel_hash_to_seq.remove(&packet_hash) {
                    let now_ms = self.transport.clock().now_ms();
                    let rtt_ms = self
                        .link_manager
                        .link(&link_id)
                        .map(|l| l.rtt_ms())
                        .unwrap_or(500);
                    let _delivered = self
                        .link_manager
                        .mark_channel_delivered(&link_id, sequence, now_ms, rtt_ms);
                }
                self.events.push(NodeEvent::LinkDeliveryConfirmed {
                    link_id,
                    packet_hash,
                });
            }

            LinkEvent::ChannelReceiptUpdated {
                link_id,
                new_hash,
                old_hash,
                sequence,
            } => {
                // Remove stale hash→sequence mapping from previous send/retransmit
                if let Some(old) = old_hash {
                    self.channel_hash_to_seq.remove(&old);
                }
                // Insert new hash→sequence mapping for proof matching
                self.channel_hash_to_seq
                    .insert(new_hash, (link_id, sequence));
            }

            LinkEvent::ChannelRetransmit {
                link_id,
                sequence,
                tries,
            } => {
                self.events.push(NodeEvent::ChannelRetransmit {
                    link_id,
                    sequence,
                    tries,
                });
            }

            LinkEvent::ProofRequested {
                link_id,
                packet_hash,
            } => {
                // PROVE_APP strategy: delegate proof decision to the application.
                // The app receives this event and calls send_data_proof() if appropriate.
                self.events.push(NodeEvent::LinkProofRequested {
                    link_id,
                    packet_hash,
                });
            }
        }
    }

    pub(super) fn send_pending_packets(&mut self) {
        let packets: Vec<_> = self.link_manager.drain_pending_packets().collect();
        for packet in packets {
            match packet {
                PendingPacket::Rtt { data, .. } | PendingPacket::Close { data, .. } => {
                    // RTT and Close packets are broadcast on all interfaces
                    self.transport.send_on_all_interfaces(&data);
                }
                PendingPacket::Keepalive { link_id, data }
                | PendingPacket::Channel { link_id, data }
                | PendingPacket::Proof { link_id, data } => {
                    // Route via attached interface if known, otherwise path lookup
                    if let Some(link) = self.link_manager.link(&link_id) {
                        if let Some(iface_idx) = link.attached_interface() {
                            let _ = self.transport.send_on_interface(iface_idx, &data);
                        } else {
                            let dest_hash = *link.destination_hash();
                            let _ = self
                                .transport
                                .send_to_destination(dest_hash.as_bytes(), &data);
                        }
                    }
                }
            }
        }
    }

    pub(super) fn repack_packet(&self, packet: &Packet) -> Vec<u8> {
        let mut buf = [0u8; crate::constants::MTU];
        let len = packet.pack(&mut buf).unwrap_or(0);
        buf[..len].to_vec()
    }
}
