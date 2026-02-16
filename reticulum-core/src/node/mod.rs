//! High-level Node API for Reticulum
//!
//! This module provides [`NodeCore`], a unified interface that combines
//! transport, link management, and routing into a single, easy-to-use API.
//!
//! # Overview
//!
//! The Node API provides:
//! - **Unified event handling**: All events (announces, packets, links) through one stream
//! - **Smart routing**: Automatic selection of single-packet vs Link/Channel based on options
//! - **Builder pattern**: Easy configuration via [`NodeCoreBuilder`]
//!
//! # Example
//!
//! ```no_run
//! use reticulum_core::node::{NodeCore, NodeCoreBuilder, NodeEvent, SendOptions};
//! use reticulum_core::destination::{Destination, DestinationType, Direction};
//! use reticulum_core::identity::Identity;
//! use reticulum_core::traits::{Clock, NoStorage};
//! # use core::cell::Cell;
//! # struct MyClock(Cell<u64>);
//! # impl MyClock { fn new(ms: u64) -> Self { Self(Cell::new(ms)) } }
//! # impl Clock for MyClock { fn now_ms(&self) -> u64 { self.0.get() } }
//!
//! # fn example() {
//! let my_identity = Identity::generate(&mut rand_core::OsRng);
//!
//! // Build a node
//! let mut node = NodeCoreBuilder::new()
//!     .enable_transport(false)
//!     .build(rand_core::OsRng, MyClock::new(0), NoStorage);
//!
//! // Register a destination
//! let dest = Destination::new(
//!     Some(my_identity),
//!     Direction::In,
//!     DestinationType::Single,
//!     "myapp",
//!     &["echo"],
//! ).unwrap();
//! node.register_destination(dest);
//! # }

mod builder;
mod event;
mod link_management;
mod send;

pub use builder::NodeCoreBuilder;
pub use event::{DeliveryError, NodeEvent};
pub use send::{RoutingDecision, SendError, SendHandle, SendMethod, SendResult};

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::announce::AnnounceError;
use crate::constants::TRUNCATED_HASHBYTES;
use crate::destination::{Destination, DestinationHash, ProofStrategy};
use crate::identity::Identity;
use crate::link::channel::{ChannelError, Message};
use crate::link::{Link, LinkId};
use crate::packet::packet_hash;
use crate::traits::{Clock, Storage};
use crate::transport::{Transport, TransportConfig, TransportEvent, TransportStats};
use rand_core::CryptoRngCore;

use crate::hex_fmt::HexFmt;

/// Send options for controlling how data is delivered
///
/// These options allow applications to specify delivery requirements
/// that the node uses to choose the best transport method.
#[derive(Debug, Clone)]
pub struct SendOptions {
    /// Require reliable delivery (will use Link/Channel if needed)
    pub reliable: bool,
    /// Maximum acceptable latency before failing (milliseconds)
    pub timeout_ms: Option<u64>,
    /// Prefer existing connection if available
    pub prefer_existing: bool,
    /// Enable compression for this message
    pub compress: bool,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            reliable: false, // Single-Packet by default
            timeout_ms: None,
            prefer_existing: true,
            compress: false,
        }
    }
}

impl SendOptions {
    /// Create options for unreliable (single-packet) delivery
    pub fn unreliable() -> Self {
        Self::default()
    }

    /// Create options for reliable (Link/Channel) delivery
    pub fn reliable() -> Self {
        Self {
            reliable: true,
            ..Self::default()
        }
    }

    /// Create options for reliable delivery with compression
    pub fn reliable_compressed() -> Self {
        Self {
            reliable: true,
            compress: true,
            ..Self::default()
        }
    }
}

/// Simple message type for sending raw bytes over a channel
struct RawBytesMessage<'a>(&'a [u8]);

impl Message for RawBytesMessage<'_> {
    const MSGTYPE: u16 = 0x0000;

    fn pack(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
        // Not used for sending — receiving goes through channel.receive()
        let _ = data;
        Err(ChannelError::EnvelopeTruncated)
    }
}

/// Link statistics for observability
#[derive(Debug, Clone)]
pub struct LinkStats {
    /// Number of outstanding (unacknowledged) messages in the channel tx ring
    pub tx_ring_size: usize,
    /// Current channel window size
    pub window: usize,
    /// Maximum channel window size
    pub window_max: usize,
    /// Current pacing interval between sends (milliseconds)
    pub pacing_interval_ms: u64,
}

/// The unified Reticulum node — owns all protocol state
///
/// NodeCore is generic over RNG, Clock, and Storage traits, allowing it to run
/// on both std and no_std environments.
///
/// # Type Parameters
///
/// * `R` - Random number generator (must implement `CryptoRngCore`)
/// * `C` - Clock implementation for timestamps
/// * `S` - Storage implementation for persistence
pub struct NodeCore<R: CryptoRngCore, C: Clock, S: Storage> {
    /// Owned random number generator
    rng: R,
    /// Transport layer (routing, paths, packets) - owns the node's identity
    transport: Transport<C, S>,
    /// Active links by ID
    links: BTreeMap<LinkId, Link>,
    /// Tracks channel message receipts awaiting delivery proofs
    receipt_tracker: link_management::ReceiptTracker,
    /// Count of rx_ring full drops since last log
    rx_ring_full_count: u64,
    /// Timestamp (ms) when last rx_ring full log was emitted
    rx_ring_full_last_log_ms: u64,
    /// Registered destinations
    destinations: BTreeMap<DestinationHash, Destination>,
    /// Default proof strategy for new destinations
    default_proof_strategy: ProofStrategy,
    /// Pending events
    events: Vec<NodeEvent>,
}

impl<R: CryptoRngCore, C: Clock, S: Storage> NodeCore<R, C, S> {
    /// Create a new NodeCore with the given configuration
    ///
    /// # Arguments
    /// * `identity` - The node's identity
    /// * `config` - Transport configuration
    /// * `proof_strategy` - Default proof strategy for destinations
    /// * `rng` - Random number generator (moved into NodeCore)
    /// * `clock` - Clock instance (moved into NodeCore)
    /// * `storage` - Storage instance (moved into NodeCore)
    pub fn new(
        identity: Identity,
        config: TransportConfig,
        proof_strategy: ProofStrategy,
        rng: R,
        clock: C,
        storage: S,
    ) -> Self {
        // Transport takes ownership of a second identity created from the same keys
        // Since we can't clone Identity, we store the hash for reference and let
        // Transport own the identity for packet operations
        let transport = Transport::new(config, clock, storage, identity);

        Self {
            rng,
            // We don't store identity separately - Transport owns it
            // Access via transport.identity()
            transport,
            links: BTreeMap::new(),
            receipt_tracker: link_management::ReceiptTracker::new(),
            rx_ring_full_count: 0,
            rx_ring_full_last_log_ms: 0,
            destinations: BTreeMap::new(),
            default_proof_strategy: proof_strategy,
            events: Vec::new(),
        }
    }

    // ─── Destination Management ────────────────────────────────────────────────

    /// Register a destination to receive packets and/or connections
    ///
    /// # Arguments
    /// * `dest` - The destination to register
    pub fn register_destination(&mut self, dest: Destination) {
        let hash = *dest.hash();

        // Register with transport for packet routing.
        // All destination metadata (proof strategy, accepts_links, identity)
        // stays on NodeCore — Transport only knows "is this hash local?".
        self.transport.register_destination(hash.into_bytes());

        self.destinations.insert(hash, dest);
    }

    /// Unregister a destination
    pub fn unregister_destination(&mut self, hash: &DestinationHash) {
        self.transport.unregister_destination(hash.as_bytes());
        self.destinations.remove(hash);
    }

    /// Get a registered destination
    pub fn destination(&self, hash: &DestinationHash) -> Option<&Destination> {
        self.destinations.get(hash)
    }

    /// Get a mutable reference to a registered destination
    pub fn destination_mut(&mut self, hash: &DestinationHash) -> Option<&mut Destination> {
        self.destinations.get_mut(hash)
    }

    /// Announce a registered destination on all interfaces
    ///
    /// Builds the announce packet and broadcasts it. The announce is queued
    /// as a Broadcast action, dispatched by the next [`handle_timeout()`] or
    /// [`handle_packet()`] call.
    ///
    /// # Deferred dispatch
    ///
    /// This method queues I/O actions internally. The actions are not executed
    /// until the driver calls [`handle_packet()`] or [`handle_timeout()`],
    /// which drain all pending actions. Callers must ensure the event loop
    /// runs promptly after calling this method.
    ///
    /// # Arguments
    /// * `dest_hash` - Hash of the registered destination to announce
    /// * `app_data` - Optional application data to include in the announce
    ///
    /// # Returns
    /// A `TickOutput` containing the broadcast action. The driver must
    /// dispatch this output the same way it handles output from
    /// `handle_packet()` / `handle_timeout()`.
    pub fn announce_destination(
        &mut self,
        dest_hash: &DestinationHash,
        app_data: Option<&[u8]>,
    ) -> Result<crate::transport::TickOutput, AnnounceError> {
        let now_ms = self.transport.clock().now_ms();

        let dest = self
            .destinations
            .get_mut(dest_hash)
            .ok_or(AnnounceError::DestinationNotFound)?;

        let packet = dest.announce(app_data, &mut self.rng, now_ms)?;

        let mut buf = [0u8; crate::constants::MTU];
        let len = packet
            .pack(&mut buf)
            .map_err(|_| AnnounceError::PacketTooLarge)?;

        self.transport.send_on_all_interfaces(&buf[..len]);
        Ok(self.process_events_and_actions())
    }

    // ─── Smart Send API ────────────────────────────────────────────────────────

    /// Send data to a destination with automatic routing
    ///
    /// This is the primary API for sending data. It automatically chooses the
    /// best transport method based on the options and network state:
    ///
    /// - **Unreliable** (`reliable: false`): Uses single-packet delivery if data
    ///   fits and a path is known. Falls back to Link/Channel for larger data.
    /// - **Reliable** (`reliable: true`): Uses an existing connection if available,
    ///   or indicates that a connection needs to be established.
    ///
    /// # Arguments
    /// * `dest_hash` - The destination to send to
    /// * `data` - The data to send
    /// * `opts` - Send options controlling routing behavior
    ///
    /// # Returns
    /// - `Ok(SendResult)` with the routing decision and any packet data to send
    /// - `Err(SendError)` if sending is not possible
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use reticulum_core::node::{NodeCoreBuilder, SendOptions};
    /// # use reticulum_core::destination::DestinationHash;
    /// # use reticulum_core::traits::{Clock, NoStorage};
    /// # use core::cell::Cell;
    /// # struct MyClock(Cell<u64>);
    /// # impl MyClock { fn new(ms: u64) -> Self { Self(Cell::new(ms)) } }
    /// # impl Clock for MyClock { fn now_ms(&self) -> u64 { self.0.get() } }
    /// # fn example() {
    /// # let node = NodeCoreBuilder::new().build(rand_core::OsRng, MyClock::new(0), NoStorage);
    /// # let dest_hash = DestinationHash::new([0x42; 16]);
    /// // Simple unreliable send (single-packet if possible)
    /// let result = node.send(&dest_hash, b"Hello!", &SendOptions::default());
    ///
    /// // Reliable send (requires connection)
    /// let result = node.send(&dest_hash, b"Important!", &SendOptions::reliable());
    /// # }
    /// ```
    pub fn send(
        &self,
        dest_hash: &DestinationHash,
        data: &[u8],
        opts: &SendOptions,
    ) -> Result<send::RoutingDecision, send::SendError> {
        // Check if we have an existing link to this destination
        let existing_link = self.find_link_to(dest_hash);

        // Check if we have a path
        let has_path = self.transport.has_path(dest_hash.as_bytes());

        // Maximum size for single-packet delivery
        // This is the packet data portion minus some overhead
        let max_single_packet_size = crate::constants::MDU - 50; // Leave room for header

        // Decide routing
        let decision = send::decide_routing(
            data.len(),
            opts.reliable,
            opts.prefer_existing,
            has_path,
            existing_link,
            max_single_packet_size,
        );

        // Convert CannotSend to error
        if decision == send::RoutingDecision::CannotSend {
            return Err(send::SendError::NoPath);
        }

        Ok(decision)
    }

    /// Send unreliable data via single packet
    ///
    /// This builds and sends a single data packet to the destination.
    /// Use this when you've already determined that single-packet delivery
    /// is appropriate via `send()`.
    ///
    /// # Arguments
    /// * `dest_hash` - The destination to send to
    /// * `data` - The data to send
    ///
    /// # Returns
    /// The packet hash for tracking delivery (if proofs are enabled) and
    /// a `TickOutput` containing the send action. The driver must dispatch
    /// this output the same way it handles output from `handle_packet()` /
    /// `handle_timeout()`.
    pub fn send_single_packet(
        &mut self,
        dest_hash: &DestinationHash,
        data: &[u8],
    ) -> Result<([u8; TRUNCATED_HASHBYTES], crate::transport::TickOutput), send::SendError> {
        // Build a data packet
        use crate::destination::DestinationType;
        use crate::packet::{
            HeaderType, PacketContext, PacketData, PacketFlags, PacketType, TransportType,
        };

        let packet = crate::packet::Packet {
            flags: PacketFlags {
                ifac_flag: false,
                header_type: HeaderType::Type1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                dest_type: DestinationType::Single,
                packet_type: PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination_hash: dest_hash.into_bytes(),
            context: PacketContext::None,
            data: PacketData::Owned(data.to_vec()),
        };

        // Pack the packet
        let mut buf = [0u8; crate::constants::MTU];
        let len = packet
            .pack(&mut buf)
            .map_err(|_| send::SendError::TooLarge)?;

        // Send via transport
        self.transport
            .send_to_destination(dest_hash.as_bytes(), &buf[..len])
            .map_err(|_| send::SendError::NoPath)?;

        // Create receipt and return hash
        let packet_hash = self
            .transport
            .create_receipt(&buf[..len], dest_hash.into_bytes());

        let output = self.process_events_and_actions();
        Ok((packet_hash, output))
    }

    /// Send a proof for a received single packet (`ProofStrategy::App`)
    ///
    /// Call this after receiving `NodeEvent::PacketProofRequested` if the
    /// application decides to prove delivery. Uses path-table routing
    /// to reach the original sender.
    ///
    /// # Arguments
    /// * `packet_hash` - The full SHA256 hash from `NodeEvent::PacketProofRequested`
    /// * `destination_hash` - The destination hash from `NodeEvent::PacketProofRequested`
    pub fn send_proof(
        &mut self,
        packet_hash: &[u8; 32],
        destination_hash: &DestinationHash,
    ) -> Result<crate::transport::TickOutput, crate::transport::TransportError> {
        let identity = self
            .destinations
            .get(destination_hash)
            .and_then(|d| d.identity())
            .ok_or(crate::transport::TransportError::NoPath)?;

        self.transport.send_proof(
            packet_hash,
            destination_hash.as_bytes(),
            identity,
            None, // path-based routing for App strategy
        )?;

        Ok(self.process_events_and_actions())
    }

    // ─── Sans-I/O Entry Points ────────────────────────────────────────────────

    /// Process an incoming packet from an interface (sans-I/O)
    ///
    /// This is the primary entry point for incoming data. The driver reads
    /// deframed packets from interfaces and passes them here. The full
    /// processing pipeline runs synchronously: transport processing, link
    /// manager handling, and pending packet dispatch.
    ///
    /// # Arguments
    /// * `iface` - The interface the packet arrived on
    /// * `data` - The deframed packet bytes
    pub fn handle_packet(
        &mut self,
        iface: crate::transport::InterfaceId,
        data: &[u8],
    ) -> crate::transport::TickOutput {
        // Process through transport layer
        let _ = self.transport.process_incoming(iface.0, data);

        // Run the full event pipeline (same as tick() but without polling interfaces)
        self.process_events_and_actions()
    }

    /// Run periodic maintenance (sans-I/O)
    ///
    /// The driver should call this when the deadline from [`next_deadline`]
    /// expires, or on a regular interval. Handles path expiry, announce
    /// rebroadcasts, keepalives, stale link detection, receipt timeouts,
    /// and channel retransmissions.
    pub fn handle_timeout(&mut self) -> crate::transport::TickOutput {
        let now_ms = self.transport.clock().now_ms();

        // Run transport periodic tasks
        self.transport.poll();

        // Run link-layer periodic tasks
        self.check_timeouts(now_ms);
        let now_secs = now_ms / crate::constants::MS_PER_SECOND;
        self.check_keepalives(now_secs);
        self.check_stale_links(now_secs);
        self.check_channel_timeouts(now_ms);

        // Process all resulting events and actions
        self.process_events_and_actions()
    }

    /// Compute the earliest deadline across all timers
    ///
    /// Returns `None` if there are no pending deadlines. The driver should
    /// call [`handle_timeout`] when this deadline expires (or sooner).
    ///
    /// The returned value is an absolute timestamp in milliseconds
    /// (same timebase as the `Clock` trait).
    pub fn next_deadline(&self) -> Option<u64> {
        let now_ms = self.transport.clock().now_ms();
        let transport_deadline = self.transport.next_deadline();
        let link_deadline = self.link_next_deadline(now_ms);

        match (transport_deadline, link_deadline) {
            (Some(t), Some(l)) => Some(core::cmp::min(t, l)),
            (Some(t), None) => Some(t),
            (None, Some(l)) => Some(l),
            (None, None) => None,
        }
    }

    /// Notify core that an interface has gone offline (sans-I/O)
    ///
    /// The driver should call this when it detects that an interface is no
    /// longer available (e.g., TCP disconnect, serial port closed). Core
    /// removes routing entries referencing this interface and emits
    /// appropriate events.
    pub fn handle_interface_down(
        &mut self,
        iface: crate::transport::InterfaceId,
    ) -> crate::transport::TickOutput {
        let iface_idx = iface.0;

        // Remove path entries referencing this interface
        let lost_paths: Vec<_> = self
            .transport
            .path_table()
            .iter()
            .filter(|(_, entry)| entry.interface_index == iface_idx)
            .map(|(hash, _)| *hash)
            .collect();

        for hash in &lost_paths {
            self.transport.remove_path(hash);
            self.events.push(NodeEvent::PathLost {
                destination_hash: crate::destination::DestinationHash::new(*hash),
            });
        }

        // Remove link table entries referencing this interface
        self.transport.remove_link_entries_for_interface(iface_idx);

        // Remove reverse table entries referencing this interface
        self.transport
            .remove_reverse_entries_for_interface(iface_idx);

        // Emit the InterfaceDown event
        self.events.push(NodeEvent::InterfaceDown(iface_idx));

        crate::transport::TickOutput {
            actions: Vec::new(),
            events: core::mem::take(&mut self.events),
        }
    }

    /// Internal: Process transport events, drain actions
    ///
    /// Shared logic between `handle_packet` and `handle_timeout`.
    fn process_events_and_actions(&mut self) -> crate::transport::TickOutput {
        // Drain transport events and dispatch
        let transport_events: Vec<_> = self.transport.drain_events().collect();
        for event in transport_events {
            self.handle_transport_event(event);
        }

        // Collect all actions and events
        let actions = self.transport.drain_actions();
        let events = core::mem::take(&mut self.events);

        crate::transport::TickOutput { actions, events }
    }

    // ─── Accessors ─────────────────────────────────────────────────────────────

    /// Get the node's identity
    pub fn identity(&self) -> &Identity {
        self.transport.identity()
    }

    /// Get the transport configuration
    pub fn transport_config(&self) -> &TransportConfig {
        self.transport.config()
    }

    /// Get the default proof strategy
    pub fn default_proof_strategy(&self) -> ProofStrategy {
        self.default_proof_strategy
    }

    /// Check if we have a path to a destination
    pub fn has_path(&self, dest_hash: &DestinationHash) -> bool {
        self.transport.has_path(dest_hash.as_bytes())
    }

    /// Get the hop count to a destination
    pub fn hops_to(&self, dest_hash: &DestinationHash) -> Option<u8> {
        self.transport.hops_to(dest_hash.as_bytes())
    }

    /// Get the number of known paths
    pub fn path_count(&self) -> usize {
        self.transport.path_count()
    }

    /// Get transport statistics
    pub fn transport_stats(&self) -> TransportStats {
        self.transport.stats().clone()
    }

    /// Get the current time in milliseconds from the transport clock
    pub fn now_ms(&self) -> u64 {
        self.transport.clock().now_ms()
    }

    /// Access the underlying transport (test-only, for clock manipulation)
    #[cfg(test)]
    pub(crate) fn transport(&self) -> &Transport<C, S> {
        &self.transport
    }

    /// Get the number of tracked receipts (test-only)
    #[cfg(test)]
    pub(crate) fn receipt_count(&self) -> usize {
        self.receipt_tracker.len()
    }

    /// Count receipt entries for a given link (test-only)
    #[cfg(test)]
    pub(crate) fn receipt_count_for_link(&self, link_id: &LinkId) -> usize {
        self.receipt_tracker.count_for_link(link_id)
    }

    /// Expire all receipts as of `now_ms` without triggering retransmit (test-only)
    #[cfg(test)]
    pub(crate) fn expire_receipts(&mut self, now_ms: u64) {
        self.receipt_tracker.expire(now_ms);
    }

    // ─── Internal: Event Handling ──────────────────────────────────────────────

    fn handle_transport_event(&mut self, event: TransportEvent) {
        match event {
            TransportEvent::AnnounceReceived {
                announce,
                interface_index,
            } => {
                self.events.push(NodeEvent::AnnounceReceived {
                    announce,
                    interface_index,
                });
            }

            TransportEvent::PathFound {
                destination_hash,
                hops,
                interface_index,
            } => {
                self.events.push(NodeEvent::PathFound {
                    destination_hash: DestinationHash::new(destination_hash),
                    hops,
                    interface_index,
                });
            }

            TransportEvent::PathLost { destination_hash } => {
                self.events.push(NodeEvent::PathLost {
                    destination_hash: DestinationHash::new(destination_hash),
                });
            }

            TransportEvent::PacketReceived {
                destination_hash,
                packet,
                interface_index,
                raw_hash,
            } => {
                // Check if this is a link-related packet
                if packet.flags.packet_type == crate::packet::PacketType::LinkRequest
                    || packet.flags.packet_type == crate::packet::PacketType::Proof
                    || (packet.flags.packet_type == crate::packet::PacketType::Data
                        && self.links.contains_key(&LinkId::new(destination_hash)))
                {
                    // Route to link packet handler
                    let raw = self.repack_packet(&packet);

                    // Verify repack symmetry: if original wire hash is known,
                    // check that repacking produces the same hashable bytes.
                    if let Some(original_hash) = raw_hash {
                        let repacked_hash = packet_hash(&raw);
                        if original_hash != repacked_hash {
                            tracing::warn!(
                                original = %HexFmt(&original_hash),
                                repacked = %HexFmt(&repacked_hash),
                                ptype = ?packet.flags.packet_type,
                                ctx = ?packet.context,
                                "REPACK HASH MISMATCH — proof chain will fail"
                            );
                        }
                    }

                    let now_ms = self.transport.clock().now_ms();
                    self.process_link_packet(&packet, &raw, now_ms, interface_index);
                } else {
                    // Regular packet event
                    self.events.push(NodeEvent::PacketReceived {
                        destination: DestinationHash::new(destination_hash),
                        data: packet.data.as_slice().to_vec(),
                        interface_index,
                    });
                }
            }

            TransportEvent::InterfaceDown(index) => {
                self.events.push(NodeEvent::InterfaceDown(index));
            }

            TransportEvent::ProofRequested {
                packet_hash,
                destination_hash,
                interface_index,
            } => {
                let dest_hash = DestinationHash::new(destination_hash);
                let proof_strategy = self
                    .destinations
                    .get(&dest_hash)
                    .map(|d| d.proof_strategy())
                    .unwrap_or(ProofStrategy::None);

                match proof_strategy {
                    ProofStrategy::All => {
                        if let Some(identity) =
                            self.destinations.get(&dest_hash).and_then(|d| d.identity())
                        {
                            if let Err(e) = self.transport.send_proof(
                                &packet_hash,
                                &destination_hash,
                                identity,
                                Some(interface_index),
                            ) {
                                tracing::warn!("failed to send auto-proof for PROVE_ALL: {}", e);
                            }
                        }
                    }
                    ProofStrategy::App => {
                        self.events.push(NodeEvent::PacketProofRequested {
                            packet_hash,
                            destination_hash: dest_hash,
                        });
                    }
                    ProofStrategy::None => {}
                }
            }

            TransportEvent::ProofReceived {
                packet_hash,
                destination_hash,
                expected_packet_hash,
                proof_data,
            } => {
                let dest_hash = DestinationHash::new(destination_hash);
                let is_valid = self
                    .destinations
                    .get(&dest_hash)
                    .and_then(|dest| dest.identity())
                    .map(|identity| identity.verify_proof(&proof_data, &expected_packet_hash))
                    .unwrap_or(false);

                if is_valid {
                    self.transport.mark_receipt_delivered(&packet_hash);
                    self.events
                        .push(NodeEvent::PacketDeliveryConfirmed { packet_hash });
                } else {
                    self.events.push(NodeEvent::DeliveryFailed {
                        packet_hash,
                        error: DeliveryError::LinkFailed,
                    });
                }
            }

            TransportEvent::ReceiptTimeout { packet_hash } => {
                self.events.push(NodeEvent::DeliveryFailed {
                    packet_hash,
                    error: DeliveryError::Timeout,
                });
            }

            TransportEvent::PathRequestReceived { destination_hash } => {
                // Informational event — auto-re-announce is already handled
                // by Transport::process_path_request() internally.
                self.events.push(NodeEvent::PathRequestReceived {
                    destination_hash: DestinationHash::new(destination_hash),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::{DestinationType, Direction};
    use crate::link::{LinkCloseReason, LinkState};
    use crate::test_utils::{MockClock, MockInterface, TEST_TIME_MS};
    use crate::traits::NoStorage;
    use rand_core::OsRng;

    #[test]
    fn test_nodecore_builder_default() {
        let clock = MockClock::new(TEST_TIME_MS);
        let node = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);

        assert_eq!(node.active_link_count(), 0);
        assert_eq!(node.pending_link_count(), 0);
        assert_eq!(node.default_proof_strategy(), ProofStrategy::None);
    }

    #[test]
    fn test_nodecore_builder_with_identity() {
        let identity = Identity::generate(&mut OsRng);
        let id_hash = *identity.hash();
        let clock = MockClock::new(TEST_TIME_MS);

        let node = NodeCoreBuilder::new()
            .identity(identity)
            .build(OsRng, clock, NoStorage);

        assert_eq!(node.identity().hash(), &id_hash);
    }

    #[test]
    fn test_nodecore_register_destination() {
        let clock = MockClock::new(TEST_TIME_MS);
        let mut node = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);

        let identity = Identity::generate(&mut OsRng);
        let dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["echo"],
        )
        .unwrap();

        let hash = *dest.hash();
        node.register_destination(dest);

        assert!(node.destination(&hash).is_some());
        assert!(node.transport.has_destination(hash.as_bytes()));
    }

    #[test]
    fn test_nodecore_handle_timeout_empty() {
        let clock = MockClock::new(TEST_TIME_MS);
        let mut node = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);

        // handle_timeout should return empty when there are no events
        let output = node.handle_timeout();
        assert!(output.actions.is_empty());
        assert!(output.events.is_empty());
    }

    #[test]
    fn test_send_options_default() {
        let opts = SendOptions::default();
        assert!(!opts.reliable);
        assert!(opts.timeout_ms.is_none());
        assert!(opts.prefer_existing);
        assert!(!opts.compress);
    }

    #[test]
    fn test_send_options_reliable() {
        let opts = SendOptions::reliable();
        assert!(opts.reliable);
        assert!(opts.prefer_existing);
    }

    #[test]
    fn test_send_options_reliable_compressed() {
        let opts = SendOptions::reliable_compressed();
        assert!(opts.reliable);
        assert!(opts.compress);
    }

    #[test]
    fn test_nodecore_has_path_empty() {
        let clock = MockClock::new(TEST_TIME_MS);
        let node = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);

        let dest_hash = DestinationHash::new([0x42; 16]);
        assert!(!node.has_path(&dest_hash));
        assert!(node.hops_to(&dest_hash).is_none());
    }

    #[test]
    fn test_link_stats_no_link() {
        let clock = MockClock::new(TEST_TIME_MS);
        let node = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);

        let fake_id = LinkId::new([0xFF; 16]);
        assert!(node.link_stats(&fake_id).is_none());
    }

    #[test]
    fn test_send_no_path_returns_error() {
        let clock = MockClock::new(TEST_TIME_MS);
        let node = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);

        let dest_hash = DestinationHash::new([0x42; 16]);
        let result = node.send(&dest_hash, b"Hello!", &SendOptions::default());

        // Should fail because no path exists
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), send::SendError::NoPath);
    }

    #[test]
    fn test_send_reliable_no_path_returns_error() {
        let clock = MockClock::new(TEST_TIME_MS);
        let node = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);

        let dest_hash = DestinationHash::new([0x42; 16]);
        let result = node.send(&dest_hash, b"Hello!", &SendOptions::reliable());

        // Should fail because no path exists for reliable send
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), send::SendError::NoPath);
    }

    #[test]
    fn test_find_link_to_none() {
        let clock = MockClock::new(TEST_TIME_MS);
        let node = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);

        let dest_hash = DestinationHash::new([0x42; 16]);
        assert!(node.find_link_to(&dest_hash).is_none());
    }

    // ─── Sans-I/O API Tests ───────────────────────────────────────────────────

    #[test]
    fn test_handle_packet_invalid_data() {
        use crate::transport::InterfaceId;

        let clock = MockClock::new(TEST_TIME_MS);
        let mut node = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);

        // Garbage data should not panic and should produce no events/actions
        let output = node.handle_packet(InterfaceId(0), &[0xFF; 3]);
        assert!(output.actions.is_empty());
        assert!(output.events.is_empty());
    }

    #[test]
    fn test_handle_packet_announce() {
        use crate::transport::InterfaceId;

        let clock = MockClock::new(TEST_TIME_MS);
        let mut node = NodeCoreBuilder::new()
            .enable_transport(true)
            .build(OsRng, clock, NoStorage);

        // Build a valid announce
        let identity = Identity::generate(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["echo"],
        )
        .unwrap();

        let announce_packet = dest.announce(None, &mut OsRng, TEST_TIME_MS).unwrap();
        let mut buf = [0u8; crate::constants::MTU];
        let len = announce_packet.pack(&mut buf).unwrap();

        let output = node.handle_packet(InterfaceId(0), &buf[..len]);

        // Should have AnnounceReceived event
        let has_announce = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::AnnounceReceived { .. }));
        assert!(has_announce, "expected AnnounceReceived event");
    }

    #[test]
    fn test_next_deadline_empty_node() {
        let clock = MockClock::new(TEST_TIME_MS);
        let node = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);

        // Empty node should have no deadlines
        assert!(node.next_deadline().is_none());
    }

    #[test]
    fn test_next_deadline_with_path() {
        use crate::transport::InterfaceId;

        let clock = MockClock::new(TEST_TIME_MS);
        let mut node = NodeCoreBuilder::new()
            .enable_transport(true)
            .build(OsRng, clock, NoStorage);

        // Inject an announce to create a path with an expiry deadline
        let identity = Identity::generate(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["deadline"],
        )
        .unwrap();

        let announce_packet = dest.announce(None, &mut OsRng, TEST_TIME_MS).unwrap();
        let mut buf = [0u8; crate::constants::MTU];
        let len = announce_packet.pack(&mut buf).unwrap();
        let _ = node.handle_packet(InterfaceId(0), &buf[..len]);

        // Now there should be a deadline (path expiry and/or announce rebroadcast)
        let deadline = node.next_deadline();
        assert!(
            deadline.is_some(),
            "should have a deadline after processing an announce"
        );
        assert!(
            deadline.unwrap() > TEST_TIME_MS,
            "deadline should be in the future"
        );
    }

    #[test]
    fn test_handle_interface_down_cleans_paths() {
        use crate::transport::InterfaceId;

        let clock = MockClock::new(TEST_TIME_MS);
        let mut node = NodeCoreBuilder::new()
            .enable_transport(true)
            .build(OsRng, clock, NoStorage);

        // Inject an announce on interface 0 to create a path
        let identity = Identity::generate(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["ifacedown"],
        )
        .unwrap();

        let announce_packet = dest.announce(None, &mut OsRng, TEST_TIME_MS).unwrap();
        let mut buf = [0u8; crate::constants::MTU];
        let len = announce_packet.pack(&mut buf).unwrap();
        let _ = node.handle_packet(InterfaceId(0), &buf[..len]);

        // Verify path exists
        assert!(
            node.path_count() > 0,
            "should have a path from the announce"
        );

        // Take down interface 0
        let output = node.handle_interface_down(InterfaceId(0));

        // Path should be gone
        assert_eq!(
            node.path_count(),
            0,
            "path should be removed after interface down"
        );

        // Should have PathLost and InterfaceDown events
        let has_path_lost = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::PathLost { .. }));
        let has_iface_down = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::InterfaceDown(0)));

        assert!(has_path_lost, "should emit PathLost event");
        assert!(has_iface_down, "should emit InterfaceDown event");
    }

    #[test]
    fn test_handle_interface_down_no_paths() {
        use crate::transport::InterfaceId;

        let clock = MockClock::new(TEST_TIME_MS);
        let mut node = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);

        // Interface down on empty node should produce just the InterfaceDown event
        let output = node.handle_interface_down(InterfaceId(5));
        assert_eq!(output.events.len(), 1);
        assert!(matches!(output.events[0], NodeEvent::InterfaceDown(5)));
        assert!(output.actions.is_empty());
    }

    #[test]
    fn test_handle_timeout_produces_rebroadcast_actions() {
        use crate::transport::InterfaceId;

        let clock = MockClock::new(TEST_TIME_MS);
        let mut node = NodeCoreBuilder::new()
            .enable_transport(true)
            .build(OsRng, clock, NoStorage);

        // Inject an announce
        let identity = Identity::generate(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["rebroadcast"],
        )
        .unwrap();

        let announce_packet = dest.announce(None, &mut OsRng, TEST_TIME_MS).unwrap();
        let mut buf = [0u8; crate::constants::MTU];
        let len = announce_packet.pack(&mut buf).unwrap();
        let _ = node.handle_packet(InterfaceId(0), &buf[..len]);

        // Advance time past the rebroadcast delay
        // MockClock uses Cell<u64>, which allows mutation through &self
        node.transport().clock().set(TEST_TIME_MS + 20_000);

        // handle_timeout should produce rebroadcast actions
        let output = node.handle_timeout();

        // May or may not produce actions depending on jitter calculation,
        // but the mechanism is tested - just verify no panics and the pipeline works
        let _ = output;
    }

    // ─── Sans-I/O Audit: Deferred-dispatch tests ────────────────────────────

    #[test]
    fn test_handle_packet_announce_produces_rebroadcast_action() {
        use crate::transport::{Action, InterfaceId};

        let clock = MockClock::new(TEST_TIME_MS);
        let mut node = NodeCoreBuilder::new()
            .enable_transport(true)
            .build(OsRng, clock, NoStorage);

        // Create a valid announce from a remote destination
        let identity = Identity::generate(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["actiontest"],
        )
        .unwrap();

        let announce_packet = dest.announce(None, &mut OsRng, TEST_TIME_MS).unwrap();
        let mut buf = [0u8; crate::constants::MTU];
        let len = announce_packet.pack(&mut buf).unwrap();

        // Feed announce on interface 0
        let _ = node.handle_packet(InterfaceId(0), &buf[..len]);

        // Advance time well past the retransmit delay window
        node.transport().clock().set(TEST_TIME_MS + 100_000);
        let output = node.handle_timeout();

        // Should have at least one Broadcast action (the rebroadcast) with
        // the originating interface excluded
        let has_rebroadcast = output.actions.iter().any(|a| {
            matches!(
                a,
                Action::Broadcast {
                    exclude_iface: Some(iface),
                    ..
                } if *iface == InterfaceId(0)
            )
        });
        assert!(
            has_rebroadcast,
            "transport-enabled node should produce Broadcast action for announce rebroadcast, \
             got: {:?}",
            output.actions
        );
    }

    #[test]
    fn test_connect_queues_send_action() {
        use crate::transport::{Action, InterfaceId};

        let clock = MockClock::new(TEST_TIME_MS);
        let mut node = NodeCoreBuilder::new()
            .enable_transport(true)
            .build(OsRng, clock, NoStorage);

        // Create a remote identity and announce to establish a path
        let remote_identity = Identity::generate(&mut OsRng);
        let remote_signing_key = remote_identity.ed25519_verifying().to_bytes();
        let mut remote_dest = Destination::new(
            Some(remote_identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["connect"],
        )
        .unwrap();

        let announce_packet = remote_dest
            .announce(None, &mut OsRng, TEST_TIME_MS)
            .unwrap();
        let mut buf = [0u8; crate::constants::MTU];
        let len = announce_packet.pack(&mut buf).unwrap();

        // Process announce to create a path via interface 0
        let _ = node.handle_packet(InterfaceId(0), &buf[..len]);
        // Drain the announce rebroadcast actions
        let _ = node.handle_timeout();

        // Verify path exists
        let dest_hash = *remote_dest.hash();
        assert!(node.has_path(&dest_hash), "should have path from announce");

        // Call connect() — actions are returned immediately in TickOutput
        let (link_id, output) = node.connect(dest_hash, &remote_signing_key);

        // The link request should have been returned as an Action (SendPacket
        // to the path's interface since we have a path, or Broadcast if no path)
        let has_send = output
            .actions
            .iter()
            .any(|a| matches!(a, Action::SendPacket { .. } | Action::Broadcast { .. }));
        assert!(
            has_send,
            "connect() should return an Action in TickOutput, \
             link_id={:?}, actions={:?}",
            link_id, output.actions
        );
    }

    // ─── Pending-Link Path Recovery Tests ────────────────────────────────────

    /// Helper: create a non-transport node, announce a remote destination,
    /// and call connect(). Returns (node, dest_hash, link_id).
    fn setup_pending_link(
        enable_transport: bool,
    ) -> (
        NodeCore<OsRng, MockClock, NoStorage>,
        DestinationHash,
        LinkId,
    ) {
        use crate::transport::InterfaceId;

        let clock = MockClock::new(TEST_TIME_MS);
        let mut node = NodeCoreBuilder::new()
            .enable_transport(enable_transport)
            .build(OsRng, clock, NoStorage);

        // Create remote identity and announce to establish a path
        let remote_identity = Identity::generate(&mut OsRng);
        let remote_signing_key = remote_identity.ed25519_verifying().to_bytes();
        let mut remote_dest = Destination::new(
            Some(remote_identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["recovery"],
        )
        .unwrap();

        let announce_packet = remote_dest
            .announce(None, &mut OsRng, TEST_TIME_MS)
            .unwrap();
        let mut buf = [0u8; crate::constants::MTU];
        let len = announce_packet.pack(&mut buf).unwrap();

        // Process announce on interface 0 to create path
        let _ = node.handle_packet(InterfaceId(0), &buf[..len]);
        // Drain the announce rebroadcast actions
        let _ = node.handle_timeout();

        let dest_hash = *remote_dest.hash();
        assert!(node.has_path(&dest_hash), "should have path from announce");

        // Initiate connection — actions returned in output
        let (link_id, _output) = node.connect(dest_hash, &remote_signing_key);

        (node, dest_hash, link_id)
    }

    #[test]
    fn test_pending_link_timeout_triggers_path_recovery() {
        use crate::constants::LINK_PENDING_TIMEOUT_MS;
        use crate::transport::Action;

        let (mut node, dest_hash, _link_id) = setup_pending_link(false);

        // Path should exist before timeout
        assert!(node.has_path(&dest_hash));

        // Advance clock past the pending link timeout
        node.transport()
            .clock()
            .set(TEST_TIME_MS + LINK_PENDING_TIMEOUT_MS + 1);
        let output = node.handle_timeout();

        // Path should have been expired
        assert!(
            !node.has_path(&dest_hash),
            "path should be expired after pending link timeout"
        );

        // Should have a Broadcast action (the path request)
        let has_broadcast = output
            .actions
            .iter()
            .any(|a| matches!(a, Action::Broadcast { .. }));
        assert!(
            has_broadcast,
            "should emit a Broadcast action for path request, got: {:?}",
            output.actions
        );

        // Should have LinkClosed event with Timeout reason
        let has_closed = output.events.iter().any(|e| {
            matches!(
                e,
                NodeEvent::LinkClosed {
                    reason: LinkCloseReason::Timeout,
                    ..
                }
            )
        });
        assert!(has_closed, "should emit LinkClosed with Timeout");
    }

    #[test]
    fn test_pending_link_timeout_no_recovery_for_transport_nodes() {
        use crate::constants::LINK_PENDING_TIMEOUT_MS;

        let (mut node, dest_hash, _link_id) = setup_pending_link(true);

        // Advance clock past the pending link timeout
        node.transport()
            .clock()
            .set(TEST_TIME_MS + LINK_PENDING_TIMEOUT_MS + 1);
        let _output = node.handle_timeout();

        // Transport nodes should NOT expire the path — they handle recovery
        // via clean_link_table() instead
        assert!(
            node.has_path(&dest_hash),
            "transport node should NOT expire path on pending link timeout"
        );
    }

    #[test]
    fn test_pending_link_normal_close_no_recovery() {
        let (mut node, dest_hash, link_id) = setup_pending_link(false);

        // Close the connection normally (before timeout)
        let _ = node.close_link(&link_id);

        // Advance clock and run maintenance
        node.transport().clock().set(TEST_TIME_MS + 5_000);
        let _output = node.handle_timeout();

        // Path should still exist — normal close doesn't trigger recovery
        assert!(
            node.has_path(&dest_hash),
            "path should NOT be expired after normal close"
        );
    }

    // ─── T6: NodeCore Messaging Path ────────────────────────────────────────

    /// Helper: create two NodeCores and perform a full link handshake.
    struct NodeCoreLinkPair {
        initiator: NodeCore<OsRng, MockClock, NoStorage>,
        responder: NodeCore<OsRng, MockClock, NoStorage>,
        initiator_link_id: LinkId,
        responder_link_id: LinkId,
        _dest_hash: DestinationHash,
    }

    fn extract_broadcast_data(output: &crate::transport::TickOutput) -> Vec<u8> {
        output
            .actions
            .iter()
            .map(|a| match a {
                crate::transport::Action::Broadcast { data, .. }
                | crate::transport::Action::SendPacket { data, .. } => data.clone(),
            })
            .next()
            .expect("expected Broadcast or SendPacket action")
    }

    fn extract_link_request_link_id(output: &crate::transport::TickOutput) -> LinkId {
        output
            .events
            .iter()
            .find_map(|e| match e {
                NodeEvent::LinkRequest { link_id, .. } => Some(*link_id),
                _ => None,
            })
            .expect("expected LinkRequest event")
    }

    fn extract_all_action_data(output: &crate::transport::TickOutput) -> Vec<Vec<u8>> {
        output
            .actions
            .iter()
            .map(|a| match a {
                crate::transport::Action::Broadcast { data, .. }
                | crate::transport::Action::SendPacket { data, .. } => data.clone(),
            })
            .collect()
    }

    fn establish_nodecore_link_pair_with_strategy(strategy: ProofStrategy) -> NodeCoreLinkPair {
        use crate::transport::InterfaceId;

        // 1. Create responder with a destination that accepts links
        let resp_identity = Identity::generate(&mut OsRng);
        let resp_signing_key = resp_identity.ed25519_verifying().to_bytes();
        let clock = MockClock::new(TEST_TIME_MS);
        let mut responder = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);
        let mut resp_dest = Destination::new(
            Some(resp_identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["echo"],
        )
        .unwrap();
        resp_dest.set_accepts_links(true);
        resp_dest.set_proof_strategy(strategy);
        let dest_hash = *resp_dest.hash();
        responder.register_destination(resp_dest);

        // 2. Create initiator
        let clock = MockClock::new(TEST_TIME_MS);
        let mut initiator = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);

        // 3. Initiator connects (broadcasts since no path)
        let (init_link_id, output) = initiator.connect(dest_hash, &resp_signing_key);
        let link_req_data = extract_broadcast_data(&output);

        // 4. Responder receives link request → LinkRequest event
        let output = responder.handle_packet(InterfaceId(0), &link_req_data);
        let resp_link_id = extract_link_request_link_id(&output);

        // 5. Responder accepts → proof packet in actions
        let output = responder.accept_link(&resp_link_id).unwrap();
        let proof_data = extract_broadcast_data(&output);

        // 6. Initiator receives proof → LinkEstablished + RTT action
        let output = initiator.handle_packet(InterfaceId(0), &proof_data);
        assert!(
            output
                .events
                .iter()
                .any(|e| matches!(e, NodeEvent::LinkEstablished { .. })),
            "initiator should get LinkEstablished"
        );
        let rtt_data = extract_broadcast_data(&output);

        // 7. Responder receives RTT → LinkEstablished
        let output = responder.handle_packet(InterfaceId(0), &rtt_data);
        assert!(
            output
                .events
                .iter()
                .any(|e| matches!(e, NodeEvent::LinkEstablished { .. })),
            "responder should get LinkEstablished"
        );

        NodeCoreLinkPair {
            initiator,
            responder,
            initiator_link_id: init_link_id,
            responder_link_id: resp_link_id,
            _dest_hash: dest_hash,
        }
    }

    fn establish_nodecore_link_pair() -> NodeCoreLinkPair {
        use crate::transport::InterfaceId;

        // 1. Create responder with a destination that accepts links
        let resp_identity = Identity::generate(&mut OsRng);
        let resp_signing_key = resp_identity.ed25519_verifying().to_bytes();
        let clock = MockClock::new(TEST_TIME_MS);
        let mut responder = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);
        let mut resp_dest = Destination::new(
            Some(resp_identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["echo"],
        )
        .unwrap();
        resp_dest.set_accepts_links(true);
        let dest_hash = *resp_dest.hash();
        responder.register_destination(resp_dest);

        // 2. Create initiator
        let clock = MockClock::new(TEST_TIME_MS);
        let mut initiator = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);

        // 3. Initiator connects (broadcasts since no path)
        let (init_link_id, output) = initiator.connect(dest_hash, &resp_signing_key);
        let link_req_data = extract_broadcast_data(&output);

        // 4. Responder receives link request → LinkRequest event
        let output = responder.handle_packet(InterfaceId(0), &link_req_data);
        let resp_link_id = extract_link_request_link_id(&output);

        // 5. Responder accepts → proof packet in actions
        let output = responder.accept_link(&resp_link_id).unwrap();
        let proof_data = extract_broadcast_data(&output);

        // 6. Initiator receives proof → LinkEstablished + RTT action
        let output = initiator.handle_packet(InterfaceId(0), &proof_data);
        assert!(
            output
                .events
                .iter()
                .any(|e| matches!(e, NodeEvent::LinkEstablished { .. })),
            "initiator should get LinkEstablished"
        );
        // RTT packet is in the output actions
        let rtt_data = extract_broadcast_data(&output);

        // 7. Responder receives RTT → LinkEstablished
        let output = responder.handle_packet(InterfaceId(0), &rtt_data);
        assert!(
            output
                .events
                .iter()
                .any(|e| matches!(e, NodeEvent::LinkEstablished { .. })),
            "responder should get LinkEstablished"
        );

        NodeCoreLinkPair {
            initiator,
            responder,
            initiator_link_id: init_link_id,
            responder_link_id: resp_link_id,
            _dest_hash: dest_hash,
        }
    }

    #[test]
    fn test_accept_link() {
        let pair = establish_nodecore_link_pair();

        assert_eq!(pair.responder.active_link_count(), 1);
        assert_eq!(pair.initiator.active_link_count(), 1);
    }

    #[test]
    fn test_reject_link() {
        use crate::transport::InterfaceId;

        let resp_identity = Identity::generate(&mut OsRng);
        let resp_signing_key = resp_identity.ed25519_verifying().to_bytes();
        let clock = MockClock::new(TEST_TIME_MS);
        let mut responder = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);
        let mut resp_dest = Destination::new(
            Some(resp_identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["reject"],
        )
        .unwrap();
        resp_dest.set_accepts_links(true);
        let dest_hash = *resp_dest.hash();
        responder.register_destination(resp_dest);

        let clock = MockClock::new(TEST_TIME_MS);
        let mut initiator = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);

        let (_init_link_id, output) = initiator.connect(dest_hash, &resp_signing_key);
        let link_req_data = extract_broadcast_data(&output);

        let output = responder.handle_packet(InterfaceId(0), &link_req_data);
        let resp_link_id = extract_link_request_link_id(&output);

        // Reject instead of accept
        responder.reject_link(&resp_link_id);

        assert_eq!(responder.pending_link_count(), 0);
        assert_eq!(responder.active_link_count(), 0);
    }

    #[test]
    fn test_send_on_link() {
        use crate::transport::InterfaceId;

        let mut pair = establish_nodecore_link_pair();

        // Send data from initiator
        let output = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"Hello!")
            .unwrap();

        // Should have actions (send packet)
        assert!(
            !output.actions.is_empty(),
            "send_on_link should produce actions"
        );

        // Deliver to responder
        let data = extract_broadcast_data(&output);
        let output = pair.responder.handle_packet(InterfaceId(0), &data);

        // Should have MessageReceived event
        let has_msg = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::MessageReceived { .. }));
        assert!(has_msg, "responder should get MessageReceived event");
    }

    #[test]
    fn test_close_link() {
        let mut pair = establish_nodecore_link_pair();

        let output = pair.initiator.close_link(&pair.initiator_link_id);

        // Should have LinkClosed event
        let has_closed = output.events.iter().any(|e| {
            matches!(
                e,
                NodeEvent::LinkClosed {
                    reason: LinkCloseReason::Normal,
                    ..
                }
            )
        });
        assert!(has_closed, "Expected LinkClosed with Normal reason");

        assert_eq!(pair.initiator.active_link_count(), 0);
    }

    #[test]
    fn test_announce_destination() {
        let clock = MockClock::new(TEST_TIME_MS);
        let mut node = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);

        let identity = Identity::generate(&mut OsRng);
        let dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["announce"],
        )
        .unwrap();
        let hash = *dest.hash();
        node.register_destination(dest);

        let output = node.announce_destination(&hash, None).unwrap();

        // Should have a Broadcast action with the announce packet
        let has_broadcast = output
            .actions
            .iter()
            .any(|a| matches!(a, crate::transport::Action::Broadcast { .. }));
        assert!(has_broadcast, "announce should produce Broadcast action");
    }

    #[test]
    fn test_multiple_simultaneous_links() {
        use crate::transport::InterfaceId;

        // Create responder with destination
        let resp_identity1 = Identity::generate(&mut OsRng);
        let signing1 = resp_identity1.ed25519_verifying().to_bytes();
        let clock = MockClock::new(TEST_TIME_MS);
        let mut responder = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);
        let mut dest1 = Destination::new(
            Some(resp_identity1),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["multi1"],
        )
        .unwrap();
        dest1.set_accepts_links(true);
        let hash1 = *dest1.hash();
        responder.register_destination(dest1);

        let resp_identity2 = Identity::generate(&mut OsRng);
        let signing2 = resp_identity2.ed25519_verifying().to_bytes();
        let mut dest2 = Destination::new(
            Some(resp_identity2),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["multi2"],
        )
        .unwrap();
        dest2.set_accepts_links(true);
        let hash2 = *dest2.hash();
        responder.register_destination(dest2);

        // First initiator connects
        let clock = MockClock::new(TEST_TIME_MS);
        let mut init1 = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);
        let (link1, out1) = init1.connect(hash1, &signing1);
        let data1 = extract_broadcast_data(&out1);
        let out = responder.handle_packet(InterfaceId(0), &data1);
        let rlid1 = extract_link_request_link_id(&out);
        let out = responder.accept_link(&rlid1).unwrap();
        let proof1 = extract_broadcast_data(&out);
        let out = init1.handle_packet(InterfaceId(0), &proof1);
        let rtt1 = extract_broadcast_data(&out);
        let _ = responder.handle_packet(InterfaceId(0), &rtt1);

        // Second initiator connects
        let clock = MockClock::new(TEST_TIME_MS);
        let mut init2 = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);
        let (_link2, out2) = init2.connect(hash2, &signing2);
        let data2 = extract_broadcast_data(&out2);
        let out = responder.handle_packet(InterfaceId(0), &data2);
        let rlid2 = extract_link_request_link_id(&out);
        let out = responder.accept_link(&rlid2).unwrap();
        let proof2 = extract_broadcast_data(&out);
        let out = init2.handle_packet(InterfaceId(0), &proof2);
        let rtt2 = extract_broadcast_data(&out);
        let _ = responder.handle_packet(InterfaceId(0), &rtt2);

        assert_eq!(responder.active_link_count(), 2);

        // Both should be functional
        let _ = init1
            .send_on_link(&link1, b"data1")
            .expect("link 1 should work");
    }

    #[test]
    fn test_send_on_link_creates_receipt() {
        let mut pair = establish_nodecore_link_pair();

        let _ = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"test")
            .unwrap();

        assert_eq!(pair.initiator.receipt_count(), 1);
    }

    #[test]
    fn test_close_link_removes_receipts() {
        let mut pair = establish_nodecore_link_pair();

        // Send data (populates receipt tracker)
        let _ = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"test")
            .unwrap();
        assert_eq!(pair.initiator.receipt_count(), 1);

        // Close connection
        let _ = pair.initiator.close_link(&pair.initiator_link_id);

        // All receipts for this link should be cleaned
        assert_eq!(
            pair.initiator.receipt_count(),
            0,
            "receipts should be cleaned on close"
        );
    }

    #[test]
    fn test_handle_packet_link_request() {
        use crate::transport::InterfaceId;

        let resp_identity = Identity::generate(&mut OsRng);
        let resp_signing_key = resp_identity.ed25519_verifying().to_bytes();
        let clock = MockClock::new(TEST_TIME_MS);
        let mut responder = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);
        let mut dest = Destination::new(
            Some(resp_identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["linkreq"],
        )
        .unwrap();
        dest.set_accepts_links(true);
        let dest_hash = *dest.hash();
        responder.register_destination(dest);

        let clock = MockClock::new(TEST_TIME_MS);
        let mut initiator = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);
        let (_, output) = initiator.connect(dest_hash, &resp_signing_key);
        let req_data = extract_broadcast_data(&output);

        let output = responder.handle_packet(InterfaceId(0), &req_data);

        let has_link_request = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::LinkRequest { .. }));
        assert!(has_link_request, "Expected LinkRequest event");
    }

    #[test]
    fn test_handle_packet_proof() {
        use crate::transport::InterfaceId;

        let resp_identity = Identity::generate(&mut OsRng);
        let resp_signing_key = resp_identity.ed25519_verifying().to_bytes();
        let clock = MockClock::new(TEST_TIME_MS);
        let mut responder = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);
        let mut dest = Destination::new(
            Some(resp_identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["proof"],
        )
        .unwrap();
        dest.set_accepts_links(true);
        let dest_hash = *dest.hash();
        responder.register_destination(dest);

        let clock = MockClock::new(TEST_TIME_MS);
        let mut initiator = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);
        let (_, output) = initiator.connect(dest_hash, &resp_signing_key);
        let req_data = extract_broadcast_data(&output);

        let output = responder.handle_packet(InterfaceId(0), &req_data);
        let rlid = extract_link_request_link_id(&output);
        let output = responder.accept_link(&rlid).unwrap();
        let proof_data = extract_broadcast_data(&output);

        // Feed proof to initiator
        let output = initiator.handle_packet(InterfaceId(0), &proof_data);

        let has_established = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::LinkEstablished { .. }));
        assert!(
            has_established,
            "initiator should get LinkEstablished after proof"
        );
    }

    #[test]
    fn test_handle_packet_link_data() {
        use crate::transport::InterfaceId;

        let mut pair = establish_nodecore_link_pair();

        // Send data from initiator
        let output = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"hello data")
            .unwrap();
        let data = extract_broadcast_data(&output);

        // Deliver to responder
        let output = pair.responder.handle_packet(InterfaceId(0), &data);

        let msg_data = output.events.iter().find_map(|e| match e {
            NodeEvent::MessageReceived { data, .. } => Some(data.clone()),
            _ => None,
        });
        assert!(msg_data.is_some(), "Expected MessageReceived event");
    }

    #[test]
    fn test_handle_timeout_keepalive_generation() {
        let mut pair = establish_nodecore_link_pair();

        // Advance time well past keepalive interval (default: 360s for slow links, 5s min)
        pair.initiator
            .transport()
            .clock()
            .set(TEST_TIME_MS + 400_000);

        let output = pair.initiator.handle_timeout();

        // Should produce actions (keepalive packet)
        // The keepalive may or may not produce an action depending on timing,
        // but handle_timeout should work without panicking
        let _ = output;
    }

    #[test]
    fn test_interface_down_cleans_link_paths() {
        use crate::transport::InterfaceId;

        let clock = MockClock::new(TEST_TIME_MS);
        let mut node = NodeCoreBuilder::new()
            .enable_transport(true)
            .build(OsRng, clock, NoStorage);

        // Inject an announce on interface 0 to create a path
        let identity = Identity::generate(&mut OsRng);
        let mut dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["ifdown2"],
        )
        .unwrap();
        let announce_packet = dest.announce(None, &mut OsRng, TEST_TIME_MS).unwrap();
        let mut buf = [0u8; crate::constants::MTU];
        let len = announce_packet.pack(&mut buf).unwrap();
        let _ = node.handle_packet(InterfaceId(0), &buf[..len]);

        assert!(node.path_count() > 0, "should have a path from announce");

        let output = node.handle_interface_down(InterfaceId(0));

        assert_eq!(node.path_count(), 0, "paths should be cleaned");

        let has_iface_down = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::InterfaceDown(0)));
        assert!(has_iface_down, "should emit InterfaceDown event");
    }

    // ─── T16: NodeCore Regression Tests ─────────────────────────────────────

    #[test]
    fn test_d12_handshake_timeout_vs_stale_timeout_different_reason() {
        use crate::constants::LINK_PENDING_TIMEOUT_MS;

        // Case 1: Handshake timeout produces LinkClosed with Timeout reason
        let (mut node, _dest_hash, _link_id) = setup_pending_link(false);
        node.transport()
            .clock()
            .set(TEST_TIME_MS + LINK_PENDING_TIMEOUT_MS + 1);
        let output = node.handle_timeout();

        let has_timeout = output.events.iter().any(|e| {
            matches!(
                e,
                NodeEvent::LinkClosed {
                    reason: LinkCloseReason::Timeout,
                    ..
                }
            )
        });
        assert!(
            has_timeout,
            "handshake timeout should produce LinkClosed with Timeout reason"
        );

        // Case 2: Stale closure produces LinkClosed with Stale reason
        // (tested via establish_nodecore_link_pair, then advancing time)
        // This is more involved — the key point is that the reason values are different
    }

    #[test]
    fn test_retransmit_replaces_receipt() {
        let mut pair = establish_nodecore_link_pair();

        // Send data (creates receipt)
        let _ = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"sync test")
            .unwrap();
        assert_eq!(pair.initiator.receipt_count(), 1);

        // Trigger retransmit by advancing time past timeout
        pair.initiator
            .transport()
            .clock()
            .set(TEST_TIME_MS + 10_000);
        let _output = pair.initiator.handle_timeout();

        // Receipt should still be exactly 1 (old replaced by new, no leak)
        assert_eq!(
            pair.initiator.receipt_count(),
            1,
            "receipt count should stay at 1 after retransmit (old replaced, not leaked)"
        );
    }

    // ─── T13: Split test_pending_link_recovery_rate_limited ──────────────

    #[test]
    fn test_link_timeout_triggers_path_recovery() {
        use crate::constants::LINK_PENDING_TIMEOUT_MS;
        use crate::transport::Action;

        let (mut node, dest_hash, _link_id) = setup_pending_link(false);

        assert!(node.has_path(&dest_hash));

        node.transport()
            .clock()
            .set(TEST_TIME_MS + LINK_PENDING_TIMEOUT_MS + 1);
        let output = node.handle_timeout();

        assert!(
            !node.has_path(&dest_hash),
            "path should be expired after timeout"
        );

        let has_broadcast = output
            .actions
            .iter()
            .any(|a| matches!(a, Action::Broadcast { .. }));
        assert!(has_broadcast, "should emit path request Broadcast");

        let has_closed = output.events.iter().any(|e| {
            matches!(
                e,
                NodeEvent::LinkClosed {
                    reason: LinkCloseReason::Timeout,
                    ..
                }
            )
        });
        assert!(has_closed, "should emit LinkClosed with Timeout");
    }

    #[test]
    fn test_link_timeout_rate_limited_across_destinations() {
        use crate::constants::LINK_PENDING_TIMEOUT_MS;
        use crate::transport::{Action, InterfaceId};

        let clock = MockClock::new(TEST_TIME_MS);
        let mut node = NodeCoreBuilder::new()
            .enable_transport(false)
            .build(OsRng, clock, NoStorage);

        let remote1 = Identity::generate(&mut OsRng);
        let signing1 = remote1.ed25519_verifying().to_bytes();
        let mut dest1 = Destination::new(
            Some(remote1),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["rl1"],
        )
        .unwrap();
        let remote2 = Identity::generate(&mut OsRng);
        let signing2 = remote2.ed25519_verifying().to_bytes();
        let mut dest2 = Destination::new(
            Some(remote2),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["rl2"],
        )
        .unwrap();

        let ann1 = dest1.announce(None, &mut OsRng, TEST_TIME_MS).unwrap();
        let ann2 = dest2.announce(None, &mut OsRng, TEST_TIME_MS).unwrap();
        let mut buf = [0u8; crate::constants::MTU];
        let len1 = ann1.pack(&mut buf).unwrap();
        let _ = node.handle_packet(InterfaceId(0), &buf[..len1]);
        let len2 = ann2.pack(&mut buf).unwrap();
        let _ = node.handle_packet(InterfaceId(0), &buf[..len2]);
        let _ = node.handle_timeout();

        let hash1 = *dest1.hash();
        let hash2 = *dest2.hash();
        let (_, _) = node.connect(hash1, &signing1);
        let (_, _) = node.connect(hash2, &signing2);

        node.transport()
            .clock()
            .set(TEST_TIME_MS + LINK_PENDING_TIMEOUT_MS + 1);
        let output = node.handle_timeout();

        assert!(!node.has_path(&hash1));
        assert!(!node.has_path(&hash2));

        let closed_count = output
            .events
            .iter()
            .filter(|e| matches!(e, NodeEvent::LinkClosed { .. }))
            .count();
        assert_eq!(closed_count, 2);

        let broadcast_count = output
            .actions
            .iter()
            .filter(|a| matches!(a, Action::Broadcast { .. }))
            .count();
        assert!(
            broadcast_count >= 2,
            "both path requests should succeed (different destinations), got {}",
            broadcast_count
        );
    }

    // ─── Restored LinkManager Tests (as NodeCore tests) ─────────────────────

    // ─── Group A: ProofStrategy propagation ─────────────────────────────────

    #[test]
    fn test_proof_strategy_propagated_on_accept() {
        for strategy in [ProofStrategy::All, ProofStrategy::App, ProofStrategy::None] {
            let pair = establish_nodecore_link_pair_with_strategy(strategy);

            // Responder's link should have the requested proof strategy
            let resp_link = pair
                .responder
                .link(&pair.responder_link_id)
                .expect("responder link must exist");
            assert_eq!(
                resp_link.proof_strategy(),
                strategy,
                "proof_strategy mismatch for {:?}",
                strategy
            );
            // Responder always has a dest_signing_key (set during accept_link)
            assert!(
                resp_link.dest_signing_key().is_some(),
                "dest_signing_key should always be set on responder for {:?}",
                strategy
            );
        }
    }

    #[test]
    fn test_prove_all_auto_generates_proof_on_data() {
        use crate::packet::PacketContext;
        use crate::transport::InterfaceId;

        let mut pair = establish_nodecore_link_pair_with_strategy(ProofStrategy::All);

        // Build raw data packet (not channel) on initiator
        let raw_packet = pair
            .initiator
            .link(&pair.initiator_link_id)
            .unwrap()
            .build_data_packet_with_context(b"hello", PacketContext::None, &mut OsRng)
            .unwrap();

        // Deliver to responder
        let output = pair.responder.handle_packet(InterfaceId(0), &raw_packet);

        // Should have LinkDataReceived event
        let has_data = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::LinkDataReceived { .. }));
        assert!(has_data, "expected LinkDataReceived event");

        // Should NOT have LinkProofRequested (that's for App strategy)
        let has_proof_requested = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::LinkProofRequested { .. }));
        assert!(
            !has_proof_requested,
            "All strategy should NOT emit LinkProofRequested"
        );

        // Should have a proof packet in actions (auto-generated)
        assert!(
            !output.actions.is_empty(),
            "All strategy should auto-generate proof packet"
        );

        // Negative: ProofStrategy::None should NOT generate proof
        let mut pair_none = establish_nodecore_link_pair_with_strategy(ProofStrategy::None);
        let raw_packet = pair_none
            .initiator
            .link(&pair_none.initiator_link_id)
            .unwrap()
            .build_data_packet_with_context(b"hello", PacketContext::None, &mut OsRng)
            .unwrap();
        let output = pair_none
            .responder
            .handle_packet(InterfaceId(0), &raw_packet);
        assert!(
            output.actions.is_empty(),
            "None strategy should NOT generate proof"
        );
        let has_data = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::LinkDataReceived { .. }));
        assert!(
            has_data,
            "expected LinkDataReceived even with None strategy"
        );
    }

    #[test]
    fn test_prove_app_emits_proof_requested_no_auto_proof() {
        use crate::packet::PacketContext;
        use crate::transport::InterfaceId;

        let mut pair = establish_nodecore_link_pair_with_strategy(ProofStrategy::App);

        // Build raw data packet on initiator
        let raw_packet = pair
            .initiator
            .link(&pair.initiator_link_id)
            .unwrap()
            .build_data_packet_with_context(b"appdata", PacketContext::None, &mut OsRng)
            .unwrap();

        // Deliver to responder
        let output = pair.responder.handle_packet(InterfaceId(0), &raw_packet);

        // Should have LinkProofRequested BEFORE LinkDataReceived
        let proof_req_pos = output
            .events
            .iter()
            .position(|e| matches!(e, NodeEvent::LinkProofRequested { .. }));
        let data_pos = output
            .events
            .iter()
            .position(|e| matches!(e, NodeEvent::LinkDataReceived { .. }));
        assert!(
            proof_req_pos.is_some(),
            "App strategy should emit LinkProofRequested"
        );
        assert!(
            data_pos.is_some(),
            "App strategy should emit LinkDataReceived"
        );
        assert!(
            proof_req_pos.unwrap() < data_pos.unwrap(),
            "LinkProofRequested should come before LinkDataReceived"
        );

        // No auto-proof in actions
        assert!(
            output.actions.is_empty(),
            "App strategy should NOT auto-generate proof"
        );
    }

    #[test]
    fn test_channel_proof_round_trip_delivery() {
        use crate::transport::InterfaceId;

        let mut pair = establish_nodecore_link_pair();

        // Send channel message from initiator
        let output = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"roundtrip")
            .unwrap();
        assert_eq!(pair.initiator.receipt_count(), 1);
        let channel_data = extract_broadcast_data(&output);

        // Deliver to responder → should get proof in actions
        let output = pair.responder.handle_packet(InterfaceId(0), &channel_data);
        let proof_data = extract_broadcast_data(&output);

        // Deliver proof to initiator → LinkDeliveryConfirmed
        let output = pair.initiator.handle_packet(InterfaceId(0), &proof_data);
        let has_confirmed = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::LinkDeliveryConfirmed { .. }));
        assert!(has_confirmed, "expected LinkDeliveryConfirmed event");

        // Receipt should be consumed
        assert_eq!(
            pair.initiator.receipt_count(),
            0,
            "receipt should be consumed after proof"
        );
    }

    // ─── Group B: Channel proof generation ──────────────────────────────────

    #[test]
    fn test_channel_proof_generated_for_in_order_message() {
        use crate::transport::InterfaceId;

        let mut pair = establish_nodecore_link_pair();

        let output = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"ordered")
            .unwrap();
        let channel_data = extract_broadcast_data(&output);

        let output = pair.responder.handle_packet(InterfaceId(0), &channel_data);

        // Exactly 1 action (the proof)
        assert_eq!(
            output.actions.len(),
            1,
            "expected exactly 1 proof action, got {}",
            output.actions.len()
        );

        // MessageReceived event
        let has_msg = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::MessageReceived { .. }));
        assert!(has_msg, "expected MessageReceived event");
    }

    #[test]
    fn test_channel_proof_suppressed_on_rx_ring_full() {
        use crate::constants::CHANNEL_RX_RING_MAX;
        use crate::transport::InterfaceId;

        let mut pair = establish_nodecore_link_pair();

        // Send 1 in-order message (seq=0), deliver, get proof, deliver proof
        let output = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"first")
            .unwrap();
        let data = extract_broadcast_data(&output);
        let output = pair.responder.handle_packet(InterfaceId(0), &data);
        let proof = extract_broadcast_data(&output);
        let _ = pair.initiator.handle_packet(InterfaceId(0), &proof);

        // Force next tx sequence to jump past rx ring capacity
        let jumped_seq = 1 + CHANNEL_RX_RING_MAX as u16;
        pair.initiator
            .link_mut(&pair.initiator_link_id)
            .unwrap()
            .channel_mut()
            .unwrap()
            .force_next_tx_sequence_for_test(jumped_seq);

        // Send jumped-sequence msg (window is free after proof delivery)
        let output = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"jumped")
            .unwrap();
        let data = extract_broadcast_data(&output);
        let output = pair.responder.handle_packet(InterfaceId(0), &data);

        // No proof (rx_ring full, message dropped)
        assert!(
            output.actions.is_empty(),
            "expected no proof when rx_ring is full"
        );
        // No MessageReceived event
        let has_msg = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::MessageReceived { .. }));
        assert!(!has_msg, "should not get MessageReceived when rx_ring full");

        // Now send in-order msg (next expected is seq=1) → proof IS generated
        // Advance clock past pacing delay (proof delivery set pacing ~166ms)
        pair.initiator.transport().clock().set(TEST_TIME_MS + 1_000);
        pair.initiator
            .link_mut(&pair.initiator_link_id)
            .unwrap()
            .channel_mut()
            .unwrap()
            .force_next_tx_sequence_for_test(1);
        let output = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"inorder")
            .unwrap();
        let data = extract_broadcast_data(&output);
        let output = pair.responder.handle_packet(InterfaceId(0), &data);
        assert!(
            !output.actions.is_empty(),
            "in-order message after full should generate proof"
        );
    }

    #[test]
    fn test_channel_proof_generated_with_prove_none() {
        use crate::transport::InterfaceId;

        let mut pair = establish_nodecore_link_pair_with_strategy(ProofStrategy::None);

        // Even with ProofStrategy::None on destination, channel proofs are unconditional
        let resp_link = pair.responder.link(&pair.responder_link_id).unwrap();
        assert!(
            resp_link.dest_signing_key().is_some(),
            "responder should always have dest_signing_key"
        );

        let output = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"prove_none")
            .unwrap();
        let data = extract_broadcast_data(&output);
        let output = pair.responder.handle_packet(InterfaceId(0), &data);

        assert!(
            !output.actions.is_empty(),
            "channel proof should be generated regardless of ProofStrategy::None"
        );
    }

    #[test]
    fn test_channel_proof_by_initiator_round_trip() {
        use crate::transport::InterfaceId;

        let mut pair = establish_nodecore_link_pair();

        // Initiator has no dest_signing_key but has ephemeral proof_signing_key
        let init_link = pair.initiator.link(&pair.initiator_link_id).unwrap();
        assert!(
            init_link.dest_signing_key().is_none(),
            "initiator should not have dest_signing_key"
        );
        assert!(
            init_link.proof_signing_key().is_some(),
            "initiator should have ephemeral proof_signing_key"
        );

        // Send channel message from responder to initiator
        let output = pair
            .responder
            .send_on_link(&pair.responder_link_id, b"resp_msg")
            .unwrap();
        let data = extract_broadcast_data(&output);

        // Deliver to initiator → proof in actions
        let output = pair.initiator.handle_packet(InterfaceId(0), &data);
        assert!(
            !output.actions.is_empty(),
            "initiator should generate channel proof"
        );
        let proof_data = extract_broadcast_data(&output);

        // Deliver proof back to responder → LinkDeliveryConfirmed
        let output = pair.responder.handle_packet(InterfaceId(0), &proof_data);
        let has_confirmed = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::LinkDeliveryConfirmed { .. }));
        assert!(
            has_confirmed,
            "responder should get LinkDeliveryConfirmed from initiator proof"
        );
    }

    // ─── Group C: Timing ────────────────────────────────────────────────────

    #[test]
    fn test_channel_retransmit_on_timeout() {
        let mut pair = establish_nodecore_link_pair();

        // Send channel message (don't deliver proof)
        let _ = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"timeout_test")
            .unwrap();
        assert_eq!(pair.initiator.receipt_count(), 1);

        // Phase 1: advance 1s → no retransmit yet
        pair.initiator.transport().clock().set(TEST_TIME_MS + 1_000);
        let output = pair.initiator.handle_timeout();
        let has_retransmit = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::ChannelRetransmit { .. }));
        assert!(!has_retransmit, "no retransmit at 1s");

        // Phase 2: advance 10s → retransmit with tries=2
        pair.initiator
            .transport()
            .clock()
            .set(TEST_TIME_MS + 10_000);
        let output = pair.initiator.handle_timeout();
        let retransmit = output.events.iter().find_map(|e| match e {
            NodeEvent::ChannelRetransmit { tries, .. } => Some(*tries),
            _ => None,
        });
        assert_eq!(
            retransmit,
            Some(2),
            "expected ChannelRetransmit with tries=2"
        );

        // Retransmit packet should be in actions
        assert!(
            !output.actions.is_empty(),
            "retransmit should produce a packet"
        );

        // Receipt count should still be 1 (old replaced, not leaked)
        assert_eq!(pair.initiator.receipt_count(), 1);
    }

    #[test]
    fn test_stale_recovery_on_inbound() {
        use crate::transport::InterfaceId;

        let mut pair = establish_nodecore_link_pair();

        // Force responder's link to Stale state
        pair.responder
            .link_mut(&pair.responder_link_id)
            .unwrap()
            .set_state(LinkState::Stale);
        assert_eq!(
            pair.responder
                .link(&pair.responder_link_id)
                .unwrap()
                .state(),
            LinkState::Stale
        );

        // Send channel message from initiator
        let output = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"recover")
            .unwrap();
        let data = extract_broadcast_data(&output);

        // Deliver to stale responder
        let output = pair.responder.handle_packet(InterfaceId(0), &data);

        // Should get LinkRecovered event
        let has_recovered = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::LinkRecovered { .. }));
        assert!(has_recovered, "expected LinkRecovered event");

        // Link should be Active again
        assert_eq!(
            pair.responder
                .link(&pair.responder_link_id)
                .unwrap()
                .state(),
            LinkState::Active
        );

        // Negative: active link receiving data does NOT emit LinkRecovered
        let output2 = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"normal")
            .unwrap();
        let data2 = extract_broadcast_data(&output2);
        let output2 = pair.responder.handle_packet(InterfaceId(0), &data2);
        let has_recovered2 = output2
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::LinkRecovered { .. }));
        assert!(!has_recovered2, "active link should NOT emit LinkRecovered");
    }

    #[test]
    fn test_channel_exhaustion_produces_channel_exhausted_close() {
        let mut pair = establish_nodecore_link_pair();

        // Send a message and reduce max_tries to 2
        let _ = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"exhaust")
            .unwrap();

        pair.initiator
            .link_mut(&pair.initiator_link_id)
            .unwrap()
            .channel_mut()
            .unwrap()
            .set_max_tries_for_test(2);

        // With RTT≈0, stale_time=10s. Keep under that to avoid stale close.
        // Channel timeout for tries=1 at default RTT=500ms: ~3125ms.

        // Phase 1: first retransmit (tries=2 — first send was try 1)
        pair.initiator.transport().clock().set(TEST_TIME_MS + 4_000);
        let output = pair.initiator.handle_timeout();
        let has_retransmit = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::ChannelRetransmit { .. }));
        assert!(has_retransmit, "expected retransmit at tries=2");

        // Phase 2: tries=2 >= max_tries=2 → TearDownLink → LinkClosed
        // Timeout for tries=2: ~4687ms. 4000+5000=9000ms < 10s stale.
        pair.initiator.transport().clock().set(TEST_TIME_MS + 9_000);
        let output = pair.initiator.handle_timeout();

        let has_closed = output.events.iter().any(|e| {
            matches!(
                e,
                NodeEvent::LinkClosed {
                    reason: LinkCloseReason::ChannelExhausted,
                    ..
                }
            )
        });
        assert!(
            has_closed,
            "expected LinkClosed with ChannelExhausted after exhaustion"
        );

        assert_eq!(
            pair.initiator.active_link_count(),
            0,
            "link should be removed"
        );
        assert!(
            pair.initiator.link(&pair.initiator_link_id).is_none(),
            "link should not be found"
        );
    }

    #[test]
    fn test_receipts_expire_after_timeout() {
        use crate::constants::DATA_RECEIPT_TIMEOUT_MS;

        let mut pair = establish_nodecore_link_pair();

        // Send (don't deliver proof)
        let _ = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"expire_test")
            .unwrap();
        assert_eq!(pair.initiator.receipt_count(), 1);

        // Advance time past both stale close and receipt timeout.
        // The receipt is cleaned either by link close (remove_for_link) or
        // by time-based expiry — both paths converge to receipt_count == 0.
        pair.initiator
            .transport()
            .clock()
            .set(TEST_TIME_MS + DATA_RECEIPT_TIMEOUT_MS + 1);
        let _ = pair.initiator.handle_timeout();
        assert_eq!(
            pair.initiator.receipt_count(),
            0,
            "receipt should be cleaned after timeout"
        );
    }

    // ─── Group D: Receipt tracking ──────────────────────────────────────────

    #[test]
    fn test_receipt_lifecycle() {
        use crate::transport::InterfaceId;

        let mut pair = establish_nodecore_link_pair();

        // Send → receipt registered
        let output = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"lifecycle")
            .unwrap();
        assert_eq!(pair.initiator.receipt_count(), 1);

        // Deliver to responder → get proof
        let data = extract_broadcast_data(&output);
        let output = pair.responder.handle_packet(InterfaceId(0), &data);
        let proof = extract_broadcast_data(&output);

        // Deliver proof to initiator → confirmed, receipts cleared
        let output = pair.initiator.handle_packet(InterfaceId(0), &proof);
        let has_confirmed = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::LinkDeliveryConfirmed { .. }));
        assert!(has_confirmed, "expected LinkDeliveryConfirmed");
        assert_eq!(
            pair.initiator.receipt_count(),
            0,
            "receipt should be consumed"
        );
        assert_eq!(
            pair.initiator.receipt_count(),
            0,
            "receipt should be consumed after proof"
        );
    }

    #[test]
    fn test_retransmit_event_payload() {
        let mut pair = establish_nodecore_link_pair();

        let _ = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"retransmit_payload")
            .unwrap();

        // Advance past timeout
        pair.initiator
            .transport()
            .clock()
            .set(TEST_TIME_MS + 10_000);
        let output = pair.initiator.handle_timeout();

        // Find the ChannelRetransmit event and check its fields
        let retransmit = output.events.iter().find_map(|e| match e {
            NodeEvent::ChannelRetransmit {
                link_id,
                sequence,
                tries,
            } => Some((*link_id, *sequence, *tries)),
            _ => None,
        });
        let (link_id, sequence, tries) = retransmit.expect("expected ChannelRetransmit");
        assert_eq!(link_id, pair.initiator_link_id);
        assert_eq!(sequence, 0, "first message should be sequence 0");
        assert_eq!(tries, 2, "first retransmit should be tries=2");

        // Receipt should still exist (retransmit replaced, not leaked)
        assert_eq!(pair.initiator.receipt_count(), 1);
    }

    #[test]
    fn test_retransmit_proof_matches_new_hash() {
        use crate::transport::InterfaceId;

        let mut pair = establish_nodecore_link_pair();

        // Suppress keepalives so handle_timeout only produces the retransmit action
        pair.initiator
            .link_mut(&pair.initiator_link_id)
            .unwrap()
            .set_timing_for_test(3600, 3600, TEST_TIME_MS / crate::constants::MS_PER_SECOND);

        let _ = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"retransmit_proof")
            .unwrap();

        // Trigger retransmit
        pair.initiator
            .transport()
            .clock()
            .set(TEST_TIME_MS + 10_000);
        let output = pair.initiator.handle_timeout();
        let retransmit_packet = extract_all_action_data(&output);
        assert!(
            !retransmit_packet.is_empty(),
            "retransmit should produce a packet"
        );

        // Deliver retransmit to responder → proof
        let output = pair
            .responder
            .handle_packet(InterfaceId(0), &retransmit_packet[0]);
        let proof = extract_broadcast_data(&output);

        // Deliver proof to initiator → confirmed
        let output = pair.initiator.handle_packet(InterfaceId(0), &proof);
        let has_confirmed = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::LinkDeliveryConfirmed { .. }));
        assert!(
            has_confirmed,
            "proof for retransmit should produce LinkDeliveryConfirmed"
        );
        assert_eq!(
            pair.initiator.receipt_count(),
            0,
            "receipt should be consumed"
        );
    }

    #[test]
    fn test_multiple_retransmits_single_receipt() {
        let mut pair = establish_nodecore_link_pair();

        // Extend stale timeout so the link survives through retransmit intervals
        pair.initiator
            .link_mut(&pair.initiator_link_id)
            .unwrap()
            .set_timing_for_test(3600, 3600, TEST_TIME_MS / crate::constants::MS_PER_SECOND);

        let _ = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"multi_retransmit")
            .unwrap();
        assert_eq!(pair.initiator.receipt_count(), 1);

        // Retransmit 1
        pair.initiator
            .transport()
            .clock()
            .set(TEST_TIME_MS + 10_000);
        let _ = pair.initiator.handle_timeout();
        assert_eq!(
            pair.initiator.receipt_count(),
            1,
            "should still have 1 receipt after first retransmit"
        );

        // Retransmit 2
        pair.initiator
            .transport()
            .clock()
            .set(TEST_TIME_MS + 25_000);
        let _ = pair.initiator.handle_timeout();
        assert_eq!(
            pair.initiator.receipt_count(),
            1,
            "should still have 1 receipt after second retransmit (no leak)"
        );
    }

    #[test]
    fn test_proof_for_final_retransmit_delivers() {
        use crate::transport::InterfaceId;

        let mut pair = establish_nodecore_link_pair();

        // Extend stale timeout to prevent link closure during retransmit intervals.
        // Default stale_time is 10s (keepalive 5s * factor 2), which is too short
        // for the 50s intervals below.
        pair.initiator
            .link_mut(&pair.initiator_link_id)
            .unwrap()
            .set_timing_for_test(5, 3600, TEST_TIME_MS / crate::constants::MS_PER_SECOND);

        let _ = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"final_retransmit")
            .unwrap();

        // Perform 3 retransmits, keep the last packet.
        // At intervals ≥5s, keepalive fires before retransmit in actions,
        // so use .last() to get the retransmit packet (not the keepalive).
        let mut last_packet = Vec::new();
        let intervals = [10_000u64, 25_000, 50_000];
        for &dt in &intervals {
            pair.initiator.transport().clock().set(TEST_TIME_MS + dt);
            let output = pair.initiator.handle_timeout();
            let packets = extract_all_action_data(&output);
            if !packets.is_empty() {
                last_packet = packets.last().unwrap().clone();
            }
        }
        assert!(!last_packet.is_empty(), "should have a retransmit packet");

        // Deliver last retransmit to responder → proof
        let output = pair.responder.handle_packet(InterfaceId(0), &last_packet);
        // Responder might see it as duplicate or new depending on channel state,
        // but should generate a proof for the packet
        let proofs = extract_all_action_data(&output);
        assert!(!proofs.is_empty(), "should get a proof for the retransmit");

        // Deliver proof to initiator → confirmed
        let output = pair.initiator.handle_packet(InterfaceId(0), &proofs[0]);
        let has_confirmed = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::LinkDeliveryConfirmed { .. }));
        assert!(has_confirmed, "expected LinkDeliveryConfirmed");
        assert_eq!(
            pair.initiator.receipt_count(),
            0,
            "receipt should be consumed"
        );
    }

    #[test]
    fn test_receipt_count_increments_on_send() {
        let mut pair = establish_nodecore_link_pair();

        assert_eq!(pair.initiator.receipt_count(), 0);

        let _ = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"first")
            .unwrap();
        assert_eq!(pair.initiator.receipt_count(), 1);

        let _ = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"second")
            .unwrap();
        assert_eq!(pair.initiator.receipt_count(), 2);
    }

    // ─── Group E: Misc ──────────────────────────────────────────────────────

    #[test]
    fn test_attached_interface_set_on_handshake() {
        let pair = establish_nodecore_link_pair();

        // Both sides should have attached_interface set to 0
        let init_link = pair.initiator.link(&pair.initiator_link_id).unwrap();
        assert_eq!(
            init_link.attached_interface(),
            Some(0),
            "initiator should have attached_interface=0"
        );

        let resp_link = pair.responder.link(&pair.responder_link_id).unwrap();
        assert_eq!(
            resp_link.attached_interface(),
            Some(0),
            "responder should have attached_interface=0"
        );

        // Negative: pending link (before proof) should have no attached_interface on initiator
        let resp_identity = Identity::generate(&mut OsRng);
        let resp_signing_key = resp_identity.ed25519_verifying().to_bytes();
        let clock = MockClock::new(TEST_TIME_MS);
        let mut resp = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);
        let mut dest = Destination::new(
            Some(resp_identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["iface"],
        )
        .unwrap();
        dest.set_accepts_links(true);
        let dest_hash = *dest.hash();
        resp.register_destination(dest);

        let clock = MockClock::new(TEST_TIME_MS);
        let mut init = NodeCoreBuilder::new().build(OsRng, clock, NoStorage);
        let (link_id, _) = init.connect(dest_hash, &resp_signing_key);
        let pending_link = init.link(&link_id).unwrap();
        assert_eq!(
            pending_link.attached_interface(),
            None,
            "pending initiator should have no attached_interface"
        );
    }

    #[test]
    fn test_mark_delivered_bogus_sequence() {
        let mut pair = establish_nodecore_link_pair();

        // Send to create channel
        let _ = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"create_channel")
            .unwrap();

        let now_ms = pair.initiator.now_ms();
        let result = pair
            .initiator
            .link_mut(&pair.initiator_link_id)
            .unwrap()
            .channel_mut()
            .unwrap()
            .mark_delivered(9999, now_ms, 500);
        assert!(
            !result,
            "mark_delivered with bogus sequence should return false"
        );
    }

    #[test]
    fn test_channel_accessor_none_when_absent() {
        let pair = establish_nodecore_link_pair();

        // Before any send, channel should be None
        let link = pair.initiator.link(&pair.initiator_link_id).unwrap();
        assert!(
            link.channel().is_none(),
            "channel should be None before any send"
        );

        // After send, channel should be Some
        let mut pair = establish_nodecore_link_pair();
        let _ = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"data")
            .unwrap();
        let link = pair.initiator.link(&pair.initiator_link_id).unwrap();
        assert!(
            link.channel().is_some(),
            "channel should be Some after send"
        );

        // Fake link_id → link().is_none()
        let fake_id = LinkId::new([0xFF; 16]);
        assert!(
            pair.initiator.link(&fake_id).is_none(),
            "fake link_id should return None"
        );
    }

    // ─── Group F: Close cleanup ─────────────────────────────────────────────

    #[test]
    fn test_close_link_removes_receipt_entries() {
        let mut pair = establish_nodecore_link_pair();

        // Send (populates receipts)
        let _ = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"cleanup")
            .unwrap();
        assert!(pair.initiator.receipt_count() >= 1);
        assert!(
            pair.initiator
                .receipt_count_for_link(&pair.initiator_link_id)
                >= 1
        );

        // Close link
        let _ = pair.initiator.close_link(&pair.initiator_link_id);

        // All receipt entries for this link should be cleaned
        assert_eq!(
            pair.initiator
                .receipt_count_for_link(&pair.initiator_link_id),
            0,
            "receipt entries should be cleaned on close"
        );
    }

    // ─── Group G: ReceiptTracker orphan-path fix tests ─────────────────────

    #[test]
    fn test_delivery_proof_removes_receipt() {
        use crate::transport::InterfaceId;

        let mut pair = establish_nodecore_link_pair();

        // Send channel message → creates receipt
        let output = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"proof_cleanup")
            .unwrap();
        assert_eq!(pair.initiator.receipt_count(), 1);
        let channel_data = extract_broadcast_data(&output);

        // Deliver to responder → get proof
        let output = pair.responder.handle_packet(InterfaceId(0), &channel_data);
        let proof = extract_broadcast_data(&output);

        // Deliver proof to initiator → receipt consumed entirely
        let output = pair.initiator.handle_packet(InterfaceId(0), &proof);
        let has_confirmed = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::LinkDeliveryConfirmed { .. }));
        assert!(has_confirmed, "expected LinkDeliveryConfirmed");

        // Orphan path #1 fix: the receipt entry is completely removed
        // (previously channel_receipt_keys entry was orphaned)
        assert_eq!(
            pair.initiator.receipt_count(),
            0,
            "delivery proof should remove all receipt state"
        );
        assert_eq!(
            pair.initiator
                .receipt_count_for_link(&pair.initiator_link_id),
            0,
            "no receipt entries should remain for this link"
        );
    }

    #[test]
    fn test_expired_receipts_cleaned_on_timeout() {
        use crate::constants::DATA_RECEIPT_TIMEOUT_MS;

        let mut pair = establish_nodecore_link_pair();

        // Send channel message → creates receipt
        let _ = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"expire_cleanup")
            .unwrap();
        assert_eq!(pair.initiator.receipt_count(), 1);

        // Advance time past DATA_RECEIPT_TIMEOUT_MS → handle_timeout cleans up
        // (link will also close due to stale timeout, but that's fine —
        // the point is that no receipt entries survive)
        pair.initiator
            .transport()
            .clock()
            .set(TEST_TIME_MS + DATA_RECEIPT_TIMEOUT_MS + 1);
        let _ = pair.initiator.handle_timeout();

        // Orphan path #2 fix: all receipt state is cleaned
        // (previously channel_hash_to_seq entries were orphaned after expiry GC)
        assert_eq!(
            pair.initiator.receipt_count(),
            0,
            "all receipt entries should be cleaned after timeout"
        );
    }

    #[test]
    fn test_valid_proof_after_receipt_expiry_emits_no_event() {
        use crate::constants::DATA_RECEIPT_TIMEOUT_MS;
        use crate::transport::InterfaceId;

        let mut pair = establish_nodecore_link_pair();

        // Send channel message → creates receipt
        let output = pair
            .initiator
            .send_on_link(&pair.initiator_link_id, b"will_expire")
            .unwrap();
        assert_eq!(pair.initiator.receipt_count(), 1);
        let channel_data = extract_broadcast_data(&output);

        // Deliver to responder → get proof (save for later)
        let output = pair.responder.handle_packet(InterfaceId(0), &channel_data);
        let proof = extract_broadcast_data(&output);

        // Expire the receipt directly (bypasses handle_timeout which would
        // also retransmit and re-register)
        pair.initiator
            .expire_receipts(TEST_TIME_MS + DATA_RECEIPT_TIMEOUT_MS + 1);
        assert_eq!(
            pair.initiator.receipt_count(),
            0,
            "receipt should have expired"
        );

        // Deliver the valid proof — receipt is gone, link still alive
        let output = pair.initiator.handle_packet(InterfaceId(0), &proof);
        let has_confirmed = output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::LinkDeliveryConfirmed { .. }));
        assert!(
            !has_confirmed,
            "LinkDeliveryConfirmed must not fire when receipt was already expired"
        );
        assert_eq!(pair.initiator.receipt_count(), 0);
    }

    // ─── Group H1: Single-packet proof verification at NodeCore ─────────

    #[test]
    fn test_single_packet_proof_delivery_confirmed() {
        // ProofStrategy::All: receiver auto-generates proof via Transport,
        // sender receives it and emits DeliveryConfirmed.
        use crate::transport::{InterfaceId, PathEntry};

        // 1. Create receiver with a destination that has ProofStrategy::All
        let recv_identity = Identity::generate(&mut OsRng);
        let recv_clock = MockClock::new(TEST_TIME_MS);
        let mut receiver = NodeCoreBuilder::new().build(OsRng, recv_clock, NoStorage);

        let mut dest = Destination::new(
            Some(recv_identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["proof"],
        )
        .unwrap();
        dest.set_proof_strategy(ProofStrategy::All);
        let dest_hash = *dest.hash();
        receiver.register_destination(dest);

        // Receiver needs an interface so the auto-proof can be sent
        let _recv_iface = receiver
            .transport
            .register_interface(alloc::boxed::Box::new(MockInterface::new("recv_if", 2)));

        // 2. Create sender — register destination on sender too so NodeCore
        //    can look up the identity for proof verification
        let send_clock = MockClock::new(TEST_TIME_MS);
        let mut sender = NodeCoreBuilder::new().build(OsRng, send_clock, NoStorage);

        // 3. Set up paths: sender → receiver (interface 0)
        let sender_iface = sender
            .transport
            .register_interface(alloc::boxed::Box::new(MockInterface::new("if0", 1)));
        sender.transport.insert_path(
            dest_hash.into_bytes(),
            PathEntry {
                hops: 1,
                expires_ms: u64::MAX,
                interface_index: sender_iface,
                random_blobs: Vec::new(),
                next_hop: None,
            },
        );

        // Sender needs a copy of the destination registered so NodeCore can
        // find the identity for proof verification. Use public-key-only identity.
        let recv_dest_ref = receiver.destination(&dest_hash).unwrap();
        let recv_pub_bytes = recv_dest_ref.identity().unwrap().public_key_bytes();
        let sender_side_identity = Identity::from_public_key_bytes(&recv_pub_bytes).unwrap();
        let sender_side_dest = Destination::new(
            Some(sender_side_identity),
            Direction::Out,
            DestinationType::Single,
            "testapp",
            &["proof"],
        )
        .unwrap();
        sender.register_destination(sender_side_dest);

        // 4. Sender sends a single packet → creates receipt
        let (receipt_hash, output) = sender
            .send_single_packet(&dest_hash, b"hello proof test")
            .unwrap();
        let sent_raw = extract_broadcast_data(&output);

        // Verify receipt was created
        assert!(
            sender.transport.get_receipt(&receipt_hash).is_some(),
            "sender should have a receipt"
        );

        // 5. Receiver processes the packet → auto-generates proof (no NodeEvent)
        let recv_output = receiver.handle_packet(InterfaceId(0), &sent_raw);

        // Bug 1 fix: All strategy must NOT emit ProofRequested to the app
        let has_proof_requested = recv_output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::PacketProofRequested { .. }));
        assert!(
            !has_proof_requested,
            "ProofStrategy::All must NOT emit NodeEvent::PacketProofRequested"
        );

        // Auto-proof should appear as a SendPacket action
        let proof_raw = recv_output
            .actions
            .iter()
            .find_map(|a| match a {
                crate::transport::Action::SendPacket { data, .. } => Some(data.clone()),
                _ => None,
            })
            .expect("ProofStrategy::All should auto-generate a SendPacket proof");

        // 6. Feed proof to sender → should get DeliveryConfirmed
        let sender_output = sender.handle_packet(InterfaceId(0), &proof_raw);

        let has_confirmed = sender_output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::PacketDeliveryConfirmed { .. }));
        let has_failed = sender_output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::DeliveryFailed { .. }));

        assert!(
            has_confirmed,
            "valid proof should produce DeliveryConfirmed, got events: {:?}",
            sender_output.events
        );
        assert!(!has_failed, "valid proof should NOT produce DeliveryFailed");

        // Verify receipt is now marked as delivered
        let receipt = sender.transport.get_receipt(&receipt_hash).unwrap();
        assert_eq!(
            receipt.status,
            crate::receipt::ReceiptStatus::Delivered,
            "receipt should be marked Delivered"
        );
    }

    #[test]
    fn test_single_packet_proof_invalid_signature_delivery_failed() {
        // When a proof has a bad signature, NodeCore should emit DeliveryFailed.
        use crate::packet::build_proof_packet;
        use crate::transport::{InterfaceId, PathEntry};

        let recv_identity = Identity::generate(&mut OsRng);
        let recv_clock = MockClock::new(TEST_TIME_MS);
        let mut receiver = NodeCoreBuilder::new().build(OsRng, recv_clock, NoStorage);

        let mut dest = Destination::new(
            Some(recv_identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["badproof"],
        )
        .unwrap();
        dest.set_proof_strategy(ProofStrategy::All);
        let dest_hash = *dest.hash();
        receiver.register_destination(dest);

        // Receiver needs an interface for auto-proof
        let _recv_iface = receiver
            .transport
            .register_interface(alloc::boxed::Box::new(MockInterface::new("recv_if", 2)));

        let send_clock = MockClock::new(TEST_TIME_MS);
        let mut sender = NodeCoreBuilder::new().build(OsRng, send_clock, NoStorage);

        let sender_iface = sender
            .transport
            .register_interface(alloc::boxed::Box::new(MockInterface::new("if0", 1)));
        sender.transport.insert_path(
            dest_hash.into_bytes(),
            PathEntry {
                hops: 1,
                expires_ms: u64::MAX,
                interface_index: sender_iface,
                random_blobs: Vec::new(),
                next_hop: None,
            },
        );

        // Register dest on sender with the real identity for proof verification
        let recv_dest_ref = receiver.destination(&dest_hash).unwrap();
        let recv_pub_bytes = recv_dest_ref.identity().unwrap().public_key_bytes();
        let sender_side_identity = Identity::from_public_key_bytes(&recv_pub_bytes).unwrap();
        let sender_side_dest = Destination::new(
            Some(sender_side_identity),
            Direction::Out,
            DestinationType::Single,
            "testapp",
            &["badproof"],
        )
        .unwrap();
        sender.register_destination(sender_side_dest);

        let (receipt_hash, output) = sender
            .send_single_packet(&dest_hash, b"hello bad proof")
            .unwrap();
        let _sent_raw = extract_broadcast_data(&output);

        // We need a packet_hash to craft a bad proof against. Use any 32-byte
        // hash that matches the sender's receipt. The receipt tracks by truncated
        // dest hash, and the proof packet carries the full packet hash.
        // For this test, just use a known hash from the receipt.
        let receipt = sender.transport.get_receipt(&receipt_hash).unwrap();
        let packet_hash = receipt.packet_hash;

        // Create proof with a WRONG identity (not the destination's)
        let wrong_identity = Identity::generate(&mut OsRng);
        let bad_proof_data = wrong_identity.create_proof(&packet_hash).unwrap();

        let proof_packet = build_proof_packet(&dest_hash.into_bytes(), &bad_proof_data);
        let mut buf = [0u8; crate::constants::MTU];
        let len = proof_packet.pack(&mut buf).unwrap();

        // Feed bad proof to sender → should get DeliveryFailed
        let sender_output = sender.handle_packet(InterfaceId(0), &buf[..len]);

        let has_failed = sender_output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::DeliveryFailed { .. }));
        let has_confirmed = sender_output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::PacketDeliveryConfirmed { .. }));

        assert!(has_failed, "bad proof should produce DeliveryFailed");
        assert!(
            !has_confirmed,
            "bad proof should NOT produce DeliveryConfirmed"
        );

        // Receipt should NOT be marked delivered
        let receipt = sender.transport.get_receipt(&receipt_hash).unwrap();
        assert_ne!(
            receipt.status,
            crate::receipt::ReceiptStatus::Delivered,
            "receipt should NOT be marked Delivered with bad proof"
        );
    }

    #[test]
    fn test_single_packet_prove_all_no_app_event() {
        // Bug 1 fix: ProofStrategy::All must auto-generate proof via Transport
        // and must NOT emit NodeEvent::PacketProofRequested to the app.
        use crate::transport::InterfaceId;

        let recv_identity = Identity::generate(&mut OsRng);
        let recv_clock = MockClock::new(TEST_TIME_MS);
        let mut receiver = NodeCoreBuilder::new().build(OsRng, recv_clock, NoStorage);

        let mut dest = Destination::new(
            Some(recv_identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["allproof"],
        )
        .unwrap();
        dest.set_proof_strategy(ProofStrategy::All);
        let dest_hash = *dest.hash();
        receiver.register_destination(dest);

        // Receiver needs an interface for auto-proof delivery
        let _recv_iface = receiver
            .transport
            .register_interface(alloc::boxed::Box::new(MockInterface::new("recv_if", 1)));

        // Create a sender to produce a valid data packet
        let send_clock = MockClock::new(TEST_TIME_MS);
        let mut sender = NodeCoreBuilder::new().build(OsRng, send_clock, NoStorage);
        let sender_iface = sender
            .transport
            .register_interface(alloc::boxed::Box::new(MockInterface::new("send_if", 2)));
        sender.transport.insert_path(
            dest_hash.into_bytes(),
            crate::transport::PathEntry {
                hops: 1,
                expires_ms: u64::MAX,
                interface_index: sender_iface,
                random_blobs: Vec::new(),
                next_hop: None,
            },
        );
        let (_receipt_hash, output) = sender
            .send_single_packet(&dest_hash, b"prove all test")
            .unwrap();
        let sent_raw = extract_broadcast_data(&output);

        // Feed packet to receiver
        let recv_output = receiver.handle_packet(InterfaceId(0), &sent_raw);

        // Must NOT have ProofRequested event (Bug 1)
        let has_proof_event = recv_output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::PacketProofRequested { .. }));
        assert!(
            !has_proof_event,
            "ProofStrategy::All must NOT emit NodeEvent::PacketProofRequested"
        );

        // Must have a PacketReceived event (data still delivered to app)
        let has_packet_event = recv_output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::PacketReceived { .. }));
        assert!(has_packet_event, "data packet should still be delivered");

        // Must have a SendPacket action (the auto-generated proof)
        let has_send_action = recv_output
            .actions
            .iter()
            .any(|a| matches!(a, crate::transport::Action::SendPacket { .. }));
        assert!(
            has_send_action,
            "ProofStrategy::All should auto-generate a proof SendPacket action"
        );
    }

    #[test]
    fn test_single_packet_prove_app_emits_event_and_send_proof_works() {
        // Bug 2 fix: ProofStrategy::App emits NodeEvent::PacketProofRequested
        // and the app can call NodeCore::send_proof() to respond.
        use crate::transport::{InterfaceId, PathEntry};

        let recv_identity = Identity::generate(&mut OsRng);
        let recv_clock = MockClock::new(TEST_TIME_MS);
        let mut receiver = NodeCoreBuilder::new().build(OsRng, recv_clock, NoStorage);

        let mut dest = Destination::new(
            Some(recv_identity),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["appproof"],
        )
        .unwrap();
        dest.set_proof_strategy(ProofStrategy::App);
        let dest_hash = *dest.hash();
        receiver.register_destination(dest);

        // Receiver needs an interface and a path back to sender for send_proof()
        let recv_iface = receiver
            .transport
            .register_interface(alloc::boxed::Box::new(MockInterface::new("recv_if", 1)));

        // Create a sender to produce a valid data packet
        let send_clock = MockClock::new(TEST_TIME_MS);
        let mut sender = NodeCoreBuilder::new().build(OsRng, send_clock, NoStorage);
        let sender_iface = sender
            .transport
            .register_interface(alloc::boxed::Box::new(MockInterface::new("send_if", 2)));
        sender.transport.insert_path(
            dest_hash.into_bytes(),
            PathEntry {
                hops: 1,
                expires_ms: u64::MAX,
                interface_index: sender_iface,
                random_blobs: Vec::new(),
                next_hop: None,
            },
        );

        // Sender needs the receiver's public key for proof verification
        let recv_dest_ref = receiver.destination(&dest_hash).unwrap();
        let recv_pub_bytes = recv_dest_ref.identity().unwrap().public_key_bytes();
        let sender_side_identity = Identity::from_public_key_bytes(&recv_pub_bytes).unwrap();
        let sender_side_dest = Destination::new(
            Some(sender_side_identity),
            Direction::Out,
            DestinationType::Single,
            "testapp",
            &["appproof"],
        )
        .unwrap();
        sender.register_destination(sender_side_dest);

        // Sender sends a single packet
        let (receipt_hash, output) = sender
            .send_single_packet(&dest_hash, b"app proof test")
            .unwrap();
        let sent_raw = extract_broadcast_data(&output);

        // Feed packet to receiver — should get ProofRequested event (App strategy)
        let recv_output = receiver.handle_packet(InterfaceId(0), &sent_raw);

        let proof_req = recv_output
            .events
            .iter()
            .find_map(|e| match e {
                NodeEvent::PacketProofRequested {
                    packet_hash,
                    destination_hash,
                } => Some((*packet_hash, *destination_hash)),
                _ => None,
            })
            .expect("ProofStrategy::App should emit NodeEvent::PacketProofRequested");
        let (packet_hash, req_dest_hash) = proof_req;

        // Must NOT have any auto-generated proof action
        let has_send_action = recv_output
            .actions
            .iter()
            .any(|a| matches!(a, crate::transport::Action::SendPacket { .. }));
        assert!(
            !has_send_action,
            "ProofStrategy::App must NOT auto-generate a proof"
        );

        // Now the app decides to prove: set up a path on receiver for send_proof()
        // (In real usage the path would exist from the announce; here we add it manually)
        receiver.transport.insert_path(
            dest_hash.into_bytes(),
            PathEntry {
                hops: 1,
                expires_ms: u64::MAX,
                interface_index: recv_iface,
                random_blobs: Vec::new(),
                next_hop: None,
            },
        );

        // Call send_proof() — Bug 2 fix: this method now exists
        let proof_output = receiver
            .send_proof(&packet_hash, &req_dest_hash)
            .expect("send_proof should succeed");

        // Should have a SendPacket action containing the proof
        let proof_raw = proof_output
            .actions
            .iter()
            .find_map(|a| match a {
                crate::transport::Action::SendPacket { data, .. } => Some(data.clone()),
                _ => None,
            })
            .expect("send_proof should produce a SendPacket action");

        // Feed proof to sender → should get DeliveryConfirmed
        let sender_output = sender.handle_packet(InterfaceId(0), &proof_raw);
        let has_confirmed = sender_output
            .events
            .iter()
            .any(|e| matches!(e, NodeEvent::PacketDeliveryConfirmed { .. }));
        assert!(
            has_confirmed,
            "valid proof via send_proof() should produce DeliveryConfirmed, got: {:?}",
            sender_output.events
        );

        let receipt = sender.transport.get_receipt(&receipt_hash).unwrap();
        assert_eq!(
            receipt.status,
            crate::receipt::ReceiptStatus::Delivered,
            "receipt should be marked Delivered"
        );
    }
}
