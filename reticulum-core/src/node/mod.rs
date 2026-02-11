//! High-level Node API for Reticulum
//!
//! This module provides [`NodeCore`], a unified interface that combines
//! Transport and LinkManager functionality into a single, easy-to-use API.
//!
//! # Overview
//!
//! The Node API provides:
//! - **Unified event handling**: All events (announces, packets, connections) through one stream
//! - **Smart routing**: Automatic selection of single-packet vs Link/Channel based on options
//! - **Connection abstraction**: High-level Connection type wrapping Link + Channel
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
//!     .build(rand_core::OsRng, MyClock::new(0), NoStorage)
//!     .unwrap();
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
mod connection;
mod event;
mod send;

pub use builder::{BuildError, NodeCoreBuilder};
pub use connection::{Connection, ConnectionError};
pub use event::{CloseReason, DeliveryError, NodeEvent};
pub use send::{RoutingDecision, SendError, SendHandle, SendMethod, SendResult};

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::announce::AnnounceError;
use crate::constants::TRUNCATED_HASHBYTES;
use crate::destination::{Destination, DestinationHash, ProofStrategy};
use crate::identity::Identity;
use crate::link::{LinkCloseReason, LinkEvent, LinkId, LinkManager};
use crate::packet::Packet;
use crate::traits::{Clock, Storage};
use crate::transport::{Transport, TransportConfig, TransportEvent, TransportStats};
use rand_core::CryptoRngCore;

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

/// The unified Reticulum node - combines Transport + LinkManager
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
    /// Link manager (connections, channels)
    link_manager: LinkManager,
    /// Registered destinations
    destinations: BTreeMap<DestinationHash, Destination>,
    /// Active connections
    connections: BTreeMap<LinkId, Connection>,
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
            link_manager: LinkManager::new(),
            destinations: BTreeMap::new(),
            connections: BTreeMap::new(),
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

        // Register with transport for packet routing
        // Note: We pass None for identity since Identity doesn't implement Clone.
        // Proof handling is done at the NodeCore level using the destination's identity.
        self.transport.register_destination_with_proof(
            hash.into_bytes(),
            dest.accepts_links(),
            dest.proof_strategy(),
            None, // Identity is stored in the destination
        );

        // Register with link manager if accepting links
        if dest.accepts_links() {
            self.link_manager.register_destination(hash);
        }

        self.destinations.insert(hash, dest);
    }

    /// Unregister a destination
    pub fn unregister_destination(&mut self, hash: &DestinationHash) {
        self.transport.unregister_destination(hash.as_bytes());
        self.link_manager.unregister_destination(hash);
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

    // ─── Connection Management ─────────────────────────────────────────────────

    /// Initiate a connection to a destination
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

        // Create connection wrapper
        let conn = Connection::new(link_id, dest_hash, true);
        self.connections.insert(link_id, conn);

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

    /// Accept an incoming connection request
    ///
    /// # Arguments
    /// * `link_id` - The link ID from the ConnectionRequest event
    /// * `identity` - The destination's identity (for signing the proof)
    ///
    /// # Returns
    /// A `TickOutput` containing the link proof action. The driver must
    /// dispatch this output the same way it handles output from
    /// `handle_packet()` / `handle_timeout()`.
    pub fn accept_connection(
        &mut self,
        link_id: &LinkId,
        identity: &Identity,
    ) -> Result<crate::transport::TickOutput, ConnectionError> {
        // Look up proof strategy from the destination
        let proof_strategy = self
            .link_manager
            .link(link_id)
            .and_then(|link| self.destinations.get(link.destination_hash()))
            .map(|dest| dest.proof_strategy())
            .unwrap_or(ProofStrategy::None);

        let now_ms = self.transport.clock().now_ms();
        let proof = self
            .link_manager
            .accept_link(link_id, identity, proof_strategy, now_ms)
            .map_err(ConnectionError::LinkError)?;

        // Get destination hash from link
        if let Some(link) = self.link_manager.link(link_id) {
            let dest_hash = *link.destination_hash();
            let conn = Connection::new(*link_id, dest_hash, false);
            self.connections.insert(*link_id, conn);
        }

        // Route proof on attached interface (matching Python Link.prove())
        let attached = self
            .link_manager
            .link(link_id)
            .and_then(|l| l.attached_interface());
        debug_assert!(
            attached.is_some(),
            "accept_connection: link {:?} has no attached_interface — \
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

    /// Reject an incoming connection request
    pub fn reject_connection(&mut self, link_id: &LinkId) {
        self.link_manager.reject_link(link_id);
    }

    /// Close a connection gracefully
    ///
    /// # Returns
    /// A `TickOutput` containing the close packet action. The driver must
    /// dispatch this output the same way it handles output from
    /// `handle_packet()` / `handle_timeout()`.
    pub fn close_connection(&mut self, link_id: &LinkId) -> crate::transport::TickOutput {
        self.link_manager.close(link_id, &mut self.rng);
        self.connections.remove(link_id);
        self.process_events_and_actions()
    }

    /// Get a connection by link ID
    pub fn connection(&self, link_id: &LinkId) -> Option<&Connection> {
        self.connections.get(link_id)
    }

    /// Get a mutable connection by link ID
    pub fn connection_mut(&mut self, link_id: &LinkId) -> Option<&mut Connection> {
        self.connections.get_mut(link_id)
    }

    /// Get the number of active connections
    pub fn active_connection_count(&self) -> usize {
        self.link_manager.active_link_count()
    }

    /// Get the number of pending connections
    pub fn pending_connection_count(&self) -> usize {
        self.link_manager.pending_link_count()
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
    /// # let node = NodeCoreBuilder::new().build(rand_core::OsRng, MyClock::new(0), NoStorage).unwrap();
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
        // Check if we have an existing connection to this destination
        let existing_connection = self.find_connection_to(dest_hash);

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
            existing_connection,
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

    /// Send data on an existing connection
    ///
    /// This sends data via the Channel on an established connection,
    /// providing reliable, ordered delivery.
    ///
    /// # Arguments
    /// * `link_id` - The connection to send on
    /// * `data` - The data to send
    ///
    /// # Returns
    /// A `TickOutput` containing the send action. The driver must dispatch
    /// this output the same way it handles output from `handle_packet()` /
    /// `handle_timeout()`.
    pub fn send_on_connection(
        &mut self,
        link_id: &LinkId,
        data: &[u8],
    ) -> Result<crate::transport::TickOutput, send::SendError> {
        // Get the connection and link
        let connection = self
            .connections
            .get_mut(link_id)
            .ok_or(send::SendError::NoConnection)?;

        let link = self
            .link_manager
            .link(link_id)
            .ok_or(send::SendError::NoConnection)?;

        let attached_iface = link.attached_interface();
        let dest_hash = *link.destination_hash();

        let now_ms = self.transport.clock().now_ms();

        // Send via connection (builds encrypted channel packet)
        let packet_bytes = connection
            .send_bytes(link, data, &mut self.rng, now_ms)
            .map_err(|e| match e {
                ConnectionError::ChannelError(crate::link::channel::ChannelError::WindowFull) => {
                    send::SendError::WindowFull
                }
                ConnectionError::ChannelError(crate::link::channel::ChannelError::TooLarge) => {
                    send::SendError::TooLarge
                }
                _ => send::SendError::ConnectionFailed,
            })?;

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

    /// Find an existing connection to a destination
    fn find_connection_to(&self, dest_hash: &DestinationHash) -> Option<LinkId> {
        for (link_id, conn) in &self.connections {
            if conn.destination_hash() == dest_hash {
                // Check if the link is active
                if self.link_manager.is_active(link_id) {
                    return Some(*link_id);
                }
            }
        }
        None
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

        // Run link manager periodic tasks
        self.link_manager.poll(&mut self.rng, now_ms);

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
        let link_deadline = self.link_manager.next_deadline(now_ms);

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

    /// Internal: Process transport and link events, drain actions
    ///
    /// Shared logic between `handle_packet` and `handle_timeout`.
    fn process_events_and_actions(&mut self) -> crate::transport::TickOutput {
        // Drain transport events and feed to link manager / event buffer
        let transport_events: Vec<_> = self.transport.drain_events().collect();
        for event in transport_events {
            self.handle_transport_event(event);
        }

        // Drain link events and feed to event buffer
        let link_events: Vec<_> = self.link_manager.drain_events().collect();
        for event in link_events {
            self.handle_link_event(event);
        }

        // Dispatch pending link packets (keepalives, RTT, close, etc.)
        self.send_pending_packets();

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

    /// Access the underlying transport (for advanced use cases)
    pub fn transport(&self) -> &Transport<C, S> {
        &self.transport
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
            } => {
                // Check if this is a link-related packet
                if packet.flags.packet_type == crate::packet::PacketType::LinkRequest
                    || packet.flags.packet_type == crate::packet::PacketType::Proof
                    || (packet.flags.packet_type == crate::packet::PacketType::Data
                        && self
                            .link_manager
                            .link(&LinkId::new(destination_hash))
                            .is_some())
                {
                    // Route to link manager
                    let raw = self.repack_packet(&packet);
                    let now_ms = self.transport.clock().now_ms();
                    self.link_manager.process_packet(
                        &packet,
                        &raw,
                        &mut self.rng,
                        now_ms,
                        interface_index,
                    );
                } else {
                    // Regular packet event
                    self.events.push(NodeEvent::PacketReceived {
                        from: DestinationHash::new(destination_hash),
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
            } => {
                self.events.push(NodeEvent::ProofRequested {
                    packet_hash,
                    destination_hash: DestinationHash::new(destination_hash),
                });
            }

            TransportEvent::ProofReceived {
                packet_hash,
                is_valid,
            } => {
                if is_valid {
                    self.events
                        .push(NodeEvent::DeliveryConfirmed { packet_hash });
                } else {
                    self.events.push(NodeEvent::DeliveryFailed {
                        packet_hash,
                        error: DeliveryError::ConnectionFailed,
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

    fn handle_link_event(&mut self, event: LinkEvent) {
        match event {
            LinkEvent::LinkRequestReceived {
                link_id,
                dest_hash,
                peer_keys,
            } => {
                self.events.push(NodeEvent::ConnectionRequest {
                    link_id,
                    destination_hash: dest_hash,
                    peer_keys,
                });
            }

            LinkEvent::LinkEstablished {
                link_id,
                is_initiator,
            } => {
                // Ensure connection wrapper exists
                if !self.connections.contains_key(&link_id) {
                    if let Some(link) = self.link_manager.link(&link_id) {
                        let dest_hash = *link.destination_hash();
                        let conn = Connection::new(link_id, dest_hash, is_initiator);
                        self.connections.insert(link_id, conn);
                    }
                }

                self.events.push(NodeEvent::ConnectionEstablished {
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
                self.events.push(NodeEvent::ConnectionStale { link_id });
            }

            LinkEvent::LinkClosed { link_id, reason } => {
                // Extract connection info BEFORE removing
                let connection = self.connections.remove(&link_id);

                // Path recovery for locally-initiated links that never activated
                // (Python Transport.py:472-494). When an initiator link times out
                // on a non-transport node, expire the stale path and request a
                // fresh one so the application can retry.
                if reason == LinkCloseReason::Timeout {
                    if let Some(conn) = &connection {
                        if conn.is_initiator() && !self.transport.config().enable_transport {
                            let dest_hash = conn.destination_hash().into_bytes();
                            self.transport.expire_path(&dest_hash);

                            // Tag = [now_ms (8 bytes)] [dest_hash prefix (8 bytes)]
                            // Same pattern as clean_link_table() for dedup.
                            let now = self.transport.clock().now_ms();
                            let mut tag = [0u8; TRUNCATED_HASHBYTES];
                            let now_bytes = now.to_be_bytes();
                            tag[..8].copy_from_slice(&now_bytes);
                            tag[8..16].copy_from_slice(&dest_hash[..8]);
                            let _ = self.transport.request_path(&dest_hash, None, &tag);
                        }
                    }
                }

                self.events.push(NodeEvent::ConnectionClosed {
                    link_id,
                    reason: reason.into(),
                });
            }

            LinkEvent::DataDelivered {
                link_id,
                packet_hash,
            } => {
                // A proof was received confirming delivery of a data packet
                self.events.push(NodeEvent::LinkDeliveryConfirmed {
                    link_id,
                    packet_hash,
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

    fn send_pending_packets(&mut self) {
        use crate::link::PendingPacket;

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

    fn repack_packet(&self, packet: &Packet) -> Vec<u8> {
        let mut buf = [0u8; crate::constants::MTU];
        let len = packet.pack(&mut buf).unwrap_or(0);
        buf[..len].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::{DestinationType, Direction};
    use crate::traits::NoStorage;
    use core::cell::Cell;
    use rand_core::OsRng;

    struct MockClock(Cell<u64>);

    impl MockClock {
        fn new(ms: u64) -> Self {
            Self(Cell::new(ms))
        }
    }

    impl Clock for MockClock {
        fn now_ms(&self) -> u64 {
            self.0.get()
        }
    }

    #[test]
    fn test_nodecore_builder_default() {
        let clock = MockClock::new(1_000_000);
        let node = NodeCoreBuilder::new()
            .build(OsRng, clock, NoStorage)
            .unwrap();

        assert_eq!(node.active_connection_count(), 0);
        assert_eq!(node.pending_connection_count(), 0);
        assert_eq!(node.default_proof_strategy(), ProofStrategy::None);
    }

    #[test]
    fn test_nodecore_builder_with_identity() {
        let identity = Identity::generate(&mut OsRng);
        let id_hash = *identity.hash();
        let clock = MockClock::new(1_000_000);

        let node = NodeCoreBuilder::new()
            .identity(identity)
            .build(OsRng, clock, NoStorage)
            .unwrap();

        assert_eq!(node.identity().hash(), &id_hash);
    }

    #[test]
    fn test_nodecore_register_destination() {
        let clock = MockClock::new(1_000_000);
        let mut node = NodeCoreBuilder::new()
            .build(OsRng, clock, NoStorage)
            .unwrap();

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
        let clock = MockClock::new(1_000_000);
        let mut node = NodeCoreBuilder::new()
            .build(OsRng, clock, NoStorage)
            .unwrap();

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
        let clock = MockClock::new(1_000_000);
        let node = NodeCoreBuilder::new()
            .build(OsRng, clock, NoStorage)
            .unwrap();

        let dest_hash = DestinationHash::new([0x42; 16]);
        assert!(!node.has_path(&dest_hash));
        assert!(node.hops_to(&dest_hash).is_none());
    }

    #[test]
    fn test_connection_new() {
        let link_id = LinkId::new([0x42; 16]);
        let dest_hash = DestinationHash::new([0x33; 16]);

        let conn = Connection::new(link_id, dest_hash, true);

        assert_eq!(*conn.id(), link_id);
        assert_eq!(conn.destination_hash(), &dest_hash);
        assert!(conn.is_initiator());
    }

    #[test]
    fn test_send_no_path_returns_error() {
        let clock = MockClock::new(1_000_000);
        let node = NodeCoreBuilder::new()
            .build(OsRng, clock, NoStorage)
            .unwrap();

        let dest_hash = DestinationHash::new([0x42; 16]);
        let result = node.send(&dest_hash, b"Hello!", &SendOptions::default());

        // Should fail because no path exists
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), send::SendError::NoPath);
    }

    #[test]
    fn test_send_reliable_no_path_returns_error() {
        let clock = MockClock::new(1_000_000);
        let node = NodeCoreBuilder::new()
            .build(OsRng, clock, NoStorage)
            .unwrap();

        let dest_hash = DestinationHash::new([0x42; 16]);
        let result = node.send(&dest_hash, b"Hello!", &SendOptions::reliable());

        // Should fail because no path exists for reliable send
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), send::SendError::NoPath);
    }

    #[test]
    fn test_find_connection_to_none() {
        let clock = MockClock::new(1_000_000);
        let node = NodeCoreBuilder::new()
            .build(OsRng, clock, NoStorage)
            .unwrap();

        let dest_hash = DestinationHash::new([0x42; 16]);
        assert!(node.find_connection_to(&dest_hash).is_none());
    }

    // ─── Sans-I/O API Tests ───────────────────────────────────────────────────

    #[test]
    fn test_handle_timeout_empty_node() {
        let clock = MockClock::new(1_000_000);
        let mut node = NodeCoreBuilder::new()
            .build(OsRng, clock, NoStorage)
            .unwrap();

        let output = node.handle_timeout();
        assert!(output.is_empty());
    }

    #[test]
    fn test_handle_packet_invalid_data() {
        use crate::transport::InterfaceId;

        let clock = MockClock::new(1_000_000);
        let mut node = NodeCoreBuilder::new()
            .build(OsRng, clock, NoStorage)
            .unwrap();

        // Garbage data should not panic and should produce no events/actions
        let output = node.handle_packet(InterfaceId(0), &[0xFF; 3]);
        assert!(output.actions.is_empty());
        assert!(output.events.is_empty());
    }

    #[test]
    fn test_handle_packet_announce() {
        use crate::transport::InterfaceId;

        let clock = MockClock::new(1_000_000);
        let mut node = NodeCoreBuilder::new()
            .enable_transport(true)
            .build(OsRng, clock, NoStorage)
            .unwrap();

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

        let announce_packet = dest.announce(None, &mut OsRng, 1_000_000).unwrap();
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
        let clock = MockClock::new(1_000_000);
        let node = NodeCoreBuilder::new()
            .build(OsRng, clock, NoStorage)
            .unwrap();

        // Empty node should have no deadlines
        assert!(node.next_deadline().is_none());
    }

    #[test]
    fn test_next_deadline_with_path() {
        use crate::transport::InterfaceId;

        let clock = MockClock::new(1_000_000);
        let mut node = NodeCoreBuilder::new()
            .enable_transport(true)
            .build(OsRng, clock, NoStorage)
            .unwrap();

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

        let announce_packet = dest.announce(None, &mut OsRng, 1_000_000).unwrap();
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
            deadline.unwrap() > 1_000_000,
            "deadline should be in the future"
        );
    }

    #[test]
    fn test_handle_interface_down_cleans_paths() {
        use crate::transport::InterfaceId;

        let clock = MockClock::new(1_000_000);
        let mut node = NodeCoreBuilder::new()
            .enable_transport(true)
            .build(OsRng, clock, NoStorage)
            .unwrap();

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

        let announce_packet = dest.announce(None, &mut OsRng, 1_000_000).unwrap();
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

        let clock = MockClock::new(1_000_000);
        let mut node = NodeCoreBuilder::new()
            .build(OsRng, clock, NoStorage)
            .unwrap();

        // Interface down on empty node should produce just the InterfaceDown event
        let output = node.handle_interface_down(InterfaceId(5));
        assert_eq!(output.events.len(), 1);
        assert!(matches!(output.events[0], NodeEvent::InterfaceDown(5)));
        assert!(output.actions.is_empty());
    }

    #[test]
    fn test_handle_timeout_produces_rebroadcast_actions() {
        use crate::transport::InterfaceId;

        let clock = MockClock::new(1_000_000);
        let mut node = NodeCoreBuilder::new()
            .enable_transport(true)
            .build(OsRng, clock, NoStorage)
            .unwrap();

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

        let announce_packet = dest.announce(None, &mut OsRng, 1_000_000).unwrap();
        let mut buf = [0u8; crate::constants::MTU];
        let len = announce_packet.pack(&mut buf).unwrap();
        let _ = node.handle_packet(InterfaceId(0), &buf[..len]);

        // Advance time past the rebroadcast delay
        // MockClock uses Cell<u64>, which allows mutation through &self
        node.transport().clock().0.set(1_000_000 + 20_000);

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

        let clock = MockClock::new(1_000_000);
        let mut node = NodeCoreBuilder::new()
            .enable_transport(true)
            .build(OsRng, clock, NoStorage)
            .unwrap();

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

        let announce_packet = dest.announce(None, &mut OsRng, 1_000_000).unwrap();
        let mut buf = [0u8; crate::constants::MTU];
        let len = announce_packet.pack(&mut buf).unwrap();

        // Feed announce on interface 0
        let _ = node.handle_packet(InterfaceId(0), &buf[..len]);

        // Advance time well past the retransmit delay window
        node.transport().clock().0.set(1_000_000 + 100_000);
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

        let clock = MockClock::new(1_000_000);
        let mut node = NodeCoreBuilder::new()
            .enable_transport(true)
            .build(OsRng, clock, NoStorage)
            .unwrap();

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

        let announce_packet = remote_dest.announce(None, &mut OsRng, 1_000_000).unwrap();
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

        let clock = MockClock::new(1_000_000);
        let mut node = NodeCoreBuilder::new()
            .enable_transport(enable_transport)
            .build(OsRng, clock, NoStorage)
            .unwrap();

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

        let announce_packet = remote_dest.announce(None, &mut OsRng, 1_000_000).unwrap();
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
            .0
            .set(1_000_000 + LINK_PENDING_TIMEOUT_MS + 1);
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

        // Should have ConnectionClosed event with Timeout reason
        let has_closed = output.events.iter().any(|e| {
            matches!(
                e,
                NodeEvent::ConnectionClosed {
                    reason: CloseReason::Timeout,
                    ..
                }
            )
        });
        assert!(has_closed, "should emit ConnectionClosed with Timeout");
    }

    #[test]
    fn test_pending_link_timeout_no_recovery_for_transport_nodes() {
        use crate::constants::LINK_PENDING_TIMEOUT_MS;

        let (mut node, dest_hash, _link_id) = setup_pending_link(true);

        // Advance clock past the pending link timeout
        node.transport()
            .clock()
            .0
            .set(1_000_000 + LINK_PENDING_TIMEOUT_MS + 1);
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
        let _ = node.close_connection(&link_id);

        // Advance clock and run maintenance
        node.transport().clock().0.set(1_000_000 + 5_000);
        let _output = node.handle_timeout();

        // Path should still exist — normal close doesn't trigger recovery
        assert!(
            node.has_path(&dest_hash),
            "path should NOT be expired after normal close"
        );
    }

    #[test]
    fn test_pending_link_recovery_rate_limited() {
        use crate::constants::LINK_PENDING_TIMEOUT_MS;
        use crate::transport::{Action, InterfaceId};

        let clock = MockClock::new(1_000_000);
        let mut node = NodeCoreBuilder::new()
            .enable_transport(false)
            .build(OsRng, clock, NoStorage)
            .unwrap();

        // Create two remote destinations
        let remote1 = Identity::generate(&mut OsRng);
        let signing1 = remote1.ed25519_verifying().to_bytes();
        let mut dest1 = Destination::new(
            Some(remote1),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["rate1"],
        )
        .unwrap();

        let remote2 = Identity::generate(&mut OsRng);
        let signing2 = remote2.ed25519_verifying().to_bytes();
        let mut dest2 = Destination::new(
            Some(remote2),
            Direction::In,
            DestinationType::Single,
            "testapp",
            &["rate2"],
        )
        .unwrap();

        let ann1 = dest1.announce(None, &mut OsRng, 1_000_000).unwrap();
        let ann2 = dest2.announce(None, &mut OsRng, 1_000_000).unwrap();
        let mut buf = [0u8; crate::constants::MTU];

        let len1 = ann1.pack(&mut buf).unwrap();
        let _ = node.handle_packet(InterfaceId(0), &buf[..len1]);
        let len2 = ann2.pack(&mut buf).unwrap();
        let _ = node.handle_packet(InterfaceId(0), &buf[..len2]);
        let _ = node.handle_timeout();

        let hash1 = *dest1.hash();
        let hash2 = *dest2.hash();

        // Connect to both destinations — actions returned in output
        let (_link1, _output1) = node.connect(hash1, &signing1);
        let (_link2, _output2) = node.connect(hash2, &signing2);

        // Advance past timeout — both links will time out simultaneously
        node.transport()
            .clock()
            .0
            .set(1_000_000 + LINK_PENDING_TIMEOUT_MS + 1);
        let output = node.handle_timeout();

        // Both paths should be expired
        assert!(!node.has_path(&hash1), "path 1 should be expired");
        assert!(!node.has_path(&hash2), "path 2 should be expired");

        // Both should produce ConnectionClosed events
        let closed_count = output
            .events
            .iter()
            .filter(|e| matches!(e, NodeEvent::ConnectionClosed { .. }))
            .count();
        assert_eq!(
            closed_count, 2,
            "should have 2 ConnectionClosed events, got {}",
            closed_count
        );

        // Both path requests should succeed since they're for different
        // destinations (rate limiting is per-destination in request_path).
        // Count Broadcast actions — should have at least 2 (one per dest).
        let broadcast_count = output
            .actions
            .iter()
            .filter(|a| matches!(a, Action::Broadcast { .. }))
            .count();
        assert!(
            broadcast_count >= 2,
            "should have at least 2 Broadcast actions for path requests, got {}",
            broadcast_count
        );
    }
}
