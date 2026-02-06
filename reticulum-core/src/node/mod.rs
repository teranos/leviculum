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

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::constants::TRUNCATED_HASHBYTES;
use crate::destination::{Destination, DestinationHash, ProofStrategy};
use crate::identity::Identity;
use crate::link::{LinkEvent, LinkId, LinkManager};
use crate::packet::Packet;
use crate::traits::{Clock, Interface, Storage};
use crate::transport::{Transport, TransportConfig, TransportError, TransportEvent, TransportStats};
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

    /// Create a NodeCore builder for fluent configuration
    pub fn builder() -> NodeCoreBuilder {
        NodeCoreBuilder::new()
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
    pub fn destination(
        &self,
        hash: &DestinationHash,
    ) -> Option<&Destination> {
        self.destinations.get(hash)
    }

    /// Get a mutable reference to a registered destination
    pub fn destination_mut(
        &mut self,
        hash: &DestinationHash,
    ) -> Option<&mut Destination> {
        self.destinations.get_mut(hash)
    }

    // ─── Interface Management ──────────────────────────────────────────────────

    /// Register a network interface
    ///
    /// Returns the interface index for later reference.
    pub fn register_interface(&mut self, interface: Box<dyn Interface + Send>) -> usize {
        self.transport.register_interface(interface)
    }

    /// Unregister a network interface
    pub fn unregister_interface(&mut self, index: usize) {
        self.transport.unregister_interface(index)
    }

    // ─── Connection Management ─────────────────────────────────────────────────

    /// Initiate a connection to a destination
    ///
    /// Returns the link ID and the packet bytes to send.
    ///
    /// # Arguments
    /// * `dest_hash` - The destination to connect to
    /// * `dest_signing_key` - The destination's signing key (from announce)
    pub fn connect(
        &mut self,
        dest_hash: DestinationHash,
        dest_signing_key: &[u8; 32],
    ) -> (LinkId, Vec<u8>) {
        // Check if we have path info for this destination
        let (next_hop, hops) = if let Some(path) = self.transport.path(dest_hash.as_bytes()) {
            // Multi-hop: need transport_id
            if path.hops > 1 {
                // For multi-hop, we'd need the transport_id from the path
                // For now, just use direct connection
                (None, path.hops)
            } else {
                (None, 1)
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

        (link_id, packet)
    }

    /// Accept an incoming connection request
    ///
    /// Returns the proof packet to send back to the initiator.
    ///
    /// # Arguments
    /// * `link_id` - The link ID from the ConnectionRequest event
    /// * `identity` - The destination's identity (for signing the proof)
    pub fn accept_connection(
        &mut self,
        link_id: &LinkId,
        identity: &Identity,
    ) -> Result<Vec<u8>, ConnectionError> {
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

        Ok(proof)
    }

    /// Reject an incoming connection request
    pub fn reject_connection(&mut self, link_id: &LinkId) {
        self.link_manager.reject_link(link_id);
    }

    /// Close a connection gracefully
    pub fn close_connection(&mut self, link_id: &LinkId) {
        self.link_manager.close(link_id, &mut self.rng);
        self.connections.remove(link_id);
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
    /// The packet hash for tracking delivery (if proofs are enabled)
    pub fn send_single_packet(
        &mut self,
        dest_hash: &DestinationHash,
        data: &[u8],
    ) -> Result<[u8; TRUNCATED_HASHBYTES], send::SendError> {
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
        let len = packet.pack(&mut buf).map_err(|_| send::SendError::TooLarge)?;

        // Send via transport
        self.transport
            .send_to_destination(dest_hash.as_bytes(), &buf[..len])
            .map_err(|_| send::SendError::NoPath)?;

        // Create receipt and return hash
        let packet_hash = self
            .transport
            .create_receipt(&buf[..len], dest_hash.into_bytes());

        Ok(packet_hash)
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
    /// The packet data to transmit, or an error
    pub fn send_on_connection(
        &mut self,
        link_id: &LinkId,
        data: &[u8],
    ) -> Result<Vec<u8>, send::SendError> {
        // Get the connection and link
        let connection = self
            .connections
            .get_mut(link_id)
            .ok_or(send::SendError::NoConnection)?;

        let link = self
            .link_manager
            .link(link_id)
            .ok_or(send::SendError::NoConnection)?;

        let now_ms = self.transport.clock().now_ms();

        // Send via connection
        connection
            .send_bytes(link, data, &mut self.rng, now_ms)
            .map_err(|e| match e {
                ConnectionError::ChannelError(crate::link::channel::ChannelError::WindowFull) => {
                    send::SendError::WindowFull
                }
                ConnectionError::ChannelError(crate::link::channel::ChannelError::TooLarge) => {
                    send::SendError::TooLarge
                }
                _ => send::SendError::ConnectionFailed,
            })
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

    // ─── Packet Processing ─────────────────────────────────────────────────────

    /// Process an incoming raw packet from an interface
    ///
    /// # Arguments
    /// * `interface_index` - The interface the packet arrived on
    /// * `raw` - The raw packet bytes
    pub fn receive_packet(
        &mut self,
        interface_index: usize,
        raw: &[u8],
    ) -> Result<(), TransportError> {
        self.transport.process_incoming(interface_index, raw)
    }

    /// Send a packet on a specific interface
    pub fn send_on_interface(
        &mut self,
        interface_index: usize,
        data: &[u8],
    ) -> Result<(), TransportError> {
        self.transport.send_on_interface(interface_index, data)
    }

    /// Send a packet to a destination via its known path
    pub fn send_to_destination(
        &mut self,
        dest_hash: &DestinationHash,
        data: &[u8],
    ) -> Result<(), TransportError> {
        self.transport.send_to_destination(dest_hash.as_bytes(), data)
    }

    // ─── Polling ───────────────────────────────────────────────────────────────

    /// Drive the node for one tick, returning all events.
    ///
    /// Single entry point: polls interfaces, runs maintenance, processes events.
    /// This is the preferred way to drive the node in an event loop.
    pub fn tick(&mut self) -> Vec<NodeEvent> {
        self.transport.poll_interfaces();

        let now_ms = self.transport.clock().now_ms();
        self.transport.poll();
        self.link_manager.poll(&mut self.rng, now_ms);

        let transport_events: Vec<_> = self.transport.drain_events().collect();
        for event in transport_events {
            self.handle_transport_event(event);
        }
        let link_events: Vec<_> = self.link_manager.drain_events().collect();
        for event in link_events {
            self.handle_link_event(event);
        }
        self.send_pending_packets();

        core::mem::take(&mut self.events)
    }

    /// Poll registered interfaces for incoming data.
    ///
    /// Reads from each interface registered via `register_interface()` and
    /// feeds received packets into the transport layer for processing.
    pub fn poll_interfaces(&mut self) {
        self.transport.poll_interfaces();
    }

    /// Poll for the next event
    ///
    /// This processes transport events, link events, and returns unified NodeEvents.
    /// Call this in your main loop to handle all node activity.
    pub fn poll(&mut self) -> Option<NodeEvent> {
        // Check for pending events first
        if !self.events.is_empty() {
            return Some(self.events.remove(0));
        }

        let now_ms = self.transport.clock().now_ms();

        // Poll transport for periodic work
        self.transport.poll();

        // Poll link manager
        self.link_manager.poll(&mut self.rng, now_ms);

        // Collect transport events first to avoid borrow issues
        let transport_events: Vec<_> = self.transport.drain_events().collect();
        for event in transport_events {
            self.handle_transport_event(event);
        }

        // Collect link events first to avoid borrow issues
        let link_events: Vec<_> = self.link_manager.drain_events().collect();
        for event in link_events {
            self.handle_link_event(event);
        }

        // Handle pending RTT packets (need to send after link establishment)
        self.send_pending_packets();

        // Return next event if available
        if !self.events.is_empty() {
            Some(self.events.remove(0))
        } else {
            None
        }
    }

    /// Drain all pending events
    pub fn drain_events(&mut self) -> alloc::vec::Drain<'_, NodeEvent> {
        self.events.drain(..)
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

    /// Get the number of links being relayed through this node
    pub fn relayed_link_count(&self) -> usize {
        self.transport.link_table_count()
    }

    /// Access the underlying transport (for advanced use cases)
    pub fn transport(&self) -> &Transport<C, S> {
        &self.transport
    }

    /// Access the underlying transport mutably
    pub fn transport_mut(&mut self) -> &mut Transport<C, S> {
        &mut self.transport
    }

    /// Access the underlying link manager (for advanced use cases)
    pub fn link_manager(&self) -> &LinkManager {
        &self.link_manager
    }

    /// Access the underlying link manager mutably
    pub fn link_manager_mut(&mut self) -> &mut LinkManager {
        &mut self.link_manager
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
                self.events
                    .push(NodeEvent::PathLost { destination_hash: DestinationHash::new(destination_hash) });
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
                        && self.link_manager.link(&LinkId::new(destination_hash)).is_some())
                {
                    // Route to link manager
                    let raw = self.repack_packet(&packet);
                    let now_ms = self.transport.clock().now_ms();
                    self.link_manager.process_packet(&packet, &raw, &mut self.rng, now_ms);
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

            TransportEvent::PathRequestReceived {
                destination_hash,
            } => {
                // For now, emit as a path found event so the application
                // can re-announce the destination
                self.events.push(NodeEvent::PathFound {
                    destination_hash: DestinationHash::new(destination_hash),
                    hops: 0,
                    interface_index: 0,
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
                self.connections.remove(&link_id);
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
                // App-level proof request from link layer (PROVE_APP strategy)
                // For now we expose this as a link-level ProofRequested event
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
                    // Route to destination via transport
                    if let Some(link) = self.link_manager.link(&link_id) {
                        let dest_hash = *link.destination_hash();
                        let _ = self.transport.send_to_destination(dest_hash.as_bytes(), &data);
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
    fn test_nodecore_poll_empty() {
        let clock = MockClock::new(1_000_000);
        let mut node = NodeCoreBuilder::new()
            .build(OsRng, clock, NoStorage)
            .unwrap();

        // Poll should return None when there are no events
        assert!(node.poll().is_none());
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
}
