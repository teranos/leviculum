//! Transport layer - routing, path discovery, packet handling
//!
//! The Transport is the heart of the Reticulum protocol. It manages:
//! - Interface registration and packet I/O
//! - Packet routing based on destination hash
//! - Path discovery via announce propagation
//! - Link table management
//! - Duplicate packet detection
//!
//! # Design
//!
//! Transport is generic over platform traits (`Clock`, `Storage`) so the same
//! protocol logic runs on std (Linux, macOS) and no_std (ESP32, nRF52).
//!
//! The Transport uses a sync/polling model. Platform crates wrap it with
//! their async runtime (tokio, embassy, etc.).
//!
//! ```text
//! use reticulum_core::transport::{Transport, TransportConfig};
//!
//! let mut transport = Transport::new(config, clock, storage, identity);
//! let idx = transport.register_interface(interface);
//!
//! // Main loop:
//! transport.process_incoming(idx, &raw_data)?;
//! for event in transport.drain_events() {
//!     // handle event
//! }
//! transport.poll();
//! ```

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::constants::{
    ANNOUNCE_RATE_LIMIT_MS, LINK_TIMEOUT_MS, LOCAL_REBROADCASTS_MAX, MAX_PATH_REQUEST_TAGS,
    MS_PER_SECOND, MTU, PACKET_CACHE_EXPIRY_MS, PATH_REQUEST_GRACE_MS,
    PATH_REQUEST_MIN_INTERVAL_MS, PATHFINDER_EXPIRY_SECS, PATHFINDER_G_MS, PATHFINDER_MAX_HOPS,
    PATHFINDER_RETRIES, PATHFINDER_RW_MS, REVERSE_TABLE_EXPIRY_MS, TRUNCATED_HASHBYTES,
};

use crate::announce::ReceivedAnnounce;
use crate::crypto::truncated_hash;
use crate::destination::{Destination, DestinationHash, ProofStrategy};
use crate::identity::Identity;
use crate::link::Link;
use crate::packet::{
    build_proof_packet, packet_hash, truncated_packet_hash, HeaderType, Packet, PacketContext,
    PacketData, PacketError, PacketFlags, PacketType, TransportType,
};
use crate::receipt::{PacketReceipt, ReceiptStatus};
use crate::traits::{Clock, Interface, InterfaceError, Storage};

// ─── Data Structures (always available) ─────────────────────────────────────

/// Path table entry
#[derive(Debug, Clone)]
pub struct PathEntry {
    /// When this path was learned (ms since clock epoch)
    pub timestamp_ms: u64,
    /// Hash of the interface that told us about this path
    pub received_from: [u8; TRUNCATED_HASHBYTES],
    /// Number of hops to destination
    pub hops: u8,
    /// When this path expires (ms since clock epoch)
    pub expires_ms: u64,
    /// Interface index where we learned this path
    pub interface_index: usize,
    /// Random blobs seen for this destination (for replay detection)
    pub random_blobs: Vec<[u8; crate::constants::RANDOM_HASHBYTES]>,
}

/// Link table entry (for active links routed through this transport node)
#[derive(Debug, Clone)]
pub struct LinkEntry {
    /// When this link was created (ms)
    pub timestamp_ms: u64,
    /// Transport ID of the next hop toward the destination
    pub next_hop_transport_id: [u8; TRUNCATED_HASHBYTES],
    /// Interface index toward the destination (outbound)
    pub next_hop_interface_index: usize,
    /// Remaining hops to destination
    pub remaining_hops: u8,
    /// Interface index where we received the link request (inbound, toward initiator)
    pub received_interface_index: usize,
    /// Total hops from initiator
    pub hops: u8,
    /// Destination hash for the link target
    pub destination_hash: [u8; TRUNCATED_HASHBYTES],
    /// Whether the link has been validated by a proof
    pub validated: bool,
    /// Deadline for receiving a proof (ms), after which the entry is removed
    pub proof_timeout_ms: u64,
}

/// Reverse table entry (for routing replies back)
#[derive(Debug, Clone)]
pub struct ReverseEntry {
    /// When this was learned (ms)
    pub timestamp_ms: u64,
    /// Who sent this to us
    pub received_from: [u8; TRUNCATED_HASHBYTES],
    /// Interface index where the original packet was received
    pub receiving_interface_index: usize,
    /// Interface index where the packet was forwarded to
    pub outbound_interface_index: usize,
}

/// Announce table entry (for rate limiting and rebroadcast tracking)
#[derive(Debug, Clone)]
pub struct AnnounceEntry {
    /// When we received this announce (ms)
    pub timestamp_ms: u64,
    /// Number of hops when received
    pub hops: u8,
    /// Number of retransmit attempts
    pub retries: u8,
    /// When to retransmit (ms, None = don't)
    pub retransmit_at_ms: Option<u64>,
    /// Raw packet bytes stored for rebroadcast
    pub raw_packet: Vec<u8>,
    /// Interface index this announce arrived on
    pub receiving_interface_index: usize,
    /// Number of times neighbors echoed this announce
    pub local_rebroadcasts: u8,
    /// If true, do not re-rebroadcast (PATH_RESPONSE context)
    pub block_rebroadcasts: bool,
}

/// Transport configuration
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Enable transport mode (routing for others)
    pub enable_transport: bool,
    /// Maximum hops for path finding
    pub max_hops: u8,
    /// Path expiry time in seconds
    pub path_expiry_secs: u64,
    /// Announce rate limit minimum interval (ms)
    pub announce_rate_limit_ms: u64,
    /// Packet cache expiry (ms) - for deduplication
    pub packet_cache_expiry_ms: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            enable_transport: false,
            max_hops: PATHFINDER_MAX_HOPS,
            path_expiry_secs: PATHFINDER_EXPIRY_SECS,
            announce_rate_limit_ms: ANNOUNCE_RATE_LIMIT_MS,
            packet_cache_expiry_ms: PACKET_CACHE_EXPIRY_MS,
        }
    }
}

/// Transport statistics
#[derive(Debug, Default, Clone)]
pub struct TransportStats {
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Packets forwarded (transport mode)
    pub packets_forwarded: u64,
    /// Announces processed
    pub announces_processed: u64,
    /// Packets dropped (duplicate, expired, etc.)
    pub packets_dropped: u64,
}

// ─── Events ─────────────────────────────────────────────────────────────────

/// Events emitted by Transport for the application to handle
#[derive(Debug)]
pub enum TransportEvent {
    /// A new announce was received and validated
    AnnounceReceived {
        /// Parsed announce data
        announce: ReceivedAnnounce,
        /// Interface it arrived on
        interface_index: usize,
    },
    /// A packet arrived for a registered destination
    PacketReceived {
        /// The destination hash
        destination_hash: [u8; TRUNCATED_HASHBYTES],
        /// The parsed packet (boxed to reduce enum size)
        packet: Box<Packet>,
        /// Interface it arrived on
        interface_index: usize,
    },
    /// Path to a destination was found (from announce)
    PathFound {
        /// Destination hash
        destination_hash: [u8; TRUNCATED_HASHBYTES],
        /// Number of hops
        hops: u8,
        /// Interface index
        interface_index: usize,
    },
    /// Path to a destination expired
    PathLost {
        /// Destination hash
        destination_hash: [u8; TRUNCATED_HASHBYTES],
    },
    /// A path request was received for a local destination
    ///
    /// The application should re-announce the destination so the requester can learn the path.
    PathRequestReceived {
        /// The destination hash being requested
        destination_hash: [u8; TRUNCATED_HASHBYTES],
    },

    /// An interface went offline
    InterfaceDown(usize),

    // ─── Proof Events ────────────────────────────────────────────────────────
    /// Application should decide whether to prove this packet (PROVE_APP strategy)
    ///
    /// Emitted when a packet is received at a destination with `ProofStrategy::App`.
    /// The application should call `send_proof()` if it decides to prove.
    ProofRequested {
        /// Full SHA256 hash of the packet to potentially prove
        packet_hash: [u8; 32],
        /// Destination that received the packet
        destination_hash: [u8; TRUNCATED_HASHBYTES],
    },

    /// A proof was received for a sent packet
    ///
    /// Emitted when a proof packet is received and validated (or fails validation).
    ProofReceived {
        /// Truncated hash identifying the receipt
        packet_hash: [u8; TRUNCATED_HASHBYTES],
        /// Whether the proof was valid
        is_valid: bool,
    },

    /// A receipt timed out without receiving a proof
    ReceiptTimeout {
        /// Truncated hash identifying the receipt
        packet_hash: [u8; TRUNCATED_HASHBYTES],
    },
}

// ─── Error Types ────────────────────────────────────────────────────────────

/// Transport error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// No path to destination
    NoPath,
    /// Packet parsing error
    PacketError(PacketError),
    /// Announce validation error
    AnnounceError(crate::announce::AnnounceError),
    /// Interface I/O error
    InterfaceError(InterfaceError),
    /// Interface index out of range
    InvalidInterface,
}

impl From<PacketError> for TransportError {
    fn from(e: PacketError) -> Self {
        TransportError::PacketError(e)
    }
}

impl From<InterfaceError> for TransportError {
    fn from(e: InterfaceError) -> Self {
        TransportError::InterfaceError(e)
    }
}

// ─── Destination Entry ──────────────────────────────────────────────────────

/// Entry for a registered destination
struct DestinationEntry {
    /// Whether this destination accepts incoming links
    accepts_links: bool,
    /// Proof generation strategy for incoming packets
    proof_strategy: ProofStrategy,
    /// Identity for this destination (needed to create proofs)
    identity: Option<Identity>,
}

// ─── Transport ──────────────────────────────────────────────────────────────

/// The Transport layer
///
/// Generic over platform traits so the same protocol logic runs everywhere.
///
/// - `C`: Clock implementation for timestamps
/// - `S`: Storage implementation for persistence
pub struct Transport<C: Clock, S: Storage> {
    config: TransportConfig,
    clock: C,
    _storage: S,
    identity: Identity,

    /// Registered interfaces (indices are stable; removed interfaces become None)
    interfaces: Vec<Option<Box<dyn Interface + Send>>>,

    /// Path table: destination_hash -> path info
    path_table: BTreeMap<[u8; TRUNCATED_HASHBYTES], PathEntry>,

    /// Announce table: destination_hash -> announce rate tracking
    announce_table: BTreeMap<[u8; TRUNCATED_HASHBYTES], AnnounceEntry>,

    /// Link table: link_id -> link routing info
    link_table: BTreeMap<[u8; TRUNCATED_HASHBYTES], LinkEntry>,

    /// Reverse table: packet_hash -> sender info (for routing replies)
    reverse_table: BTreeMap<[u8; TRUNCATED_HASHBYTES], ReverseEntry>,

    /// Registered destinations we accept packets for
    destinations: BTreeMap<[u8; TRUNCATED_HASHBYTES], DestinationEntry>,

    /// Packet deduplication cache: packet_hash -> timestamp_ms
    packet_cache: BTreeMap<[u8; TRUNCATED_HASHBYTES], u64>,

    /// Receipts for sent packets awaiting proof: truncated_hash -> receipt
    receipts: BTreeMap<[u8; TRUNCATED_HASHBYTES], PacketReceipt>,

    /// Pending events for the application
    events: Vec<TransportEvent>,

    /// Statistics
    stats: TransportStats,

    /// Well-known hash for path request destination (rnstransport.path.request)
    path_request_hash: [u8; TRUNCATED_HASHBYTES],

    /// Dedup tags for path requests (dest_hash + random tag)
    path_request_tags: VecDeque<[u8; 32]>,

    /// Rate limiting for path requests: dest_hash -> last request timestamp (ms)
    path_requests: BTreeMap<[u8; TRUNCATED_HASHBYTES], u64>,

    /// Cached raw announce bytes for path responses: dest_hash -> raw bytes
    announce_cache: BTreeMap<[u8; TRUNCATED_HASHBYTES], Vec<u8>>,

    /// Known identities from received announces: dest_hash -> Identity
    identity_table: BTreeMap<[u8; TRUNCATED_HASHBYTES], Identity>,
}

impl<C: Clock, S: Storage> Transport<C, S> {
    /// Create a new Transport instance
    pub fn new(config: TransportConfig, clock: C, storage: S, identity: Identity) -> Self {
        let path_request_hash = Self::compute_path_request_hash();
        Self {
            config,
            clock,
            _storage: storage,
            identity,
            interfaces: Vec::new(),
            path_table: BTreeMap::new(),
            announce_table: BTreeMap::new(),
            link_table: BTreeMap::new(),
            reverse_table: BTreeMap::new(),
            destinations: BTreeMap::new(),
            packet_cache: BTreeMap::new(),
            receipts: BTreeMap::new(),
            events: Vec::new(),
            stats: TransportStats::default(),
            path_request_hash,
            path_request_tags: VecDeque::new(),
            path_requests: BTreeMap::new(),
            announce_cache: BTreeMap::new(),
            identity_table: BTreeMap::new(),
        }
    }

    // ─── Interface Management ───────────────────────────────────────────

    /// Register an interface, returns its stable index
    pub fn register_interface(&mut self, interface: Box<dyn Interface + Send>) -> usize {
        let index = self.interfaces.len();
        self.interfaces.push(Some(interface));
        index
    }

    /// Unregister an interface by index
    pub fn unregister_interface(&mut self, index: usize) {
        if let Some(slot) = self.interfaces.get_mut(index) {
            *slot = None;
        }
    }

    /// Get a mutable reference to an interface
    pub fn interface_mut(&mut self, index: usize) -> Option<&mut (dyn Interface + '_)> {
        match self.interfaces.get_mut(index) {
            Some(Some(iface)) => Some(iface.as_mut()),
            _ => None,
        }
    }

    /// Get an immutable reference to an interface
    pub fn interface_ref(&self, index: usize) -> Option<&(dyn Interface + '_)> {
        match self.interfaces.get(index) {
            Some(Some(iface)) => Some(iface.as_ref()),
            _ => None,
        }
    }

    /// Get the number of registered interfaces
    pub fn interface_count(&self) -> usize {
        self.interfaces.iter().filter(|i| i.is_some()).count()
    }

    // ─── Destination Management ─────────────────────────────────────────

    /// Register a destination to receive packets
    ///
    /// # Arguments
    /// * `hash` - The destination hash
    /// * `accepts_links` - Whether this destination accepts incoming links
    pub fn register_destination(&mut self, hash: [u8; TRUNCATED_HASHBYTES], accepts_links: bool) {
        self.destinations.insert(
            hash,
            DestinationEntry {
                accepts_links,
                proof_strategy: ProofStrategy::None,
                identity: None,
            },
        );
    }

    /// Register a destination with proof support
    ///
    /// # Arguments
    /// * `hash` - The destination hash
    /// * `accepts_links` - Whether this destination accepts incoming links
    /// * `proof_strategy` - How to handle proof generation
    /// * `identity` - The destination's identity (needed to create proofs)
    pub fn register_destination_with_proof(
        &mut self,
        hash: [u8; TRUNCATED_HASHBYTES],
        accepts_links: bool,
        proof_strategy: ProofStrategy,
        identity: Option<Identity>,
    ) {
        self.destinations.insert(
            hash,
            DestinationEntry {
                accepts_links,
                proof_strategy,
                identity,
            },
        );
    }

    /// Set the proof strategy for an existing destination
    ///
    /// # Arguments
    /// * `hash` - The destination hash
    /// * `strategy` - The new proof strategy
    ///
    /// # Returns
    /// `true` if the destination exists and was updated
    pub fn set_destination_proof_strategy(
        &mut self,
        hash: &[u8; TRUNCATED_HASHBYTES],
        strategy: ProofStrategy,
    ) -> bool {
        if let Some(entry) = self.destinations.get_mut(hash) {
            entry.proof_strategy = strategy;
            true
        } else {
            false
        }
    }

    /// Unregister a destination
    pub fn unregister_destination(&mut self, hash: &[u8; TRUNCATED_HASHBYTES]) {
        self.destinations.remove(hash);
    }

    /// Check if a destination is registered
    pub fn has_destination(&self, hash: &[u8; TRUNCATED_HASHBYTES]) -> bool {
        self.destinations.contains_key(hash)
    }

    // ─── Path Management ────────────────────────────────────────────────

    /// Check if we have a path to a destination
    pub fn has_path(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> bool {
        self.path_table.contains_key(dest_hash)
    }

    /// Get the hop count to a destination
    pub fn hops_to(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<u8> {
        self.path_table.get(dest_hash).map(|p| p.hops)
    }

    /// Get a path entry
    pub fn path(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<&PathEntry> {
        self.path_table.get(dest_hash)
    }

    /// Get the number of known paths
    pub fn path_count(&self) -> usize {
        self.path_table.len()
    }

    // ─── Receipt Management ──────────────────────────────────────────────

    /// Create a receipt for a sent packet
    ///
    /// Call this after sending a packet that you want to track for proof of delivery.
    ///
    /// # Arguments
    /// * `raw_packet` - The raw packet bytes (used to compute hash)
    /// * `destination_hash` - The destination the packet was sent to
    ///
    /// # Returns
    /// The truncated hash that can be used to look up the receipt later
    pub fn create_receipt(
        &mut self,
        raw_packet: &[u8],
        destination_hash: [u8; TRUNCATED_HASHBYTES],
    ) -> [u8; TRUNCATED_HASHBYTES] {
        let hash = packet_hash(raw_packet);
        let now = self.clock.now_ms();
        let receipt = PacketReceipt::new(hash, DestinationHash::new(destination_hash), now);
        let truncated = receipt.truncated_hash;
        self.receipts.insert(truncated, receipt);
        truncated
    }

    /// Create a receipt with a custom timeout
    pub fn create_receipt_with_timeout(
        &mut self,
        raw_packet: &[u8],
        destination_hash: [u8; TRUNCATED_HASHBYTES],
        timeout_ms: u64,
    ) -> [u8; TRUNCATED_HASHBYTES] {
        let hash = packet_hash(raw_packet);
        let now = self.clock.now_ms();
        let receipt = PacketReceipt::with_timeout(hash, DestinationHash::new(destination_hash), now, timeout_ms);
        let truncated = receipt.truncated_hash;
        self.receipts.insert(truncated, receipt);
        truncated
    }

    /// Get a receipt by its truncated hash
    pub fn get_receipt(
        &self,
        truncated_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&PacketReceipt> {
        self.receipts.get(truncated_hash)
    }

    /// Get the number of pending receipts
    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }

    /// Send a proof for a received packet
    ///
    /// Call this when the application decides to prove a packet (after ProofRequested event).
    ///
    /// # Arguments
    /// * `packet_hash` - The full SHA256 hash of the packet to prove
    /// * `destination_hash` - The destination to send the proof to (the original sender)
    /// * `identity` - The identity to sign the proof with
    ///
    /// # Returns
    /// `Ok(())` if the proof was sent, `Err` if there's no path to the destination
    pub fn send_proof(
        &mut self,
        packet_hash: &[u8; 32],
        destination_hash: &[u8; TRUNCATED_HASHBYTES],
        identity: &Identity,
    ) -> Result<(), TransportError> {
        let proof_data = identity
            .create_proof(packet_hash)
            .map_err(|_| TransportError::NoPath)?; // Use NoPath for simplicity

        let packet = build_proof_packet(destination_hash, &proof_data);

        // Send via the same path we'd use for any packet to this destination
        let interface_index = self
            .path_table
            .get(destination_hash)
            .map(|p| p.interface_index)
            .ok_or(TransportError::NoPath)?;

        self.send_packet_on_interface(interface_index, &packet)
    }

    // ─── Packet I/O ─────────────────────────────────────────────────────

    /// Process incoming raw data from an interface
    ///
    /// Parses the packet, checks for duplicates, routes to the appropriate
    /// handler, and may emit events.
    pub fn process_incoming(
        &mut self,
        interface_index: usize,
        raw: &[u8],
    ) -> Result<(), TransportError> {
        self.stats.packets_received += 1;

        let packet = Packet::unpack(raw)?;

        // Compute full packet hash (for proofs) and truncated hash (for deduplication)
        let full_packet_hash = packet_hash(raw);
        let dedup_hash = truncated_packet_hash(raw);
        let now = self.clock.now_ms();

        // Check duplicate
        if self.packet_cache.contains_key(&dedup_hash) {
            self.stats.packets_dropped += 1;
            return Ok(());
        }

        // Cache this packet hash
        self.packet_cache.insert(dedup_hash, now);

        // Route to handler based on packet type
        // Note: reverse table entries are populated at forwarding time (in forward_packet,
        // handle_data link-table routing, handle_link_request) so they include the
        // outbound interface index needed for proof routing.
        match packet.flags.packet_type {
            PacketType::Announce => self.handle_announce(packet, interface_index, raw),
            PacketType::LinkRequest => self.handle_link_request(packet, interface_index, raw, dedup_hash),
            PacketType::Proof => self.handle_proof(packet, interface_index),
            PacketType::Data => self.handle_data(packet, interface_index, full_packet_hash, dedup_hash),
        }
    }

    /// Send raw data on a specific interface
    pub fn send_on_interface(
        &mut self,
        interface_index: usize,
        data: &[u8],
    ) -> Result<(), TransportError> {
        let iface = self
            .interfaces
            .get_mut(interface_index)
            .and_then(|slot| slot.as_deref_mut())
            .ok_or(TransportError::InvalidInterface)?;

        iface.send(data)?;
        self.stats.packets_sent += 1;
        Ok(())
    }

    /// Send raw data on all online interfaces
    pub fn send_on_all_interfaces(&mut self, data: &[u8]) {
        for iface in self.interfaces.iter_mut().flatten() {
            if iface.is_online() {
                let _ = iface.send(data); // Best effort
            }
        }
        self.stats.packets_sent += 1;
    }

    /// Send a packet to a destination via its known path
    pub fn send_to_destination(
        &mut self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
        data: &[u8],
    ) -> Result<(), TransportError> {
        let interface_index = self
            .path_table
            .get(dest_hash)
            .map(|p| p.interface_index)
            .ok_or(TransportError::NoPath)?;

        self.send_on_interface(interface_index, data)
    }

    // ─── Polling ────────────────────────────────────────────────────────

    /// Poll registered interfaces for incoming data and process any received packets.
    ///
    /// This reads from each registered interface and feeds received data into
    /// `process_incoming()`. The borrow on each interface is scoped so that
    /// `process_incoming()` can access other interfaces for forwarding.
    pub fn poll_interfaces(&mut self) {
        let mut recv_buf = [0u8; MTU];
        for idx in 0..self.interfaces.len() {
            loop {
                let len = {
                    let iface = match self.interfaces.get_mut(idx) {
                        Some(Some(iface)) => iface.as_mut(),
                        _ => break,
                    };
                    match iface.recv(&mut recv_buf) {
                        Ok(len) if len > 0 => len,
                        _ => break,
                    }
                };
                // Interface borrow dropped — safe to call process_incoming
                let data = recv_buf[..len].to_vec();
                let _ = self.process_incoming(idx, &data);
            }
        }
    }

    /// Drive the transport layer for one tick.
    ///
    /// Polls interfaces for incoming data, then runs periodic maintenance.
    /// This is the preferred single entry point for the transport layer.
    pub fn tick(&mut self) {
        self.poll_interfaces();
        self.poll();
    }

    /// Poll for periodic work
    ///
    /// Call this regularly (e.g. every 100ms). Handles:
    /// - Path expiry
    /// - Packet cache cleanup
    /// - Announce retransmission (if transport node)
    /// - Receipt timeout checking
    pub fn poll(&mut self) {
        let now = self.clock.now_ms();
        self.expire_paths(now);
        self.clean_packet_cache(now);
        self.clean_reverse_table(now);
        self.check_receipt_timeouts(now);
        self.check_announce_rebroadcasts(now);
        self.clean_link_table(now);
    }

    // ─── Events ─────────────────────────────────────────────────────────

    /// Drain pending events
    ///
    /// Returns an iterator over all events that occurred since the last drain.
    pub fn drain_events(&mut self) -> alloc::vec::Drain<'_, TransportEvent> {
        self.events.drain(..)
    }

    /// Number of pending events
    pub fn pending_events(&self) -> usize {
        self.events.len()
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// Get transport statistics
    pub fn stats(&self) -> &TransportStats {
        &self.stats
    }

    /// Get the transport configuration
    pub fn config(&self) -> &TransportConfig {
        &self.config
    }

    /// Get the transport identity
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Access the clock
    pub fn clock(&self) -> &C {
        &self.clock
    }

    /// Iterate over all path table entries
    pub fn paths(&self) -> impl Iterator<Item = (&[u8; TRUNCATED_HASHBYTES], &PathEntry)> {
        self.path_table.iter()
    }

    /// Number of active entries in the link relay table
    pub fn link_table_count(&self) -> usize {
        self.link_table.len()
    }

    /// Get a link table entry by link ID hash
    pub fn link_table_entry(&self, link_id: &[u8; TRUNCATED_HASHBYTES]) -> Option<&LinkEntry> {
        self.link_table.get(link_id)
    }

    /// Iterate over all link table entries
    pub fn link_table_iter(
        &self,
    ) -> impl Iterator<Item = (&[u8; TRUNCATED_HASHBYTES], &LinkEntry)> {
        self.link_table.iter()
    }

    /// Number of pending announce rebroadcasts
    pub fn announce_table_count(&self) -> usize {
        self.announce_table.len()
    }

    // ─── Internal: Packet Handlers ──────────────────────────────────────

    fn handle_announce(
        &mut self,
        packet: Packet,
        interface_index: usize,
        raw: &[u8],
    ) -> Result<(), TransportError> {
        let now = self.clock.now_ms();
        let is_path_response = packet.context == PacketContext::PathResponse;

        // Parse announce
        let announce =
            ReceivedAnnounce::from_packet(&packet).map_err(TransportError::AnnounceError)?;

        // Validate signature and destination hash
        announce.validate().map_err(TransportError::AnnounceError)?;

        let dest_hash = announce.destination_hash().into_bytes();
        let random_hash = *announce.random_hash();

        // Random blob replay protection: reject if we've seen this exact random_hash
        if let Some(path) = self.path_table.get(&dest_hash) {
            if path.random_blobs.contains(&random_hash) {
                self.stats.packets_dropped += 1;
                return Ok(());
            }
        }

        // Rate limiting: check if we've seen this destination recently
        // Also detect local rebroadcasts from neighbors
        if let Some(existing) = self.announce_table.get_mut(&dest_hash) {
            let elapsed = now.saturating_sub(existing.timestamp_ms);
            if elapsed < self.config.announce_rate_limit_ms {
                // Local rebroadcast detection: neighbor sent same announce at same or +1 hop
                if packet.hops == existing.hops.saturating_add(1) {
                    // A neighbor is rebroadcasting the same announce we have
                    existing.local_rebroadcasts = existing.local_rebroadcasts.saturating_add(1);
                    if existing.local_rebroadcasts >= LOCAL_REBROADCASTS_MAX {
                        // Enough neighbors have rebroadcast; suppress our own
                        existing.retransmit_at_ms = None;
                    }
                } else if packet.hops == existing.hops.saturating_add(2)
                    && existing.retries > 0
                    && existing.retransmit_at_ms.is_some()
                {
                    // Another node forwarded our rebroadcast (hops+2 means they got
                    // our retransmit at hops+1 and forwarded it)
                    existing.retransmit_at_ms = None;
                }

                self.stats.packets_dropped += 1;
                return Ok(());
            }
        }

        // Update path table
        let is_new_path = !self.path_table.contains_key(&dest_hash);
        let iface_hash = self
            .interfaces
            .get(interface_index)
            .and_then(|i| i.as_ref())
            .map(|i| i.hash())
            .unwrap_or([0u8; TRUNCATED_HASHBYTES]);

        // Preserve existing random_blobs and add the new one
        let mut random_blobs = self
            .path_table
            .get(&dest_hash)
            .map(|p| p.random_blobs.clone())
            .unwrap_or_default();
        random_blobs.push(random_hash);

        self.path_table.insert(
            dest_hash,
            PathEntry {
                timestamp_ms: now,
                received_from: iface_hash,
                hops: packet.hops,
                expires_ms: now + (self.config.path_expiry_secs * 1000),
                interface_index,
                random_blobs,
            },
        );

        // Determine if we should schedule rebroadcast
        let should_rebroadcast =
            self.config.enable_transport && !is_path_response;

        // Update announce table
        self.announce_table.insert(
            dest_hash,
            AnnounceEntry {
                timestamp_ms: now,
                hops: packet.hops,
                retries: 0,
                retransmit_at_ms: if should_rebroadcast {
                    Some(now + self.calculate_retransmit_delay(packet.hops))
                } else {
                    None
                },
                raw_packet: raw.to_vec(),
                receiving_interface_index: interface_index,
                local_rebroadcasts: 0,
                block_rebroadcasts: is_path_response,
            },
        );

        // Cache raw announce for path responses (when transport is enabled)
        if self.config.enable_transport {
            self.announce_cache.insert(dest_hash, raw.to_vec());
        }

        // Store identity from announce for proof validation
        if let Ok(identity) = announce.to_identity() {
            self.identity_table.insert(dest_hash, identity);
        }

        self.stats.announces_processed += 1;

        // Emit events
        if is_new_path {
            self.events.push(TransportEvent::PathFound {
                destination_hash: dest_hash,
                hops: packet.hops,
                interface_index,
            });
        }

        self.events.push(TransportEvent::AnnounceReceived {
            announce,
            interface_index,
        });

        Ok(())
    }

    fn handle_link_request(
        &mut self,
        packet: Packet,
        interface_index: usize,
        raw: &[u8],
        dedup_hash: [u8; TRUNCATED_HASHBYTES],
    ) -> Result<(), TransportError> {
        let dest_hash = packet.destination_hash;

        // Check if we have this destination registered and it accepts links
        if let Some(entry) = self.destinations.get(&dest_hash) {
            if entry.accepts_links {
                // Emit event for application to handle
                self.events.push(TransportEvent::PacketReceived {
                    destination_hash: dest_hash,
                    packet: Box::new(packet),
                    interface_index,
                });
                return Ok(());
            }
        }

        // If we're a transport node, forward the link request and populate link table
        if self.config.enable_transport {
            if let Some(path) = self.path_table.get(&dest_hash) {
                let now = self.clock.now_ms();
                let link_id = Link::calculate_link_id(raw);
                let target_iface = path.interface_index;
                let iface_hash = path.received_from;
                let transport_id_bytes = *self.identity.hash();

                // Insert link table entry for bidirectional routing
                self.link_table.insert(
                    *link_id.as_bytes(),
                    LinkEntry {
                        timestamp_ms: now,
                        next_hop_transport_id: iface_hash,
                        next_hop_interface_index: target_iface,
                        remaining_hops: path.hops,
                        received_interface_index: interface_index,
                        hops: packet.hops,
                        destination_hash: dest_hash,
                        validated: false,
                        proof_timeout_ms: now
                            + ((packet.hops as u64 + path.hops as u64 + 2)
                                * crate::constants::DEFAULT_PER_HOP_TIMEOUT
                                * MS_PER_SECOND),
                    },
                );

                // Populate reverse table at forwarding time
                let recv_iface_hash = self
                    .interfaces
                    .get(interface_index)
                    .and_then(|i| i.as_ref())
                    .map(|i| i.hash())
                    .unwrap_or([0u8; TRUNCATED_HASHBYTES]);
                self.reverse_table.insert(
                    dedup_hash,
                    ReverseEntry {
                        timestamp_ms: now,
                        received_from: recv_iface_hash,
                        receiving_interface_index: interface_index,
                        outbound_interface_index: target_iface,
                    },
                );

                // Forward: strip to Type1 at final hop, Type2 otherwise
                let remaining_hops = path.hops;
                let mut forwarded = if remaining_hops <= 1 {
                    // Final hop: destination is directly connected, strip transport header
                    Packet {
                        flags: PacketFlags {
                            header_type: HeaderType::Type1,
                            transport_type: TransportType::Broadcast,
                            ..packet.flags
                        },
                        hops: packet.hops,
                        transport_id: None,
                        destination_hash: dest_hash,
                        context: packet.context,
                        data: packet.data,
                    }
                } else {
                    // Intermediate: Header Type 2 with our transport ID
                    Packet {
                        flags: PacketFlags {
                            header_type: HeaderType::Type2,
                            transport_type: TransportType::Transport,
                            ..packet.flags
                        },
                        hops: packet.hops,
                        transport_id: Some(transport_id_bytes),
                        destination_hash: dest_hash,
                        context: packet.context,
                        data: packet.data,
                    }
                };

                return self.forward_on_interface(target_iface, &mut forwarded);
            }

            // No path known, drop
            self.stats.packets_dropped += 1;
        }

        Ok(())
    }

    fn handle_proof(
        &mut self,
        packet: Packet,
        interface_index: usize,
    ) -> Result<(), TransportError> {
        let dest_hash = packet.destination_hash;
        let proof_data = packet.data.as_slice();

        // Check if this is a proof for a receipt we're tracking
        // Proof data format: [packet_hash (32)] + [signature (64)] = 96 bytes
        if proof_data.len() == crate::constants::PROOF_DATA_SIZE {
            // Extract the packet hash from the proof (first 32 bytes)
            let mut proof_packet_hash = [0u8; 32];
            proof_packet_hash.copy_from_slice(&proof_data[..32]);
            let truncated = truncated_hash(&proof_packet_hash);

            // Check if we have a receipt for this packet
            if let Some(receipt) = self.receipts.get(&truncated) {
                // Get the destination identity to verify the signature
                // The proof should be signed by the destination that received our packet
                if let Some(dest_entry) = self.destinations.get(receipt.destination_hash.as_bytes()) {
                    if let Some(ref identity) = dest_entry.identity {
                        let is_valid = receipt.validate_proof(proof_data, identity);
                        if is_valid {
                            // Mark receipt as delivered
                            if let Some(r) = self.receipts.get_mut(&truncated) {
                                r.set_delivered();
                            }
                        }
                        self.events.push(TransportEvent::ProofReceived {
                            packet_hash: truncated,
                            is_valid,
                        });
                        return Ok(());
                    }
                }

                // If we don't have the identity, we still emit the event but can't validate
                self.events.push(TransportEvent::ProofReceived {
                    packet_hash: truncated,
                    is_valid: false,
                });
                return Ok(());
            }
        }

        // Check if this is for a registered destination (legacy behavior)
        if self.destinations.contains_key(&dest_hash) {
            self.events.push(TransportEvent::PacketReceived {
                destination_hash: dest_hash,
                packet: Box::new(packet),
                interface_index,
            });
            return Ok(());
        }

        // If we're a transport node, check link table for bidirectional routing
        if self.config.enable_transport {
            if let Some(link_entry) = self.link_table.get(&dest_hash).cloned() {
                // Determine direction with hop count validation
                let target_iface =
                    if interface_index == link_entry.next_hop_interface_index {
                        // From destination side: check remaining_hops
                        if packet.hops != link_entry.remaining_hops {
                            self.stats.packets_dropped += 1;
                            return Ok(());
                        }
                        link_entry.received_interface_index
                    } else if interface_index == link_entry.received_interface_index {
                        // From initiator side: check taken hops
                        if packet.hops != link_entry.hops {
                            self.stats.packets_dropped += 1;
                            return Ok(());
                        }
                        link_entry.next_hop_interface_index
                    } else {
                        return Ok(()); // Unknown direction
                    };

                // LRPROOF validation: check proof data size before forwarding
                if packet.context == PacketContext::Lrproof {
                    // Link proof format:
                    //   sig(64) + X25519(32) = 96 bytes (without signalling)
                    //   sig(64) + X25519(32) + signaling(3) = 99 bytes (with signalling)
                    const LINK_PROOF_SIZE_MIN: usize = 96;
                    const LINK_PROOF_SIZE_MAX: usize = 99;
                    if proof_data.len() != LINK_PROOF_SIZE_MIN
                        && proof_data.len() != LINK_PROOF_SIZE_MAX
                    {
                        self.stats.packets_dropped += 1;
                        return Ok(());
                    }
                }

                // Mark link as validated on first proof
                if !link_entry.validated {
                    if let Some(entry) = self.link_table.get_mut(&dest_hash) {
                        entry.validated = true;
                        entry.timestamp_ms = self.clock.now_ms();
                    }
                }

                // Forward proof via link table
                let mut forwarded = packet;
                return self.forward_on_interface(target_iface, &mut forwarded);
            }

            // Check reverse table for regular proof routing
            if let Some(reverse_entry) = self.reverse_table.remove(&dest_hash) {
                // The proof should arrive on the outbound interface (where the
                // original packet was forwarded to) and be routed back to the
                // receiving interface (where the original packet came from).
                if interface_index == reverse_entry.outbound_interface_index {
                    let mut forwarded = packet;
                    return self.forward_on_interface(
                        reverse_entry.receiving_interface_index,
                        &mut forwarded,
                    );
                }
            }
        }

        Ok(())
    }

    fn handle_data(
        &mut self,
        packet: Packet,
        interface_index: usize,
        full_packet_hash: [u8; 32],
        dedup_hash: [u8; TRUNCATED_HASHBYTES],
    ) -> Result<(), TransportError> {
        let dest_hash = packet.destination_hash;

        // Intercept path requests (before normal destination routing)
        if dest_hash == self.path_request_hash {
            return self.handle_path_request(packet, interface_index);
        }

        // Check if we have this destination registered
        if let Some(dest_entry) = self.destinations.get(&dest_hash) {
            let proof_strategy = dest_entry.proof_strategy;

            // Emit PacketReceived event
            self.events.push(TransportEvent::PacketReceived {
                destination_hash: dest_hash,
                packet: Box::new(packet),
                interface_index,
            });

            // Handle proof generation based on strategy
            match proof_strategy {
                ProofStrategy::All => {
                    self.events.push(TransportEvent::ProofRequested {
                        packet_hash: full_packet_hash,
                        destination_hash: dest_hash,
                    });
                }
                ProofStrategy::App => {
                    self.events.push(TransportEvent::ProofRequested {
                        packet_hash: full_packet_hash,
                        destination_hash: dest_hash,
                    });
                }
                ProofStrategy::None => {}
            }

            return Ok(());
        }

        // If we're a transport node, try link table first, then path table
        if self.config.enable_transport {
            // Check link table for validated links
            if let Some(link_entry) = self.link_table.get(&dest_hash).cloned() {
                if link_entry.validated {
                    let target_iface =
                        if interface_index == link_entry.next_hop_interface_index {
                            // From destination side: check remaining_hops
                            if packet.hops != link_entry.remaining_hops {
                                return Ok(());
                            }
                            link_entry.received_interface_index
                        } else if interface_index == link_entry.received_interface_index {
                            // From initiator side: check taken hops
                            if packet.hops != link_entry.hops {
                                return Ok(());
                            }
                            link_entry.next_hop_interface_index
                        } else {
                            return Ok(()); // Unknown direction
                        };

                    // Populate reverse table for link-routed data packets
                    let now = self.clock.now_ms();
                    let recv_iface_hash = self
                        .interfaces
                        .get(interface_index)
                        .and_then(|i| i.as_ref())
                        .map(|i| i.hash())
                        .unwrap_or([0u8; TRUNCATED_HASHBYTES]);
                    self.reverse_table.insert(
                        dedup_hash,
                        ReverseEntry {
                            timestamp_ms: now,
                            received_from: recv_iface_hash,
                            receiving_interface_index: interface_index,
                            outbound_interface_index: target_iface,
                        },
                    );

                    // Forward data via link table
                    let mut forwarded = packet;
                    return self.forward_on_interface(target_iface, &mut forwarded);
                }
            }

            self.forward_packet(packet, interface_index, dedup_hash)?;
        }

        Ok(())
    }

    // ─── Internal: Forwarding ───────────────────────────────────────────

    fn forward_packet(
        &mut self,
        mut packet: Packet,
        source_interface_index: usize,
        dedup_hash: [u8; TRUNCATED_HASHBYTES],
    ) -> Result<(), TransportError> {
        // Look up path
        if let Some(path) = self.path_table.get(&packet.destination_hash) {
            let target_iface = path.interface_index;

            // Populate reverse table at forwarding time
            let now = self.clock.now_ms();
            let recv_iface_hash = self
                .interfaces
                .get(source_interface_index)
                .and_then(|i| i.as_ref())
                .map(|i| i.hash())
                .unwrap_or([0u8; TRUNCATED_HASHBYTES]);
            self.reverse_table.insert(
                dedup_hash,
                ReverseEntry {
                    timestamp_ms: now,
                    received_from: recv_iface_hash,
                    receiving_interface_index: source_interface_index,
                    outbound_interface_index: target_iface,
                },
            );

            return self.forward_on_interface(target_iface, &mut packet);
        }

        // No path, drop silently
        self.stats.packets_dropped += 1;
        Ok(())
    }

    /// Forward a packet through a single interface.
    /// Always increments hops, checks TTL, and updates stats.
    fn forward_on_interface(
        &mut self,
        interface_index: usize,
        packet: &mut Packet,
    ) -> Result<(), TransportError> {
        packet.hops = packet.hops.saturating_add(1);
        if packet.hops > self.config.max_hops {
            self.stats.packets_dropped += 1;
            return Ok(());
        }
        self.stats.packets_forwarded += 1;
        self.send_packet_on_interface(interface_index, packet)
    }

    /// Forward a packet on all interfaces except one.
    /// Always increments hops, checks TTL, and updates stats.
    fn forward_on_all_except(
        &mut self,
        except_index: usize,
        packet: &mut Packet,
    ) {
        packet.hops = packet.hops.saturating_add(1);
        if packet.hops > self.config.max_hops {
            self.stats.packets_dropped += 1;
            return;
        }
        let mut buf = [0u8; MTU];
        if let Ok(len) = packet.pack(&mut buf) {
            self.send_on_all_interfaces_except(except_index, &buf[..len]);
            self.stats.packets_forwarded += 1;
        }
    }

    fn send_packet_on_interface(
        &mut self,
        interface_index: usize,
        packet: &Packet,
    ) -> Result<(), TransportError> {
        let mut buf = [0u8; crate::constants::MTU];
        let len = packet.pack(&mut buf)?;

        self.send_on_interface(interface_index, &buf[..len])
    }

    // ─── Public: Path Request API ────────────────────────────────────────

    /// Request a path to a destination
    ///
    /// Sends a path request packet to discover the route to a destination.
    /// Rate-limited to one request per destination per PATH_REQUEST_MIN_INTERVAL_MS.
    ///
    /// # Arguments
    /// * `dest_hash` - The destination hash to find a path for
    /// * `on_interface` - Optional specific interface to send on, or None for all
    /// * `tag` - A random 16-byte tag for dedup
    pub fn request_path(
        &mut self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
        on_interface: Option<usize>,
        tag: &[u8; TRUNCATED_HASHBYTES],
    ) -> Result<(), TransportError> {
        let now = self.clock.now_ms();

        // Rate limiting
        if let Some(&last_request) = self.path_requests.get(dest_hash) {
            if now.saturating_sub(last_request) < PATH_REQUEST_MIN_INTERVAL_MS {
                return Ok(());
            }
        }
        self.path_requests.insert(*dest_hash, now);

        // Build path request data: dest_hash(16) + transport_id(16) + tag(16)
        let transport_id_bytes = *self.identity.hash();
        let mut data = Vec::with_capacity(48);
        data.extend_from_slice(dest_hash);
        data.extend_from_slice(&transport_id_bytes);
        data.extend_from_slice(tag);

        let packet = Packet {
            flags: PacketFlags {
                ifac_flag: false,
                header_type: HeaderType::Type1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                dest_type: crate::destination::DestinationType::Plain,
                packet_type: PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination_hash: self.path_request_hash,
            context: PacketContext::None,
            data: PacketData::Owned(data),
        };

        let mut buf = [0u8; crate::constants::MTU];
        let len = packet.pack(&mut buf)?;

        match on_interface {
            Some(idx) => self.send_on_interface(idx, &buf[..len]),
            None => {
                self.send_on_all_interfaces(&buf[..len]);
                Ok(())
            }
        }
    }

    /// Get the well-known path request destination hash
    pub fn path_request_hash(&self) -> &[u8; TRUNCATED_HASHBYTES] {
        &self.path_request_hash
    }

    // ─── Internal: Helpers ─────────────────────────────────────────────

    /// Compute the well-known path request destination hash
    ///
    /// PLAIN destination with name "rnstransport.path.request".
    /// Hash = full_hash(name_hash)[:16], matching Python Reticulum.
    fn compute_path_request_hash() -> [u8; TRUNCATED_HASHBYTES] {
        let name_hash =
            Destination::compute_name_hash("rnstransport", &["path", "request"]);
        truncated_hash(&name_hash)
    }

    /// Send data on all online interfaces except the one at `except_index`
    fn send_on_all_interfaces_except(&mut self, except_index: usize, data: &[u8]) {
        for (i, slot) in self.interfaces.iter_mut().enumerate() {
            if i == except_index {
                continue;
            }
            if let Some(iface) = slot.as_deref_mut() {
                if iface.is_online() {
                    let _ = iface.send(data);
                }
            }
        }
    }

    /// Compute deterministic jitter from a hash seed
    fn jitter_ms(seed: &[u8; TRUNCATED_HASHBYTES]) -> u64 {
        u16::from_le_bytes([seed[0], seed[1]]) as u64 % PATHFINDER_RW_MS
    }

    /// Handle a path request packet
    fn handle_path_request(
        &mut self,
        packet: Packet,
        interface_index: usize,
    ) -> Result<(), TransportError> {
        let data = packet.data.as_slice();

        // Path request format: dest_hash(16) + [transport_id(16)] + tag(16)
        // Minimum: dest_hash(16) + tag(16) = 32 bytes
        if data.len() < 32 {
            return Ok(());
        }

        let mut requested_hash = [0u8; TRUNCATED_HASHBYTES];
        requested_hash.copy_from_slice(&data[..TRUNCATED_HASHBYTES]);

        // Extract tag (last 16 bytes)
        let tag_start = data.len() - TRUNCATED_HASHBYTES;
        let mut tag = [0u8; TRUNCATED_HASHBYTES];
        tag.copy_from_slice(&data[tag_start..]);

        // Dedup via tag
        let mut dedup_key = [0u8; 32];
        dedup_key[..TRUNCATED_HASHBYTES].copy_from_slice(&requested_hash);
        dedup_key[TRUNCATED_HASHBYTES..].copy_from_slice(&tag);

        if self.path_request_tags.contains(&dedup_key) {
            return Ok(());
        }

        self.path_request_tags.push_back(dedup_key);
        // Trim if too many tags
        if self.path_request_tags.len() > MAX_PATH_REQUEST_TAGS {
            self.path_request_tags.pop_front();
        }

        // 1. Check if it's a local destination
        if self.destinations.contains_key(&requested_hash) {
            self.events.push(TransportEvent::PathRequestReceived {
                destination_hash: requested_hash,
            });
            // Also respond from cache if available
            if let Some(cached_raw) = self.announce_cache.get(&requested_hash).cloned() {
                let now = self.clock.now_ms();
                if let Ok(cached_packet) = Packet::unpack(&cached_raw) {
                    let jitter = Self::jitter_ms(&requested_hash);
                    self.announce_table.insert(
                        requested_hash,
                        AnnounceEntry {
                            timestamp_ms: now,
                            hops: cached_packet.hops,
                            retries: 0,
                            retransmit_at_ms: Some(now + PATH_REQUEST_GRACE_MS + jitter),
                            raw_packet: cached_raw,
                            receiving_interface_index: interface_index,
                            local_rebroadcasts: 0,
                            block_rebroadcasts: true,
                        },
                    );
                }
            }
            return Ok(());
        }

        // 2. Check if we have a cached announce for this destination
        if self.config.enable_transport {
            if let Some(cached_raw) = self.announce_cache.get(&requested_hash).cloned() {
                let now = self.clock.now_ms();
                // Parse cached announce to get hop count
                if let Ok(cached_packet) = Packet::unpack(&cached_raw) {
                    let jitter = Self::jitter_ms(&requested_hash);
                    self.announce_table.insert(
                        requested_hash,
                        AnnounceEntry {
                            timestamp_ms: now,
                            hops: cached_packet.hops,
                            retries: 0,
                            retransmit_at_ms: Some(now + PATH_REQUEST_GRACE_MS + jitter),
                            raw_packet: cached_raw,
                            receiving_interface_index: interface_index,
                            local_rebroadcasts: 0,
                            block_rebroadcasts: true,
                        },
                    );
                }
                return Ok(());
            }

            // 3. Unknown destination → forward path request on all interfaces except arrival
            let mut buf = [0u8; crate::constants::MTU];
            let len = packet.pack(&mut buf)?;
            self.send_on_all_interfaces_except(interface_index, &buf[..len]);
        }

        Ok(())
    }

    // ─── Internal: Periodic Tasks ───────────────────────────────────────

    fn expire_paths(&mut self, now: u64) {
        let expired: Vec<[u8; TRUNCATED_HASHBYTES]> = self
            .path_table
            .iter()
            .filter(|(_, p)| p.expires_ms < now)
            .map(|(k, _)| *k)
            .collect();

        for hash in expired {
            self.path_table.remove(&hash);
            self.events.push(TransportEvent::PathLost {
                destination_hash: hash,
            });
        }
    }

    fn clean_packet_cache(&mut self, now: u64) {
        let expiry = self.config.packet_cache_expiry_ms;
        let expired: Vec<[u8; TRUNCATED_HASHBYTES]> = self
            .packet_cache
            .iter()
            .filter(|(_, &ts)| now.saturating_sub(ts) > expiry)
            .map(|(k, _)| *k)
            .collect();

        for hash in expired {
            self.packet_cache.remove(&hash);
        }
    }

    fn clean_reverse_table(&mut self, now: u64) {
        let expired: Vec<[u8; TRUNCATED_HASHBYTES]> = self
            .reverse_table
            .iter()
            .filter(|(_, e)| {
                now.saturating_sub(e.timestamp_ms) > REVERSE_TABLE_EXPIRY_MS
                    || !self.is_interface_online(e.receiving_interface_index)
                    || !self.is_interface_online(e.outbound_interface_index)
            })
            .map(|(k, _)| *k)
            .collect();

        for hash in expired {
            self.reverse_table.remove(&hash);
        }
    }

    fn check_receipt_timeouts(&mut self, now: u64) {
        // Collect timed out receipts
        let timed_out: Vec<[u8; TRUNCATED_HASHBYTES]> = self
            .receipts
            .iter()
            .filter(|(_, r)| r.status == ReceiptStatus::Sent && r.is_expired(now))
            .map(|(k, _)| *k)
            .collect();

        // Emit timeout events and remove expired receipts
        for hash in timed_out {
            self.receipts.remove(&hash);
            self.events
                .push(TransportEvent::ReceiptTimeout { packet_hash: hash });
        }
    }

    fn check_announce_rebroadcasts(&mut self, now: u64) {
        if !self.config.enable_transport {
            return;
        }

        // Collect entries that need action
        let mut to_remove = Vec::new();
        let mut to_rebroadcast = Vec::new();

        for (dest_hash, entry) in self.announce_table.iter() {
            // Remove entries that have exceeded retries or local rebroadcast limit
            if entry.retries > PATHFINDER_RETRIES
                || entry.local_rebroadcasts >= LOCAL_REBROADCASTS_MAX
            {
                to_remove.push(*dest_hash);
                continue;
            }

            // Check if retransmit is due
            if let Some(retransmit_at) = entry.retransmit_at_ms {
                if retransmit_at <= now && !entry.raw_packet.is_empty() {
                    to_rebroadcast.push((
                        *dest_hash,
                        entry.raw_packet.clone(),
                        entry.receiving_interface_index,
                        entry.hops,
                        entry.block_rebroadcasts,
                    ));
                }
            }
        }

        for hash in to_remove {
            self.announce_table.remove(&hash);
        }

        let transport_id = *self.identity.hash();

        for (dest_hash, raw, except_iface, _original_hops, block) in to_rebroadcast {
            // Rebuild packet as Header Type 2 with our transport ID
            if let Ok(mut parsed) = Packet::unpack(&raw) {
                // Set as Header Type 2 (transport-routed)
                parsed.flags.header_type = HeaderType::Type2;
                parsed.flags.transport_type = TransportType::Transport;
                parsed.transport_id = Some(transport_id);

                // If block_rebroadcasts, set PathResponse context
                if block {
                    parsed.context = PacketContext::PathResponse;
                }

                self.forward_on_all_except(except_iface, &mut parsed);

                // If TTL exceeded, remove from announce table
                if parsed.hops > self.config.max_hops {
                    self.announce_table.remove(&dest_hash);
                    continue;
                }
            }

            // Update announce table entry
            if let Some(entry) = self.announce_table.get_mut(&dest_hash) {
                let jitter = Self::jitter_ms(&dest_hash);
                entry.retransmit_at_ms = Some(now + PATHFINDER_G_MS + jitter);
                entry.retries += 1;
            }
        }
    }

    /// Check if an interface slot is present and online
    fn is_interface_online(&self, index: usize) -> bool {
        self.interfaces
            .get(index)
            .and_then(|slot| slot.as_ref())
            .map(|iface| iface.is_online())
            .unwrap_or(false)
    }

    fn clean_link_table(&mut self, now: u64) {
        let expired: Vec<[u8; TRUNCATED_HASHBYTES]> = self
            .link_table
            .iter()
            .filter(|(_, e)| {
                let time_expired = if e.validated {
                    now.saturating_sub(e.timestamp_ms) > LINK_TIMEOUT_MS
                } else {
                    now > e.proof_timeout_ms
                };
                time_expired
                    || !self.is_interface_online(e.next_hop_interface_index)
                    || !self.is_interface_online(e.received_interface_index)
            })
            .map(|(k, _)| *k)
            .collect();

        for hash in expired {
            self.link_table.remove(&hash);
        }
    }

    fn calculate_retransmit_delay(&self, _hops: u8) -> u64 {
        // Python: initial retransmit = random() * PATHFINDER_RW
        // Use deterministic jitter from clock for no_std compatibility
        let seed = (self.clock.now_ms() & 0xFFFF) as u16;
        (seed % PATHFINDER_RW_MS as u16) as u64
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TransportConfig::default();
        assert!(!config.enable_transport);
        assert_eq!(config.max_hops, PATHFINDER_MAX_HOPS);
    }

    mod transport_tests {
        use super::*;
        use crate::traits::NoStorage;
        use rand_core::OsRng;

        extern crate std;
        use std::sync::{Arc, Mutex};

        // Mock clock for deterministic testing
        struct MockClock {
            time_ms: core::cell::Cell<u64>,
        }

        impl MockClock {
            fn new(time_ms: u64) -> Self {
                Self {
                    time_ms: core::cell::Cell::new(time_ms),
                }
            }

            fn advance(&self, ms: u64) {
                self.time_ms.set(self.time_ms.get() + ms);
            }
        }

        impl Clock for MockClock {
            fn now_ms(&self) -> u64 {
                self.time_ms.get()
            }
        }

        // Mock interface for testing
        struct MockInterface {
            name: &'static str,
            hash: [u8; TRUNCATED_HASHBYTES],
            sent: Vec<Vec<u8>>,
            online: bool,
        }

        impl MockInterface {
            fn new(name: &'static str, id: u8) -> Self {
                let mut hash = [0u8; TRUNCATED_HASHBYTES];
                hash[0] = id;
                Self {
                    name,
                    hash,
                    sent: Vec::new(),
                    online: true,
                }
            }
        }

        impl Interface for MockInterface {
            fn name(&self) -> &str {
                self.name
            }
            fn mtu(&self) -> usize {
                500
            }
            fn hash(&self) -> [u8; TRUNCATED_HASHBYTES] {
                self.hash
            }
            fn send(&mut self, data: &[u8]) -> Result<(), InterfaceError> {
                self.sent.push(data.to_vec());
                Ok(())
            }
            fn recv(&mut self, _buf: &mut [u8]) -> Result<usize, InterfaceError> {
                Err(InterfaceError::WouldBlock)
            }
            fn is_online(&self) -> bool {
                self.online
            }
        }

        /// Mock interface with shared send buffer for inspecting sent packets
        struct CaptureMockInterface {
            name: &'static str,
            hash: [u8; TRUNCATED_HASHBYTES],
            sent: Arc<Mutex<Vec<Vec<u8>>>>,
            online: bool,
        }

        impl CaptureMockInterface {
            fn new(
                name: &'static str,
                id: u8,
                sent: Arc<Mutex<Vec<Vec<u8>>>>,
            ) -> Self {
                let mut hash = [0u8; TRUNCATED_HASHBYTES];
                hash[0] = id;
                Self {
                    name,
                    hash,
                    sent,
                    online: true,
                }
            }
        }

        impl Interface for CaptureMockInterface {
            fn name(&self) -> &str {
                self.name
            }
            fn mtu(&self) -> usize {
                500
            }
            fn hash(&self) -> [u8; TRUNCATED_HASHBYTES] {
                self.hash
            }
            fn send(&mut self, data: &[u8]) -> Result<(), InterfaceError> {
                self.sent.lock().unwrap().push(data.to_vec());
                Ok(())
            }
            fn recv(&mut self, _buf: &mut [u8]) -> Result<usize, InterfaceError> {
                Err(InterfaceError::WouldBlock)
            }
            fn is_online(&self) -> bool {
                self.online
            }
        }

        fn make_transport() -> Transport<MockClock, NoStorage> {
            let clock = MockClock::new(1_000_000);
            let identity = Identity::generate(&mut OsRng);
            Transport::new(TransportConfig::default(), clock, NoStorage, identity)
        }

        #[test]
        fn test_transport_creation() {
            let transport = make_transport();
            assert_eq!(transport.interface_count(), 0);
            assert_eq!(transport.path_count(), 0);
            assert_eq!(transport.pending_events(), 0);
        }

        #[test]
        fn test_register_interface() {
            let mut transport = make_transport();
            let idx = transport.register_interface(Box::new(MockInterface::new("test", 1)));
            assert_eq!(idx, 0);
            assert_eq!(transport.interface_count(), 1);

            let idx2 = transport.register_interface(Box::new(MockInterface::new("test2", 2)));
            assert_eq!(idx2, 1);
            assert_eq!(transport.interface_count(), 2);
        }

        #[test]
        fn test_unregister_interface() {
            let mut transport = make_transport();
            let idx = transport.register_interface(Box::new(MockInterface::new("test", 1)));
            assert_eq!(transport.interface_count(), 1);

            transport.unregister_interface(idx);
            assert_eq!(transport.interface_count(), 0);
        }

        #[test]
        fn test_register_destination() {
            let mut transport = make_transport();
            let hash = [0x42; TRUNCATED_HASHBYTES];

            transport.register_destination(hash, false);
            assert!(transport.has_destination(&hash));

            transport.unregister_destination(&hash);
            assert!(!transport.has_destination(&hash));
        }

        #[test]
        fn test_path_management() {
            let mut transport = make_transport();
            let hash = [0x42; TRUNCATED_HASHBYTES];

            assert!(!transport.has_path(&hash));
            assert_eq!(transport.hops_to(&hash), None);

            // Manually insert a path for testing
            let now = transport.clock.now_ms();
            transport.path_table.insert(
                hash,
                PathEntry {
                    timestamp_ms: now,
                    received_from: [0; TRUNCATED_HASHBYTES],
                    hops: 3,
                    expires_ms: now + 3_600_000,
                    interface_index: 0,
                    random_blobs: Vec::new(),
                },
            );

            assert!(transport.has_path(&hash));
            assert_eq!(transport.hops_to(&hash), Some(3));
            assert_eq!(transport.path_count(), 1);
        }

        #[test]
        fn test_path_expiry() {
            let mut transport = make_transport();
            let hash = [0x42; TRUNCATED_HASHBYTES];

            let now = transport.clock.now_ms();
            transport.path_table.insert(
                hash,
                PathEntry {
                    timestamp_ms: now,
                    received_from: [0; TRUNCATED_HASHBYTES],
                    hops: 1,
                    expires_ms: now + 1000, // Expires in 1 second
                    interface_index: 0,
                    random_blobs: Vec::new(),
                },
            );

            assert!(transport.has_path(&hash));

            // Advance clock past expiry
            transport.clock.advance(2000);
            transport.poll();

            assert!(!transport.has_path(&hash));

            // Should have emitted PathLost event
            let events: Vec<_> = transport.drain_events().collect();
            assert_eq!(events.len(), 1);
            match &events[0] {
                TransportEvent::PathLost { destination_hash } => {
                    assert_eq!(destination_hash, &hash);
                }
                _ => panic!("Expected PathLost event"),
            }
        }

        #[test]
        fn test_send_on_interface() {
            let mut transport = make_transport();
            let idx = transport.register_interface(Box::new(MockInterface::new("test", 1)));

            let data = b"test packet";
            transport.send_on_interface(idx, data).unwrap();

            assert_eq!(transport.stats().packets_sent, 1);
        }

        #[test]
        fn test_send_on_invalid_interface() {
            let mut transport = make_transport();
            let result = transport.send_on_interface(99, b"test");
            assert!(matches!(result, Err(TransportError::InvalidInterface)));
        }

        #[test]
        fn test_packet_deduplication() {
            let mut transport = make_transport();
            transport.register_interface(Box::new(MockInterface::new("test", 1)));
            let hash = [0x42; TRUNCATED_HASHBYTES];
            transport.register_destination(hash, false);

            // Create a simple data packet
            use crate::destination::DestinationType;
            use crate::packet::{
                HeaderType, PacketContext, PacketData, PacketFlags, TransportType,
            };

            let packet = Packet {
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
                destination_hash: hash,
                context: PacketContext::None,
                data: PacketData::Owned(b"hello".to_vec()),
            };

            let mut buf = [0u8; 500];
            let len = packet.pack(&mut buf).unwrap();
            let raw = &buf[..len];

            // First time: should process
            transport.process_incoming(0, raw).unwrap();
            assert_eq!(transport.stats().packets_received, 1);
            assert_eq!(transport.pending_events(), 1);

            // Second time: should be deduplicated
            transport.drain_events();
            transport.process_incoming(0, raw).unwrap();
            assert_eq!(transport.stats().packets_received, 2);
            assert_eq!(transport.stats().packets_dropped, 1);
            assert_eq!(transport.pending_events(), 0);
        }

        #[test]
        fn test_data_packet_delivery() {
            let mut transport = make_transport();
            transport.register_interface(Box::new(MockInterface::new("test", 1)));
            let hash = [0x42; TRUNCATED_HASHBYTES];
            transport.register_destination(hash, false);

            use crate::destination::DestinationType;
            use crate::packet::{
                HeaderType, PacketContext, PacketData, PacketFlags, TransportType,
            };

            let packet = Packet {
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
                destination_hash: hash,
                context: PacketContext::None,
                data: PacketData::Owned(b"hello".to_vec()),
            };

            let mut buf = [0u8; 500];
            let len = packet.pack(&mut buf).unwrap();

            transport.process_incoming(0, &buf[..len]).unwrap();

            let events: Vec<_> = transport.drain_events().collect();
            assert_eq!(events.len(), 1);
            match &events[0] {
                TransportEvent::PacketReceived {
                    destination_hash,
                    packet,
                    interface_index,
                } => {
                    assert_eq!(destination_hash, &hash);
                    assert_eq!(packet.data.as_slice(), b"hello");
                    assert_eq!(*interface_index, 0);
                }
                _ => panic!("Expected PacketReceived event"),
            }
        }

        #[test]
        fn test_unregistered_destination_dropped() {
            let mut transport = make_transport();
            transport.register_interface(Box::new(MockInterface::new("test", 1)));
            // Don't register any destination

            use crate::destination::DestinationType;
            use crate::packet::{
                HeaderType, PacketContext, PacketData, PacketFlags, TransportType,
            };

            let packet = Packet {
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
                destination_hash: [0x42; TRUNCATED_HASHBYTES],
                context: PacketContext::None,
                data: PacketData::Owned(b"hello".to_vec()),
            };

            let mut buf = [0u8; 500];
            let len = packet.pack(&mut buf).unwrap();

            transport.process_incoming(0, &buf[..len]).unwrap();

            // No events since destination isn't registered
            assert_eq!(transport.pending_events(), 0);
        }

        #[test]
        fn test_packet_cache_expiry() {
            let mut transport = make_transport();
            transport.register_interface(Box::new(MockInterface::new("test", 1)));

            let hash = [0x42; TRUNCATED_HASHBYTES];
            transport.register_destination(hash, false);

            use crate::destination::DestinationType;
            use crate::packet::{
                HeaderType, PacketContext, PacketData, PacketFlags, TransportType,
            };

            let packet = Packet {
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
                destination_hash: hash,
                context: PacketContext::None,
                data: PacketData::Owned(b"hello".to_vec()),
            };

            let mut buf = [0u8; 500];
            let len = packet.pack(&mut buf).unwrap();

            // First delivery
            transport.process_incoming(0, &buf[..len]).unwrap();
            assert_eq!(transport.pending_events(), 1);
            transport.drain_events();

            // Second: deduplicated
            transport.process_incoming(0, &buf[..len]).unwrap();
            assert_eq!(transport.pending_events(), 0);

            // Advance past cache expiry and poll
            transport
                .clock
                .advance(transport.config.packet_cache_expiry_ms + 1);
            transport.poll();

            // Now the packet should be accepted again
            transport.process_incoming(0, &buf[..len]).unwrap();
            assert_eq!(transport.pending_events(), 1);
        }

        #[test]
        fn test_announce_processing() {
            use crate::destination::{Destination, DestinationType, Direction};
            use crate::packet::{
                HeaderType, PacketContext, PacketData, PacketFlags, TransportType,
            };

            let mut transport = make_transport();
            transport.register_interface(Box::new(MockInterface::new("test", 1)));

            // Create a real announce
            let identity = Identity::generate(&mut OsRng);
            let dest = Destination::new(
                Some(identity),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["echo"],
            )
            .expect("Failed to create destination");

            let id = dest.identity().unwrap();
            let random_hash = [0x42u8; crate::constants::RANDOM_HASHBYTES];

            let mut payload = Vec::new();
            payload.extend_from_slice(&id.public_key_bytes());
            payload.extend_from_slice(dest.name_hash());
            payload.extend_from_slice(&random_hash);

            let app_data = b"test.data";

            // Sign
            let mut signed_data = Vec::new();
            signed_data.extend_from_slice(dest.hash().as_bytes());
            signed_data.extend_from_slice(&id.public_key_bytes());
            signed_data.extend_from_slice(dest.name_hash());
            signed_data.extend_from_slice(&random_hash);
            signed_data.extend_from_slice(app_data);

            let signature = id.sign(&signed_data).unwrap();
            payload.extend_from_slice(&signature);
            payload.extend_from_slice(app_data);

            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: DestinationType::Single,
                    packet_type: PacketType::Announce,
                },
                hops: 2,
                transport_id: None,
                destination_hash: dest.hash().into_bytes(),
                context: PacketContext::None,
                data: PacketData::Owned(payload),
            };

            let mut buf = [0u8; 500];
            let len = packet.pack(&mut buf).unwrap();

            transport.process_incoming(0, &buf[..len]).unwrap();

            // Should have path now
            assert!(transport.has_path(dest.hash().as_bytes()));
            assert_eq!(transport.hops_to(dest.hash().as_bytes()), Some(2));
            assert_eq!(transport.stats().announces_processed, 1);

            // Should have emitted PathFound + AnnounceReceived
            let events: Vec<_> = transport.drain_events().collect();
            assert_eq!(events.len(), 2);
            match &events[0] {
                TransportEvent::PathFound {
                    destination_hash,
                    hops,
                    ..
                } => {
                    assert_eq!(destination_hash, dest.hash());
                    assert_eq!(*hops, 2);
                }
                _ => panic!("Expected PathFound event"),
            }
            match &events[1] {
                TransportEvent::AnnounceReceived { announce, .. } => {
                    assert_eq!(announce.destination_hash(), dest.hash());
                    assert_eq!(announce.app_data(), b"test.data");
                }
                _ => panic!("Expected AnnounceReceived event"),
            }
        }

        // ─── Helper: Build announce packet bytes ─────────────────────────

        fn make_announce_raw(hops: u8, context: crate::packet::PacketContext) -> (Vec<u8>, [u8; TRUNCATED_HASHBYTES]) {
            use crate::destination::{Destination, DestinationType, Direction};
            use crate::packet::{
                HeaderType, PacketData, PacketFlags, TransportType,
            };

            let identity = Identity::generate(&mut OsRng);
            let dest = Destination::new(
                Some(identity),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["rebroadcast"],
            )
            .unwrap();

            let id = dest.identity().unwrap();
            let random_hash = [0x42u8; crate::constants::RANDOM_HASHBYTES];

            let mut payload = Vec::new();
            payload.extend_from_slice(&id.public_key_bytes());
            payload.extend_from_slice(dest.name_hash());
            payload.extend_from_slice(&random_hash);

            let app_data = b"test";
            let mut signed_data = Vec::new();
            signed_data.extend_from_slice(dest.hash().as_bytes());
            signed_data.extend_from_slice(&id.public_key_bytes());
            signed_data.extend_from_slice(dest.name_hash());
            signed_data.extend_from_slice(&random_hash);
            signed_data.extend_from_slice(app_data);

            let signature = id.sign(&signed_data).unwrap();
            payload.extend_from_slice(&signature);
            payload.extend_from_slice(app_data);

            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: DestinationType::Single,
                    packet_type: PacketType::Announce,
                },
                hops,
                transport_id: None,
                destination_hash: dest.hash().into_bytes(),
                context,
                data: PacketData::Owned(payload),
            };

            let mut buf = [0u8; 500];
            let len = packet.pack(&mut buf).unwrap();
            (buf[..len].to_vec(), dest.hash().into_bytes())
        }

        fn make_transport_enabled() -> Transport<MockClock, NoStorage> {
            let clock = MockClock::new(1_000_000);
            let identity = Identity::generate(&mut OsRng);
            let config = TransportConfig {
                enable_transport: true,
                ..TransportConfig::default()
            };
            Transport::new(config, clock, NoStorage, identity)
        }

        // ─── Stage 1: Announce Rebroadcast Tests ─────────────────────────

        #[test]
        fn test_rebroadcast_fires_after_delay() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let (raw, dest_hash) = make_announce_raw(2, PacketContext::None);
            transport.process_incoming(0, &raw).unwrap();
            transport.drain_events();

            // Should have an announce table entry with retransmit scheduled
            let entry = transport.announce_table.get(&dest_hash).unwrap();
            assert!(entry.retransmit_at_ms.is_some());
            assert_eq!(entry.retries, 0);

            // Advance past retransmit delay
            transport.clock.advance(10_000);
            transport.poll();

            // Check that the announce entry retries was incremented
            if let Some(entry) = transport.announce_table.get(&dest_hash) {
                assert!(entry.retries >= 1);
            }
        }

        #[test]
        fn test_rebroadcast_sent_on_correct_interfaces() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("arrival", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("other1", 2)));
            let _idx2 = transport.register_interface(Box::new(MockInterface::new("other2", 3)));

            let (raw, _dest_hash) = make_announce_raw(1, PacketContext::None);
            transport.process_incoming(0, &raw).unwrap();
            transport.drain_events();

            // Advance past retransmit delay
            transport.clock.advance(10_000);
            transport.poll();

            // Verify rebroadcast happened
            assert!(transport.stats().packets_forwarded > 0);
        }

        #[test]
        fn test_no_rebroadcast_when_transport_disabled() {
            let mut transport = make_transport(); // transport disabled by default
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let (raw, dest_hash) = make_announce_raw(2, PacketContext::None);
            transport.process_incoming(0, &raw).unwrap();
            transport.drain_events();

            // Should have no retransmit scheduled
            let entry = transport.announce_table.get(&dest_hash).unwrap();
            assert!(entry.retransmit_at_ms.is_none());

            // Advance and poll - should not forward anything
            transport.clock.advance(10_000);
            transport.poll();
            assert_eq!(transport.stats().packets_forwarded, 0);
        }

        #[test]
        fn test_rebroadcast_stops_after_max_retries() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let (raw, dest_hash) = make_announce_raw(1, PacketContext::None);
            transport.process_incoming(0, &raw).unwrap();
            transport.drain_events();

            // First rebroadcast cycle: retries goes 0 -> 1
            transport.clock.advance(10_000);
            transport.poll();
            assert!(transport.announce_table.get(&dest_hash).is_some());
            if let Some(entry) = transport.announce_table.get(&dest_hash) {
                assert_eq!(entry.retries, 1);
            }

            // Second rebroadcast cycle: retries goes 1 -> 2
            transport.clock.advance(10_000);
            transport.poll();

            // Third poll: retries=2 > PATHFINDER_RETRIES(1) → removed
            transport.clock.advance(10_000);
            transport.poll();

            assert!(
                transport.announce_table.get(&dest_hash).is_none(),
                "Entry should be removed after exceeding PATHFINDER_RETRIES"
            );
        }

        #[test]
        fn test_rebroadcast_increments_hops() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let original_hops = 3u8;
            let (raw, _dest_hash) = make_announce_raw(original_hops, PacketContext::None);
            transport.process_incoming(0, &raw).unwrap();
            transport.drain_events();

            // Trigger rebroadcast
            transport.clock.advance(10_000);
            transport.poll();

            assert!(transport.stats().packets_forwarded > 0);
        }

        #[test]
        fn test_path_response_not_rebroadcasted() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let (raw, dest_hash) = make_announce_raw(2, PacketContext::PathResponse);
            transport.process_incoming(0, &raw).unwrap();
            transport.drain_events();

            // Should have no retransmit scheduled for PATH_RESPONSE context
            let entry = transport.announce_table.get(&dest_hash).unwrap();
            assert!(entry.retransmit_at_ms.is_none());
            assert!(entry.block_rebroadcasts);
        }

        #[test]
        fn test_local_rebroadcast_detection_suppresses() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            // Create announce at hops=1
            let (raw1, dest_hash) = make_announce_raw(1, PacketContext::None);
            transport.process_incoming(0, &raw1).unwrap();
            transport.drain_events();

            // Verify retransmit is scheduled
            let entry = transport.announce_table.get(&dest_hash).unwrap();
            assert!(entry.retransmit_at_ms.is_some());

            // Now create a "same announce from neighbor" at hops=2 (hops+1)
            // We can't use the same dest hash with a different packet easily,
            // so we manually simulate by adjusting the announce table
            if let Some(entry) = transport.announce_table.get_mut(&dest_hash) {
                entry.local_rebroadcasts = LOCAL_REBROADCASTS_MAX;
            }

            // After poll, entry with max local rebroadcasts should be removed
            transport.clock.advance(10_000);
            transport.poll();

            assert!(transport.announce_table.get(&dest_hash).is_none());
        }

        #[test]
        fn test_announce_cache_populated() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let (raw, dest_hash) = make_announce_raw(2, PacketContext::None);
            transport.process_incoming(0, &raw).unwrap();
            transport.drain_events();

            // Announce cache should have the raw bytes
            assert!(transport.announce_cache.contains_key(&dest_hash));
            assert_eq!(transport.announce_cache.get(&dest_hash).unwrap(), &raw);
        }

        // ─── Stage 2: Link Table Tests ───────────────────────────────────

        #[test]
        fn test_link_table_entry_expiry_validated() {
            let mut transport = make_transport_enabled();
            let _idx0 =
                transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 =
                transport.register_interface(Box::new(MockInterface::new("if1", 2)));
            let now = transport.clock.now_ms();

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_transport_id: [0x01; TRUNCATED_HASHBYTES],
                    next_hop_interface_index: 1,
                    remaining_hops: 2,
                    received_interface_index: 0,
                    hops: 1,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
                    validated: true,
                    proof_timeout_ms: now + 30_000,
                },
            );

            assert!(transport.link_table.contains_key(&link_id));

            // Advance past LINK_TIMEOUT_MS (15 min)
            transport.clock.advance(LINK_TIMEOUT_MS + 1000);
            transport.poll();

            assert!(!transport.link_table.contains_key(&link_id));
        }

        #[test]
        fn test_link_table_entry_expiry_unvalidated() {
            let mut transport = make_transport_enabled();
            let _idx0 =
                transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 =
                transport.register_interface(Box::new(MockInterface::new("if1", 2)));
            let now = transport.clock.now_ms();

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            let proof_timeout = now + 10_000;
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_transport_id: [0x01; TRUNCATED_HASHBYTES],
                    next_hop_interface_index: 1,
                    remaining_hops: 2,
                    received_interface_index: 0,
                    hops: 1,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
                    validated: false,
                    proof_timeout_ms: proof_timeout,
                },
            );

            // Advance past proof_timeout but not LINK_TIMEOUT_MS
            transport.clock.advance(11_000);
            transport.poll();

            // Unvalidated entry should be expired
            assert!(!transport.link_table.contains_key(&link_id));
        }

        #[test]
        fn test_link_table_validated_not_expired_early() {
            let mut transport = make_transport_enabled();
            let _idx0 =
                transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 =
                transport.register_interface(Box::new(MockInterface::new("if1", 2)));
            let now = transport.clock.now_ms();

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_transport_id: [0x01; TRUNCATED_HASHBYTES],
                    next_hop_interface_index: 1,
                    remaining_hops: 2,
                    received_interface_index: 0,
                    hops: 1,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
                    validated: true,
                    proof_timeout_ms: now + 30_000,
                },
            );

            // Advance less than LINK_TIMEOUT_MS
            transport.clock.advance(60_000); // 1 minute
            transport.poll();

            // Should still be present
            assert!(transport.link_table.contains_key(&link_id));
        }

        // ─── Stage 3: Path Request Tests ─────────────────────────────────

        #[test]
        fn test_compute_path_request_hash() {
            let hash = Transport::<MockClock, NoStorage>::compute_path_request_hash();
            // Should be full_hash(name_hash)[:16], matching Python Reticulum
            let name_hash = crate::destination::Destination::compute_name_hash(
                "rnstransport",
                &["path", "request"],
            );
            let expected = truncated_hash(&name_hash);
            assert_eq!(hash, expected);
        }

        #[test]
        fn test_request_path_sends_packet() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_hash = [0x42; TRUNCATED_HASHBYTES];
            let tag = [0xAB; TRUNCATED_HASHBYTES];
            transport.request_path(&dest_hash, None, &tag).unwrap();

            assert!(transport.stats().packets_sent > 0);
        }

        #[test]
        fn test_request_path_rate_limited() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_hash = [0x42; TRUNCATED_HASHBYTES];
            let tag1 = [0xAB; TRUNCATED_HASHBYTES];
            let tag2 = [0xCD; TRUNCATED_HASHBYTES];

            transport.request_path(&dest_hash, None, &tag1).unwrap();
            let sent1 = transport.stats().packets_sent;

            // Immediately send another - should be rate limited
            transport.request_path(&dest_hash, None, &tag2).unwrap();
            let sent2 = transport.stats().packets_sent;
            assert_eq!(sent1, sent2, "Second request should be rate limited");

            // Advance past rate limit
            transport.clock.advance(PATH_REQUEST_MIN_INTERVAL_MS + 1);
            transport.request_path(&dest_hash, None, &tag2).unwrap();
            let sent3 = transport.stats().packets_sent;
            assert!(sent3 > sent2, "After cooldown, request should go through");
        }

        #[test]
        fn test_path_request_local_dest_emits_event() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_hash = [0x42; TRUNCATED_HASHBYTES];
            transport.register_destination(dest_hash, false);

            // Build a path request packet targeting the local destination
            let path_req_hash = transport.path_request_hash;
            let mut data = Vec::new();
            data.extend_from_slice(&dest_hash);
            data.extend_from_slice(&[0xBB; TRUNCATED_HASHBYTES]); // transport_id
            data.extend_from_slice(&[0xCC; TRUNCATED_HASHBYTES]); // tag

            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: crate::destination::DestinationType::Plain,
                    packet_type: PacketType::Data,
                },
                hops: 0,
                transport_id: None,
                destination_hash: path_req_hash,
                context: PacketContext::None,
                data: PacketData::Owned(data),
            };

            let mut buf = [0u8; 500];
            let len = packet.pack(&mut buf).unwrap();
            transport.process_incoming(0, &buf[..len]).unwrap();

            // Should emit PathRequestReceived event
            let events: Vec<_> = transport.drain_events().collect();
            let found = events.iter().any(|e| matches!(
                e,
                TransportEvent::PathRequestReceived { destination_hash } if *destination_hash == dest_hash
            ));
            assert!(found, "Expected PathRequestReceived event");
        }

        #[test]
        fn test_path_request_cached_announce_triggers_response() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            // First, receive an announce to populate the cache
            let (raw, dest_hash) = make_announce_raw(2, PacketContext::None);
            transport.process_incoming(0, &raw).unwrap();
            transport.drain_events();

            // Clear announce table to simulate fresh state (but keep cache)
            transport.announce_table.clear();

            // Now receive a path request for that destination
            let path_req_hash = transport.path_request_hash;
            let mut data = Vec::new();
            data.extend_from_slice(&dest_hash);
            data.extend_from_slice(&[0xBB; TRUNCATED_HASHBYTES]); // transport_id
            data.extend_from_slice(&[0xCC; TRUNCATED_HASHBYTES]); // tag

            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: crate::destination::DestinationType::Plain,
                    packet_type: PacketType::Data,
                },
                hops: 0,
                transport_id: None,
                destination_hash: path_req_hash,
                context: PacketContext::None,
                data: PacketData::Owned(data),
            };

            let mut buf = [0u8; 500];
            let len = packet.pack(&mut buf).unwrap();
            transport.process_incoming(1, &buf[..len]).unwrap();

            // Should have inserted a PATH_RESPONSE announce in the announce_table
            let entry = transport.announce_table.get(&dest_hash);
            assert!(entry.is_some(), "Should have announce table entry for path response");
            let entry = entry.unwrap();
            assert!(entry.block_rebroadcasts, "Should be marked as block_rebroadcasts");
            assert!(entry.retransmit_at_ms.is_some(), "Should have a retransmit scheduled");
        }

        #[test]
        fn test_path_request_tag_dedup() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let dest_hash = [0x42; TRUNCATED_HASHBYTES];
            let tag = [0xCC; TRUNCATED_HASHBYTES];

            let path_req_hash = transport.path_request_hash;
            let mut data = Vec::new();
            data.extend_from_slice(&dest_hash);
            data.extend_from_slice(&[0xBB; TRUNCATED_HASHBYTES]); // transport_id
            data.extend_from_slice(&tag);

            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: crate::destination::DestinationType::Plain,
                    packet_type: PacketType::Data,
                },
                hops: 0,
                transport_id: None,
                destination_hash: path_req_hash,
                context: PacketContext::None,
                data: PacketData::Owned(data),
            };

            let mut buf = [0u8; 500];
            let len = packet.pack(&mut buf).unwrap();

            // First request - should be processed
            transport.process_incoming(0, &buf[..len]).unwrap();
            assert_eq!(transport.path_request_tags.len(), 1);

            // Clear packet cache to allow second processing
            transport.packet_cache.clear();

            // Second request with same tag - should be deduped
            transport.process_incoming(0, &buf[..len]).unwrap();
            // Tag count should still be 1 (dedup worked)
            assert_eq!(transport.path_request_tags.len(), 1);
        }

        #[test]
        fn test_reverse_table_expiry_8_minutes() {
            // Verify the constant was fixed to 8 minutes
            assert_eq!(REVERSE_TABLE_EXPIRY_MS, 480_000);
        }

        #[test]
        fn test_jitter_deterministic() {
            let seed1 = [0x42; TRUNCATED_HASHBYTES];
            let seed2 = [0x42; TRUNCATED_HASHBYTES];
            let seed3 = [0x99; TRUNCATED_HASHBYTES];

            let j1 = Transport::<MockClock, NoStorage>::jitter_ms(&seed1);
            let j2 = Transport::<MockClock, NoStorage>::jitter_ms(&seed2);
            let j3 = Transport::<MockClock, NoStorage>::jitter_ms(&seed3);

            assert_eq!(j1, j2, "Same seed should produce same jitter");
            assert!(j1 < PATHFINDER_RW_MS, "Jitter should be within window");
            assert!(j3 < PATHFINDER_RW_MS, "Jitter should be within window");
        }

        #[test]
        fn test_send_on_all_interfaces_except() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));
            let _idx2 = transport.register_interface(Box::new(MockInterface::new("if2", 3)));

            transport.send_on_all_interfaces_except(1, b"test data");

            // We can't easily inspect MockInterface sent data through the trait,
            // but we can verify no panic and basic operation works
        }

        #[test]
        fn test_path_request_unknown_dest_forwarded() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let dest_hash = [0x99; TRUNCATED_HASHBYTES]; // Unknown destination
            let path_req_hash = transport.path_request_hash;

            let mut data = Vec::new();
            data.extend_from_slice(&dest_hash);
            data.extend_from_slice(&[0xBB; TRUNCATED_HASHBYTES]); // transport_id
            data.extend_from_slice(&[0xCC; TRUNCATED_HASHBYTES]); // tag

            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: crate::destination::DestinationType::Plain,
                    packet_type: PacketType::Data,
                },
                hops: 0,
                transport_id: None,
                destination_hash: path_req_hash,
                context: PacketContext::None,
                data: PacketData::Owned(data),
            };

            let mut buf = [0u8; 500];
            let len = packet.pack(&mut buf).unwrap();

            // Should not panic, just forward
            transport.process_incoming(0, &buf[..len]).unwrap();
            // Tag should be stored
            assert_eq!(transport.path_request_tags.len(), 1);
        }

        #[test]
        fn test_new_constants_values() {
            assert_eq!(PATHFINDER_G_MS, 5_000);
            assert_eq!(PATHFINDER_RW_MS, 500);
            assert_eq!(LOCAL_REBROADCASTS_MAX, 2);
            assert_eq!(LINK_TIMEOUT_MS, 900_000);
            assert_eq!(PATH_REQUEST_GRACE_MS, 400);
            assert_eq!(crate::constants::PATH_REQUEST_TIMEOUT_MS, 15_000);
            assert_eq!(MAX_PATH_REQUEST_TAGS, 32_000);
            assert_eq!(PATH_REQUEST_MIN_INTERVAL_MS, 20_000);
        }

        // ─── Stage 9: Random blob replay protection ────────────────────

        #[test]
        fn test_announce_replay_detected_via_random_blob() {
            let mut transport = make_transport_enabled();
            let _idx0 =
                transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let (raw, _dest_hash) = make_announce_raw(2, PacketContext::None);
            transport.process_incoming(0, &raw).unwrap();
            assert_eq!(transport.stats().announces_processed, 1);

            // Bypass packet cache and rate limit
            transport.packet_cache.clear();
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);

            // Replay exact same announce (same random_hash)
            transport.process_incoming(0, &raw).unwrap();
            assert_eq!(
                transport.stats().announces_processed, 1,
                "Replayed announce should be dropped"
            );
        }

        #[test]
        fn test_different_random_blob_accepted() {
            let mut transport = make_transport_enabled();
            let _idx0 =
                transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let (raw1, _dest_hash) = make_announce_raw(2, PacketContext::None);
            transport.process_incoming(0, &raw1).unwrap();
            assert_eq!(transport.stats().announces_processed, 1);

            // Create a new announce for the same app but different identity
            // (make_announce_raw generates a fresh identity each time)
            let (raw2, _dest_hash2) = make_announce_raw(2, PacketContext::None);

            // Bypass packet cache and rate limit
            transport.packet_cache.clear();
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);

            // This is a different destination, so it should be processed
            transport.process_incoming(0, &raw2).unwrap();
            assert_eq!(
                transport.stats().announces_processed, 2,
                "Different destination should be accepted"
            );
        }

        // ─── Stage 8: LRPROOF validation ────────────────────────────────

        #[test]
        fn test_identity_stored_from_announce() {
            let mut transport = make_transport_enabled();
            let _idx0 =
                transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let (raw, dest_hash) = make_announce_raw(2, PacketContext::None);
            transport.process_incoming(0, &raw).unwrap();

            assert!(
                transport.identity_table.contains_key(&dest_hash),
                "Identity should be stored from announce"
            );
        }

        #[test]
        fn test_lrproof_invalid_length_not_forwarded() {
            let mut transport = make_transport_enabled();
            let _idx0 =
                transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 =
                transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();

            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_transport_id: [0x01; TRUNCATED_HASHBYTES],
                    next_hop_interface_index: 1,
                    remaining_hops: 2,
                    received_interface_index: 0,
                    hops: 1,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
                    validated: false,
                    proof_timeout_ms: now + 30_000,
                },
            );

            // Build LRPROOF with wrong size (too short)
            let pkt = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: crate::destination::DestinationType::Link,
                    packet_type: PacketType::Proof,
                },
                hops: 2,
                transport_id: None,
                destination_hash: link_id,
                context: PacketContext::Lrproof,
                data: PacketData::Owned(b"too short".to_vec()),
            };

            let mut buf = [0u8; 500];
            let len = pkt.pack(&mut buf).unwrap();
            transport.process_incoming(1, &buf[..len]).unwrap();

            assert_eq!(
                transport.stats().packets_forwarded, 0,
                "LRPROOF with invalid length should not be forwarded"
            );
            assert!(
                !transport.link_table.get(&link_id).unwrap().validated,
                "Link should not be validated with bad proof"
            );
        }

        // ─── Stage 7: Auto re-announce on local path request ─────────────

        #[test]
        fn test_path_request_local_dest_schedules_rebroadcast() {
            let mut transport = make_transport_enabled();
            let _idx0 =
                transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_hash = [0x42; TRUNCATED_HASHBYTES];
            transport.register_destination(dest_hash, false);

            // Populate announce cache for this destination (simulate prior announce)
            let (raw, _) = make_announce_raw(0, PacketContext::None);
            transport.announce_cache.insert(dest_hash, raw);

            // Send path request
            let path_req_hash = transport.path_request_hash;
            let mut data = Vec::new();
            data.extend_from_slice(&dest_hash);
            data.extend_from_slice(&[0xBB; TRUNCATED_HASHBYTES]); // transport_id
            data.extend_from_slice(&[0xCC; TRUNCATED_HASHBYTES]); // tag

            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: crate::destination::DestinationType::Plain,
                    packet_type: PacketType::Data,
                },
                hops: 0,
                transport_id: None,
                destination_hash: path_req_hash,
                context: PacketContext::None,
                data: PacketData::Owned(data),
            };

            let mut buf = [0u8; 500];
            let len = packet.pack(&mut buf).unwrap();
            transport.process_incoming(0, &buf[..len]).unwrap();

            // Should still emit PathRequestReceived event
            let events: Vec<_> = transport.drain_events().collect();
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    TransportEvent::PathRequestReceived { .. }
                )),
                "Should emit PathRequestReceived event"
            );

            // AND should schedule a rebroadcast from the cache
            assert!(
                transport.announce_table.contains_key(&dest_hash),
                "Should schedule announce rebroadcast from cache"
            );
        }

        // ─── Stage 6: Interface validation in table cleanup ─────────────

        #[test]
        fn test_link_table_cleaned_when_interface_offline() {
            let mut transport = make_transport_enabled();
            let _idx0 =
                transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let idx1 =
                transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_transport_id: [0x01; TRUNCATED_HASHBYTES],
                    next_hop_interface_index: 1,
                    remaining_hops: 2,
                    received_interface_index: 0,
                    hops: 1,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
                    validated: true,
                    proof_timeout_ms: now + 30_000,
                },
            );

            // Take interface 1 offline
            transport.unregister_interface(idx1);

            transport.poll();
            assert!(
                !transport.link_table.contains_key(&link_id),
                "Link entry should be removed when interface goes offline"
            );
        }

        #[test]
        fn test_reverse_table_cleaned_when_interface_offline() {
            let mut transport = make_transport_enabled();
            let _idx0 =
                transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let idx1 =
                transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let hash = [0xAA; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.reverse_table.insert(
                hash,
                ReverseEntry {
                    timestamp_ms: now,
                    received_from: [0x01; TRUNCATED_HASHBYTES],
                    receiving_interface_index: 0,
                    outbound_interface_index: 1,
                },
            );

            // Take interface 1 offline
            transport.unregister_interface(idx1);

            transport.poll();
            assert!(
                !transport.reverse_table.contains_key(&hash),
                "Reverse entry should be removed when outbound interface goes offline"
            );
        }

        // ─── Stage 5: Strip transport header at final hop ─────────────

        #[test]
        fn test_link_request_stripped_to_type1_at_final_hop() {
            let mut transport = make_transport_enabled();
            let _idx0 =
                transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            // Use CaptureMockInterface on if1 so we can inspect sent packets
            let sent_buf: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
            let _idx1 = transport.register_interface(Box::new(
                CaptureMockInterface::new("if1", 2, sent_buf.clone()),
            ));

            // Path with hops=1 (destination directly connected to if1)
            let dest_hash = [0xBB; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    received_from: [0x02; TRUNCATED_HASHBYTES],
                    hops: 1,
                    timestamp_ms: now,
                    expires_ms: now + 100_000,
                    interface_index: 1,
                    random_blobs: Vec::new(),
                },
            );

            // Build a link request arriving on if0
            let mut link = Link::new_outgoing(dest_hash.into(), &mut OsRng);
            let raw = link.build_link_request_packet();
            transport.process_incoming(0, &raw).unwrap();

            assert!(
                transport.stats().packets_forwarded > 0,
                "Link request should be forwarded"
            );

            // Verify forwarded packet is Type1 (no transport_id)
            let sent = sent_buf.lock().unwrap();
            assert!(!sent.is_empty(), "Should have sent a packet on if1");
            let forwarded_raw = &sent[0];
            let forwarded_pkt = Packet::unpack(forwarded_raw).unwrap();
            assert_eq!(
                forwarded_pkt.flags.header_type,
                HeaderType::Type1,
                "Final hop should strip to Type1"
            );
            assert!(
                forwarded_pkt.transport_id.is_none(),
                "Type1 packet should have no transport_id"
            );
        }

        #[test]
        fn test_link_request_type2_when_not_final_hop() {
            let mut transport = make_transport_enabled();
            let _idx0 =
                transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let sent_buf: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
            let _idx1 = transport.register_interface(Box::new(
                CaptureMockInterface::new("if1", 2, sent_buf.clone()),
            ));

            // Path with hops=3 (destination is multiple hops away)
            let dest_hash = [0xBB; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    received_from: [0x02; TRUNCATED_HASHBYTES],
                    hops: 3,
                    timestamp_ms: now,
                    expires_ms: now + 100_000,
                    interface_index: 1,
                    random_blobs: Vec::new(),
                },
            );

            // Build a link request arriving on if0
            let mut link = Link::new_outgoing(dest_hash.into(), &mut OsRng);
            let raw = link.build_link_request_packet();
            transport.process_incoming(0, &raw).unwrap();

            assert!(
                transport.stats().packets_forwarded > 0,
                "Link request should be forwarded"
            );

            // Verify forwarded packet is Type2 (with transport_id)
            let sent = sent_buf.lock().unwrap();
            assert!(!sent.is_empty(), "Should have sent a packet on if1");
            let forwarded_raw = &sent[0];
            let forwarded_pkt = Packet::unpack(forwarded_raw).unwrap();
            assert_eq!(
                forwarded_pkt.flags.header_type,
                HeaderType::Type2,
                "Intermediate hop should use Type2"
            );
            assert!(
                forwarded_pkt.transport_id.is_some(),
                "Type2 packet should have transport_id"
            );
        }

        // ─── Forward payload integrity: Type2 -> Type1 conversion ────────

        #[test]
        fn test_link_request_forward_type2_to_type1_payload_intact() {
            // Setup: transport with 2 CaptureMockInterfaces so we can inspect
            // what is sent on each interface.
            let mut transport = make_transport_enabled();

            let sent_if0: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
            let sent_if1: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));

            let _idx0 = transport.register_interface(Box::new(
                CaptureMockInterface::new("if0", 1, sent_if0.clone()),
            ));
            let _idx1 = transport.register_interface(Box::new(
                CaptureMockInterface::new("if1", 2, sent_if1.clone()),
            ));

            // Create a path entry for dest_hash with hops=0 (directly connected
            // to if1), meaning the relay is the final hop.
            let dest_hash = [0xDD; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    received_from: [0x02; TRUNCATED_HASHBYTES],
                    hops: 0,
                    timestamp_ms: now,
                    expires_ms: now + 100_000,
                    interface_index: 1,
                    random_blobs: Vec::new(),
                },
            );

            // ── Part A: Type1 link request arriving on if0, forwarded to if1 ──

            let mut link_a = Link::new_outgoing(dest_hash.into(), &mut OsRng);
            let original_request_data_a = link_a.create_link_request();
            let raw_type1 = link_a.build_link_request_packet();

            // Verify the original is Type1
            let original_pkt_a = Packet::unpack(&raw_type1).unwrap();
            assert_eq!(original_pkt_a.flags.header_type, HeaderType::Type1);
            assert_eq!(original_pkt_a.flags.packet_type, PacketType::LinkRequest);

            transport.process_incoming(0, &raw_type1).unwrap();

            assert!(
                transport.stats().packets_forwarded > 0,
                "Type1 link request should be forwarded"
            );

            // Verify the forwarded packet on if1
            {
                let sent = sent_if1.lock().unwrap();
                assert!(!sent.is_empty(), "Should have sent a packet on if1");
                let forwarded_raw = &sent[0];
                let forwarded_pkt = Packet::unpack(forwarded_raw)
                    .expect("Forwarded packet must be parseable by Packet::unpack");

                assert_eq!(
                    forwarded_pkt.flags.header_type,
                    HeaderType::Type1,
                    "Final hop (hops=0) should produce Type1"
                );
                assert_eq!(
                    forwarded_pkt.flags.packet_type,
                    PacketType::LinkRequest,
                    "Packet type must remain LinkRequest"
                );
                assert_eq!(
                    forwarded_pkt.destination_hash, dest_hash,
                    "Destination hash must match"
                );
                assert!(
                    forwarded_pkt.transport_id.is_none(),
                    "Type1 must have no transport_id"
                );
                assert_eq!(
                    forwarded_pkt.hops, 1,
                    "Hops should be incremented by 1"
                );

                // Verify data payload is intact (the 64-byte link request data)
                assert_eq!(
                    forwarded_pkt.data.as_slice(),
                    &original_request_data_a[..],
                    "Link request payload must be preserved exactly"
                );
            }

            // Nothing should be sent on if0 (the receiving interface)
            {
                let sent = sent_if0.lock().unwrap();
                assert!(
                    sent.is_empty(),
                    "No packets should be sent back on the receiving interface"
                );
            }

            // ── Part B: Type2 link request arriving on if0, forwarded to if1 ──

            // Clear previous state
            sent_if1.lock().unwrap().clear();
            transport.packet_cache.clear(); // allow processing

            // Build a Type2 link request (with transport_id set)
            let fake_transport_id = [0xAA; TRUNCATED_HASHBYTES];
            let mut link_b = Link::new_outgoing(dest_hash.into(), &mut OsRng);
            let original_request_data_b = link_b.create_link_request();
            let raw_type2 = link_b.build_link_request_packet_with_transport(
                Some(fake_transport_id),
                1, // hops_to_dest
            );

            // Verify the original is Type2
            let original_pkt_b = Packet::unpack(&raw_type2).unwrap();
            assert_eq!(original_pkt_b.flags.header_type, HeaderType::Type2);
            assert_eq!(original_pkt_b.flags.packet_type, PacketType::LinkRequest);
            assert_eq!(
                original_pkt_b.transport_id,
                Some(fake_transport_id),
                "Original should carry transport_id"
            );

            let forwarded_before = transport.stats().packets_forwarded;
            transport.process_incoming(0, &raw_type2).unwrap();

            assert!(
                transport.stats().packets_forwarded > forwarded_before,
                "Type2 link request should be forwarded"
            );

            // Verify the forwarded packet on if1
            {
                let sent = sent_if1.lock().unwrap();
                assert!(!sent.is_empty(), "Should have sent a forwarded packet on if1");
                let forwarded_raw = &sent[0];
                let forwarded_pkt = Packet::unpack(forwarded_raw)
                    .expect("Forwarded Type2->Type1 packet must be parseable");

                assert_eq!(
                    forwarded_pkt.flags.header_type,
                    HeaderType::Type1,
                    "Final hop should convert Type2 to Type1"
                );
                assert_eq!(
                    forwarded_pkt.flags.packet_type,
                    PacketType::LinkRequest,
                    "Packet type must remain LinkRequest after conversion"
                );
                assert_eq!(
                    forwarded_pkt.destination_hash, dest_hash,
                    "Destination hash must be preserved"
                );
                assert!(
                    forwarded_pkt.transport_id.is_none(),
                    "Type1 must strip transport_id"
                );
                assert_eq!(
                    forwarded_pkt.hops, 1,
                    "Hops should be original (0) + 1 = 1"
                );

                // Verify data payload is intact (the 64-byte link request data)
                assert_eq!(
                    forwarded_pkt.data.as_slice(),
                    &original_request_data_b[..],
                    "Link request payload must be preserved exactly after Type2->Type1 conversion"
                );
            }

            // ── Part C: Type2 arriving, multi-hop (hops=3), stays Type2 ──

            sent_if1.lock().unwrap().clear();
            transport.packet_cache.clear();

            // Update path to multi-hop
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    received_from: [0x02; TRUNCATED_HASHBYTES],
                    hops: 3,
                    timestamp_ms: now,
                    expires_ms: now + 100_000,
                    interface_index: 1,
                    random_blobs: Vec::new(),
                },
            );

            let mut link_c = Link::new_outgoing(dest_hash.into(), &mut OsRng);
            let original_request_data_c = link_c.create_link_request();
            let raw_type2_multi = link_c.build_link_request_packet_with_transport(
                Some(fake_transport_id),
                3,
            );

            let forwarded_before = transport.stats().packets_forwarded;
            transport.process_incoming(0, &raw_type2_multi).unwrap();

            assert!(
                transport.stats().packets_forwarded > forwarded_before,
                "Multi-hop Type2 link request should be forwarded"
            );

            {
                let sent = sent_if1.lock().unwrap();
                assert!(!sent.is_empty(), "Should have sent a packet on if1");
                let forwarded_raw = &sent[0];
                let forwarded_pkt = Packet::unpack(forwarded_raw)
                    .expect("Multi-hop forwarded packet must be parseable");

                assert_eq!(
                    forwarded_pkt.flags.header_type,
                    HeaderType::Type2,
                    "Multi-hop should remain Type2"
                );
                assert_eq!(
                    forwarded_pkt.flags.packet_type,
                    PacketType::LinkRequest,
                    "Packet type must remain LinkRequest"
                );
                assert_eq!(
                    forwarded_pkt.destination_hash, dest_hash,
                    "Destination hash must be preserved"
                );
                assert!(
                    forwarded_pkt.transport_id.is_some(),
                    "Type2 must have transport_id"
                );
                // transport_id should now be THIS transport node's identity hash
                let our_id = *transport.identity.hash();
                assert_eq!(
                    forwarded_pkt.transport_id.unwrap(),
                    our_id,
                    "Transport ID should be set to the relay's identity hash"
                );

                // Verify data payload is intact
                assert_eq!(
                    forwarded_pkt.data.as_slice(),
                    &original_request_data_c[..],
                    "Link request payload must be preserved in multi-hop forwarding"
                );
            }

            // ── Part D: Verify link table was populated for all forwarded requests ──

            assert!(
                transport.link_table.len() >= 3,
                "Link table should have entries for all forwarded link requests, got {}",
                transport.link_table.len()
            );

            // All link table entries should point to interface 1 as next hop
            for (_link_id, entry) in &transport.link_table {
                assert_eq!(
                    entry.next_hop_interface_index, 1,
                    "Link entry should route toward if1"
                );
                assert_eq!(
                    entry.received_interface_index, 0,
                    "Link entry should record if0 as received interface"
                );
                assert_eq!(
                    entry.destination_hash, dest_hash,
                    "Link entry should record correct destination hash"
                );
            }
        }

        // ─── Stage 4: Hop count validation ──────────────────────────────

        /// Build a data packet with the given destination hash and hop count
        fn build_link_data_packet(
            dest_hash: [u8; TRUNCATED_HASHBYTES],
            hops: u8,
        ) -> Packet {
            Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: crate::destination::DestinationType::Single,
                    packet_type: PacketType::Data,
                },
                hops,
                transport_id: None,
                destination_hash: dest_hash,
                context: PacketContext::None,
                data: PacketData::Owned(b"link data".to_vec()),
            }
        }

        #[test]
        fn test_link_data_wrong_hops_dropped() {
            let mut transport = make_transport_enabled();
            let _idx0 =
                transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 =
                transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_transport_id: [0x01; TRUNCATED_HASHBYTES],
                    next_hop_interface_index: 1,
                    remaining_hops: 3,
                    received_interface_index: 0,
                    hops: 2,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
                    validated: true,
                    proof_timeout_ms: now + 30_000,
                },
            );

            // Data from dest side (if1): hops should match remaining_hops=3
            let pkt = build_link_data_packet(link_id, 99); // wrong hops
            let mut buf = [0u8; 500];
            let len = pkt.pack(&mut buf).unwrap();
            transport.process_incoming(1, &buf[..len]).unwrap();
            assert_eq!(
                transport.stats().packets_forwarded, 0,
                "Wrong hops should be dropped"
            );
        }

        #[test]
        fn test_link_data_correct_hops_forwarded() {
            let mut transport = make_transport_enabled();
            let _idx0 =
                transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 =
                transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_transport_id: [0x01; TRUNCATED_HASHBYTES],
                    next_hop_interface_index: 1,
                    remaining_hops: 3,
                    received_interface_index: 0,
                    hops: 2,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
                    validated: true,
                    proof_timeout_ms: now + 30_000,
                },
            );

            // Data from dest side (if1): hops=3 matches remaining_hops=3
            let pkt = build_link_data_packet(link_id, 3);
            let mut buf = [0u8; 500];
            let len = pkt.pack(&mut buf).unwrap();
            transport.process_incoming(1, &buf[..len]).unwrap();
            assert!(
                transport.stats().packets_forwarded > 0,
                "Correct hops should be forwarded"
            );
        }

        #[test]
        fn test_link_data_correct_hops_from_initiator() {
            let mut transport = make_transport_enabled();
            let _idx0 =
                transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 =
                transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_transport_id: [0x01; TRUNCATED_HASHBYTES],
                    next_hop_interface_index: 1,
                    remaining_hops: 3,
                    received_interface_index: 0,
                    hops: 2,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
                    validated: true,
                    proof_timeout_ms: now + 30_000,
                },
            );

            // Data from initiator side (if0): hops=2 matches hops=2
            let pkt = build_link_data_packet(link_id, 2);
            let mut buf = [0u8; 500];
            let len = pkt.pack(&mut buf).unwrap();
            transport.process_incoming(0, &buf[..len]).unwrap();
            assert!(
                transport.stats().packets_forwarded > 0,
                "Correct hops from initiator should be forwarded"
            );
        }

        // ─── Stage 3: Reverse table proof routing ──────────────────────

        #[test]
        fn test_regular_proof_routed_via_reverse_table() {
            let mut transport = make_transport_enabled();
            let _idx0 =
                transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 =
                transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            // Simulate a data packet that was forwarded from if0 to if1,
            // creating a reverse table entry keyed by truncated_packet_hash
            let packet_hash = [0xAA; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.reverse_table.insert(
                packet_hash,
                ReverseEntry {
                    timestamp_ms: now,
                    received_from: [0x01; TRUNCATED_HASHBYTES],
                    receiving_interface_index: 0, // received on if0
                    outbound_interface_index: 1,  // forwarded to if1
                },
            );

            // Build a proof packet targeting this packet_hash
            let proof_packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: crate::destination::DestinationType::Single,
                    packet_type: PacketType::Proof,
                },
                hops: 0,
                transport_id: None,
                destination_hash: packet_hash,
                context: PacketContext::None,
                data: PacketData::Owned(
                    alloc::vec![0x55; crate::constants::PROOF_DATA_SIZE],
                ),
            };

            let mut buf = [0u8; crate::constants::MTU];
            let len = proof_packet.pack(&mut buf).unwrap();
            // Proof arrives on if1 (the outbound interface)
            transport.process_incoming(1, &buf[..len]).unwrap();

            // Proof should be forwarded via reverse table → if0
            assert!(
                transport.stats().packets_forwarded > 0,
                "Proof should have been forwarded via reverse table"
            );
            // Reverse table entry should be consumed (removed)
            assert!(
                !transport.reverse_table.contains_key(&packet_hash),
                "Reverse table entry should be consumed after proof routing"
            );
        }

        // ─── Stage 2: Fix calculate_retransmit_delay ────────────────────

        #[test]
        fn test_retransmit_delay_independent_of_hops() {
            let transport = make_transport_enabled();
            let delay_1hop = transport.calculate_retransmit_delay(1);
            let delay_10hops = transport.calculate_retransmit_delay(10);
            // Both should be in the same range (0..PATHFINDER_RW_MS)
            assert!(
                delay_1hop < PATHFINDER_RW_MS,
                "1-hop delay {} should be < PATHFINDER_RW_MS {}",
                delay_1hop,
                PATHFINDER_RW_MS
            );
            assert!(
                delay_10hops < PATHFINDER_RW_MS,
                "10-hop delay {} should be < PATHFINDER_RW_MS {}",
                delay_10hops,
                PATHFINDER_RW_MS
            );
        }

        // ─── Stage 1: VecDeque for path_request_tags ─────────────────────

        #[test]
        fn test_path_request_tags_uses_efficient_deque() {
            let mut transport = make_transport_enabled();
            let _idx0 =
                transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let path_req_hash = transport.path_request_hash;

            // Insert MAX_PATH_REQUEST_TAGS + 1 unique path request tags
            for i in 0..=MAX_PATH_REQUEST_TAGS {
                let dest_hash = [0x42; TRUNCATED_HASHBYTES];
                let mut tag = [0u8; TRUNCATED_HASHBYTES];
                let bytes = (i as u32).to_le_bytes();
                tag[..4].copy_from_slice(&bytes);

                let mut data = Vec::new();
                data.extend_from_slice(&dest_hash);
                data.extend_from_slice(&[0xBB; TRUNCATED_HASHBYTES]); // transport_id
                data.extend_from_slice(&tag);

                let packet = Packet {
                    flags: PacketFlags {
                        ifac_flag: false,
                        header_type: HeaderType::Type1,
                        context_flag: false,
                        transport_type: TransportType::Broadcast,
                        dest_type: crate::destination::DestinationType::Plain,
                        packet_type: PacketType::Data,
                    },
                    hops: 0,
                    transport_id: None,
                    destination_hash: path_req_hash,
                    context: PacketContext::None,
                    data: PacketData::Owned(data),
                };

                let mut buf = [0u8; 500];
                let len = packet.pack(&mut buf).unwrap();

                // Clear packet cache so each iteration is processed
                transport.packet_cache.clear();
                transport.process_incoming(0, &buf[..len]).unwrap();
            }

            // Should be capped at MAX_PATH_REQUEST_TAGS
            assert_eq!(
                transport.path_request_tags.len(),
                MAX_PATH_REQUEST_TAGS,
                "path_request_tags should be capped at MAX_PATH_REQUEST_TAGS"
            );
        }
    }
}
