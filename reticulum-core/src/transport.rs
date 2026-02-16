//! Transport layer - routing, path discovery, packet handling (sans-I/O)
//!
//! The Transport is the heart of the Reticulum protocol. It manages:
//! - Packet routing based on destination hash
//! - Path discovery via announce propagation
//! - Link table management
//! - Duplicate packet detection
//!
//! # Sans-I/O Design
//!
//! Transport never performs I/O directly. Instead it:
//! - Accepts incoming packets via `process_incoming(iface_index, data)`
//! - Emits outbound I/O as `Action` values (`SendPacket`, `Broadcast`)
//! - Emits protocol events via `drain_events()`
//!
//! The driver (in `reticulum-std` or an embedded crate) owns the interfaces,
//! handles framing, and dispatches Actions to the network.
//!
//! ```text
//! use reticulum_core::transport::{Transport, TransportConfig};
//!
//! let mut transport = Transport::new(config, clock, storage, identity);
//!
//! // Driver feeds incoming packets:
//! transport.process_incoming(iface_index, &raw_data)?;
//!
//! // Driver dispatches outbound actions:
//! for action in transport.drain_actions() {
//!     // send via interface
//! }
//!
//! // Driver runs periodic maintenance:
//! transport.poll();
//! ```

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::constants::{
    ANNOUNCE_RATE_GRACE, ANNOUNCE_RATE_LIMIT_MS, ANNOUNCE_RATE_PENALTY_MS, LINK_TIMEOUT_MS,
    LOCAL_REBROADCASTS_MAX, MAX_PATH_REQUEST_TAGS, MAX_RANDOM_BLOBS, MS_PER_SECOND, MTU,
    PACKET_CACHE_EXPIRY_MS, PATHFINDER_EXPIRY_SECS, PATHFINDER_G_MS, PATHFINDER_MAX_HOPS,
    PATHFINDER_RETRIES, PATHFINDER_RW_MS, PATH_REQUEST_GRACE_MS, PATH_REQUEST_MIN_INTERVAL_MS,
    REVERSE_TABLE_EXPIRY_MS, TRUNCATED_HASHBYTES,
};

use crate::announce::{emission_from_random_hash, max_emission_from_blobs, ReceivedAnnounce};
use crate::crypto::truncated_hash;
use crate::destination::{Destination, DestinationHash, DestinationType};
use crate::identity::Identity;
use crate::link::Link;
use crate::packet::{
    build_proof_packet, packet_hash, truncated_packet_hash, HeaderType, Packet, PacketContext,
    PacketData, PacketError, PacketFlags, PacketType, TransportType,
};
use crate::receipt::{PacketReceipt, ReceiptStatus};
use crate::traits::{Clock, Storage};

// ─── Sans-I/O Types ─────────────────────────────────────────────────────────

/// Opaque interface identifier
///
/// Core never inspects what an `InterfaceId` refers to — it stores and returns
/// them so the driver can map them back to actual interface objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InterfaceId(pub usize);

impl core::fmt::Display for InterfaceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "iface:{}", self.0)
    }
}

/// I/O action for the driver to execute
///
/// Core never performs I/O directly — instead it returns `Action` values that
/// describe what the driver should do. The driver matches on these and
/// dispatches to the appropriate interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send a packet on a specific interface
    SendPacket {
        /// The target interface
        iface: InterfaceId,
        /// The packet data (already framed for the wire)
        data: Vec<u8>,
    },
    /// Broadcast a packet on all online interfaces, optionally excluding one
    Broadcast {
        /// The packet data (already framed for the wire)
        data: Vec<u8>,
        /// Interface to skip (typically the one the packet arrived on)
        exclude_iface: Option<InterfaceId>,
    },
}

/// Output from any core method that may produce I/O or events
///
/// Returned by `handle_packet()`, `handle_timeout()`, and other methods that
/// may trigger outbound I/O or application-visible events. The returned
/// `TickOutput` **must** be dispatched to interfaces by the driver — dropping
/// it silently loses outbound packets and application events.
#[derive(Default)]
#[must_use = "TickOutput contains actions that must be dispatched to interfaces"]
pub struct TickOutput {
    /// I/O actions for the driver to execute
    pub actions: Vec<Action>,
    /// Application-visible events
    pub events: Vec<super::node::NodeEvent>,
}

impl TickOutput {
    /// Create an empty TickOutput
    pub fn empty() -> Self {
        Self::default()
    }

    /// Check if this output contains no actions or events
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty() && self.events.is_empty()
    }

    /// Merge another TickOutput into this one
    ///
    /// Appends all actions and events from `other` to `self`.
    pub fn merge(&mut self, other: TickOutput) {
        self.actions.extend(other.actions);
        self.events.extend(other.events);
    }
}

impl core::fmt::Debug for TickOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TickOutput")
            .field("actions", &self.actions.len())
            .field("events", &self.events.len())
            .finish()
    }
}

// ─── Data Structures (always available) ─────────────────────────────────────

/// Path quality state (for path recovery)
///
/// Tracks whether a path is known to be working, unresponsive, or unknown.
/// Used to allow accepting same-emission worse-hop announces when the
/// current path has been marked unresponsive (Python Transport.py:1672-1681).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// Default state — no knowledge about path quality
    Unknown,
    /// Communication attempt failed (unvalidated link expired)
    Unresponsive,
    /// Communication succeeded (defined for API completeness; not used internally)
    Responsive,
}

/// Path table entry
#[derive(Debug, Clone)]
pub(crate) struct PathEntry {
    /// Number of hops to destination
    pub hops: u8,
    /// When this path expires (ms since clock epoch)
    pub expires_ms: u64,
    /// Interface index where we learned this path
    pub interface_index: usize,
    /// Random blobs seen for this destination (for replay detection)
    pub random_blobs: Vec<[u8; crate::constants::RANDOM_HASHBYTES]>,
    /// Identity hash of the next relay hop (from announce transport_id)
    pub next_hop: Option<[u8; TRUNCATED_HASHBYTES]>,
}

impl PathEntry {
    /// Destination is directly connected (no relay needed).
    /// Rust stores raw wire hops: 0 = direct neighbor.
    /// Python equivalent: hops == 1 (Python increments on receipt).
    pub(crate) fn is_direct(&self) -> bool {
        self.hops == 0
    }

    /// Destination requires relay forwarding AND we know the next hop.
    pub(crate) fn needs_relay(&self) -> bool {
        self.hops > 0 && self.next_hop.is_some()
    }
}

/// Link table entry (for active links routed through this transport node)
#[derive(Debug, Clone)]
pub(crate) struct LinkEntry {
    /// When this link was created (ms)
    pub timestamp_ms: u64,
    /// Interface index toward the destination (outbound)
    pub next_hop_interface_index: usize,
    /// Remaining hops to destination
    pub remaining_hops: u8,
    /// Interface index where we received the link request (inbound, toward initiator)
    pub received_interface_index: usize,
    /// Total hops from initiator
    pub hops: u8,
    /// Whether the link has been validated by a proof
    pub validated: bool,
    /// Deadline for receiving a proof (ms), after which the entry is removed
    pub proof_timeout_ms: u64,
    /// Destination hash for path rediscovery on unvalidated link expiry
    pub destination_hash: [u8; TRUNCATED_HASHBYTES],
}

/// Reverse table entry (for routing replies back)
#[derive(Debug, Clone)]
pub(crate) struct ReverseEntry {
    /// When this was learned (ms)
    pub timestamp_ms: u64,
    /// Interface index where the original packet was received
    pub receiving_interface_index: usize,
    /// Interface index where the packet was forwarded to
    pub outbound_interface_index: usize,
}

/// Announce table entry (for rate limiting and rebroadcast tracking)
#[derive(Debug, Clone)]
pub(crate) struct AnnounceEntry {
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

/// Per-destination announce rate tracking entry (Python: announce_rate_table)
///
/// Tracks violations when a destination announces too frequently and blocks
/// rebroadcast (but not path table updates) when violations exceed grace.
#[derive(Debug, Clone)]
pub(crate) struct AnnounceRateEntry {
    /// Timestamp of last accepted (non-violating) announce (ms)
    pub last_ms: u64,
    /// Number of rate violations (incremented on too-fast, decremented on good-rate)
    pub rate_violations: u8,
    /// Announces are blocked until this timestamp (ms)
    pub blocked_until_ms: u64,
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
    /// Per-destination announce rate target (ms). None = disabled (default).
    /// When set, announces arriving faster than this interval accumulate violations.
    pub announce_rate_target_ms: Option<u64>,
    /// Number of rate violations allowed before blocking rebroadcast. Default 0.
    pub announce_rate_grace: u8,
    /// Additional blocking penalty (ms) added to the blocking window. Default 0.
    pub announce_rate_penalty_ms: u64,
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
            announce_rate_target_ms: None,
            announce_rate_grace: ANNOUNCE_RATE_GRACE,
            announce_rate_penalty_ms: ANNOUNCE_RATE_PENALTY_MS,
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
        /// Hash of original wire bytes (for repack symmetry verification)
        raw_hash: Option<[u8; 32]>,
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
    /// Proof generation requested for a received packet
    ///
    /// Emitted for every data packet received at a local destination.
    /// NodeCore looks up the proof strategy from its own destination registry
    /// and dispatches accordingly (auto-prove, forward to app, or ignore).
    ProofRequested {
        /// Full SHA256 hash of the packet to potentially prove
        packet_hash: [u8; 32],
        /// Destination that received the packet
        destination_hash: [u8; TRUNCATED_HASHBYTES],
        /// The interface the packet was received on
        interface_index: usize,
    },

    /// A proof was received for a sent packet
    ///
    /// Emitted when a proof packet arrives matching a tracked receipt.
    /// NodeCore performs the actual signature verification using its
    /// Destination's identity.
    ProofReceived {
        /// Truncated hash identifying the receipt
        packet_hash: [u8; TRUNCATED_HASHBYTES],
        /// Destination hash (to find the identity on NodeCore)
        destination_hash: [u8; TRUNCATED_HASHBYTES],
        /// Full packet hash from the receipt (for cross-check in verify_proof)
        expected_packet_hash: [u8; 32],
        /// Raw proof data (96 bytes: full_hash(32) + signature(64))
        proof_data: Vec<u8>,
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
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransportError::NoPath => write!(f, "no path to destination"),
            TransportError::PacketError(e) => write!(f, "packet error: {}", e),
            TransportError::AnnounceError(e) => write!(f, "announce error: {}", e),
        }
    }
}

impl From<PacketError> for TransportError {
    fn from(e: PacketError) -> Self {
        TransportError::PacketError(e)
    }
}

// ─── Transport ──────────────────────────────────────────────────────────────

/// The Transport layer (sans-I/O state machine)
///
/// Generic over platform traits so the same protocol logic runs everywhere.
/// Transport never performs I/O directly — all outbound data is expressed as
/// `Action` values that the driver dispatches to actual network interfaces.
///
/// - `C`: Clock implementation for timestamps
/// - `S`: Storage implementation for persistence
pub struct Transport<C: Clock, S: Storage> {
    config: TransportConfig,
    clock: C,
    _storage: S,
    identity: Identity,

    /// Path table: destination_hash -> path info
    path_table: BTreeMap<[u8; TRUNCATED_HASHBYTES], PathEntry>,

    /// Path state tracking: destination_hash -> quality state
    /// Used for path recovery (accepting worse-hop announces for unresponsive paths)
    path_states: BTreeMap<[u8; TRUNCATED_HASHBYTES], PathState>,

    /// Announce table: destination_hash -> announce rate tracking
    announce_table: BTreeMap<[u8; TRUNCATED_HASHBYTES], AnnounceEntry>,

    /// Link table: link_id -> link routing info
    link_table: BTreeMap<[u8; TRUNCATED_HASHBYTES], LinkEntry>,

    /// Reverse table: packet_hash -> sender info (for routing replies)
    reverse_table: BTreeMap<[u8; TRUNCATED_HASHBYTES], ReverseEntry>,

    /// Registered destinations we accept packets for
    local_destinations: BTreeSet<[u8; TRUNCATED_HASHBYTES]>,

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

    /// Per-destination announce rate tracking (Python: announce_rate_table)
    announce_rate_table: BTreeMap<[u8; TRUNCATED_HASHBYTES], AnnounceRateEntry>,

    /// Pending I/O actions for the driver (sans-I/O buffer)
    pending_actions: Vec<Action>,

    /// Interfaces for test use only (not used in production sans-I/O path)
    #[cfg(test)]
    interfaces: Vec<Option<Box<dyn crate::traits::Interface + Send>>>,
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
            path_table: BTreeMap::new(),
            path_states: BTreeMap::new(),
            announce_table: BTreeMap::new(),
            link_table: BTreeMap::new(),
            reverse_table: BTreeMap::new(),
            local_destinations: BTreeSet::new(),
            packet_cache: BTreeMap::new(),
            receipts: BTreeMap::new(),
            events: Vec::new(),
            stats: TransportStats::default(),
            path_request_hash,
            path_request_tags: VecDeque::new(),
            path_requests: BTreeMap::new(),
            announce_cache: BTreeMap::new(),
            identity_table: BTreeMap::new(),
            announce_rate_table: BTreeMap::new(),
            pending_actions: Vec::new(),
            #[cfg(test)]
            interfaces: Vec::new(),
        }
    }

    // ─── Test-only Interface Management ───────────────────────────────
    //
    // These methods exist only in test builds to support existing protocol
    // tests that use MockInterface. In production, Transport is sans-I/O
    // and does not own interfaces.

    /// Register an interface (test-only)
    #[cfg(test)]
    pub fn register_interface(
        &mut self,
        interface: Box<dyn crate::traits::Interface + Send>,
    ) -> usize {
        let index = self.interfaces.len();
        self.interfaces.push(Some(interface));
        index
    }

    /// Unregister an interface (test-only)
    #[cfg(test)]
    pub fn unregister_interface(&mut self, index: usize) {
        if let Some(slot) = self.interfaces.get_mut(index) {
            *slot = None;
        }
    }

    /// Get interface count (test-only)
    #[cfg(test)]
    pub fn interface_count(&self) -> usize {
        self.interfaces.iter().filter(|i| i.is_some()).count()
    }

    /// Get mutable interface reference (test-only)
    #[cfg(test)]
    pub fn interface_mut(
        &mut self,
        index: usize,
    ) -> Option<&mut (dyn crate::traits::Interface + '_)> {
        match self.interfaces.get_mut(index) {
            Some(Some(iface)) => Some(iface.as_mut()),
            _ => None,
        }
    }

    /// Number of pending events (test-only)
    #[cfg(test)]
    pub fn pending_events(&self) -> usize {
        self.events.len()
    }

    /// Number of pending I/O actions (test-only)
    #[cfg(test)]
    pub fn pending_action_count(&self) -> usize {
        self.pending_actions.len()
    }

    // ─── Destination Management ─────────────────────────────────────────

    /// Register a destination to receive packets
    ///
    /// Transport only tracks whether a hash is local. All destination metadata
    /// (proof strategy, accepts_links, identity) lives on NodeCore.
    pub fn register_destination(&mut self, hash: [u8; TRUNCATED_HASHBYTES]) {
        self.local_destinations.insert(hash);
    }

    /// Unregister a destination
    pub fn unregister_destination(&mut self, hash: &[u8; TRUNCATED_HASHBYTES]) {
        self.local_destinations.remove(hash);
    }

    /// Check if a destination is registered
    pub fn has_destination(&self, hash: &[u8; TRUNCATED_HASHBYTES]) -> bool {
        self.local_destinations.contains(hash)
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
    pub(crate) fn path(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<&PathEntry> {
        self.path_table.get(dest_hash)
    }

    /// Get the number of known paths
    pub fn path_count(&self) -> usize {
        self.path_table.len()
    }

    // ─── Path State Management ──────────────────────────────────────────

    /// Mark a path as unresponsive
    ///
    /// Only succeeds if the destination exists in the path table.
    /// Called when an unvalidated link expires for a 1-hop destination/initiator.
    pub fn mark_path_unresponsive(&mut self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> bool {
        if self.path_table.contains_key(dest_hash) {
            self.path_states.insert(*dest_hash, PathState::Unresponsive);
            true
        } else {
            false
        }
    }

    /// Mark a path as responsive
    ///
    /// Only succeeds if the destination exists in the path table.
    /// Defined for API completeness (not called internally, matching Python).
    pub fn mark_path_responsive(&mut self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> bool {
        if self.path_table.contains_key(dest_hash) {
            self.path_states.insert(*dest_hash, PathState::Responsive);
            true
        } else {
            false
        }
    }

    /// Reset path state to unknown
    ///
    /// Only succeeds if the destination exists in the path table.
    /// Called when a new announce successfully updates the path table.
    pub(crate) fn mark_path_unknown_state(
        &mut self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> bool {
        if self.path_table.contains_key(dest_hash) {
            self.path_states.insert(*dest_hash, PathState::Unknown);
            true
        } else {
            false
        }
    }

    /// Check if a path is marked as unresponsive
    pub fn path_is_unresponsive(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> bool {
        self.path_states.get(dest_hash) == Some(&PathState::Unresponsive)
    }

    /// Force-expire a path entry
    ///
    /// Removes the path table entry and emits `PathLost`. Returns true if
    /// the path existed and was removed.
    pub fn expire_path(&mut self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> bool {
        if self.path_table.remove(dest_hash).is_some() {
            self.events.push(TransportEvent::PathLost {
                destination_hash: *dest_hash,
            });
            true
        } else {
            false
        }
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
        let receipt = PacketReceipt::with_timeout(
            hash,
            DestinationHash::new(destination_hash),
            now,
            timeout_ms,
        );
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

    /// Mark a receipt as delivered after NodeCore verified the proof
    ///
    /// Called by NodeCore when it successfully validates a single-packet proof
    /// using the destination's identity.
    pub fn mark_receipt_delivered(&mut self, truncated_hash: &[u8; TRUNCATED_HASHBYTES]) {
        if let Some(receipt) = self.receipts.get_mut(truncated_hash) {
            receipt.set_delivered();
        }
    }

    /// Send a proof for a received packet
    ///
    /// Call this when the application decides to prove a packet (after ProofRequested event).
    ///
    /// # Arguments
    /// * `packet_hash` - The full SHA256 hash of the packet to prove
    /// * `destination_hash` - The destination to send the proof to (the original sender)
    /// * `identity` - The identity to sign the proof with
    /// * `receiving_interface` - If `Some`, send proof on this interface (used for
    ///   auto-proofs where we know the receiving interface). If `None`,
    ///   fall back to path table lookup (used for app-initiated proofs).
    ///
    /// # Returns
    /// `Ok(())` if the proof was sent, `Err` if there's no path to the destination
    pub fn send_proof(
        &mut self,
        packet_hash: &[u8; 32],
        destination_hash: &[u8; TRUNCATED_HASHBYTES],
        identity: &Identity,
        receiving_interface: Option<usize>,
    ) -> Result<(), TransportError> {
        let proof_data = identity
            .create_proof(packet_hash)
            .map_err(|_| TransportError::NoPath)?; // Use NoPath for simplicity

        let packet = build_proof_packet(destination_hash, &proof_data);

        // Prefer explicit interface (PROVE_ALL), fall back to path lookup (PROVE_APP)
        let interface_index = match receiving_interface {
            Some(iface) => iface,
            None => self
                .path_table
                .get(destination_hash)
                .map(|p| p.interface_index)
                .ok_or(TransportError::NoPath)?,
        };

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

        // Filter HEADER_2 packets not addressed to this transport instance
        // (Python Transport.py:1193-1196). Announces are exempt.
        if packet.transport_id.is_some()
            && packet.flags.packet_type != PacketType::Announce
            && packet.transport_id != Some(*self.identity.hash())
        {
            self.stats.packets_dropped += 1;
            return Ok(());
        }

        // Filter PLAIN and GROUP destination packets (Python Transport.py:1205-1225).
        // These destination types are for direct neighbors only.
        if packet.flags.dest_type == DestinationType::Plain
            || packet.flags.dest_type == DestinationType::Group
        {
            // PLAIN/GROUP announces are always invalid
            if packet.flags.packet_type == PacketType::Announce {
                self.stats.packets_dropped += 1;
                return Ok(());
            }
            // Non-announce: drop if hops > 0 (PLAIN/GROUP are direct-neighbor only).
            // Python checks hops > 1 AFTER incrementing on receipt; Rust stores
            // raw wire hops without increment, so the equivalent is hops > 0.
            if packet.hops > 0 {
                self.stats.packets_dropped += 1;
                return Ok(());
            }
        }

        // Compute full packet hash (for proofs) and truncated hash (for deduplication)
        let full_packet_hash = packet_hash(raw);
        let dedup_hash = truncated_packet_hash(raw);
        let now = self.clock.now_ms();

        // Check duplicate
        if self.packet_cache.contains_key(&dedup_hash) {
            self.stats.packets_dropped += 1;
            return Ok(());
        }

        // Defer cache insertion for link-table and LRPROOF packets
        // (Python Transport.py:1355-1372). On shared media, these packets
        // may be heard before reaching us via the correct link path.
        // Inserting early would block the correct copy. The handler inserts
        // the hash on successful processing; failed packets stay uncached
        // so the correct copy can still pass dedup.
        let defer_cache_insert = self.link_table.contains_key(&packet.destination_hash)
            || (packet.flags.packet_type == PacketType::Proof
                && packet.context == PacketContext::Lrproof);

        if !defer_cache_insert {
            self.packet_cache.insert(dedup_hash, now);
        }

        // Route to handler based on packet type
        // Note: reverse table entries are populated at forwarding time (in forward_packet,
        // handle_data link-table routing, handle_link_request) so they include the
        // outbound interface index needed for proof routing.
        match packet.flags.packet_type {
            PacketType::Announce => self.handle_announce(packet, interface_index, raw),
            PacketType::LinkRequest => {
                self.handle_link_request(packet, interface_index, raw, dedup_hash)
            }
            PacketType::Proof => self.handle_proof(packet, interface_index, dedup_hash),
            PacketType::Data => {
                self.handle_data(packet, interface_index, full_packet_hash, dedup_hash)
            }
        }
    }

    /// Send raw data on a specific interface
    pub fn send_on_interface(
        &mut self,
        interface_index: usize,
        data: &[u8],
    ) -> Result<(), TransportError> {
        self.pending_actions.push(Action::SendPacket {
            iface: InterfaceId(interface_index),
            data: data.to_vec(),
        });
        self.stats.packets_sent += 1;
        Ok(())
    }

    /// Send raw data on all online interfaces (emits Broadcast action)
    pub fn send_on_all_interfaces(&mut self, data: &[u8]) {
        // Cache outbound packet hash so echoes returning via redundant paths
        // are dropped by the dedup check in process_incoming() (line 688).
        // This matches Python Reticulum's Transport.py:1168-1169.
        let dedup_hash = truncated_packet_hash(data);
        let now = self.clock.now_ms();
        self.packet_cache.insert(dedup_hash, now);

        self.stats.packets_sent += 1;
        self.pending_actions.push(Action::Broadcast {
            data: data.to_vec(),
            exclude_iface: None,
        });
    }

    /// Send a packet to a destination via its known path
    pub fn send_to_destination(
        &mut self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
        data: &[u8],
    ) -> Result<(), TransportError> {
        let path = self
            .path_table
            .get(dest_hash)
            .ok_or(TransportError::NoPath)?;

        let interface_index = path.interface_index;

        // Only convert Type1 packets to Type2 for relay routing.
        // Type2 packets (e.g., link requests from initiate_with_path) are
        // already correctly formatted — pass them through unchanged.
        let is_type1 = data.len() >= 2 && (data[0] & 0x40) == 0;

        if path.needs_relay() && is_type1 {
            // Multi-hop: convert Type1 packet to Type2 with transport header.
            // Python equivalent: Transport.py outbound() lines 980-991.
            //
            // Wire format change:
            //   Type1: [flags][hops][dest_hash(16)][context][data...]
            //   Type2: [flags'][hops][next_hop(16)][dest_hash(16)][context][data...]
            //
            // flags' = header_type=Type2, transport_type=Transport, keep lower 4 bits
            let next_hop = path.next_hop.ok_or(TransportError::NoPath)?;

            let mut buf = alloc::vec![0u8; data.len() + TRUNCATED_HASHBYTES];

            // Rewrite flags: set Type2 header + Transport type, preserve lower 4 bits
            buf[0] = (1u8 << 6) | (1u8 << 4) | (data[0] & 0x0F);
            // Keep hops byte
            buf[1] = data[1];
            // Insert transport_id (next-hop relay identity hash)
            buf[2..2 + TRUNCATED_HASHBYTES].copy_from_slice(&next_hop);
            // Copy the rest: dest_hash + context + payload
            buf[2 + TRUNCATED_HASHBYTES..].copy_from_slice(&data[2..]);

            self.send_on_interface(interface_index, &buf)
        } else {
            // Direct neighbor or already Type2: send as-is
            self.send_on_interface(interface_index, data)
        }
    }

    // ─── Polling ────────────────────────────────────────────────────────

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
        self.clean_path_states();
        self.clean_announce_rate_table();
    }

    // ─── Events ─────────────────────────────────────────────────────────

    /// Drain pending events
    ///
    /// Returns an iterator over all events that occurred since the last drain.
    pub fn drain_events(&mut self) -> alloc::vec::Drain<'_, TransportEvent> {
        self.events.drain(..)
    }

    // ─── Actions (Sans-I/O) ─────────────────────────────────────────────

    /// Drain pending I/O actions
    ///
    /// Returns all actions that have accumulated since the last drain.
    /// The driver should execute these (send packets on interfaces).
    pub fn drain_actions(&mut self) -> Vec<Action> {
        core::mem::take(&mut self.pending_actions)
    }

    /// Compute the earliest deadline across all transport-layer timers
    ///
    /// Returns `None` if there are no pending deadlines. The returned
    /// value is an absolute timestamp in milliseconds.
    pub fn next_deadline(&self) -> Option<u64> {
        let now = self.clock.now_ms();
        let mut earliest: Option<u64> = None;

        let mut update = |deadline_ms: u64| {
            earliest = Some(match earliest {
                Some(e) => core::cmp::min(e, deadline_ms),
                None => deadline_ms,
            });
        };

        // Path expiry deadlines
        for entry in self.path_table.values() {
            update(entry.expires_ms);
        }

        // Receipt timeout deadlines
        for receipt in self.receipts.values() {
            if receipt.status == ReceiptStatus::Sent {
                update(receipt.sent_at_ms.saturating_add(receipt.timeout_ms));
            }
        }

        // Announce rebroadcast deadlines
        if self.config.enable_transport {
            for entry in self.announce_table.values() {
                if let Some(retransmit_at) = entry.retransmit_at_ms {
                    update(retransmit_at);
                }
            }
        }

        // Link table expiry deadlines
        for entry in self.link_table.values() {
            if entry.validated {
                update(entry.timestamp_ms.saturating_add(LINK_TIMEOUT_MS));
            } else {
                update(entry.proof_timeout_ms);
            }
        }

        // Packet cache cleanup and reverse table cleanup are background —
        // use a fixed interval rather than scanning every entry
        if !self.packet_cache.is_empty() || !self.reverse_table.is_empty() {
            let cleanup_interval = 60_000; // Check every 60s
            update(now.saturating_add(cleanup_interval));
        }

        earliest
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

    /// Read-only access to the path table (for sans-I/O deadline computation)
    pub(crate) fn path_table(&self) -> &BTreeMap<[u8; TRUNCATED_HASHBYTES], PathEntry> {
        &self.path_table
    }

    /// Insert a path entry (test-only, for setting up direct routing)
    #[cfg(test)]
    pub(crate) fn insert_path(&mut self, hash: [u8; TRUNCATED_HASHBYTES], entry: PathEntry) {
        self.path_table.insert(hash, entry);
    }

    /// Remove a path entry by destination hash
    pub(crate) fn remove_path(&mut self, hash: &[u8; TRUNCATED_HASHBYTES]) {
        self.path_table.remove(hash);
    }

    /// Remove link table entries referencing a specific interface
    pub(crate) fn remove_link_entries_for_interface(&mut self, iface_idx: usize) {
        let to_remove: Vec<_> = self
            .link_table
            .iter()
            .filter(|(_, e)| {
                e.next_hop_interface_index == iface_idx || e.received_interface_index == iface_idx
            })
            .map(|(k, _)| *k)
            .collect();
        for hash in to_remove {
            self.link_table.remove(&hash);
        }
    }

    /// Remove reverse table entries referencing a specific interface
    pub(crate) fn remove_reverse_entries_for_interface(&mut self, iface_idx: usize) {
        let to_remove: Vec<_> = self
            .reverse_table
            .iter()
            .filter(|(_, e)| {
                e.receiving_interface_index == iface_idx || e.outbound_interface_index == iface_idx
            })
            .map(|(k, _)| *k)
            .collect();
        for hash in to_remove {
            self.reverse_table.remove(&hash);
        }
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

        // Determine whether to update the path table (hop count comparison).
        // Matches Python Transport.py:1620-1681 logic:
        // - Equal or fewer hops: accept if emission timestamp is newer
        // - More hops: accept only if path is expired, emission is newer,
        //   or path is unresponsive with same emission (path recovery)
        let should_update = if let Some(existing) = self.path_table.get(&dest_hash) {
            let announce_emitted = emission_from_random_hash(&random_hash);
            let path_timebase = max_emission_from_blobs(&existing.random_blobs);
            if packet.hops <= existing.hops {
                // Equal or fewer hops: accept if emission is newer
                if announce_emitted > path_timebase {
                    self.mark_path_unknown_state(&dest_hash);
                    true
                } else {
                    false
                }
            } else {
                // More hops than current path
                if now >= existing.expires_ms {
                    // Path expired: accept with new random blob
                    self.mark_path_unknown_state(&dest_hash);
                    true
                } else if announce_emitted > path_timebase {
                    // Newer emission: accept
                    self.mark_path_unknown_state(&dest_hash);
                    true
                } else if announce_emitted == path_timebase && self.path_is_unresponsive(&dest_hash)
                {
                    // Same emission but path is unresponsive: accept worse-hop
                    // announce as alternative route (Python Transport.py:1677-1679).
                    // NOTE: do NOT call mark_path_unknown_state() here — state
                    // stays UNRESPONSIVE until a fresh announce resets it.
                    true
                } else {
                    false
                }
            }
        } else {
            true // New destination
        };

        if should_update {
            // Preserve existing random_blobs and add the new one
            let mut random_blobs = self
                .path_table
                .get(&dest_hash)
                .map(|p| p.random_blobs.clone())
                .unwrap_or_default();
            random_blobs.push(random_hash);

            // Cap random_blobs to prevent unbounded growth (matches Python MAX_RANDOM_BLOBS)
            if random_blobs.len() > MAX_RANDOM_BLOBS {
                let excess = random_blobs.len() - MAX_RANDOM_BLOBS;
                random_blobs.drain(..excess);
            }

            self.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: packet.hops,
                    expires_ms: now + (self.config.path_expiry_secs * 1000),
                    interface_index,
                    random_blobs,
                    next_hop: packet.transport_id,
                },
            );

            // Per-destination announce rate limiting (Python Transport.py:1692-1719)
            // Only blocks rebroadcast (announce_table insertion), path_table is already updated.
            // Skipped for PATH_RESPONSE context packets.
            let rate_blocked = if !is_path_response {
                self.check_announce_rate(&dest_hash, now)
            } else {
                false
            };

            // Determine if we should schedule rebroadcast
            let should_rebroadcast = self.config.enable_transport && !is_path_response;

            // Update announce table (skipped when rate-blocked to prevent rebroadcast)
            if !rate_blocked {
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
            }

            // Cache raw announce for path responses (when transport is enabled)
            if self.config.enable_transport {
                self.announce_cache.insert(dest_hash, raw.to_vec());
            }

            // Store identity from announce for proof validation
            if let Ok(identity) = announce.to_identity() {
                self.identity_table.insert(dest_hash, identity);
            }

            self.stats.announces_processed += 1;

            // Emit events — PathFound on every update (not just new paths)
            // so consumers always see current hop counts
            self.events.push(TransportEvent::PathFound {
                destination_hash: dest_hash,
                hops: packet.hops,
                interface_index,
            });

            self.events.push(TransportEvent::AnnounceReceived {
                announce,
                interface_index,
            });
        } else {
            // Path not updated, but still record the random_blob for replay detection
            if let Some(existing) = self.path_table.get_mut(&dest_hash) {
                existing.random_blobs.push(random_hash);
                if existing.random_blobs.len() > MAX_RANDOM_BLOBS {
                    let excess = existing.random_blobs.len() - MAX_RANDOM_BLOBS;
                    existing.random_blobs.drain(..excess);
                }
            }
        }

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

        // Check if we have this destination registered (NodeCore gates accepts_links)
        if self.local_destinations.contains(&dest_hash) {
            self.events.push(TransportEvent::PacketReceived {
                destination_hash: dest_hash,
                packet: Box::new(packet),
                interface_index,
                raw_hash: Some(packet_hash(raw)),
            });
            return Ok(());
        }

        // If we're a transport node, forward the link request and populate link table
        if self.config.enable_transport {
            if let Some(path) = self.path_table.get(&dest_hash) {
                let now = self.clock.now_ms();
                let link_id = Link::calculate_link_id(raw);
                let target_iface = path.interface_index;

                // Insert link table entry for bidirectional routing
                self.link_table.insert(
                    *link_id.as_bytes(),
                    LinkEntry {
                        timestamp_ms: now,
                        next_hop_interface_index: target_iface,
                        remaining_hops: path.hops,
                        received_interface_index: interface_index,
                        hops: packet.hops,
                        validated: false,
                        proof_timeout_ms: now
                            + ((packet.hops as u64 + path.hops as u64 + 2)
                                * crate::constants::DEFAULT_PER_HOP_TIMEOUT
                                * MS_PER_SECOND),
                        destination_hash: dest_hash,
                    },
                );

                // Populate reverse table at forwarding time

                self.reverse_table.insert(
                    dedup_hash,
                    ReverseEntry {
                        timestamp_ms: now,
                        receiving_interface_index: interface_index,
                        outbound_interface_index: target_iface,
                    },
                );

                // Forward: strip at final hop, keep Type2 otherwise.
                let mut forwarded = if !path.needs_relay() {
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
                    // Intermediate: Header Type 2 with next-hop transport identity
                    Packet {
                        flags: PacketFlags {
                            header_type: HeaderType::Type2,
                            transport_type: TransportType::Transport,
                            ..packet.flags
                        },
                        hops: packet.hops,
                        transport_id: path.next_hop,
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
        dedup_hash: [u8; TRUNCATED_HASHBYTES],
    ) -> Result<(), TransportError> {
        let dest_hash = packet.destination_hash;
        let proof_data = packet.data.as_slice();

        // Check if this is a proof for a receipt we're tracking.
        // Two proof formats (Python defaults to implicit):
        //   Explicit: [packet_hash (32)] + [signature (64)] = 96 bytes
        //   Implicit: [signature (64)] only — destination_hash IS the truncated_packet_hash
        if proof_data.len() == crate::constants::PROOF_DATA_SIZE {
            // Explicit proof: extract packet hash from proof data
            let mut proof_packet_hash = [0u8; 32];
            proof_packet_hash.copy_from_slice(&proof_data[..32]);
            let truncated = truncated_hash(&proof_packet_hash);

            if let Some(receipt) = self.receipts.get(&truncated) {
                let receipt_dest = *receipt.destination_hash.as_bytes();
                let expected = receipt.packet_hash;
                self.events.push(TransportEvent::ProofReceived {
                    packet_hash: truncated,
                    destination_hash: receipt_dest,
                    expected_packet_hash: expected,
                    proof_data: proof_data.to_vec(),
                });
                return Ok(());
            }
        } else if proof_data.len() == crate::constants::IMPLICIT_PROOF_SIZE {
            // Implicit proof: destination_hash of the proof packet IS the
            // truncated packet hash (see Python ProofDestination class).
            // Look up receipt by that hash, then reconstruct explicit format
            // so NodeCore can verify uniformly.
            if let Some(receipt) = self.receipts.get(&dest_hash) {
                let receipt_dest = *receipt.destination_hash.as_bytes();
                let expected = receipt.packet_hash;
                // Normalize to explicit format: packet_hash + signature
                let mut explicit = Vec::with_capacity(crate::constants::PROOF_DATA_SIZE);
                explicit.extend_from_slice(&expected);
                explicit.extend_from_slice(proof_data);
                self.events.push(TransportEvent::ProofReceived {
                    packet_hash: dest_hash,
                    destination_hash: receipt_dest,
                    expected_packet_hash: expected,
                    proof_data: explicit,
                });
                return Ok(());
            }
        }

        // Check if this is for a registered destination (legacy behavior)
        if self.local_destinations.contains(&dest_hash) {
            // Deferred cache insert for LRPROOF local delivery
            // (Python Transport.py:2072). Non-LRPROOF proofs for registered
            // destinations were already cached in process_incoming().
            self.packet_cache.insert(dedup_hash, self.clock.now_ms());
            self.events.push(TransportEvent::PacketReceived {
                destination_hash: dest_hash,
                packet: Box::new(packet),
                interface_index,
                raw_hash: None,
            });
            return Ok(());
        }

        // If we're a transport node, check link table for bidirectional routing
        if self.config.enable_transport {
            if let Some(link_entry) = self.link_table.get(&dest_hash).cloned() {
                // Determine direction with hop count validation
                let target_iface = if interface_index == link_entry.next_hop_interface_index {
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

                // Insert hash for non-LRPROOF proofs (Python Transport.py:1543).
                // LRPROOF hashes are intentionally NOT cached during link-table
                // forwarding (Python Transport.py:2016-2039).
                if packet.context != PacketContext::Lrproof {
                    self.packet_cache.insert(dedup_hash, self.clock.now_ms());
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

        // Deliver link-addressed proofs to local links.
        //
        // LRPROOF (link establishment proofs, context=Lrproof) need delivery
        // for non-transport nodes (Python Transport.py:2054-2073).
        // Data proofs (96 bytes, context=None) need delivery for channel ACK
        // processing (Python Link.py:1173 generates proof for every CHANNEL packet).
        //
        // If we reach this point:
        // - Not in Transport::receipts (receipt check at line 1404 failed)
        // - Not for a registered destination (check at line 1435 failed)
        // - Not forwarded by transport (enable_transport is false, or link_id
        //   not in our link_table — initiator's own links are never in link_table)
        //
        // The node layer routes Proof packets to process_link_packet(),
        // which distinguishes LRPROOF (link establishment) from data proofs
        // (PROOF_DATA_SIZE + context=None) and validates each cryptographically.
        if packet.flags.dest_type == DestinationType::Link {
            self.packet_cache.insert(dedup_hash, self.clock.now_ms());
            self.events.push(TransportEvent::PacketReceived {
                destination_hash: dest_hash,
                packet: Box::new(packet),
                interface_index,
                raw_hash: None,
            });
            return Ok(());
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
        if self.local_destinations.contains(&dest_hash) {
            self.events.push(TransportEvent::PacketReceived {
                destination_hash: dest_hash,
                packet: Box::new(packet),
                interface_index,
                raw_hash: Some(full_packet_hash),
            });

            // Always emit ProofRequested — NodeCore decides based on strategy
            self.events.push(TransportEvent::ProofRequested {
                packet_hash: full_packet_hash,
                destination_hash: dest_hash,
                interface_index,
            });

            return Ok(());
        }

        // If we're a transport node, try link table first, then path table
        if self.config.enable_transport {
            // Check link table for validated links
            if let Some(link_entry) = self.link_table.get(&dest_hash).cloned() {
                if link_entry.validated {
                    let target_iface = if interface_index == link_entry.next_hop_interface_index {
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
                    self.reverse_table.insert(
                        dedup_hash,
                        ReverseEntry {
                            timestamp_ms: now,
                            receiving_interface_index: interface_index,
                            outbound_interface_index: target_iface,
                        },
                    );

                    // Deferred cache insert: hash was skipped in process_incoming()
                    // because dest_hash is in link_table. Insert now that we've
                    // validated direction and will forward (Python Transport.py:1543).
                    self.packet_cache.insert(dedup_hash, now);

                    // Forward data via link table
                    let mut forwarded = packet;
                    return self.forward_on_interface(target_iface, &mut forwarded);
                }
            }

            // Non-link-addressed packets: forward via path table.
            // Link-addressed packets not in link_table are for our own local
            // links (link_ids never appear in path_table) — fall through to
            // the delivery code below.
            if packet.flags.dest_type != DestinationType::Link {
                self.forward_packet(packet, interface_index, dedup_hash)?;
                return Ok(());
            }
        }

        // Deliver link-addressed Data packets to local links (Python Transport.py:1969-1994).
        // On non-transport nodes, link_table routing is skipped entirely.
        // On transport nodes, relayed links are handled via link_table above;
        // only packets for our own local links reach this point.
        if packet.flags.dest_type == DestinationType::Link {
            self.packet_cache.insert(dedup_hash, self.clock.now_ms());
            self.events.push(TransportEvent::PacketReceived {
                destination_hash: dest_hash,
                packet: Box::new(packet),
                interface_index,
                raw_hash: Some(full_packet_hash),
            });
            return Ok(());
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

            self.reverse_table.insert(
                dedup_hash,
                ReverseEntry {
                    timestamp_ms: now,
                    receiving_interface_index: source_interface_index,
                    outbound_interface_index: target_iface,
                },
            );

            if path.needs_relay() {
                // Intermediate relay: keep Type2, replace transport_id with next hop
                packet.flags.header_type = HeaderType::Type2;
                packet.flags.transport_type = TransportType::Transport;
                packet.transport_id = path.next_hop; // guaranteed Some by needs_relay()
            } else {
                // Directly connected or no next_hop: strip to Type1
                packet.flags.header_type = HeaderType::Type1;
                packet.flags.transport_type = TransportType::Broadcast;
                packet.transport_id = None;
            }

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
    fn forward_on_all_except(&mut self, except_index: usize, packet: &mut Packet) {
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
        let name_hash = Destination::compute_name_hash("rnstransport", &["path", "request"]);
        truncated_hash(&name_hash)
    }

    /// Send data on all online interfaces except the one at `except_index` (emits Broadcast action)
    fn send_on_all_interfaces_except(&mut self, except_index: usize, data: &[u8]) {
        self.pending_actions.push(Action::Broadcast {
            data: data.to_vec(),
            exclude_iface: Some(InterfaceId(except_index)),
        });
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
        if self.local_destinations.contains(&requested_hash) {
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
            .filter(|(_, e)| now.saturating_sub(e.timestamp_ms) > REVERSE_TABLE_EXPIRY_MS)
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

    /// Check if an interface is considered online
    ///
    fn clean_link_table(&mut self, now: u64) {
        // Collect expired entries with their data for rediscovery logic
        let expired: Vec<([u8; TRUNCATED_HASHBYTES], LinkEntry)> = self
            .link_table
            .iter()
            .filter(|(_, e)| {
                if e.validated {
                    now.saturating_sub(e.timestamp_ms) > LINK_TIMEOUT_MS
                } else {
                    now > e.proof_timeout_ms
                }
            })
            .map(|(k, e)| (*k, e.clone()))
            .collect();

        for (link_hash, entry) in expired {
            self.link_table.remove(&link_hash);

            // Path rediscovery only for unvalidated links (proof never arrived).
            // Matches Python Transport.py:629-699.
            if entry.validated {
                continue;
            }

            let dest_hash = entry.destination_hash;

            // Check path request rate limiting
            let path_request_throttled = if let Some(&last_req) = self.path_requests.get(&dest_hash)
            {
                now.saturating_sub(last_req) < PATH_REQUEST_MIN_INTERVAL_MS
            } else {
                false
            };

            let mut should_request_path = false;

            if !self.path_table.contains_key(&dest_hash) {
                // Sub-case 1: Path missing — unconditionally try to rediscover
                // (no throttle check). Python Transport.py:644.
                should_request_path = true;
            } else if !path_request_throttled
                && self
                    .path_table
                    .get(&dest_hash)
                    .is_some_and(|p| p.is_direct())
            {
                // Sub-case 2: Destination directly connected — may have roamed.
                // Python checks hops_to(dest) == 1 after increment; Rust
                // equivalent: is_direct() (hops == 0). Python Transport.py:660-676.
                should_request_path = true;
                if self.config.enable_transport {
                    self.mark_path_unresponsive(&dest_hash);
                }
            } else if !path_request_throttled && entry.hops == 0 {
                // Sub-case 3: Initiator directly connected (0 wire hops away).
                // Python checks lr_taken_hops == 1 after increment; Rust
                // equivalent: entry.hops == 0. Python Transport.py:682-689.
                should_request_path = true;
                if self.config.enable_transport {
                    self.mark_path_unresponsive(&dest_hash);
                }
            }

            if should_request_path {
                // For non-transport nodes, force-expire the current path so
                // higher-hop-count announces can be accepted.
                // Python Transport.py:695-699.
                if !self.config.enable_transport {
                    self.expire_path(&dest_hash);
                }

                // Request path directly — deterministic tag from clock + dest_hash
                // ensures uniqueness per (destination, time) for dedup.
                let mut tag = [0u8; TRUNCATED_HASHBYTES];
                let now_bytes = now.to_be_bytes();
                tag[..8].copy_from_slice(&now_bytes);
                tag[8..16].copy_from_slice(&dest_hash[..8]);
                let _ = self.request_path(&dest_hash, None, &tag);
            }
        }
    }

    /// Remove path_states entries for destinations no longer in path_table.
    /// Matches Python Transport.py:601-604, 813-814.
    fn clean_path_states(&mut self) {
        let stale: Vec<[u8; TRUNCATED_HASHBYTES]> = self
            .path_states
            .keys()
            .filter(|h| !self.path_table.contains_key(*h))
            .copied()
            .collect();
        for hash in stale {
            self.path_states.remove(&hash);
        }
    }

    /// Remove announce_rate_table entries for destinations no longer in path_table.
    fn clean_announce_rate_table(&mut self) {
        self.announce_rate_table
            .retain(|h, _| self.path_table.contains_key(h));
    }

    /// Check announce rate for a destination, returning true if rebroadcast should be blocked.
    ///
    /// Matches Python Transport.py:1692-1719. Only blocks rebroadcast (announce_table insertion),
    /// NOT path_table updates. Skipped for PATH_RESPONSE context and when rate target is None.
    fn check_announce_rate(&mut self, dest_hash: &[u8; TRUNCATED_HASHBYTES], now: u64) -> bool {
        let rate_target = match self.config.announce_rate_target_ms {
            Some(t) => t,
            None => return false, // Disabled
        };

        if let Some(entry) = self.announce_rate_table.get_mut(dest_hash) {
            // Currently blocked?
            if now <= entry.blocked_until_ms {
                return true;
            }

            // Check rate
            let current_rate = now.saturating_sub(entry.last_ms);
            if current_rate < rate_target {
                entry.rate_violations = entry.rate_violations.saturating_add(1);
            } else {
                entry.rate_violations = entry.rate_violations.saturating_sub(1);
            }

            if entry.rate_violations > self.config.announce_rate_grace {
                entry.blocked_until_ms =
                    entry.last_ms + rate_target + self.config.announce_rate_penalty_ms;
                return true;
            }

            // Good — update last timestamp
            entry.last_ms = now;
            false
        } else {
            // First time seeing this destination — create entry, not blocked
            self.announce_rate_table.insert(
                *dest_hash,
                AnnounceRateEntry {
                    last_ms: now,
                    rate_violations: 0,
                    blocked_until_ms: 0,
                },
            );
            false
        }
    }

    /// Get the number of entries in the announce rate table (for testing/stats)
    pub fn announce_rate_table_count(&self) -> usize {
        self.announce_rate_table.len()
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

    // ─── Sans-I/O Type Tests ────────────────────────────────────────────

    mod sans_io_types {
        use super::*;
        extern crate alloc;
        use alloc::vec;

        #[test]
        fn test_interface_id_basics() {
            let id = InterfaceId(0);
            let id2 = InterfaceId(0);
            let id3 = InterfaceId(1);

            // PartialEq, Eq
            assert_eq!(id, id2);
            assert_ne!(id, id3);

            // Ord
            assert!(id < id3);

            // Copy
            let copied = id;
            assert_eq!(copied, id);

            // Debug
            extern crate std;
            let debug_str = std::format!("{:?}", id);
            assert!(debug_str.contains("InterfaceId"));

            // Display
            let display_str = std::format!("{}", id);
            assert_eq!(display_str, "iface:0");
        }

        #[test]
        fn test_interface_id_hash() {
            // Verify InterfaceId can be used as BTreeMap key
            let mut map = alloc::collections::BTreeMap::new();
            map.insert(InterfaceId(0), "first");
            map.insert(InterfaceId(1), "second");
            assert_eq!(map.get(&InterfaceId(0)), Some(&"first"));
            assert_eq!(map.get(&InterfaceId(1)), Some(&"second"));
            assert_eq!(map.get(&InterfaceId(2)), None);
        }

        #[test]
        fn test_action_send_packet() {
            let action = Action::SendPacket {
                iface: InterfaceId(3),
                data: vec![1, 2, 3],
            };

            // Clone
            let cloned = action.clone();
            assert_eq!(action, cloned);

            // Debug
            extern crate std;
            let debug = std::format!("{:?}", action);
            assert!(debug.contains("SendPacket"));
            assert!(debug.contains("InterfaceId(3)"));
        }

        #[test]
        fn test_action_broadcast() {
            let action_no_exclude = Action::Broadcast {
                data: vec![10, 20],
                exclude_iface: None,
            };
            let action_with_exclude = Action::Broadcast {
                data: vec![10, 20],
                exclude_iface: Some(InterfaceId(2)),
            };

            assert_ne!(action_no_exclude, action_with_exclude);

            // Same data but different exclude
            let action_no_exclude2 = Action::Broadcast {
                data: vec![10, 20],
                exclude_iface: None,
            };
            assert_eq!(action_no_exclude, action_no_exclude2);
        }

        #[test]
        fn test_action_variants_not_equal() {
            let send = Action::SendPacket {
                iface: InterfaceId(0),
                data: vec![1],
            };
            let broadcast = Action::Broadcast {
                data: vec![1],
                exclude_iface: None,
            };
            assert_ne!(send, broadcast);
        }

        #[test]
        fn test_tick_output_empty() {
            let output = TickOutput::empty();
            assert!(output.is_empty());
            assert!(output.actions.is_empty());
            assert!(output.events.is_empty());
        }

        #[test]
        fn test_tick_output_with_actions() {
            let output = TickOutput {
                actions: vec![Action::SendPacket {
                    iface: InterfaceId(0),
                    data: vec![42],
                }],
                events: Vec::new(),
            };
            assert!(!output.is_empty());
            assert_eq!(output.actions.len(), 1);
        }

        #[test]
        fn test_tick_output_debug() {
            let output = TickOutput {
                actions: vec![
                    Action::SendPacket {
                        iface: InterfaceId(0),
                        data: vec![1],
                    },
                    Action::Broadcast {
                        data: vec![2],
                        exclude_iface: None,
                    },
                ],
                events: Vec::new(),
            };

            extern crate std;
            let debug = std::format!("{:?}", output);
            assert!(debug.contains("actions: 2"));
            assert!(debug.contains("events: 0"));
        }
    }

    mod transport_tests {
        use super::*;
        use crate::test_utils::{test_transport, MockClock, MockInterface, TEST_TIME_MS};
        use crate::traits::NoStorage;
        use rand_core::OsRng;

        extern crate std;

        #[test]
        fn test_transport_creation() {
            let transport = test_transport();
            assert_eq!(transport.interface_count(), 0);
            assert_eq!(transport.path_count(), 0);
            assert_eq!(transport.pending_events(), 0);
            assert_eq!(transport.pending_action_count(), 0);
        }

        #[test]
        fn test_drain_actions_initially_empty() {
            let mut transport = test_transport();
            let actions = transport.drain_actions();
            assert!(actions.is_empty());
            assert_eq!(transport.pending_action_count(), 0);
        }

        #[test]
        fn test_register_interface() {
            let mut transport = test_transport();
            let idx = transport.register_interface(Box::new(MockInterface::new("test", 1)));
            assert_eq!(idx, 0);
            assert_eq!(transport.interface_count(), 1);

            let idx2 = transport.register_interface(Box::new(MockInterface::new("test2", 2)));
            assert_eq!(idx2, 1);
            assert_eq!(transport.interface_count(), 2);
        }

        #[test]
        fn test_unregister_interface() {
            let mut transport = test_transport();
            let idx = transport.register_interface(Box::new(MockInterface::new("test", 1)));
            assert_eq!(transport.interface_count(), 1);

            transport.unregister_interface(idx);
            assert_eq!(transport.interface_count(), 0);
        }

        #[test]
        fn test_register_destination() {
            let mut transport = test_transport();
            let hash = [0x42; TRUNCATED_HASHBYTES];

            transport.register_destination(hash);
            assert!(transport.has_destination(&hash));

            transport.unregister_destination(&hash);
            assert!(!transport.has_destination(&hash));
        }

        #[test]
        fn test_path_management() {
            let mut transport = test_transport();
            let hash = [0x42; TRUNCATED_HASHBYTES];

            assert!(!transport.has_path(&hash));
            assert_eq!(transport.hops_to(&hash), None);

            // Manually insert a path for testing
            let now = transport.clock.now_ms();
            transport.path_table.insert(
                hash,
                PathEntry {
                    hops: 3,
                    expires_ms: now + 3_600_000,
                    interface_index: 0,
                    random_blobs: Vec::new(),
                    next_hop: None,
                },
            );

            assert!(transport.has_path(&hash));
            assert_eq!(transport.hops_to(&hash), Some(3));
            assert_eq!(transport.path_count(), 1);
        }

        #[test]
        fn test_path_expiry() {
            let mut transport = test_transport();
            let hash = [0x42; TRUNCATED_HASHBYTES];

            let now = transport.clock.now_ms();
            transport.path_table.insert(
                hash,
                PathEntry {
                    hops: 1,
                    expires_ms: now + 1000, // Expires in 1 second
                    interface_index: 0,
                    random_blobs: Vec::new(),
                    next_hop: None,
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
            let mut transport = test_transport();
            let idx = transport.register_interface(Box::new(MockInterface::new("test", 1)));

            let data = b"test packet";
            transport.send_on_interface(idx, data).unwrap();

            assert_eq!(transport.stats().packets_sent, 1);
        }

        #[test]
        fn test_send_on_unregistered_interface_emits_action() {
            let mut transport = test_transport();
            // Sending on an unregistered interface still emits an Action
            // (the driver is responsible for dispatching to real interfaces)
            let result = transport.send_on_interface(99, b"test");
            assert!(result.is_ok());
            assert_eq!(transport.pending_action_count(), 1);
            let actions = transport.drain_actions();
            assert_eq!(
                actions[0],
                Action::SendPacket {
                    iface: InterfaceId(99),
                    data: b"test".to_vec()
                }
            );
        }

        #[test]
        fn test_packet_deduplication() {
            let mut transport = test_transport();
            transport.register_interface(Box::new(MockInterface::new("test", 1)));
            let hash = [0x42; TRUNCATED_HASHBYTES];
            transport.register_destination(hash);

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

            // First time: should process (PacketReceived + ProofRequested)
            transport.process_incoming(0, raw).unwrap();
            assert_eq!(transport.stats().packets_received, 1);
            assert_eq!(transport.pending_events(), 2);

            // Second time: should be deduplicated
            transport.drain_events();
            transport.process_incoming(0, raw).unwrap();
            assert_eq!(transport.stats().packets_received, 2);
            assert_eq!(transport.stats().packets_dropped, 1);
            assert_eq!(transport.pending_events(), 0);
        }

        #[test]
        fn test_data_packet_delivery() {
            let mut transport = test_transport();
            transport.register_interface(Box::new(MockInterface::new("test", 1)));
            let hash = [0x42; TRUNCATED_HASHBYTES];
            transport.register_destination(hash);

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
            assert_eq!(events.len(), 2); // PacketReceived + ProofRequested
            match &events[0] {
                TransportEvent::PacketReceived {
                    destination_hash,
                    packet,
                    interface_index,
                    ..
                } => {
                    assert_eq!(destination_hash, &hash);
                    assert_eq!(packet.data.as_slice(), b"hello");
                    assert_eq!(*interface_index, 0);
                }
                _ => panic!("Expected PacketReceived event"),
            }
            assert!(
                matches!(&events[1], TransportEvent::ProofRequested { .. }),
                "Expected ProofRequested event"
            );
        }

        #[test]
        fn test_unregistered_destination_dropped() {
            let mut transport = test_transport();
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
            let mut transport = test_transport();
            transport.register_interface(Box::new(MockInterface::new("test", 1)));

            let hash = [0x42; TRUNCATED_HASHBYTES];
            transport.register_destination(hash);

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

            // First delivery (PacketReceived + ProofRequested)
            transport.process_incoming(0, &buf[..len]).unwrap();
            assert_eq!(transport.pending_events(), 2);
            transport.drain_events();

            // Second: deduplicated
            transport.process_incoming(0, &buf[..len]).unwrap();
            assert_eq!(transport.pending_events(), 0);

            // Advance past cache expiry and poll
            transport
                .clock
                .advance(transport.config.packet_cache_expiry_ms + 1);
            transport.poll();

            // Now the packet should be accepted again (PacketReceived + ProofRequested)
            transport.process_incoming(0, &buf[..len]).unwrap();
            assert_eq!(transport.pending_events(), 2);
        }

        #[test]
        fn test_announce_processing() {
            use crate::destination::{Destination, DestinationType, Direction};
            use crate::packet::{
                HeaderType, PacketContext, PacketData, PacketFlags, TransportType,
            };

            let mut transport = test_transport();
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

        fn make_announce_raw(
            hops: u8,
            context: crate::packet::PacketContext,
        ) -> (Vec<u8>, [u8; TRUNCATED_HASHBYTES]) {
            use crate::destination::{Destination, DestinationType, Direction};
            use crate::packet::{HeaderType, PacketData, PacketFlags, TransportType};

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
            let clock = MockClock::new(TEST_TIME_MS);
            let identity = Identity::generate(&mut OsRng);
            let config = TransportConfig {
                enable_transport: true,
                ..TransportConfig::default()
            };
            Transport::new(config, clock, NoStorage, identity)
        }

        /// Check if actions contain a path request broadcast for the given destination.
        /// Path request packet (Type1): flags(1) + hops(1) + path_request_hash(16) + context(1) = 19 header bytes
        /// Payload: target_dest_hash(16) + transport_id(16) + tag(16) = 48 bytes
        fn has_path_request_broadcast(
            actions: &[Action],
            dest_hash: &[u8; TRUNCATED_HASHBYTES],
        ) -> bool {
            actions.iter().any(|a| match a {
                Action::Broadcast { data, .. } => {
                    data.len() >= 19 + TRUNCATED_HASHBYTES
                        && data[19..19 + TRUNCATED_HASHBYTES] == *dest_hash
                }
                _ => false,
            })
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
            let mut transport = test_transport(); // transport disabled by default
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
            assert!(transport.announce_table.contains_key(&dest_hash));
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
                !transport.announce_table.contains_key(&dest_hash),
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
            let _ = transport.drain_actions(); // clear initial actions

            // Trigger rebroadcast
            transport.clock.advance(10_000);
            transport.poll();

            assert!(transport.stats().packets_forwarded > 0);

            // Parse the rebroadcasted packet and verify hops was incremented
            let actions = transport.drain_actions();
            let broadcast_data = actions
                .iter()
                .find_map(|a| match a {
                    Action::Broadcast { data, .. } => Some(data.as_slice()),
                    _ => None,
                })
                .expect("Should have a Broadcast action for the rebroadcast");
            let rebroadcasted = Packet::unpack(broadcast_data).unwrap();
            assert_eq!(
                rebroadcasted.hops,
                original_hops + 1,
                "Rebroadcasted announce should have hops incremented by 1"
            );
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

            assert!(!transport.announce_table.contains_key(&dest_hash));
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
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));
            let now = transport.clock.now_ms();

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 1,
                    remaining_hops: 2,
                    received_interface_index: 0,
                    hops: 1,
                    validated: true,
                    proof_timeout_ms: now + 30_000,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
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
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));
            let now = transport.clock.now_ms();

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            let proof_timeout = now + 10_000;
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 1,
                    remaining_hops: 2,
                    received_interface_index: 0,
                    hops: 1,
                    validated: false,
                    proof_timeout_ms: proof_timeout,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
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
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));
            let now = transport.clock.now_ms();

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 1,
                    remaining_hops: 2,
                    received_interface_index: 0,
                    hops: 1,
                    validated: true,
                    proof_timeout_ms: now + 30_000,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
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
            transport.register_destination(dest_hash);

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
            assert!(
                entry.is_some(),
                "Should have announce table entry for path response"
            );
            let entry = entry.unwrap();
            assert!(
                entry.block_rebroadcasts,
                "Should be marked as block_rebroadcasts"
            );
            assert!(
                entry.retransmit_at_ms.is_some(),
                "Should have a retransmit scheduled"
            );
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
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let (raw, _dest_hash) = make_announce_raw(2, PacketContext::None);
            transport.process_incoming(0, &raw).unwrap();
            assert_eq!(transport.stats().announces_processed, 1);

            // Bypass packet cache and rate limit
            transport.packet_cache.clear();
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);

            // Replay exact same announce (same random_hash)
            transport.process_incoming(0, &raw).unwrap();
            assert_eq!(
                transport.stats().announces_processed,
                1,
                "Replayed announce should be dropped"
            );
        }

        #[test]
        fn test_different_random_blob_accepted() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

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
                transport.stats().announces_processed,
                2,
                "Different destination should be accepted"
            );
        }

        // ─── Stage 8: LRPROOF validation ────────────────────────────────

        #[test]
        fn test_identity_stored_from_announce() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

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
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();

            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 1,
                    remaining_hops: 2,
                    received_interface_index: 0,
                    hops: 1,
                    validated: false,
                    proof_timeout_ms: now + 30_000,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
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
                transport.stats().packets_forwarded,
                0,
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
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_hash = [0x42; TRUNCATED_HASHBYTES];
            transport.register_destination(dest_hash);

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
                events
                    .iter()
                    .any(|e| matches!(e, TransportEvent::PathRequestReceived { .. })),
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
        fn test_link_table_cleaned_when_interface_down() {
            let mut transport = make_transport_enabled();

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 1,
                    remaining_hops: 2,
                    received_interface_index: 0,
                    hops: 1,
                    validated: true,
                    proof_timeout_ms: now + 30_000,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
                },
            );

            // Notify that interface 1 is down (sans-I/O: driver calls this)
            transport.remove_link_entries_for_interface(1);

            assert!(
                !transport.link_table.contains_key(&link_id),
                "Link entry should be removed when interface goes down"
            );
        }

        #[test]
        fn test_reverse_table_cleaned_when_interface_down() {
            let mut transport = make_transport_enabled();

            let hash = [0xAA; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.reverse_table.insert(
                hash,
                ReverseEntry {
                    timestamp_ms: now,
                    receiving_interface_index: 0,
                    outbound_interface_index: 1,
                },
            );

            // Notify that interface 1 is down (sans-I/O: driver calls this)
            transport.remove_reverse_entries_for_interface(1);

            assert!(
                !transport.reverse_table.contains_key(&hash),
                "Reverse entry should be removed when interface goes down"
            );
        }

        // ─── Stage 5: Strip transport header at final hop ─────────────

        #[test]
        fn test_link_request_stripped_to_type1_at_final_hop() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            // Path with hops=1 (destination directly connected to if1)
            let dest_hash = [0xBB; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 1,
                    expires_ms: now + 100_000,
                    interface_index: 1,
                    random_blobs: Vec::new(),
                    next_hop: None,
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
            let actions = transport.drain_actions();
            let forwarded_raw = actions
                .iter()
                .find_map(|a| match a {
                    Action::SendPacket { iface, data } if iface.0 == 1 => Some(data.as_slice()),
                    _ => None,
                })
                .expect("Should have a SendPacket action for iface 1");
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
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            // Path with hops=3 (destination is multiple hops away)
            let dest_hash = [0xBB; TRUNCATED_HASHBYTES];
            let next_hop_hash = [0xCC; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 3,
                    expires_ms: now + 100_000,
                    interface_index: 1,
                    random_blobs: Vec::new(),
                    next_hop: Some(next_hop_hash),
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
            let actions = transport.drain_actions();
            let forwarded_raw = actions
                .iter()
                .find_map(|a| match a {
                    Action::SendPacket { iface, data } if iface.0 == 1 => Some(data.as_slice()),
                    _ => None,
                })
                .expect("Should have a SendPacket action for iface 1");
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
            assert_eq!(
                forwarded_pkt.transport_id.unwrap(),
                next_hop_hash,
                "Transport ID should be set to the next-hop relay's identity hash"
            );
        }

        // ─── Forward payload integrity: Type2 -> Type1 conversion ────────

        #[test]
        fn test_link_request_forward_type2_to_type1_payload_intact() {
            // Setup: transport with 2 MockInterfaces; inspect via drain_actions()
            let mut transport = make_transport_enabled();

            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            // Create a path entry for dest_hash with hops=0 (directly connected
            // to if1), meaning the relay is the final hop.
            let dest_hash = [0xDD; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 0,
                    expires_ms: now + 100_000,
                    interface_index: 1,
                    random_blobs: Vec::new(),
                    next_hop: None,
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
                let actions = transport.drain_actions();
                let forwarded_raw = actions
                    .iter()
                    .find_map(|a| match a {
                        Action::SendPacket { iface, data } if iface.0 == 1 => Some(data.as_slice()),
                        _ => None,
                    })
                    .expect("Should have a SendPacket action for iface 1");
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
                assert_eq!(forwarded_pkt.hops, 1, "Hops should be incremented by 1");

                // Verify data payload is intact (the 64-byte link request data)
                assert_eq!(
                    forwarded_pkt.data.as_slice(),
                    &original_request_data_a[..],
                    "Link request payload must be preserved exactly"
                );

                // Nothing should be sent on if0 (the receiving interface)
                assert!(
                    !actions.iter().any(|a| matches!(
                        a,
                        Action::SendPacket { iface, .. } if iface.0 == 0
                    )),
                    "No packets should be sent back on the receiving interface"
                );
            }

            // ── Part B: Type2 link request arriving on if0, forwarded to if1 ──

            // Clear previous actions and packet cache
            transport.drain_actions();
            transport.packet_cache.clear(); // allow processing

            // Build a Type2 link request with transport_id = our own identity hash
            // (in the real protocol, transport_id identifies the next relay node)
            let own_transport_id = *transport.identity.hash();
            let mut link_b = Link::new_outgoing(dest_hash.into(), &mut OsRng);
            let original_request_data_b = link_b.create_link_request();
            let raw_type2 = link_b.build_link_request_packet_with_transport(
                Some(own_transport_id),
                1, // hops_to_dest
            );

            // Verify the original is Type2
            let original_pkt_b = Packet::unpack(&raw_type2).unwrap();
            assert_eq!(original_pkt_b.flags.header_type, HeaderType::Type2);
            assert_eq!(original_pkt_b.flags.packet_type, PacketType::LinkRequest);
            assert_eq!(
                original_pkt_b.transport_id,
                Some(own_transport_id),
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
                let actions = transport.drain_actions();
                let forwarded_raw = actions
                    .iter()
                    .find_map(|a| match a {
                        Action::SendPacket { iface, data } if iface.0 == 1 => Some(data.as_slice()),
                        _ => None,
                    })
                    .expect("Should have a SendPacket action for iface 1");
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
                assert_eq!(forwarded_pkt.hops, 1, "Hops should be original (0) + 1 = 1");

                // Verify data payload is intact (the 64-byte link request data)
                assert_eq!(
                    forwarded_pkt.data.as_slice(),
                    &original_request_data_b[..],
                    "Link request payload must be preserved exactly after Type2->Type1 conversion"
                );
            }

            // ── Part C: Type2 arriving, multi-hop (hops=3), stays Type2 ──

            transport.drain_actions();
            transport.packet_cache.clear();

            // Update path to multi-hop with a next-hop relay identity
            let next_hop_relay = [0xEE; TRUNCATED_HASHBYTES];
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 3,
                    expires_ms: now + 100_000,
                    interface_index: 1,
                    random_blobs: Vec::new(),
                    next_hop: Some(next_hop_relay),
                },
            );

            let mut link_c = Link::new_outgoing(dest_hash.into(), &mut OsRng);
            let original_request_data_c = link_c.create_link_request();
            let raw_type2_multi =
                link_c.build_link_request_packet_with_transport(Some(own_transport_id), 3);

            let forwarded_before = transport.stats().packets_forwarded;
            transport.process_incoming(0, &raw_type2_multi).unwrap();

            assert!(
                transport.stats().packets_forwarded > forwarded_before,
                "Multi-hop Type2 link request should be forwarded"
            );

            {
                let actions = transport.drain_actions();
                let forwarded_raw = actions
                    .iter()
                    .find_map(|a| match a {
                        Action::SendPacket { iface, data } if iface.0 == 1 => Some(data.as_slice()),
                        _ => None,
                    })
                    .expect("Should have a SendPacket action for iface 1");
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
                // transport_id should be the next-hop relay's identity hash
                assert_eq!(
                    forwarded_pkt.transport_id.unwrap(),
                    next_hop_relay,
                    "Transport ID should be set to the next-hop relay's identity hash"
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
            for entry in transport.link_table.values() {
                assert_eq!(
                    entry.next_hop_interface_index, 1,
                    "Link entry should route toward if1"
                );
                assert_eq!(
                    entry.received_interface_index, 0,
                    "Link entry should record if0 as received interface"
                );
            }
        }

        // ─── Stage 4: Hop count validation ──────────────────────────────

        /// Build a data packet with the given destination hash and hop count
        fn build_link_data_packet(dest_hash: [u8; TRUNCATED_HASHBYTES], hops: u8) -> Packet {
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
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 1,
                    remaining_hops: 3,
                    received_interface_index: 0,
                    hops: 2,
                    validated: true,
                    proof_timeout_ms: now + 30_000,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
                },
            );

            // Data from dest side (if1): hops should match remaining_hops=3
            let pkt = build_link_data_packet(link_id, 99); // wrong hops
            let mut buf = [0u8; 500];
            let len = pkt.pack(&mut buf).unwrap();
            transport.process_incoming(1, &buf[..len]).unwrap();
            assert_eq!(
                transport.stats().packets_forwarded,
                0,
                "Wrong hops should be dropped"
            );
        }

        #[test]
        fn test_link_data_correct_hops_forwarded() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 1,
                    remaining_hops: 3,
                    received_interface_index: 0,
                    hops: 2,
                    validated: true,
                    proof_timeout_ms: now + 30_000,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
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

            // Parse forwarded packet and verify hops incremented, header type preserved
            let actions = transport.drain_actions();
            let forwarded_raw = actions
                .iter()
                .find_map(|a| match a {
                    Action::SendPacket { data, .. } => Some(data.as_slice()),
                    _ => None,
                })
                .expect("Should have a SendPacket action");
            let forwarded = Packet::unpack(forwarded_raw).unwrap();
            assert_eq!(forwarded.hops, 4, "Forwarded hops should be 3+1=4");
            assert_eq!(
                forwarded.flags.header_type,
                HeaderType::Type1,
                "Link-routed data should stay Type1"
            );
        }

        #[test]
        fn test_link_data_correct_hops_from_initiator() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 1,
                    remaining_hops: 3,
                    received_interface_index: 0,
                    hops: 2,
                    validated: true,
                    proof_timeout_ms: now + 30_000,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
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

            // Parse forwarded packet and verify hops incremented
            let actions = transport.drain_actions();
            let forwarded_raw = actions
                .iter()
                .find_map(|a| match a {
                    Action::SendPacket { data, .. } => Some(data.as_slice()),
                    _ => None,
                })
                .expect("Should have a SendPacket action");
            let forwarded = Packet::unpack(forwarded_raw).unwrap();
            assert_eq!(forwarded.hops, 3, "Forwarded hops should be 2+1=3");
        }

        // ─── Stage 3: Reverse table proof routing ──────────────────────

        #[test]
        fn test_regular_proof_routed_via_reverse_table() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            // Simulate a data packet that was forwarded from if0 to if1,
            // creating a reverse table entry keyed by truncated_packet_hash
            let packet_hash = [0xAA; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.reverse_table.insert(
                packet_hash,
                ReverseEntry {
                    timestamp_ms: now,
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
                data: PacketData::Owned(alloc::vec![0x55; crate::constants::PROOF_DATA_SIZE]),
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

            // Parse forwarded proof and verify target interface, hops, and packet type
            let actions = transport.drain_actions();
            let (target_iface, forwarded_raw) = actions
                .iter()
                .find_map(|a| match a {
                    Action::SendPacket { iface, data } => Some((*iface, data.as_slice())),
                    _ => None,
                })
                .expect("Should have a SendPacket action for routed proof");
            assert_eq!(
                target_iface,
                InterfaceId(0),
                "Proof should be routed back to receiving interface (if0)"
            );
            let forwarded = Packet::unpack(forwarded_raw).unwrap();
            assert_eq!(forwarded.hops, 1, "Forwarded proof hops should be 0+1=1");
            assert_eq!(
                forwarded.flags.packet_type,
                PacketType::Proof,
                "Forwarded packet should still be a Proof"
            );
        }

        // ─── Bug #12: Path-table data forwarding header promotion ────────

        #[test]
        fn test_path_table_forward_header2_replaces_transport_id() {
            // A HEADER_2 data packet forwarded via path table should have its
            // transport_id replaced with next_hop from the path entry (remaining > 1).
            use crate::destination::DestinationType;
            use crate::packet::{HeaderType, PacketData, PacketFlags, TransportType};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let dest_hash = [0xCC; TRUNCATED_HASHBYTES];
            let next_hop_hash = [0xDD; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();

            // Path entry with hops=2 (multi-hop: not the final relay)
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 2,
                    expires_ms: now + 100_000,
                    interface_index: 1,
                    random_blobs: Vec::new(),
                    next_hop: Some(next_hop_hash),
                },
            );

            // Build a HEADER_2 data packet addressed to dest_hash, with our own
            // transport_id (as if we are the current relay in the chain).
            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type2,
                    context_flag: false,
                    transport_type: TransportType::Transport,
                    dest_type: DestinationType::Single,
                    packet_type: PacketType::Data,
                },
                hops: 1,
                transport_id: Some(*transport.identity.hash()),
                destination_hash: dest_hash,
                context: PacketContext::None,
                data: PacketData::Owned(b"multi-hop payload".to_vec()),
            };

            let mut buf = [0u8; crate::constants::MTU];
            let len = packet.pack(&mut buf).unwrap();
            transport.process_incoming(0, &buf[..len]).unwrap();

            assert!(
                transport.stats().packets_forwarded > 0,
                "Packet should be forwarded via path table"
            );

            let actions = transport.drain_actions();
            let forwarded_raw = actions
                .iter()
                .find_map(|a| match a {
                    Action::SendPacket { iface, data } if iface.0 == 1 => Some(data.as_slice()),
                    _ => None,
                })
                .expect("Should have a SendPacket action for iface 1");
            let forwarded = Packet::unpack(forwarded_raw).unwrap();

            // Hops should be incremented
            assert_eq!(forwarded.hops, 2, "Forwarded hops should be 1+1=2");
            // Destination hash should be preserved
            assert_eq!(
                forwarded.destination_hash, dest_hash,
                "Destination hash must be preserved"
            );
            // Should still be Type2 (multi-hop, remaining > 1)
            assert_eq!(
                forwarded.flags.header_type,
                HeaderType::Type2,
                "Multi-hop forward should stay Type2"
            );
            // transport_id should be replaced with next_hop (BUG: currently stays as own hash)
            assert_eq!(
                forwarded.transport_id,
                Some(next_hop_hash),
                "transport_id should be replaced with next_hop from path entry"
            );
            // Data payload should be intact
            assert_eq!(
                forwarded.data.as_slice(),
                b"multi-hop payload",
                "Data payload must be preserved"
            );
        }

        #[test]
        fn test_path_table_forward_header2_strips_to_type1_at_final_hop() {
            // When a HEADER_2 data packet reaches the final relay (path hops == 0,
            // destination directly connected), it should be stripped to HEADER_1
            // with no transport_id.
            //
            // Rust stores raw wire hops (no increment on receipt), so hops == 0
            // means directly connected — the Python equivalent of hops == 1
            // (Python increments on receipt, Transport.py:1319).
            use crate::destination::DestinationType;
            use crate::packet::{HeaderType, PacketData, PacketFlags, TransportType};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let dest_hash = [0xCC; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();

            // Path entry with hops=0 (destination is directly connected to us)
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 0,
                    expires_ms: now + 100_000,
                    interface_index: 1,
                    random_blobs: Vec::new(),
                    next_hop: None,
                },
            );

            // Build a HEADER_2 data packet addressed to dest_hash
            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type2,
                    context_flag: false,
                    transport_type: TransportType::Transport,
                    dest_type: DestinationType::Single,
                    packet_type: PacketType::Data,
                },
                hops: 1,
                transport_id: Some(*transport.identity.hash()),
                destination_hash: dest_hash,
                context: PacketContext::None,
                data: PacketData::Owned(b"final-hop payload".to_vec()),
            };

            let mut buf = [0u8; crate::constants::MTU];
            let len = packet.pack(&mut buf).unwrap();
            transport.process_incoming(0, &buf[..len]).unwrap();

            assert!(
                transport.stats().packets_forwarded > 0,
                "Packet should be forwarded via path table"
            );

            let actions = transport.drain_actions();
            let forwarded_raw = actions
                .iter()
                .find_map(|a| match a {
                    Action::SendPacket { iface, data } if iface.0 == 1 => Some(data.as_slice()),
                    _ => None,
                })
                .expect("Should have a SendPacket action for iface 1");
            let forwarded = Packet::unpack(forwarded_raw).unwrap();

            // Hops should be incremented
            assert_eq!(forwarded.hops, 2, "Forwarded hops should be 1+1=2");
            // Destination hash should be preserved
            assert_eq!(
                forwarded.destination_hash, dest_hash,
                "Destination hash must be preserved"
            );
            // Should be stripped to Type1 (final hop: BUG: currently stays Type2)
            assert_eq!(
                forwarded.flags.header_type,
                HeaderType::Type1,
                "Final-hop forward should strip to Type1"
            );
            // transport_id should be None (BUG: currently stays Some(own hash))
            assert_eq!(
                forwarded.transport_id, None,
                "Final-hop forward should have no transport_id"
            );
            // Data payload should be intact
            assert_eq!(
                forwarded.data.as_slice(),
                b"final-hop payload",
                "Data payload must be preserved"
            );
        }

        #[test]
        fn test_announce_header2_populates_next_hop() {
            // A HEADER_2 announce (relayed) should populate next_hop with the relay's transport_id.
            use crate::announce::build_announce_payload;
            use crate::destination::{Destination, DestinationType, Direction};
            use crate::packet::{HeaderType, PacketData, PacketFlags, TransportType};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let identity = Identity::generate(&mut OsRng);
            let dest = Destination::new(
                Some(identity),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["nexthop"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            let now_ms = transport.clock.now_ms();
            let payload = build_announce_payload(
                dest.identity().unwrap(),
                dest.hash().as_bytes(),
                dest.name_hash(),
                None,
                Some(b"test"),
                &mut OsRng,
                now_ms,
            )
            .unwrap();

            // Wrap as HEADER_2 with a known relay transport_id
            let relay_hash = [0xAA; TRUNCATED_HASHBYTES];
            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type2,
                    context_flag: false,
                    transport_type: TransportType::Transport,
                    dest_type: DestinationType::Single,
                    packet_type: PacketType::Announce,
                },
                hops: 1,
                transport_id: Some(relay_hash),
                destination_hash: dest_hash,
                context: PacketContext::None,
                data: PacketData::Owned(payload),
            };

            let mut buf = [0u8; MTU];
            let len = packet.pack(&mut buf).unwrap();
            transport.process_incoming(0, &buf[..len]).unwrap();

            // Path should exist with next_hop = relay_hash
            let path = transport
                .path(&dest_hash)
                .expect("path should exist after announce");
            assert_eq!(
                path.next_hop,
                Some(relay_hash),
                "HEADER_2 announce should populate next_hop with relay transport_id"
            );
        }

        #[test]
        fn test_announce_header1_has_no_next_hop() {
            // A HEADER_1 announce (direct) should have next_hop = None.
            use crate::destination::{Destination, DestinationType, Direction};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let identity = Identity::generate(&mut OsRng);
            let dest = Destination::new(
                Some(identity),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["direct"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            let now_ms = transport.clock.now_ms();
            let raw = make_announce_raw_for_dest(&dest, 0, now_ms);
            transport.process_incoming(0, &raw).unwrap();

            // Path should exist with next_hop = None
            let path = transport
                .path(&dest_hash)
                .expect("path should exist after announce");
            assert_eq!(
                path.next_hop, None,
                "HEADER_1 announce should have no next_hop"
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
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

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

        // ─── Stage 2: Dual-write verification tests ────────────────────────

        #[test]
        fn test_send_on_interface_produces_action() {
            let mut transport = test_transport();
            let idx = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let data = b"hello world";
            transport.send_on_interface(idx, data).unwrap();

            let actions = transport.drain_actions();
            assert_eq!(actions.len(), 1);
            assert_eq!(
                actions[0],
                Action::SendPacket {
                    iface: InterfaceId(idx),
                    data: data.to_vec(),
                }
            );
        }

        #[test]
        fn test_send_on_interface_no_registered_iface_still_emits_action() {
            let mut transport = test_transport();

            // No interfaces registered; action is still emitted for sans-I/O driver
            let result = transport.send_on_interface(99, b"data");
            assert!(result.is_ok());

            assert_eq!(transport.pending_action_count(), 1);
            let actions = transport.drain_actions();
            assert_eq!(
                actions[0],
                Action::SendPacket {
                    iface: InterfaceId(99),
                    data: b"data".to_vec()
                }
            );
        }

        #[test]
        fn test_send_on_all_interfaces_produces_broadcast_action() {
            let mut transport = test_transport();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let data = b"broadcast data";
            transport.send_on_all_interfaces(data);

            let actions = transport.drain_actions();
            assert_eq!(actions.len(), 1);
            assert_eq!(
                actions[0],
                Action::Broadcast {
                    data: data.to_vec(),
                    exclude_iface: None,
                }
            );
        }

        #[test]
        fn test_send_on_all_interfaces_except_produces_broadcast_action() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));
            let _idx2 = transport.register_interface(Box::new(MockInterface::new("if2", 3)));

            let data = b"selective broadcast";
            transport.send_on_all_interfaces_except(1, data);

            let actions = transport.drain_actions();
            assert_eq!(actions.len(), 1);
            assert_eq!(
                actions[0],
                Action::Broadcast {
                    data: data.to_vec(),
                    exclude_iface: Some(InterfaceId(1)),
                }
            );
        }

        #[test]
        fn test_send_on_all_interfaces_caches_packet_for_dedup() {
            let mut transport = test_transport();
            transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let hash = [0x42; TRUNCATED_HASHBYTES];
            transport.register_destination(hash);

            // Build a valid data packet
            use crate::destination::DestinationType;

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
                data: PacketData::Owned(b"echo test".to_vec()),
            };

            let mut buf = [0u8; 500];
            let len = packet.pack(&mut buf).unwrap();
            let raw = &buf[..len];

            // Broadcast the packet (simulates originating node sending)
            transport.send_on_all_interfaces(raw);
            transport.drain_actions();

            // Simulate the same packet echoing back on a different interface
            transport.process_incoming(1, raw).unwrap();

            // The echo must be dropped by dedup
            assert_eq!(transport.stats().packets_dropped, 1);
            assert_eq!(transport.pending_events(), 0);
        }

        #[test]
        fn test_send_to_destination_produces_send_action() {
            let mut transport = test_transport();
            let idx = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            // Manually insert a path
            let dest_hash = [0x42; TRUNCATED_HASHBYTES];
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 1,
                    expires_ms: u64::MAX,
                    interface_index: idx,
                    random_blobs: Vec::new(),
                    next_hop: None,
                },
            );

            let data = b"routed packet";
            transport.send_to_destination(&dest_hash, data).unwrap();

            let actions = transport.drain_actions();
            assert_eq!(actions.len(), 1);
            assert_eq!(
                actions[0],
                Action::SendPacket {
                    iface: InterfaceId(idx),
                    data: data.to_vec(),
                }
            );
        }

        #[test]
        fn test_send_to_destination_relay_converts_type1_to_type2() {
            use crate::packet::{HeaderType, PacketFlags, TransportType};

            let mut transport = test_transport();
            let idx = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_hash = [0x42; TRUNCATED_HASHBYTES];
            let next_hop = [0xAA; TRUNCATED_HASHBYTES];
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 1,
                    expires_ms: u64::MAX,
                    interface_index: idx,
                    random_blobs: Vec::new(),
                    next_hop: Some(next_hop),
                },
            );

            // Build a Type1 data packet: flags(1) + hops(1) + dest_hash(16) + context(1) + payload
            let flags = PacketFlags {
                ifac_flag: false,
                header_type: HeaderType::Type1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                dest_type: crate::destination::DestinationType::Single,
                packet_type: crate::packet::PacketType::Data,
            };
            let mut pkt = alloc::vec![flags.to_byte(), 0]; // flags + hops=0
            pkt.extend_from_slice(&dest_hash); // dest_hash
            pkt.push(0x00); // context
            pkt.extend_from_slice(b"hello"); // payload

            transport.send_to_destination(&dest_hash, &pkt).unwrap();

            let actions = transport.drain_actions();
            assert_eq!(actions.len(), 1);
            if let Action::SendPacket { data, .. } = &actions[0] {
                // Should be 16 bytes longer (transport_id inserted)
                assert_eq!(data.len(), pkt.len() + TRUNCATED_HASHBYTES);
                // Parse the output flags
                let out_flags = PacketFlags::from_byte(data[0]).unwrap();
                assert_eq!(out_flags.header_type, HeaderType::Type2, "should be Type2");
                assert_eq!(
                    out_flags.transport_type,
                    TransportType::Transport,
                    "should be Transport"
                );
                // transport_id should be the next_hop
                assert_eq!(&data[2..2 + TRUNCATED_HASHBYTES], &next_hop);
                // dest_hash follows the transport_id
                assert_eq!(
                    &data[2 + TRUNCATED_HASHBYTES..2 + 2 * TRUNCATED_HASHBYTES],
                    &dest_hash
                );
                // payload at the end
                assert_eq!(&data[data.len() - 5..], b"hello");
            } else {
                panic!("expected SendPacket action");
            }
        }

        #[test]
        fn test_send_to_destination_type2_not_double_wrapped() {
            use crate::packet::{HeaderType, PacketFlags, TransportType};

            let mut transport = test_transport();
            let idx = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_hash = [0x42; TRUNCATED_HASHBYTES];
            let next_hop = [0xAA; TRUNCATED_HASHBYTES];
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 1,
                    expires_ms: u64::MAX,
                    interface_index: idx,
                    random_blobs: Vec::new(),
                    next_hop: Some(next_hop),
                },
            );

            // Build a Type2 packet (already has transport header)
            let flags = PacketFlags {
                ifac_flag: false,
                header_type: HeaderType::Type2,
                context_flag: false,
                transport_type: TransportType::Transport,
                dest_type: crate::destination::DestinationType::Single,
                packet_type: crate::packet::PacketType::Data,
            };
            let mut pkt = alloc::vec![flags.to_byte(), 0]; // flags + hops
            pkt.extend_from_slice(&next_hop); // transport_id
            pkt.extend_from_slice(&dest_hash); // dest_hash
            pkt.push(0x00); // context
            pkt.extend_from_slice(b"hello"); // payload
            let original_len = pkt.len();

            transport.send_to_destination(&dest_hash, &pkt).unwrap();

            let actions = transport.drain_actions();
            assert_eq!(actions.len(), 1);
            if let Action::SendPacket { data, .. } = &actions[0] {
                // Should NOT grow — Type2 packets are passed through unchanged
                assert_eq!(
                    data.len(),
                    original_len,
                    "Type2 packet should not be re-wrapped"
                );
            } else {
                panic!("expected SendPacket action");
            }
        }

        #[test]
        fn test_send_to_destination_no_path_no_action() {
            let mut transport = test_transport();
            let _idx = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_hash = [0x42; TRUNCATED_HASHBYTES];
            let result = transport.send_to_destination(&dest_hash, b"data");
            assert!(result.is_err());

            assert_eq!(transport.pending_action_count(), 0);
        }

        #[test]
        fn test_drain_actions_clears_buffer() {
            let mut transport = test_transport();
            let idx = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            transport.send_on_interface(idx, b"first").unwrap();
            transport.send_on_interface(idx, b"second").unwrap();

            assert_eq!(transport.pending_action_count(), 2);

            let actions = transport.drain_actions();
            assert_eq!(actions.len(), 2);

            // Buffer should be empty after drain
            assert_eq!(transport.pending_action_count(), 0);
            let actions2 = transport.drain_actions();
            assert!(actions2.is_empty());
        }

        #[test]
        fn test_multiple_sends_accumulate_actions() {
            let mut transport = test_transport();
            let idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            // Mix of different send types
            transport.send_on_interface(idx0, b"unicast").unwrap();
            transport.send_on_all_interfaces(b"broadcast");
            transport.send_on_interface(idx1, b"unicast2").unwrap();
            transport.send_on_all_interfaces_except(0, b"selective");

            let actions = transport.drain_actions();
            assert_eq!(actions.len(), 4);

            assert_eq!(
                actions[0],
                Action::SendPacket {
                    iface: InterfaceId(0),
                    data: b"unicast".to_vec(),
                }
            );
            assert_eq!(
                actions[1],
                Action::Broadcast {
                    data: b"broadcast".to_vec(),
                    exclude_iface: None,
                }
            );
            assert_eq!(
                actions[2],
                Action::SendPacket {
                    iface: InterfaceId(1),
                    data: b"unicast2".to_vec(),
                }
            );
            assert_eq!(
                actions[3],
                Action::Broadcast {
                    data: b"selective".to_vec(),
                    exclude_iface: Some(InterfaceId(0)),
                }
            );
        }

        #[test]
        fn test_announce_rebroadcast_produces_action() {
            // When an announce is rebroadcast, it should produce a Broadcast action
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let (raw, _dest_hash) = make_announce_raw(1, PacketContext::None);
            let _ = transport.process_incoming(0, &raw);

            // Drain actions from the initial processing (no rebroadcast yet)
            let _ = transport.drain_actions();

            // Advance time past the retransmit delay
            transport.clock.advance(PATHFINDER_RW_MS + 1000);
            transport.poll();

            // Should have a Broadcast action for the rebroadcast
            let actions = transport.drain_actions();
            assert!(
                !actions.is_empty(),
                "announce rebroadcast should produce actions"
            );

            // All rebroadcast actions should be Broadcast with exclude,
            // and the rebroadcasted packet should be Type2/Transport with our transport_id
            for action in &actions {
                match action {
                    Action::Broadcast {
                        exclude_iface,
                        data,
                    } => {
                        assert_eq!(
                            *exclude_iface,
                            Some(InterfaceId(0)),
                            "rebroadcast should exclude the receiving interface"
                        );
                        let pkt = Packet::unpack(data).unwrap();
                        assert_eq!(
                            pkt.flags.header_type,
                            HeaderType::Type2,
                            "rebroadcast announce should be Header Type 2"
                        );
                        assert_eq!(
                            pkt.flags.transport_type,
                            TransportType::Transport,
                            "rebroadcast announce should have Transport transport_type"
                        );
                        assert_eq!(
                            pkt.transport_id,
                            Some(*transport.identity.hash()),
                            "rebroadcast announce transport_id should be our identity hash"
                        );
                    }
                    other => panic!("expected Broadcast action, got {:?}", other),
                }
            }
        }

        // ─── Sans-I/O Audit: Action coverage tests ──────────────────────────

        #[test]
        fn test_forward_on_interface_produces_send_action() {
            // A transport-mode data packet destined for a link_table entry
            // should produce a SendPacket action on the correct next-hop interface.
            use crate::destination::DestinationType;
            use crate::packet::{HeaderType, PacketData, PacketFlags, TransportType};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            // Insert a validated link_table entry: link_hash routes from if0 → if1
            let link_hash = [0xAA; TRUNCATED_HASHBYTES];
            transport.link_table.insert(
                link_hash,
                LinkEntry {
                    timestamp_ms: transport.clock.now_ms(),
                    next_hop_interface_index: 1, // toward destination
                    remaining_hops: 1,
                    received_interface_index: 0, // toward initiator
                    hops: 1,
                    validated: true,
                    proof_timeout_ms: u64::MAX,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
                },
            );

            // Build a data packet addressed to link_hash, arriving on if0 (initiator side)
            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: DestinationType::Link,
                    packet_type: PacketType::Data,
                },
                hops: 1, // matches link_entry.hops
                transport_id: None,
                destination_hash: link_hash,
                context: PacketContext::None,
                data: PacketData::Owned(b"test payload".to_vec()),
            };
            let mut buf = [0u8; MTU];
            let len = packet.pack(&mut buf).unwrap();

            // Process the packet arriving on if0
            let _ = transport.process_incoming(0, &buf[..len]);
            let actions = transport.drain_actions();

            // Should produce a SendPacket on if1 (the next_hop_interface_index)
            assert!(
                actions.iter().any(|a| matches!(
                    a,
                    Action::SendPacket { iface, .. } if *iface == InterfaceId(1)
                )),
                "forward_on_interface should produce SendPacket on iface 1, got: {:?}",
                actions
            );
        }

        #[test]
        fn test_forward_on_all_except_produces_broadcast_action() {
            // A path request arriving on if0 with no cached announce should
            // be forwarded as a Broadcast excluding if0 (transport mode only).
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            // Build a path request for an unknown destination
            let unknown_hash = [0xBB; TRUNCATED_HASHBYTES];
            let tag = [0xCC; TRUNCATED_HASHBYTES];
            let transport_id = [0xDD; TRUNCATED_HASHBYTES];

            let mut data = Vec::new();
            data.extend_from_slice(&unknown_hash);
            data.extend_from_slice(&transport_id);
            data.extend_from_slice(&tag);

            let path_req_hash = *transport.path_request_hash();

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
            let mut buf = [0u8; MTU];
            let len = packet.pack(&mut buf).unwrap();

            let _ = transport.process_incoming(0, &buf[..len]);
            let actions = transport.drain_actions();

            assert!(
                actions.iter().any(|a| matches!(
                    a,
                    Action::Broadcast { exclude_iface: Some(iface), .. }
                        if *iface == InterfaceId(0)
                )),
                "path request forwarding should produce Broadcast excluding iface 0, got: {:?}",
                actions
            );
        }

        #[test]
        fn test_send_proof_produces_send_action() {
            let mut transport = test_transport();
            let idx = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            // Insert a path so send_proof can route
            let dest_hash = [0x42; TRUNCATED_HASHBYTES];
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 1,
                    expires_ms: u64::MAX,
                    interface_index: idx,
                    random_blobs: Vec::new(),
                    next_hop: None,
                },
            );

            let identity = Identity::generate(&mut OsRng);
            let packet_hash = [0xAA; 32];

            transport
                .send_proof(&packet_hash, &dest_hash, &identity, None)
                .unwrap();

            let actions = transport.drain_actions();
            assert!(
                actions.iter().any(|a| matches!(
                    a,
                    Action::SendPacket { iface, .. } if *iface == InterfaceId(idx)
                )),
                "send_proof should produce SendPacket action, got: {:?}",
                actions
            );
        }

        #[test]
        fn test_request_path_produces_action() {
            let mut transport = test_transport();
            let _idx = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_hash = [0x42; TRUNCATED_HASHBYTES];
            let tag = [0xCC; TRUNCATED_HASHBYTES];

            // Request path on all interfaces (None)
            transport.request_path(&dest_hash, None, &tag).unwrap();

            let actions = transport.drain_actions();
            assert!(
                !actions.is_empty(),
                "request_path should produce at least one action"
            );
            assert!(
                actions
                    .iter()
                    .any(|a| matches!(a, Action::Broadcast { .. })),
                "request_path with no specific interface should broadcast, got: {:?}",
                actions
            );
        }

        #[test]
        fn test_handle_path_request_produces_broadcast_action() {
            // Register a destination and cache an announce, then process a path
            // request. The announce should be scheduled for rebroadcast.
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            // First, create an announce and process it to populate the cache
            let (raw, dest_hash) = make_announce_raw(1, PacketContext::None);
            let _ = transport.process_incoming(0, &raw);
            let _ = transport.drain_actions();
            let _ = transport.drain_events();

            // Now send a path request for that destination from a different interface
            let tag = [0xCC; TRUNCATED_HASHBYTES];
            let requester_id = [0xDD; TRUNCATED_HASHBYTES];

            let mut data = Vec::new();
            data.extend_from_slice(&dest_hash);
            data.extend_from_slice(&requester_id);
            data.extend_from_slice(&tag);

            let path_req_hash = *transport.path_request_hash();

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
            let mut buf = [0u8; MTU];
            let len = packet.pack(&mut buf).unwrap();

            let _ = transport.process_incoming(1, &buf[..len]);
            let _ = transport.drain_actions();

            // Advance time past the grace period + jitter to trigger rebroadcast
            transport
                .clock
                .advance(PATH_REQUEST_GRACE_MS + PATHFINDER_RW_MS + 1000);
            transport.poll();

            let actions = transport.drain_actions();
            assert!(
                !actions.is_empty(),
                "handle_path_request should schedule announce rebroadcast that produces actions"
            );
        }

        // ─── Helper: Build announce for a specific destination ──────────

        /// Build a raw announce packet for a given destination at a specific
        /// hop count. Each call produces a new random_hash (different timestamp
        /// from MockClock, different random bytes from OsRng), so the resulting
        /// packet hash is unique and passes packet_cache dedup.
        fn make_announce_raw_for_dest(
            dest: &crate::destination::Destination,
            hops: u8,
            now_ms: u64,
        ) -> Vec<u8> {
            use crate::announce::build_announce_payload;
            use crate::packet::{HeaderType, PacketData, PacketFlags, TransportType};

            let identity = dest.identity().unwrap();
            let payload = build_announce_payload(
                identity,
                dest.hash().as_bytes(),
                dest.name_hash(),
                None, // no ratchet
                Some(b"test"),
                &mut OsRng,
                now_ms,
            )
            .unwrap();

            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: crate::destination::DestinationType::Single,
                    packet_type: PacketType::Announce,
                },
                hops,
                transport_id: None,
                destination_hash: dest.hash().into_bytes(),
                context: PacketContext::None,
                data: PacketData::Owned(payload),
            };

            let mut buf = [0u8; MTU];
            let len = packet.pack(&mut buf).unwrap();
            buf[..len].to_vec()
        }

        // ─── Stage 10: Hop count comparison in handle_announce ──────────

        #[test]
        fn test_worse_hop_announce_with_newer_emission_updates_path() {
            // Per Python Transport.py:1664-1668: a worse-hop announce with a
            // newer emission timestamp DOES update the path, even if not expired.
            use crate::destination::{Destination, DestinationType, Direction};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let identity = Identity::generate(&mut OsRng);
            let dest = Destination::new(
                Some(identity),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["hops"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            // Inject announce at hops=1
            let now1 = transport.clock.now_ms();
            let a1 = make_announce_raw_for_dest(&dest, 1, now1);
            transport.process_incoming(0, &a1).unwrap();
            assert_eq!(transport.hops_to(&dest_hash), Some(1));

            // Advance past rate limit so second announce isn't rate-limited
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);

            // Inject announce at hops=3 (worse) with newer timestamp
            let now2 = transport.clock.now_ms();
            let a2 = make_announce_raw_for_dest(&dest, 3, now2);
            transport.process_incoming(0, &a2).unwrap();

            // Per Python: newer emission overwrites regardless of hop count
            assert_eq!(
                transport.hops_to(&dest_hash),
                Some(3),
                "Worse-hop announce with newer emission should update path (per Python)"
            );
        }

        #[test]
        fn test_better_hop_announce_replaces_worse_path() {
            use crate::destination::{Destination, DestinationType, Direction};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let identity = Identity::generate(&mut OsRng);
            let dest = Destination::new(
                Some(identity),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["hops"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            // Inject announce at hops=3
            let now1 = transport.clock.now_ms();
            let a1 = make_announce_raw_for_dest(&dest, 3, now1);
            transport.process_incoming(0, &a1).unwrap();
            assert_eq!(transport.hops_to(&dest_hash), Some(3));

            // Advance past rate limit
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);

            // Inject announce at hops=1 (better) with newer timestamp
            let now2 = transport.clock.now_ms();
            let a2 = make_announce_raw_for_dest(&dest, 1, now2);
            transport.process_incoming(0, &a2).unwrap();

            // Path should be updated to hops=1
            assert_eq!(
                transport.hops_to(&dest_hash),
                Some(1),
                "Better-hop announce should replace worse path"
            );
        }

        #[test]
        fn test_worse_hop_announce_accepted_when_path_expired() {
            use crate::destination::{Destination, DestinationType, Direction};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let identity = Identity::generate(&mut OsRng);
            let dest = Destination::new(
                Some(identity),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["hops"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            // Inject announce at hops=1
            let now1 = transport.clock.now_ms();
            let a1 = make_announce_raw_for_dest(&dest, 1, now1);
            transport.process_incoming(0, &a1).unwrap();
            assert_eq!(transport.hops_to(&dest_hash), Some(1));

            // Advance past path expiry (path_expiry_secs * 1000) + rate limit
            let expiry_ms = transport.config.path_expiry_secs * 1000;
            transport
                .clock
                .advance(expiry_ms + ANNOUNCE_RATE_LIMIT_MS + 1);

            // Inject announce at hops=3 (worse) — should be accepted because path expired
            let now2 = transport.clock.now_ms();
            let a2 = make_announce_raw_for_dest(&dest, 3, now2);
            transport.process_incoming(0, &a2).unwrap();

            assert_eq!(
                transport.hops_to(&dest_hash),
                Some(3),
                "Worse-hop announce should be accepted when path is expired"
            );
        }

        #[test]
        fn test_equal_hop_announce_with_newer_emission_updates_path() {
            use crate::destination::{Destination, DestinationType, Direction};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let identity = Identity::generate(&mut OsRng);
            let dest = Destination::new(
                Some(identity),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["hops"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            // Inject announce at hops=2 via interface 0
            let now1 = transport.clock.now_ms();
            let a1 = make_announce_raw_for_dest(&dest, 2, now1);
            transport.process_incoming(0, &a1).unwrap();
            assert_eq!(transport.hops_to(&dest_hash), Some(2));
            assert_eq!(transport.path(&dest_hash).unwrap().interface_index, 0);

            // Advance past rate limit
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);

            // Inject equal-hop announce via interface 1 with newer timestamp
            let now2 = transport.clock.now_ms();
            let a2 = make_announce_raw_for_dest(&dest, 2, now2);
            transport.process_incoming(1, &a2).unwrap();

            // Should update to the newer path (interface 1)
            assert_eq!(
                transport.path(&dest_hash).unwrap().interface_index,
                1,
                "Equal-hop announce with newer emission should update path"
            );
        }

        #[test]
        fn test_equal_hop_announce_with_same_emission_does_not_update() {
            // Per Python Transport.py:1627: equal hops require announce_emitted > path_timebase.
            // If emission is the same (not newer), path should NOT update.
            use crate::destination::{Destination, DestinationType, Direction};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let identity = Identity::generate(&mut OsRng);
            let dest = Destination::new(
                Some(identity),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["hops"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            // Inject announce at hops=2 via interface 0 at time T
            let now = transport.clock.now_ms();
            let a1 = make_announce_raw_for_dest(&dest, 2, now);
            transport.process_incoming(0, &a1).unwrap();
            assert_eq!(transport.hops_to(&dest_hash), Some(2));
            assert_eq!(transport.path(&dest_hash).unwrap().interface_index, 0);

            // Advance past rate limit but use SAME timestamp for announce
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);

            // Inject equal-hop announce via interface 1 but with SAME emission time
            let a2 = make_announce_raw_for_dest(&dest, 2, now); // same now_ms!
            transport.process_incoming(1, &a2).unwrap();

            // Path should NOT update — emission is not newer
            assert_eq!(
                transport.path(&dest_hash).unwrap().interface_index,
                0,
                "Equal-hop announce with same emission should not update path"
            );
        }

        // ─── Stage 10b: Random blobs cap ────────────────────────────────

        #[test]
        fn test_random_blobs_capped_at_max() {
            use crate::constants::MAX_RANDOM_BLOBS;
            use crate::destination::{Destination, DestinationType, Direction};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let identity = Identity::generate(&mut OsRng);
            let dest = Destination::new(
                Some(identity),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["blobs"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            // Inject MAX_RANDOM_BLOBS + 10 announces, advancing clock each time
            for i in 0..(MAX_RANDOM_BLOBS + 10) {
                transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);
                let now = transport.clock.now_ms();
                let raw = make_announce_raw_for_dest(&dest, 1, now);
                transport.process_incoming(0, &raw).unwrap();

                // Verify path exists after first announce
                if i == 0 {
                    assert!(transport.has_path(&dest_hash));
                }
            }

            let path = transport.path(&dest_hash).unwrap();
            assert!(
                path.random_blobs.len() <= MAX_RANDOM_BLOBS,
                "random_blobs should be capped at {}, got {}",
                MAX_RANDOM_BLOBS,
                path.random_blobs.len()
            );
        }

        // ─── Stage 10c: Out-of-order announce arrival ────────────────────

        #[test]
        fn test_stale_worse_hop_announce_does_not_overwrite_fresher_better_path() {
            // Models mesh out-of-order arrival: destination D announces at T=5M
            // (propagates via slow 3-hop path) then again at T=10M (propagates
            // via fast 1-hop path). Receiver gets the 1-hop fresh announce
            // first, then the 3-hop stale announce later.
            use crate::destination::{Destination, DestinationType, Direction};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let identity = Identity::generate(&mut OsRng);
            let dest = Destination::new(
                Some(identity),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["ooo"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            // Build both announces with decoupled emission timestamps
            let a_stale = make_announce_raw_for_dest(&dest, 3, 5_000_000); // old emission, long path
            let a_fresh = make_announce_raw_for_dest(&dest, 1, 10_000_000); // newer emission, short path

            // Fresh announce arrives first at T=12M via iface_0
            transport.clock.set(12_000_000);
            transport.process_incoming(0, &a_fresh).unwrap();
            assert_eq!(transport.hops_to(&dest_hash), Some(1));
            assert_eq!(transport.path(&dest_hash).unwrap().interface_index, 0);

            // Drain and verify PathFound + AnnounceReceived events
            let events: Vec<_> = transport.drain_events().collect();
            assert!(
                events.len() >= 2,
                "Expected PathFound + AnnounceReceived, got {} events",
                events.len()
            );
            let initial_processed = transport.stats().announces_processed;
            assert_eq!(initial_processed, 1);

            // Stale announce arrives later at T=15M via iface_1
            // (past rate limit relative to the fresh announce)
            transport.clock.set(15_000_000);
            transport.process_incoming(1, &a_stale).unwrap();

            // Path must NOT be overwritten: older emission (5M < 10M),
            // worse hops (3 > 1), path not expired → rejected
            assert_eq!(
                transport.hops_to(&dest_hash),
                Some(1),
                "Stale worse-hop announce must not overwrite fresher better path"
            );
            assert_eq!(
                transport.path(&dest_hash).unwrap().interface_index,
                0,
                "Interface must remain iface_0 (fresh path), not iface_1 (stale)"
            );

            // Random blob still recorded for replay detection (both announces)
            assert_eq!(
                transport.path(&dest_hash).unwrap().random_blobs.len(),
                2,
                "Both random blobs should be recorded for replay detection"
            );

            // announces_processed should NOT increment for the rejected announce
            assert_eq!(
                transport.stats().announces_processed,
                initial_processed,
                "Rejected stale announce must not increment announces_processed"
            );

            // No new events emitted for the rejected announce
            let stale_events: Vec<_> = transport.drain_events().collect();
            assert!(
                stale_events.is_empty(),
                "Rejected stale announce must not emit events, got {} events",
                stale_events.len()
            );
        }

        #[test]
        fn test_stale_arrives_first_then_fresh_replaces() {
            // Inverse scenario: stale 3-hop announce arrives first, then fresh
            // 1-hop announce arrives and correctly replaces the path.
            use crate::destination::{Destination, DestinationType, Direction};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let identity = Identity::generate(&mut OsRng);
            let dest = Destination::new(
                Some(identity),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["ooo"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            // Same two announces as above
            let a_stale = make_announce_raw_for_dest(&dest, 3, 5_000_000);
            let a_fresh = make_announce_raw_for_dest(&dest, 1, 10_000_000);

            // Stale announce arrives first at T=8M via iface_1
            transport.clock.set(8_000_000);
            transport.process_incoming(1, &a_stale).unwrap();
            assert_eq!(transport.hops_to(&dest_hash), Some(3));
            assert_eq!(transport.path(&dest_hash).unwrap().interface_index, 1);

            // Fresh announce arrives later at T=12M via iface_0
            transport.clock.set(12_000_000);
            transport.process_incoming(0, &a_fresh).unwrap();

            // Path should be updated: newer emission (10M > 5M), better hops (1 < 3)
            assert_eq!(
                transport.hops_to(&dest_hash),
                Some(1),
                "Fresh better-hop announce must replace stale worse path"
            );
            assert_eq!(
                transport.path(&dest_hash).unwrap().interface_index,
                0,
                "Interface must be updated to iface_0 (fresh path)"
            );

            // Both announces processed
            assert_eq!(transport.stats().announces_processed, 2);
        }

        // ─── Bug #14: HEADER_2 filtering for non-own transport_id ────────

        #[test]
        fn test_header2_non_own_transport_id_dropped() {
            // HEADER_2 data packet with a foreign transport_id should be silently dropped
            // BEFORE polluting the dedup cache, and BEFORE being forwarded.
            // Python Transport.py:1193-1196
            use crate::packet::{HeaderType, PacketData, PacketFlags, TransportType};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let foreign_transport_id = [0xBB; TRUNCATED_HASHBYTES];
            let dest_hash = [0xCC; TRUNCATED_HASHBYTES];
            let next_hop_hash = [0xDD; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();

            // Insert a path table entry so the packet WOULD be forwarded without the filter
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 2,
                    expires_ms: now + 100_000,
                    interface_index: 1,
                    random_blobs: Vec::new(),
                    next_hop: Some(next_hop_hash),
                },
            );

            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type2,
                    context_flag: false,
                    transport_type: TransportType::Transport,
                    dest_type: crate::destination::DestinationType::Single,
                    packet_type: PacketType::Data,
                },
                hops: 1,
                transport_id: Some(foreign_transport_id),
                destination_hash: dest_hash,
                context: PacketContext::None,
                data: PacketData::Owned(b"foreign relay payload".to_vec()),
            };

            let mut buf = [0u8; MTU];
            let len = packet.pack(&mut buf).unwrap();

            let dropped_before = transport.stats().packets_dropped;
            transport.process_incoming(0, &buf[..len]).unwrap();

            assert_eq!(
                transport.stats().packets_dropped,
                dropped_before + 1,
                "Foreign transport_id HEADER_2 data packet should be dropped"
            );
            // Must NOT be forwarded — the packet is not for us
            assert_eq!(
                transport.stats().packets_forwarded,
                0,
                "Foreign transport_id packet must not be forwarded"
            );
            assert!(
                transport.drain_actions().is_empty(),
                "No actions should be emitted for dropped packet"
            );
            // Must NOT pollute dedup cache (dropped before cache insert)
            assert!(
                transport.packet_cache.is_empty(),
                "Dedup cache should not be polluted by foreign transport_id packet"
            );
        }

        #[test]
        fn test_header2_own_transport_id_processed() {
            // HEADER_2 data packet with our own transport_id should be processed normally
            // (forwarded via path table).
            use crate::packet::{HeaderType, PacketData, PacketFlags, TransportType};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let dest_hash = [0xCC; TRUNCATED_HASHBYTES];
            let next_hop_hash = [0xDD; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();

            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 2,
                    expires_ms: now + 100_000,
                    interface_index: 1,
                    random_blobs: Vec::new(),
                    next_hop: Some(next_hop_hash),
                },
            );

            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type2,
                    context_flag: false,
                    transport_type: TransportType::Transport,
                    dest_type: crate::destination::DestinationType::Single,
                    packet_type: PacketType::Data,
                },
                hops: 1,
                transport_id: Some(*transport.identity.hash()),
                destination_hash: dest_hash,
                context: PacketContext::None,
                data: PacketData::Owned(b"own relay payload".to_vec()),
            };

            let mut buf = [0u8; MTU];
            let len = packet.pack(&mut buf).unwrap();
            transport.process_incoming(0, &buf[..len]).unwrap();

            assert!(
                transport.stats().packets_forwarded > 0,
                "Own transport_id HEADER_2 packet should be forwarded"
            );
            let actions = transport.drain_actions();
            assert!(
                actions
                    .iter()
                    .any(|a| matches!(a, Action::SendPacket { .. })),
                "Should have a SendPacket action for forwarded packet"
            );
        }

        #[test]
        fn test_header2_announce_not_filtered_by_transport_id() {
            // HEADER_2 announce with a foreign transport_id should NOT be dropped —
            // announces are exempt from the transport_id filter.
            // Python Transport.py:1193-1196
            use crate::announce::build_announce_payload;
            use crate::destination::{Destination, DestinationType, Direction};
            use crate::packet::{HeaderType, PacketData, PacketFlags, TransportType};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let identity = Identity::generate(&mut OsRng);
            let dest = Destination::new(
                Some(identity),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["filter"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            let now_ms = transport.clock.now_ms();
            let payload = build_announce_payload(
                dest.identity().unwrap(),
                dest.hash().as_bytes(),
                dest.name_hash(),
                None,
                Some(b"test"),
                &mut OsRng,
                now_ms,
            )
            .unwrap();

            let foreign_transport_id = [0xCC; TRUNCATED_HASHBYTES];
            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type2,
                    context_flag: false,
                    transport_type: TransportType::Transport,
                    dest_type: DestinationType::Single,
                    packet_type: PacketType::Announce,
                },
                hops: 1,
                transport_id: Some(foreign_transport_id),
                destination_hash: dest_hash,
                context: PacketContext::None,
                data: PacketData::Owned(payload),
            };

            let mut buf = [0u8; MTU];
            let len = packet.pack(&mut buf).unwrap();
            transport.process_incoming(0, &buf[..len]).unwrap();

            // Announce should be processed, not dropped
            assert!(
                transport.path(&dest_hash).is_some(),
                "HEADER_2 announce with foreign transport_id should still be processed"
            );
            assert!(
                transport.stats().announces_processed > 0,
                "Announce should be counted as processed"
            );
        }

        // ─── Bug #15: PLAIN/GROUP hop restriction ─────────────────────────

        #[test]
        fn test_plain_packet_with_hops_above_1_dropped() {
            // PLAIN data packets with hops > 0 must be dropped — PLAIN destinations
            // are for direct neighbors only. Python Transport.py:1205-1213
            use crate::destination::DestinationType;
            use crate::packet::{HeaderType, PacketData, PacketFlags, TransportType};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_hash = [0xAA; TRUNCATED_HASHBYTES];

            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: DestinationType::Plain,
                    packet_type: PacketType::Data,
                },
                hops: 2,
                transport_id: None,
                destination_hash: dest_hash,
                context: PacketContext::None,
                data: PacketData::Owned(b"plain too far".to_vec()),
            };

            let mut buf = [0u8; MTU];
            let len = packet.pack(&mut buf).unwrap();

            let dropped_before = transport.stats().packets_dropped;
            transport.process_incoming(0, &buf[..len]).unwrap();

            assert_eq!(
                transport.stats().packets_dropped,
                dropped_before + 1,
                "PLAIN data packet with hops=2 should be dropped"
            );
            assert!(
                transport.drain_actions().is_empty(),
                "No actions should be emitted for dropped PLAIN packet"
            );
            // Must NOT pollute dedup cache (dropped before cache insert)
            assert!(
                transport.packet_cache.is_empty(),
                "Dedup cache should not be polluted by dropped PLAIN packet"
            );
        }

        #[test]
        fn test_plain_packet_with_hops_0_processed() {
            // PLAIN data packets with hops=0 should be delivered normally.
            use crate::destination::DestinationType;
            use crate::packet::{HeaderType, PacketData, PacketFlags, TransportType};

            let mut transport = test_transport();
            transport.register_interface(Box::new(MockInterface::new("test", 1)));
            let dest_hash = [0xAA; TRUNCATED_HASHBYTES];
            transport.register_destination(dest_hash);

            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: DestinationType::Plain,
                    packet_type: PacketType::Data,
                },
                hops: 0,
                transport_id: None,
                destination_hash: dest_hash,
                context: PacketContext::None,
                data: PacketData::Owned(b"plain neighbor".to_vec()),
            };

            let mut buf = [0u8; 500];
            let len = packet.pack(&mut buf).unwrap();
            transport.process_incoming(0, &buf[..len]).unwrap();

            assert_eq!(
                transport.stats().packets_dropped,
                0,
                "PLAIN data packet with hops=0 should NOT be dropped"
            );
            assert!(
                transport.pending_events() > 0,
                "PLAIN data packet with hops=0 should generate events"
            );
        }

        #[test]
        fn test_plain_packet_with_hops_1_dropped() {
            // PLAIN data packets with hops=1 must be dropped — PLAIN destinations
            // are for direct neighbors only (hops == 0). Python checks hops > 1
            // after increment; Rust equivalent without increment: hops > 0.
            use crate::destination::DestinationType;
            use crate::packet::{HeaderType, PacketData, PacketFlags, TransportType};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_hash = [0xAA; TRUNCATED_HASHBYTES];

            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: DestinationType::Plain,
                    packet_type: PacketType::Data,
                },
                hops: 1,
                transport_id: None,
                destination_hash: dest_hash,
                context: PacketContext::None,
                data: PacketData::Owned(b"plain one hop".to_vec()),
            };

            let mut buf = [0u8; MTU];
            let len = packet.pack(&mut buf).unwrap();

            let dropped_before = transport.stats().packets_dropped;
            transport.process_incoming(0, &buf[..len]).unwrap();

            assert_eq!(
                transport.stats().packets_dropped,
                dropped_before + 1,
                "PLAIN data packet with hops=1 should be dropped"
            );
            assert!(
                transport.drain_actions().is_empty(),
                "No actions should be emitted for dropped PLAIN packet"
            );
        }

        #[test]
        fn test_plain_announce_always_dropped() {
            // PLAIN announces are always invalid — dropped unconditionally
            // regardless of hop count. Python Transport.py:1211-1213
            use crate::destination::DestinationType;
            use crate::packet::{HeaderType, PacketData, PacketFlags, TransportType};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_hash = [0xAA; TRUNCATED_HASHBYTES];

            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: DestinationType::Plain,
                    packet_type: PacketType::Announce,
                },
                hops: 0,
                transport_id: None,
                destination_hash: dest_hash,
                context: PacketContext::None,
                data: PacketData::Owned(b"fake plain announce".to_vec()),
            };

            let mut buf = [0u8; MTU];
            let len = packet.pack(&mut buf).unwrap();

            let dropped_before = transport.stats().packets_dropped;
            transport.process_incoming(0, &buf[..len]).unwrap();

            assert_eq!(
                transport.stats().packets_dropped,
                dropped_before + 1,
                "PLAIN announce should always be dropped"
            );
            assert!(
                transport.packet_cache.is_empty(),
                "Dedup cache should not be polluted by invalid PLAIN announce"
            );
        }

        #[test]
        fn test_group_packet_with_hops_above_1_dropped() {
            // GROUP data packets with hops > 0 must be dropped — GROUP destinations
            // are for direct neighbors only. Python Transport.py:1215-1225
            use crate::destination::DestinationType;
            use crate::packet::{HeaderType, PacketData, PacketFlags, TransportType};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_hash = [0xBB; TRUNCATED_HASHBYTES];

            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: DestinationType::Group,
                    packet_type: PacketType::Data,
                },
                hops: 2,
                transport_id: None,
                destination_hash: dest_hash,
                context: PacketContext::None,
                data: PacketData::Owned(b"group too far".to_vec()),
            };

            let mut buf = [0u8; MTU];
            let len = packet.pack(&mut buf).unwrap();

            let dropped_before = transport.stats().packets_dropped;
            transport.process_incoming(0, &buf[..len]).unwrap();

            assert_eq!(
                transport.stats().packets_dropped,
                dropped_before + 1,
                "GROUP data packet with hops=2 should be dropped"
            );
            assert!(
                transport.drain_actions().is_empty(),
                "No actions should be emitted for dropped GROUP packet"
            );
            assert!(
                transport.packet_cache.is_empty(),
                "Dedup cache should not be polluted by dropped GROUP packet"
            );
        }

        #[test]
        fn test_group_announce_always_dropped() {
            // GROUP announces are always invalid — dropped unconditionally
            // regardless of hop count. Python Transport.py:1223-1225
            use crate::destination::DestinationType;
            use crate::packet::{HeaderType, PacketData, PacketFlags, TransportType};

            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_hash = [0xBB; TRUNCATED_HASHBYTES];

            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: DestinationType::Group,
                    packet_type: PacketType::Announce,
                },
                hops: 0,
                transport_id: None,
                destination_hash: dest_hash,
                context: PacketContext::None,
                data: PacketData::Owned(b"fake group announce".to_vec()),
            };

            let mut buf = [0u8; MTU];
            let len = packet.pack(&mut buf).unwrap();

            let dropped_before = transport.stats().packets_dropped;
            transport.process_incoming(0, &buf[..len]).unwrap();

            assert_eq!(
                transport.stats().packets_dropped,
                dropped_before + 1,
                "GROUP announce should always be dropped"
            );
            assert!(
                transport.packet_cache.is_empty(),
                "Dedup cache should not be polluted by invalid GROUP announce"
            );
        }

        // ─── Bug #9/#10: Deferred hash caching for link-table & LRPROOF ──

        #[test]
        fn test_link_table_data_deferred_hash_allows_retry() {
            // Shared-medium scenario: a link-table DATA packet arrives on the wrong
            // interface first (hop check fails), then on the correct interface.
            // The dedup hash must NOT be cached on failure, allowing the retry.
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 1,
                    remaining_hops: 3,
                    received_interface_index: 0,
                    hops: 2,
                    validated: true,
                    proof_timeout_ms: now + 30_000,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
                },
            );

            // Build DATA packet: dest_hash=link_id, hops=2 (matches hops for initiator side)
            let pkt = build_link_data_packet(link_id, 2);
            let mut buf = [0u8; 500];
            let len = pkt.pack(&mut buf).unwrap();

            // Step 1: arrives on if1 (destination side) — hops=2 != remaining_hops=3 → dropped
            transport.process_incoming(1, &buf[..len]).unwrap();
            assert_eq!(transport.stats().packets_forwarded, 0);
            assert!(
                transport.packet_cache.is_empty(),
                "Hash must NOT be cached when link-table hop check fails"
            );

            // Step 2: same packet arrives on if0 (initiator side) — hops=2 == hops=2 → forwarded
            transport.process_incoming(0, &buf[..len]).unwrap();
            assert_eq!(
                transport.stats().packets_forwarded,
                1,
                "Retry on correct interface should succeed"
            );
            assert!(
                !transport.packet_cache.is_empty(),
                "Hash should be cached after successful forwarding"
            );
        }

        #[test]
        fn test_link_table_data_successful_forward_caches_hash() {
            // Regression: successful link-table forwarding MUST cache the hash
            // so that a second copy is dropped as duplicate.
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 1,
                    remaining_hops: 3,
                    received_interface_index: 0,
                    hops: 2,
                    validated: true,
                    proof_timeout_ms: now + 30_000,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
                },
            );

            let pkt = build_link_data_packet(link_id, 2);
            let mut buf = [0u8; 500];
            let len = pkt.pack(&mut buf).unwrap();

            // First copy: forwarded
            transport.process_incoming(0, &buf[..len]).unwrap();
            assert_eq!(transport.stats().packets_forwarded, 1);
            assert!(
                !transport.packet_cache.is_empty(),
                "Hash should be cached after successful forwarding"
            );

            // Second copy: dropped as duplicate
            let dropped_before = transport.stats().packets_dropped;
            transport.process_incoming(0, &buf[..len]).unwrap();
            assert_eq!(
                transport.stats().packets_dropped,
                dropped_before + 1,
                "Duplicate should be dropped"
            );
            assert_eq!(
                transport.stats().packets_forwarded,
                1,
                "Only the first copy should be forwarded"
            );
        }

        #[test]
        fn test_non_link_table_data_immediate_hash() {
            // Normal (non-link-table) data is cached immediately in process_incoming,
            // so a second copy on another interface is dropped.
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let dest_hash = [0xBB; TRUNCATED_HASHBYTES];
            transport.register_destination(dest_hash);

            let pkt = build_link_data_packet(dest_hash, 0);
            let mut buf = [0u8; 500];
            let len = pkt.pack(&mut buf).unwrap();

            // First copy: delivered
            transport.process_incoming(0, &buf[..len]).unwrap();
            let events: Vec<_> = transport.drain_events().collect();
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, TransportEvent::PacketReceived { .. })),
                "First copy should be delivered"
            );

            // Second copy on different interface: dropped as duplicate
            let dropped_before = transport.stats().packets_dropped;
            transport.process_incoming(1, &buf[..len]).unwrap();
            assert_eq!(
                transport.stats().packets_dropped,
                dropped_before + 1,
                "Second copy should be dropped"
            );
        }

        #[test]
        fn test_lrproof_not_cached_on_link_table_forward() {
            // LRPROOF forwarded via link table should NOT be cached
            // (matches Python Transport.py:2016-2039).
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 1,
                    remaining_hops: 3,
                    received_interface_index: 0,
                    hops: 2,
                    validated: false,
                    proof_timeout_ms: now + 30_000,
                    destination_hash: [0xBB; TRUNCATED_HASHBYTES],
                },
            );

            // Build LRPROOF with valid size (96 bytes = sig(64) + X25519(32))
            let pkt = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: crate::destination::DestinationType::Link,
                    packet_type: PacketType::Proof,
                },
                hops: 3, // matches remaining_hops (arriving on dest side = if1)
                transport_id: None,
                destination_hash: link_id,
                context: PacketContext::Lrproof,
                data: PacketData::Owned([0xCC; 96].to_vec()),
            };

            let mut buf = [0u8; 500];
            let len = pkt.pack(&mut buf).unwrap();

            // Arrives on if1 (dest side), remaining_hops=3 matches hops=3 → forwarded
            transport.process_incoming(1, &buf[..len]).unwrap();
            assert!(
                transport.stats().packets_forwarded > 0,
                "LRPROOF should be forwarded"
            );
            assert!(
                transport.packet_cache.is_empty(),
                "LRPROOF hash must NOT be cached during link-table forwarding"
            );
        }

        #[test]
        fn test_lrproof_local_delivery_caches_hash() {
            // LRPROOF delivered to a registered destination IS cached.
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_hash = [0xDD; TRUNCATED_HASHBYTES];
            transport.register_destination(dest_hash);

            // Build LRPROOF targeting the registered destination (not in link_table)
            let pkt = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: crate::destination::DestinationType::Link,
                    packet_type: PacketType::Proof,
                },
                hops: 0,
                transport_id: None,
                destination_hash: dest_hash,
                context: PacketContext::Lrproof,
                data: PacketData::Owned([0xCC; 96].to_vec()),
            };

            let mut buf = [0u8; 500];
            let len = pkt.pack(&mut buf).unwrap();

            transport.process_incoming(0, &buf[..len]).unwrap();

            // Should emit PacketReceived
            let events: Vec<_> = transport.drain_events().collect();
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, TransportEvent::PacketReceived { .. })),
                "LRPROOF should be delivered to registered destination"
            );

            // Hash should be cached
            assert!(
                !transport.packet_cache.is_empty(),
                "LRPROOF hash should be cached after local delivery"
            );
        }

        // ─── Stage 12: Path Recovery Tests ──────────────────────────────

        /// Build an announce packet with a controlled random_hash.
        ///
        /// This allows creating two announces from the SAME destination with the
        /// SAME emission timestamp but different random bytes (for replay detection).
        /// The random_hash is 10 bytes: first 5 are random, last 5 are the emission
        /// timestamp (big-endian).
        fn make_announce_raw_with_random_hash(
            dest: &crate::destination::Destination,
            hops: u8,
            random_hash: &[u8; crate::constants::RANDOM_HASHBYTES],
        ) -> Vec<u8> {
            use crate::packet::{HeaderType, PacketData, PacketFlags, TransportType};

            let identity = dest.identity().unwrap();
            let public_key = identity.public_key_bytes();
            let app_data = b"test";

            // Build signed data (same as announce.rs build_signed_data)
            let mut signed_data = Vec::new();
            signed_data.extend_from_slice(dest.hash().as_bytes());
            signed_data.extend_from_slice(&public_key);
            signed_data.extend_from_slice(dest.name_hash());
            signed_data.extend_from_slice(random_hash);
            signed_data.extend_from_slice(app_data);

            let signature = identity.sign(&signed_data).unwrap();

            // Build payload: public_key + name_hash + random_hash + signature + app_data
            let mut payload = Vec::new();
            payload.extend_from_slice(&public_key);
            payload.extend_from_slice(dest.name_hash());
            payload.extend_from_slice(random_hash);
            payload.extend_from_slice(&signature);
            payload.extend_from_slice(app_data);

            let packet = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: crate::destination::DestinationType::Single,
                    packet_type: PacketType::Announce,
                },
                hops,
                transport_id: None,
                destination_hash: dest.hash().into_bytes(),
                context: PacketContext::None,
                data: PacketData::Owned(payload),
            };

            let mut buf = [0u8; MTU];
            let len = packet.pack(&mut buf).unwrap();
            buf[..len].to_vec()
        }

        /// Build a random_hash with the given random prefix bytes and emission value.
        fn make_random_hash(
            random_prefix: [u8; 5],
            emission: u64,
        ) -> [u8; crate::constants::RANDOM_HASHBYTES] {
            let mut hash = [0u8; crate::constants::RANDOM_HASHBYTES];
            hash[..5].copy_from_slice(&random_prefix);
            // Last 5 bytes: big-endian emission (lower 40 bits)
            hash[5] = ((emission >> 32) & 0xFF) as u8;
            hash[6] = ((emission >> 24) & 0xFF) as u8;
            hash[7] = ((emission >> 16) & 0xFF) as u8;
            hash[8] = ((emission >> 8) & 0xFF) as u8;
            hash[9] = (emission & 0xFF) as u8;
            hash
        }

        fn make_test_dest() -> crate::destination::Destination {
            use crate::destination::{Destination, DestinationType, Direction};
            let identity = Identity::generate(&mut OsRng);
            Destination::new(
                Some(identity),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["recovery"],
            )
            .unwrap()
        }

        #[test]
        fn test_path_state_api_basic() {
            let mut transport = make_transport_enabled();
            let dest_hash = [0x42; TRUNCATED_HASHBYTES];

            // Insert a path entry manually
            let now = transport.clock.now_ms();
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 1,
                    expires_ms: now + 3_600_000,
                    interface_index: 0,
                    random_blobs: Vec::new(),
                    next_hop: None,
                },
            );

            // Default state: not unresponsive
            assert!(!transport.path_is_unresponsive(&dest_hash));

            // Mark unresponsive
            assert!(transport.mark_path_unresponsive(&dest_hash));
            assert!(transport.path_is_unresponsive(&dest_hash));

            // Reset to unknown
            assert!(transport.mark_path_unknown_state(&dest_hash));
            assert!(!transport.path_is_unresponsive(&dest_hash));

            // Mark responsive
            assert!(transport.mark_path_responsive(&dest_hash));
            assert!(!transport.path_is_unresponsive(&dest_hash));

            // Non-existent destination returns false
            assert!(!transport.mark_path_unresponsive(&[0xFF; TRUNCATED_HASHBYTES]));
        }

        #[test]
        fn test_path_state_orphan_cleanup() {
            let mut transport = make_transport_enabled();
            let dest_hash = [0x42; TRUNCATED_HASHBYTES];

            // Insert path and mark unresponsive
            let now = transport.clock.now_ms();
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 1,
                    expires_ms: now + 3_600_000,
                    interface_index: 0,
                    random_blobs: Vec::new(),
                    next_hop: None,
                },
            );
            assert!(transport.mark_path_unresponsive(&dest_hash));

            // Remove path
            transport.remove_path(&dest_hash);

            // Poll should clean up orphaned state
            transport.poll();

            // Re-insert path — state should be gone (not unresponsive)
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 1,
                    expires_ms: transport.clock.now_ms() + 3_600_000,
                    interface_index: 0,
                    random_blobs: Vec::new(),
                    next_hop: None,
                },
            );
            assert!(
                !transport.path_is_unresponsive(&dest_hash),
                "State should have been cleaned up when path was removed"
            );
        }

        #[test]
        fn test_announce_acceptance_resets_state_to_unknown() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest = make_test_dest();
            let dest_hash = dest.hash().into_bytes();

            // Process initial announce (creates path)
            let rh1 = make_random_hash([0x01, 0x02, 0x03, 0x04, 0x05], 1000);
            let a1 = make_announce_raw_with_random_hash(&dest, 1, &rh1);
            transport.process_incoming(0, &a1).unwrap();
            assert_eq!(transport.hops_to(&dest_hash), Some(1));

            // Mark unresponsive
            assert!(transport.mark_path_unresponsive(&dest_hash));
            assert!(transport.path_is_unresponsive(&dest_hash));

            // Advance past rate limit
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);

            // Process newer announce (same dest, newer emission) — should reset state
            let rh2 = make_random_hash([0x0A, 0x0B, 0x0C, 0x0D, 0x0E], 2000);
            let a2 = make_announce_raw_with_random_hash(&dest, 1, &rh2);
            transport.process_incoming(0, &a2).unwrap();

            assert!(
                !transport.path_is_unresponsive(&dest_hash),
                "State should be reset to UNKNOWN after normal announce acceptance"
            );
        }

        #[test]
        fn test_unresponsive_path_accepts_same_emission_worse_hop_announce() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let dest = make_test_dest();
            let dest_hash = dest.hash().into_bytes();

            // Process announce A (hops=1, interface 0)
            let emission = 5000u64;
            let rh_a = make_random_hash([0x01, 0x02, 0x03, 0x04, 0x05], emission);
            let a1 = make_announce_raw_with_random_hash(&dest, 1, &rh_a);
            transport.process_incoming(0, &a1).unwrap();
            assert_eq!(transport.hops_to(&dest_hash), Some(1));

            // Advance past rate limit
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);

            // Process announce B (hops=3, same emission, different random)
            // WITHOUT marking unresponsive — should be REJECTED
            let rh_b = make_random_hash([0x0A, 0x0B, 0x0C, 0x0D, 0x0E], emission);
            let a2 = make_announce_raw_with_random_hash(&dest, 3, &rh_b);
            transport.process_incoming(1, &a2).unwrap();
            assert_eq!(
                transport.hops_to(&dest_hash),
                Some(1),
                "Worse-hop same-emission announce should be rejected when path is UNKNOWN"
            );

            // Now mark path unresponsive
            assert!(transport.mark_path_unresponsive(&dest_hash));

            // Clear packet cache so announce B can be re-processed
            transport.packet_cache.clear();
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);

            // Re-process announce B — should be ACCEPTED now
            let rh_c = make_random_hash([0x0F, 0x10, 0x11, 0x12, 0x13], emission);
            let a3 = make_announce_raw_with_random_hash(&dest, 3, &rh_c);
            transport.process_incoming(1, &a3).unwrap();
            assert_eq!(
                transport.hops_to(&dest_hash),
                Some(3),
                "Worse-hop same-emission announce should be accepted when path is UNRESPONSIVE"
            );
        }

        #[test]
        fn test_unknown_path_rejects_same_emission_worse_hop_announce() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest = make_test_dest();
            let dest_hash = dest.hash().into_bytes();

            // Process announce A (hops=1)
            let emission = 5000u64;
            let rh_a = make_random_hash([0x01, 0x02, 0x03, 0x04, 0x05], emission);
            let a1 = make_announce_raw_with_random_hash(&dest, 1, &rh_a);
            transport.process_incoming(0, &a1).unwrap();
            assert_eq!(transport.hops_to(&dest_hash), Some(1));

            // Advance past rate limit
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);

            // Process announce B (hops=3, same emission, different random)
            let rh_b = make_random_hash([0x0A, 0x0B, 0x0C, 0x0D, 0x0E], emission);
            let a2 = make_announce_raw_with_random_hash(&dest, 3, &rh_b);
            transport.process_incoming(0, &a2).unwrap();

            assert_eq!(
                transport.hops_to(&dest_hash),
                Some(1),
                "Worse-hop same-emission announce should be rejected when path is UNKNOWN"
            );
        }

        #[test]
        fn test_link_table_expiry_unvalidated_marks_unresponsive_1hop_dest() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let dest_hash = [0xDD; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();

            // Insert path entry with hops=0 (directly connected).
            // Rust stores raw wire hops; 0 = direct neighbor.
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 0,
                    expires_ms: now + 3_600_000,
                    interface_index: 0,
                    random_blobs: Vec::new(),
                    next_hop: None,
                },
            );

            // Insert unvalidated link entry: hops=2 (initiator 2 hops away),
            // dest is directly connected → sub-case 2 (dest is_direct)
            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 1,
                    remaining_hops: 0,
                    received_interface_index: 0,
                    hops: 2,
                    validated: false,
                    proof_timeout_ms: now + 1000,
                    destination_hash: dest_hash,
                },
            );

            assert!(!transport.path_is_unresponsive(&dest_hash));

            // Advance past proof_timeout
            transport.clock.advance(1001);
            transport.poll();

            // Sub-case 2: dest directly connected, transport enabled → mark unresponsive
            assert!(
                transport.path_is_unresponsive(&dest_hash),
                "Path should be marked unresponsive when unvalidated link expires for direct dest"
            );

            // Link should be removed
            assert!(!transport.link_table.contains_key(&link_id));
        }

        #[test]
        fn test_link_table_expiry_unvalidated_marks_unresponsive_1hop_initiator() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let dest_hash = [0xDD; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();

            // Insert path entry with hops=3 (destination is far away)
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 3,
                    expires_ms: now + 3_600_000,
                    interface_index: 0,
                    random_blobs: Vec::new(),
                    next_hop: None,
                },
            );

            // Insert unvalidated link: hops=0 (initiator directly connected).
            // Rust stores raw wire hops; 0 = direct neighbor.
            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 1,
                    remaining_hops: 3,
                    received_interface_index: 0,
                    hops: 0,
                    validated: false,
                    proof_timeout_ms: now + 1000,
                    destination_hash: dest_hash,
                },
            );

            transport.clock.advance(1001);
            transport.poll();

            // Sub-case 3: initiator directly connected → mark unresponsive
            assert!(
                transport.path_is_unresponsive(&dest_hash),
                "Path should be marked unresponsive when initiator was directly connected"
            );
        }

        #[test]
        fn test_link_table_expiry_unvalidated_no_mark_when_dest_far() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let dest_hash = [0xDD; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();

            // Path with hops=3 (not 1-hop)
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 3,
                    expires_ms: now + 3_600_000,
                    interface_index: 0,
                    random_blobs: Vec::new(),
                    next_hop: None,
                },
            );

            // Unvalidated link: hops=2 (initiator 2 hops, not 1)
            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 1,
                    remaining_hops: 3,
                    received_interface_index: 0,
                    hops: 2,
                    validated: false,
                    proof_timeout_ms: now + 1000,
                    destination_hash: dest_hash,
                },
            );

            transport.clock.advance(1001);
            transport.poll();

            // Neither sub-case 3 nor 4 applies — should NOT be marked
            assert!(
                !transport.path_is_unresponsive(&dest_hash),
                "Path should NOT be marked unresponsive when dest and initiator are far"
            );

            // Link should still be removed
            assert!(!transport.link_table.contains_key(&link_id));
        }

        #[test]
        fn test_link_table_expiry_unvalidated_sends_path_request() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let dest_hash = [0xDD; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();

            // Path with hops=0 (directly connected — sub-case 2)
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 0,
                    expires_ms: now + 3_600_000,
                    interface_index: 0,
                    random_blobs: Vec::new(),
                    next_hop: None,
                },
            );

            // hops=2 (not 0, so sub-case 3 doesn't trigger before sub-case 2)
            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 1,
                    remaining_hops: 0,
                    received_interface_index: 0,
                    hops: 2,
                    validated: false,
                    proof_timeout_ms: now + 1000,
                    destination_hash: dest_hash,
                },
            );

            // Drain any events/actions from setup
            transport.drain_events();
            transport.drain_actions();

            transport.clock.advance(1001);
            transport.poll();

            let actions = transport.drain_actions();
            assert!(
                has_path_request_broadcast(&actions, &dest_hash),
                "Should send path request broadcast for unvalidated link expiry"
            );
        }

        #[test]
        fn test_link_table_expiry_unvalidated_path_missing_sends_path_request() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_hash = [0xDD; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();

            // NO path entry — sub-case 1
            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 0,
                    remaining_hops: 2,
                    received_interface_index: 0,
                    hops: 0,
                    validated: false,
                    proof_timeout_ms: now + 1000,
                    destination_hash: dest_hash,
                },
            );

            transport.drain_events();
            transport.drain_actions();
            transport.clock.advance(1001);
            transport.poll();

            let actions = transport.drain_actions();
            assert!(
                has_path_request_broadcast(&actions, &dest_hash),
                "Should send path request broadcast when path is missing"
            );
        }

        #[test]
        fn test_link_table_expiry_validated_no_rediscovery() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let dest_hash = [0xDD; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();

            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 1,
                    expires_ms: now + 3_600_000,
                    interface_index: 0,
                    random_blobs: Vec::new(),
                    next_hop: None,
                },
            );

            // Validated link
            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 1,
                    remaining_hops: 1,
                    received_interface_index: 0,
                    hops: 0,
                    validated: true,
                    proof_timeout_ms: now + 1000,
                    destination_hash: dest_hash,
                },
            );

            transport.drain_events();
            transport.drain_actions();

            // Advance past LINK_TIMEOUT_MS
            transport.clock.advance(LINK_TIMEOUT_MS + 1000);
            transport.poll();

            // Link removed, but NO path request
            assert!(!transport.link_table.contains_key(&link_id));

            let actions = transport.drain_actions();
            assert!(
                !has_path_request_broadcast(&actions, &dest_hash),
                "Validated link expiry should NOT send path request"
            );

            // Path state unchanged
            assert!(!transport.path_is_unresponsive(&dest_hash));
        }

        #[test]
        fn test_expire_path_removes_entry() {
            let mut transport = make_transport_enabled();
            let dest_hash = [0x42; TRUNCATED_HASHBYTES];

            let now = transport.clock.now_ms();
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 1,
                    expires_ms: now + 3_600_000,
                    interface_index: 0,
                    random_blobs: Vec::new(),
                    next_hop: None,
                },
            );

            assert!(transport.has_path(&dest_hash));

            // Expire it
            assert!(transport.expire_path(&dest_hash));
            assert!(!transport.has_path(&dest_hash));

            // Should emit PathLost
            let events: Vec<_> = transport.drain_events().collect();
            let has_path_lost = events.iter().any(|e| {
                matches!(
                    e,
                    TransportEvent::PathLost { destination_hash }
                    if *destination_hash == dest_hash
                )
            });
            assert!(has_path_lost, "expire_path should emit PathLost");

            // Second call returns false
            assert!(!transport.expire_path(&dest_hash));
        }

        #[test]
        fn test_expire_path_allows_worse_hop_announce() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest = make_test_dest();
            let dest_hash = dest.hash().into_bytes();

            // Process announce A (hops=1)
            let rh_a = make_random_hash([0x01, 0x02, 0x03, 0x04, 0x05], 1000);
            let a1 = make_announce_raw_with_random_hash(&dest, 1, &rh_a);
            transport.process_incoming(0, &a1).unwrap();
            assert_eq!(transport.hops_to(&dest_hash), Some(1));

            // Expire path
            assert!(transport.expire_path(&dest_hash));
            assert!(!transport.has_path(&dest_hash));

            // Clear packet cache
            transport.packet_cache.clear();
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);

            // Process announce B (hops=5) — should be accepted (no existing path)
            let rh_b = make_random_hash([0x0A, 0x0B, 0x0C, 0x0D, 0x0E], 2000);
            let a2 = make_announce_raw_with_random_hash(&dest, 5, &rh_b);
            transport.process_incoming(0, &a2).unwrap();
            assert_eq!(
                transport.hops_to(&dest_hash),
                Some(5),
                "After expire_path, worse-hop announce should be accepted as new path"
            );
        }

        #[test]
        fn test_link_expiry_non_transport_calls_expire_path() {
            let mut transport = test_transport();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_hash = [0xDD; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();

            // Insert path entry
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 2,
                    expires_ms: now + 3_600_000,
                    interface_index: 0,
                    random_blobs: Vec::new(),
                    next_hop: None,
                },
            );

            // Insert unvalidated link
            let link_id = [0xAA; TRUNCATED_HASHBYTES];
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 0,
                    remaining_hops: 2,
                    received_interface_index: 0,
                    hops: 0,
                    validated: false,
                    proof_timeout_ms: now + 1000,
                    destination_hash: dest_hash,
                },
            );

            transport.drain_events();
            transport.drain_actions();

            transport.clock.advance(1001);
            transport.poll();

            // Non-transport node should force-expire the path
            assert!(
                !transport.has_path(&dest_hash),
                "Non-transport node should expire path on unvalidated link expiry"
            );

            let events: Vec<_> = transport.drain_events().collect();
            let has_path_lost = events.iter().any(|e| {
                matches!(
                    e,
                    TransportEvent::PathLost { destination_hash }
                    if *destination_hash == dest_hash
                )
            });
            assert!(has_path_lost, "Should emit PathLost");

            let actions = transport.drain_actions();
            assert!(
                has_path_request_broadcast(&actions, &dest_hash),
                "Should send path request broadcast"
            );
        }

        #[test]
        fn test_full_recovery_cycle() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let dest = make_test_dest();
            let dest_hash = dest.hash().into_bytes();

            // Step 1: Process announce A (hops=0 = directly connected)
            let emission = 5000u64;
            let rh_a = make_random_hash([0x01, 0x02, 0x03, 0x04, 0x05], emission);
            let a1 = make_announce_raw_with_random_hash(&dest, 0, &rh_a);
            transport.process_incoming(0, &a1).unwrap();
            assert_eq!(transport.hops_to(&dest_hash), Some(0));

            // Step 2: Insert unvalidated link_table entry (simulates relay)
            // hops=2 so sub-case 3 (initiator hops==0) doesn't take priority
            // over sub-case 2 (dest is_direct)
            let link_id = [0xCC; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.link_table.insert(
                link_id,
                LinkEntry {
                    timestamp_ms: now,
                    next_hop_interface_index: 1,
                    remaining_hops: 0,
                    received_interface_index: 0,
                    hops: 2,
                    validated: false,
                    proof_timeout_ms: now + 1000,
                    destination_hash: dest_hash,
                },
            );

            // Step 3: Advance past proof_timeout
            transport.clock.advance(1001);
            transport.drain_events();
            transport.poll();

            // Step 4: Verify sub-case 2 fired
            assert!(
                transport.path_is_unresponsive(&dest_hash),
                "Path should be marked unresponsive after unvalidated link expiry"
            );

            // Check path request broadcast was emitted
            let actions = transport.drain_actions();
            assert!(
                has_path_request_broadcast(&actions, &dest_hash),
                "Should send path request broadcast"
            );

            // Step 5: Clear packet cache and advance past rate limit
            transport.packet_cache.clear();
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);

            // Step 6: Process announce B (hops=3, same emission, different random)
            // Should be ACCEPTED because path is UNRESPONSIVE
            let rh_b = make_random_hash([0x0A, 0x0B, 0x0C, 0x0D, 0x0E], emission);
            let a2 = make_announce_raw_with_random_hash(&dest, 3, &rh_b);
            transport.process_incoming(1, &a2).unwrap();
            assert_eq!(
                transport.hops_to(&dest_hash),
                Some(3),
                "Worse-hop same-emission announce should be accepted for unresponsive path"
            );

            // Step 7: State should still be UNRESPONSIVE (not reset)
            assert!(
                transport.path_is_unresponsive(&dest_hash),
                "State should remain UNRESPONSIVE after same-emission update (per Python)"
            );

            // Step 8: Clear caches and process newer announce C
            transport.packet_cache.clear();
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);

            let rh_c = make_random_hash([0x10, 0x11, 0x12, 0x13, 0x14], emission + 1000);
            let a3 = make_announce_raw_with_random_hash(&dest, 2, &rh_c);
            transport.process_incoming(1, &a3).unwrap();
            assert_eq!(transport.hops_to(&dest_hash), Some(2));

            // Step 9: Normal announce should reset state to UNKNOWN
            assert!(
                !transport.path_is_unresponsive(&dest_hash),
                "State should be reset to UNKNOWN after normal announce acceptance"
            );
        }

        // ─── Announce Rate Limiting Tests ─────────────────────────────────

        /// Helper: create a transport with rate limiting enabled
        fn make_transport_rate_limited(
            target_ms: u64,
            grace: u8,
            penalty_ms: u64,
        ) -> Transport<MockClock, NoStorage> {
            let clock = MockClock::new(TEST_TIME_MS);
            let identity = Identity::generate(&mut OsRng);
            let config = TransportConfig {
                enable_transport: true,
                announce_rate_target_ms: Some(target_ms),
                announce_rate_grace: grace,
                announce_rate_penalty_ms: penalty_ms,
                ..TransportConfig::default()
            };
            Transport::new(config, clock, NoStorage, identity)
        }

        #[test]
        fn test_announce_rate_within_limit_accepted() {
            use crate::destination::{Destination, DestinationType, Direction};

            let mut transport = make_transport_rate_limited(5_000, 0, 0);
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest = Destination::new(
                Some(Identity::generate(&mut OsRng)),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["rate"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            // First announce
            let now1 = transport.clock.now_ms();
            let raw1 = make_announce_raw_for_dest(&dest, 1, now1);
            transport.process_incoming(0, &raw1).unwrap();
            assert!(transport.announce_table.contains_key(&dest_hash));
            assert_eq!(transport.announce_rate_table_count(), 1);

            // Advance past both the simple rate limit and the rate target
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 5_001);
            transport.packet_cache.clear();

            // Second announce — spaced well beyond target
            let now2 = transport.clock.now_ms();
            let raw2 = make_announce_raw_for_dest(&dest, 1, now2);
            transport.process_incoming(0, &raw2).unwrap();

            // Should be accepted into announce_table
            assert!(
                transport.announce_table.contains_key(&dest_hash),
                "Announce within rate limit should be accepted"
            );
        }

        #[test]
        fn test_announce_rate_exceeds_limit_after_grace() {
            use crate::destination::{Destination, DestinationType, Direction};

            // grace=0 means first violation triggers blocking
            let mut transport = make_transport_rate_limited(10_000, 0, 0);
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest = Destination::new(
                Some(Identity::generate(&mut OsRng)),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["rateblock"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            // First announce — creates rate entry
            let now1 = transport.clock.now_ms();
            let raw1 = make_announce_raw_for_dest(&dest, 1, now1);
            transport.process_incoming(0, &raw1).unwrap();
            assert!(transport.announce_table.contains_key(&dest_hash));
            assert!(transport.has_path(&dest_hash));

            // Advance past simple rate limit but LESS than rate target (10s)
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);
            transport.packet_cache.clear();

            // Second announce — too fast (2s < 10s target)
            let now2 = transport.clock.now_ms();
            let raw2 = make_announce_raw_for_dest(&dest, 1, now2);
            transport.process_incoming(0, &raw2).unwrap();

            // Path table SHOULD be updated (rate limiting only blocks rebroadcast)
            assert!(
                transport.has_path(&dest_hash),
                "Path table should still be updated even when rate-blocked"
            );

            // Announce table entry should NOT be updated (rebroadcast blocked)
            // The announce_table still has the first entry's timestamp
            let entry = transport.announce_table.get(&dest_hash).unwrap();
            assert_eq!(
                entry.timestamp_ms, now1,
                "Announce table should not be updated when rate-blocked"
            );
        }

        #[test]
        fn test_announce_rate_penalty_extends_blocking() {
            use crate::destination::{Destination, DestinationType, Direction};

            // 10s target + 5s penalty = blocking until last_ms + 15s
            let mut transport = make_transport_rate_limited(10_000, 0, 5_000);
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest = Destination::new(
                Some(Identity::generate(&mut OsRng)),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["penalty"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            // First announce at T=1_000_000
            let t0 = transport.clock.now_ms();
            let raw1 = make_announce_raw_for_dest(&dest, 1, t0);
            transport.process_incoming(0, &raw1).unwrap();

            // Trigger violation: advance 3s (< 10s target)
            transport.clock.advance(3_000);
            transport.packet_cache.clear();
            let now2 = transport.clock.now_ms();
            let raw2 = make_announce_raw_for_dest(&dest, 1, now2);
            transport.process_incoming(0, &raw2).unwrap();

            // blocked_until should be t0 + 10_000 + 5_000 = t0 + 15_000
            let rate_entry = transport.announce_rate_table.get(&dest_hash).unwrap();
            assert_eq!(rate_entry.blocked_until_ms, t0 + 10_000 + 5_000);

            // At t0 + 14_999 — still blocked
            transport.clock.set(t0 + 14_999);
            transport.packet_cache.clear();
            let now3 = transport.clock.now_ms();
            let raw3 = make_announce_raw_for_dest(&dest, 1, now3);
            transport.process_incoming(0, &raw3).unwrap();
            let entry = transport.announce_table.get(&dest_hash).unwrap();
            assert_eq!(
                entry.timestamp_ms, t0,
                "Should still be blocked at t0 + 14_999"
            );

            // At t0 + 15_001 — block expired
            transport.clock.set(t0 + 15_001);
            transport.packet_cache.clear();
            let now4 = transport.clock.now_ms();
            let raw4 = make_announce_raw_for_dest(&dest, 1, now4);
            transport.process_incoming(0, &raw4).unwrap();
            let entry = transport.announce_table.get(&dest_hash).unwrap();
            assert_eq!(
                entry.timestamp_ms, now4,
                "Should be accepted after block expires"
            );
        }

        #[test]
        fn test_announce_rate_independent_per_destination() {
            use crate::destination::{Destination, DestinationType, Direction};

            let mut transport = make_transport_rate_limited(10_000, 0, 0);
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest_a = Destination::new(
                Some(Identity::generate(&mut OsRng)),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["dest_a"],
            )
            .unwrap();
            let dest_b = Destination::new(
                Some(Identity::generate(&mut OsRng)),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["dest_b"],
            )
            .unwrap();
            let hash_a = dest_a.hash().into_bytes();
            let hash_b = dest_b.hash().into_bytes();

            // First announces for both
            let now1 = transport.clock.now_ms();
            let raw_a1 = make_announce_raw_for_dest(&dest_a, 1, now1);
            let raw_b1 = make_announce_raw_for_dest(&dest_b, 1, now1);
            transport.process_incoming(0, &raw_a1).unwrap();
            transport.process_incoming(0, &raw_b1).unwrap();

            // Trigger violation for dest_a only (too fast)
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);
            transport.packet_cache.clear();
            let now2 = transport.clock.now_ms();
            let raw_a2 = make_announce_raw_for_dest(&dest_a, 1, now2);
            transport.process_incoming(0, &raw_a2).unwrap();

            // dest_a should be rate-blocked (announce_table timestamp unchanged)
            let entry_a = transport.announce_table.get(&hash_a).unwrap();
            assert_eq!(entry_a.timestamp_ms, now1, "dest_a should be rate-blocked");

            // dest_b should still be able to accept announces
            let raw_b2 = make_announce_raw_for_dest(&dest_b, 1, now2);
            transport.process_incoming(0, &raw_b2).unwrap();

            // dest_b announce_table entry should be updated (not blocked)
            // Note: the simple rate limit (announce_rate_limit_ms) also applies,
            // but we already advanced past it. The rate target check is separate.
            // dest_b's rate entry: now2 - now1 = ANNOUNCE_RATE_LIMIT_MS + 1 < 10_000
            // So dest_b will ALSO be rate-blocked. Let's verify independence differently:
            // advance enough for dest_b to be within target
            transport.clock.advance(10_000);
            transport.packet_cache.clear();
            let now3 = transport.clock.now_ms();
            let raw_b3 = make_announce_raw_for_dest(&dest_b, 1, now3);
            transport.process_incoming(0, &raw_b3).unwrap();

            let entry_b = transport.announce_table.get(&hash_b).unwrap();
            assert_eq!(
                entry_b.timestamp_ms, now3,
                "dest_b should be accepted (not blocked by dest_a's violation)"
            );

            // dest_a should STILL be blocked (blocked_until = now1 + 10_000)
            // now3 = now1 + ANNOUNCE_RATE_LIMIT_MS + 1 + 10_000 = now1 + 12_001
            // blocked_until = now1 + 10_000 = now1 + 10_000
            // now3 > blocked_until, so dest_a block has expired by now
            // But the rate entry's last_ms is still now1, so current_rate = now3 - now1 > target
            // which means violations would decrement. So dest_a should now be unblocked too.
        }

        #[test]
        fn test_announce_rate_violations_decrement_on_good_rate() {
            use crate::destination::{Destination, DestinationType, Direction};

            // grace=2 means 3 violations needed to trigger blocking
            let mut transport = make_transport_rate_limited(5_000, 2, 0);
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest = Destination::new(
                Some(Identity::generate(&mut OsRng)),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["decrement"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            // First announce
            let t0 = transport.clock.now_ms();
            let raw1 = make_announce_raw_for_dest(&dest, 1, t0);
            transport.process_incoming(0, &raw1).unwrap();

            // Violation 1: too fast (2s < 5s)
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);
            transport.packet_cache.clear();
            let raw2 = make_announce_raw_for_dest(&dest, 1, transport.clock.now_ms());
            transport.process_incoming(0, &raw2).unwrap();

            let rate_entry = transport.announce_rate_table.get(&dest_hash).unwrap();
            assert_eq!(rate_entry.rate_violations, 1, "Should have 1 violation");

            // Violation 2: too fast again
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);
            transport.packet_cache.clear();
            let raw3 = make_announce_raw_for_dest(&dest, 1, transport.clock.now_ms());
            transport.process_incoming(0, &raw3).unwrap();

            let rate_entry = transport.announce_rate_table.get(&dest_hash).unwrap();
            assert_eq!(rate_entry.rate_violations, 2, "Should have 2 violations");

            // Good rate: advance well past target (10s > 5s)
            transport.clock.advance(10_000);
            transport.packet_cache.clear();
            let now_good = transport.clock.now_ms();
            let raw4 = make_announce_raw_for_dest(&dest, 1, now_good);
            transport.process_incoming(0, &raw4).unwrap();

            let rate_entry = transport.announce_rate_table.get(&dest_hash).unwrap();
            assert_eq!(
                rate_entry.rate_violations, 1,
                "Violations should decrement on good rate"
            );

            // Another good rate
            transport.clock.advance(10_000);
            transport.packet_cache.clear();
            let raw5 = make_announce_raw_for_dest(&dest, 1, transport.clock.now_ms());
            transport.process_incoming(0, &raw5).unwrap();

            let rate_entry = transport.announce_rate_table.get(&dest_hash).unwrap();
            assert_eq!(
                rate_entry.rate_violations, 0,
                "Violations should be back to 0 after enough good-rate announces"
            );

            // Announce should be accepted (not blocked)
            assert!(
                transport.announce_table.contains_key(&dest_hash),
                "Announce should be accepted when violations are within grace"
            );
        }

        #[test]
        fn test_announce_rate_recovery_after_block_expires() {
            use crate::destination::{Destination, DestinationType, Direction};

            let mut transport = make_transport_rate_limited(10_000, 0, 0);
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest = Destination::new(
                Some(Identity::generate(&mut OsRng)),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["recovery"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            // First announce at T0
            let t0 = transport.clock.now_ms();
            let raw1 = make_announce_raw_for_dest(&dest, 1, t0);
            transport.process_incoming(0, &raw1).unwrap();

            // Trigger blocking (too fast)
            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);
            transport.packet_cache.clear();
            let raw2 = make_announce_raw_for_dest(&dest, 1, transport.clock.now_ms());
            transport.process_incoming(0, &raw2).unwrap();

            // Verify blocked
            let rate_entry = transport.announce_rate_table.get(&dest_hash).unwrap();
            assert!(rate_entry.blocked_until_ms > 0, "Should be blocked");

            // Advance past blocked_until (t0 + 10_000)
            transport.clock.set(t0 + 10_001);
            transport.packet_cache.clear();
            let now_after = transport.clock.now_ms();
            let raw3 = make_announce_raw_for_dest(&dest, 1, now_after);
            transport.process_incoming(0, &raw3).unwrap();

            // current_rate = now_after - t0 = 10_001 > 10_000 target → good rate
            // violations decrement from 1 to 0, not blocked
            let entry = transport.announce_table.get(&dest_hash).unwrap();
            assert_eq!(
                entry.timestamp_ms, now_after,
                "Announce should be accepted after block expires"
            );
        }

        #[test]
        fn test_announce_rate_disabled_by_default() {
            // Default config has announce_rate_target_ms: None
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest = crate::destination::Destination::new(
                Some(Identity::generate(&mut OsRng)),
                crate::destination::Direction::In,
                crate::destination::DestinationType::Single,
                "testapp",
                &["norlimit"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            // Rapid announces (only bypass simple rate limit and packet cache)
            let now1 = transport.clock.now_ms();
            let raw1 = make_announce_raw_for_dest(&dest, 1, now1);
            transport.process_incoming(0, &raw1).unwrap();
            assert!(transport.announce_table.contains_key(&dest_hash));

            transport.clock.advance(ANNOUNCE_RATE_LIMIT_MS + 1);
            transport.packet_cache.clear();
            let now2 = transport.clock.now_ms();
            let raw2 = make_announce_raw_for_dest(&dest, 1, now2);
            transport.process_incoming(0, &raw2).unwrap();

            // Should be accepted (rate limiting is disabled)
            let entry = transport.announce_table.get(&dest_hash).unwrap();
            assert_eq!(
                entry.timestamp_ms, now2,
                "Announce should be accepted when rate limiting is disabled"
            );

            // No rate table entries should exist
            assert_eq!(
                transport.announce_rate_table_count(),
                0,
                "Rate table should be empty when rate limiting is disabled"
            );
        }

        #[test]
        fn test_announce_rate_path_response_exempt() {
            let mut transport = make_transport_rate_limited(10_000, 0, 0);
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            // Use make_announce_raw which supports context
            let (raw, dest_hash) = make_announce_raw(1, PacketContext::PathResponse);
            transport.process_incoming(0, &raw).unwrap();

            // PATH_RESPONSE should not create a rate entry
            assert_eq!(
                transport.announce_rate_table_count(),
                0,
                "PATH_RESPONSE announces should not be rate-tracked"
            );

            // Should be in announce_table
            assert!(
                transport.announce_table.contains_key(&dest_hash),
                "PATH_RESPONSE announce should be in announce_table"
            );
        }

        #[test]
        fn test_announce_rate_table_cleanup() {
            use crate::destination::{Destination, DestinationType, Direction};

            let mut transport = make_transport_rate_limited(10_000, 0, 0);
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest = Destination::new(
                Some(Identity::generate(&mut OsRng)),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["cleanup"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            // Create announce to populate path_table and rate_table
            let now = transport.clock.now_ms();
            let raw = make_announce_raw_for_dest(&dest, 1, now);
            transport.process_incoming(0, &raw).unwrap();
            assert_eq!(transport.announce_rate_table_count(), 1);
            assert!(transport.has_path(&dest_hash));

            // Remove from path_table
            transport.path_table.remove(&dest_hash);

            // Run poll to trigger cleanup
            transport.poll();

            assert_eq!(
                transport.announce_rate_table_count(),
                0,
                "Rate table entry should be cleaned up when path is removed"
            );
        }

        #[test]
        fn test_announce_rate_last_ms_not_updated_on_violation() {
            use crate::destination::{Destination, DestinationType, Direction};

            // grace=0: first violation immediately triggers blocking
            let mut transport = make_transport_rate_limited(10_000, 0, 0);
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let dest = Destination::new(
                Some(Identity::generate(&mut OsRng)),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["lastms"],
            )
            .unwrap();
            let dest_hash = dest.hash().into_bytes();

            // First announce at T0
            let t0 = transport.clock.now_ms();
            let raw1 = make_announce_raw_for_dest(&dest, 1, t0);
            transport.process_incoming(0, &raw1).unwrap();

            let rate_entry = transport.announce_rate_table.get(&dest_hash).unwrap();
            assert_eq!(rate_entry.last_ms, t0);

            // Violation: too fast (3s < 10s target) — triggers blocking (grace=0)
            transport.clock.advance(3_000);
            transport.packet_cache.clear();
            let now2 = transport.clock.now_ms();
            let raw2 = make_announce_raw_for_dest(&dest, 1, now2);
            transport.process_incoming(0, &raw2).unwrap();

            // last_ms should NOT be updated — blocking was triggered
            let rate_entry = transport.announce_rate_table.get(&dest_hash).unwrap();
            assert_eq!(
                rate_entry.last_ms, t0,
                "last_ms should not be updated when violation triggers blocking"
            );
            assert_eq!(rate_entry.rate_violations, 1);
            assert!(
                rate_entry.blocked_until_ms > 0,
                "Should be blocked after violation with grace=0"
            );

            // Another too-fast announce while blocked — last_ms still anchored
            transport.clock.advance(3_000);
            transport.packet_cache.clear();
            let now3 = transport.clock.now_ms();
            let raw3 = make_announce_raw_for_dest(&dest, 1, now3);
            transport.process_incoming(0, &raw3).unwrap();

            let rate_entry = transport.announce_rate_table.get(&dest_hash).unwrap();
            assert_eq!(
                rate_entry.last_ms, t0,
                "last_ms should still be anchored to original accepted announce"
            );
        }

        // ─── T11: Transport Gap Tests ───────────────────────────────────

        #[test]
        fn test_hop_limit_forward_drops_at_max() {
            // A packet at PATHFINDER_MAX_HOPS gets +1 on forward → exceeds limit → dropped
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));
            let _idx1 = transport.register_interface(Box::new(MockInterface::new("if1", 2)));

            let dest_hash = [0x42; TRUNCATED_HASHBYTES];
            let now = transport.clock.now_ms();
            transport.path_table.insert(
                dest_hash,
                PathEntry {
                    hops: 1,
                    expires_ms: now + 100_000,
                    interface_index: 1,
                    random_blobs: Vec::new(),
                    next_hop: None,
                },
            );

            // Register as a local destination so process_incoming doesn't just
            // drop it as unregistered — but we need it to go through forwarding.
            // Actually: for forwarding, the destination must NOT be local but
            // must have a path. Also need enable_transport=true (done above).

            // Build a data packet with hops = PATHFINDER_MAX_HOPS (128)
            let pkt = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: crate::destination::DestinationType::Single,
                    packet_type: PacketType::Data,
                },
                hops: PATHFINDER_MAX_HOPS,
                transport_id: None,
                destination_hash: dest_hash,
                context: PacketContext::None,
                data: PacketData::Owned(b"should be dropped".to_vec()),
            };

            let mut buf = [0u8; 500];
            let len = pkt.pack(&mut buf).unwrap();
            let forwarded_before = transport.stats().packets_forwarded;
            transport.process_incoming(0, &buf[..len]).unwrap();

            assert_eq!(
                transport.stats().packets_forwarded,
                forwarded_before,
                "Packet at max hops should NOT be forwarded (saturating_add(1) → 129 > 128)"
            );
        }

        #[test]
        fn test_announce_invalid_signature_dropped_at_transport() {
            let mut transport = make_transport_enabled();
            let _idx0 = transport.register_interface(Box::new(MockInterface::new("if0", 1)));

            let (mut raw, dest_hash) = make_announce_raw(2, PacketContext::None);

            // Tamper with one byte near the end (in the signature region)
            // Announce payload layout: public_key(64) + name_hash(16) + random(16) + signature(64) + app_data
            // The raw bytes include the header, so tamper near the end of raw data
            let tamper_idx = raw.len() - 10;
            raw[tamper_idx] ^= 0xFF;

            // process_incoming returns an error for invalid signatures —
            // the important thing is that no path is created
            let _ = transport.process_incoming(0, &raw);

            assert!(
                !transport.has_path(&dest_hash),
                "Tampered announce should not create a path"
            );
            assert_eq!(
                transport.stats().announces_processed,
                0,
                "Tampered announce should not be counted as processed"
            );
        }

        #[test]
        fn test_create_and_get_receipt() {
            let mut transport = test_transport();
            let dest_hash = [0x42; TRUNCATED_HASHBYTES];

            // Build a minimal valid packet to create a receipt from
            let pkt = Packet {
                flags: PacketFlags {
                    ifac_flag: false,
                    header_type: HeaderType::Type1,
                    context_flag: false,
                    transport_type: TransportType::Broadcast,
                    dest_type: crate::destination::DestinationType::Single,
                    packet_type: PacketType::Data,
                },
                hops: 0,
                transport_id: None,
                destination_hash: dest_hash,
                context: PacketContext::None,
                data: PacketData::Owned(b"receipt test".to_vec()),
            };

            let mut buf = [0u8; 500];
            let len = pkt.pack(&mut buf).unwrap();
            let raw = &buf[..len];

            let truncated = transport.create_receipt(raw, dest_hash);

            // Should be retrievable
            let receipt = transport.get_receipt(&truncated);
            assert!(receipt.is_some(), "Receipt should exist after creation");

            let receipt = receipt.unwrap();
            assert_eq!(
                receipt.destination_hash,
                crate::destination::DestinationHash::new(dest_hash),
                "Receipt should contain correct destination hash"
            );
        }
    }
}
