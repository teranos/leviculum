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
use alloc::vec::Vec;

use crate::constants::{PATHFINDER_EXPIRY_SECS, PATHFINDER_MAX_HOPS, TRUNCATED_HASHBYTES};

// ─── Transport Time Constants ────────────────────────────────────────────────

/// Default announce rate limit interval in milliseconds
const ANNOUNCE_RATE_LIMIT_DEFAULT_MS: u64 = 2_000;
/// Default packet cache expiry time in milliseconds
const PACKET_CACHE_EXPIRY_DEFAULT_MS: u64 = 60_000;
/// Reverse table entry expiry time in milliseconds
const REVERSE_TABLE_EXPIRY_MS: u64 = 60_000;
/// Milliseconds per second (for retransmit delay calculation)
const MS_PER_SECOND: u64 = 1_000;

use crate::announce::ReceivedAnnounce;
use crate::crypto::truncated_hash;
use crate::identity::Identity;
use crate::packet::{Packet, PacketError, PacketType};
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
}

/// Link table entry (for active links through this node)
#[derive(Debug, Clone)]
pub struct LinkEntry {
    /// Number of hops
    pub hops: u8,
    /// When this was learned (ms)
    pub timestamp_ms: u64,
    /// Interface index
    pub interface_index: usize,
}

/// Reverse table entry (for routing replies back)
#[derive(Debug, Clone)]
pub struct ReverseEntry {
    /// When this was learned (ms)
    pub timestamp_ms: u64,
    /// Who sent this to us
    pub received_from: [u8; TRUNCATED_HASHBYTES],
    /// Interface index
    pub interface_index: usize,
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
            announce_rate_limit_ms: ANNOUNCE_RATE_LIMIT_DEFAULT_MS,
            packet_cache_expiry_ms: PACKET_CACHE_EXPIRY_DEFAULT_MS,
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
    /// An interface went offline
    InterfaceDown(usize),
}

// ─── Error Types ────────────────────────────────────────────────────────────

/// Transport error type
#[derive(Debug)]
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

    /// Pending events for the application
    events: Vec<TransportEvent>,

    /// Statistics
    stats: TransportStats,
}

impl<C: Clock, S: Storage> Transport<C, S> {
    /// Create a new Transport instance
    pub fn new(config: TransportConfig, clock: C, storage: S, identity: Identity) -> Self {
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
            events: Vec::new(),
            stats: TransportStats::default(),
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

    /// Get the number of registered interfaces
    pub fn interface_count(&self) -> usize {
        self.interfaces.iter().filter(|i| i.is_some()).count()
    }

    // ─── Destination Management ─────────────────────────────────────────

    /// Register a destination to receive packets
    pub fn register_destination(&mut self, hash: [u8; TRUNCATED_HASHBYTES], accepts_links: bool) {
        self.destinations
            .insert(hash, DestinationEntry { accepts_links });
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

        // Compute packet hash for deduplication
        let packet_hash = truncated_hash(raw);
        let now = self.clock.now_ms();

        // Check duplicate
        if self.packet_cache.contains_key(&packet_hash) {
            self.stats.packets_dropped += 1;
            return Ok(());
        }

        // Cache this packet hash
        self.packet_cache.insert(packet_hash, now);

        // Store reverse path for replies
        if let Some(iface) = self
            .interfaces
            .get(interface_index)
            .and_then(|i| i.as_ref())
        {
            self.reverse_table.insert(
                packet_hash,
                ReverseEntry {
                    timestamp_ms: now,
                    received_from: iface.hash(),
                    interface_index,
                },
            );
        }

        // Route to handler based on packet type
        match packet.flags.packet_type {
            PacketType::Announce => self.handle_announce(packet, interface_index),
            PacketType::LinkRequest => self.handle_link_request(packet, interface_index),
            PacketType::Proof => self.handle_proof(packet, interface_index),
            PacketType::Data => self.handle_data(packet, interface_index),
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

    /// Poll for periodic work
    ///
    /// Call this regularly (e.g. every 100ms). Handles:
    /// - Path expiry
    /// - Packet cache cleanup
    /// - Announce retransmission (if transport node)
    pub fn poll(&mut self) {
        let now = self.clock.now_ms();
        self.expire_paths(now);
        self.clean_packet_cache(now);
        self.clean_reverse_table(now);
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

    // ─── Internal: Packet Handlers ──────────────────────────────────────

    fn handle_announce(
        &mut self,
        packet: Packet,
        interface_index: usize,
    ) -> Result<(), TransportError> {
        let now = self.clock.now_ms();

        // Parse announce
        let announce =
            ReceivedAnnounce::from_packet(&packet).map_err(TransportError::AnnounceError)?;

        // Validate signature and destination hash
        announce.validate().map_err(TransportError::AnnounceError)?;

        let dest_hash = *announce.destination_hash();

        // Rate limiting: check if we've seen this destination recently
        if let Some(entry) = self.announce_table.get(&dest_hash) {
            let elapsed = now.saturating_sub(entry.timestamp_ms);
            if elapsed < self.config.announce_rate_limit_ms {
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

        self.path_table.insert(
            dest_hash,
            PathEntry {
                timestamp_ms: now,
                received_from: iface_hash,
                hops: packet.hops,
                expires_ms: now + (self.config.path_expiry_secs * 1000),
                interface_index,
            },
        );

        // Update announce table
        self.announce_table.insert(
            dest_hash,
            AnnounceEntry {
                timestamp_ms: now,
                hops: packet.hops,
                retries: 0,
                retransmit_at_ms: if self.config.enable_transport {
                    Some(now + self.calculate_retransmit_delay(packet.hops))
                } else {
                    None
                },
            },
        );

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

        // If we're a transport node, forward the link request
        if self.config.enable_transport {
            self.forward_packet(packet)?;
        }

        Ok(())
    }

    fn handle_proof(
        &mut self,
        packet: Packet,
        interface_index: usize,
    ) -> Result<(), TransportError> {
        let dest_hash = packet.destination_hash;

        // Check if this is for a registered destination
        if self.destinations.contains_key(&dest_hash) {
            self.events.push(TransportEvent::PacketReceived {
                destination_hash: dest_hash,
                packet: Box::new(packet),
                interface_index,
            });
            return Ok(());
        }

        // If we're a transport node, check link table for routing
        if self.config.enable_transport {
            if let Some(link_entry) = self.link_table.get(&dest_hash) {
                let target_iface = link_entry.interface_index;
                return self.send_packet_on_interface(target_iface, &packet);
            }
        }

        Ok(())
    }

    fn handle_data(
        &mut self,
        packet: Packet,
        interface_index: usize,
    ) -> Result<(), TransportError> {
        let dest_hash = packet.destination_hash;

        // Check if we have this destination registered
        if self.destinations.contains_key(&dest_hash) {
            self.events.push(TransportEvent::PacketReceived {
                destination_hash: dest_hash,
                packet: Box::new(packet),
                interface_index,
            });
            return Ok(());
        }

        // If we're a transport node, try to forward
        if self.config.enable_transport {
            self.forward_packet(packet)?;
        }

        Ok(())
    }

    // ─── Internal: Forwarding ───────────────────────────────────────────

    fn forward_packet(&mut self, mut packet: Packet) -> Result<(), TransportError> {
        packet.hops = packet.hops.saturating_add(1);
        if packet.hops > self.config.max_hops {
            self.stats.packets_dropped += 1;
            return Ok(()); // TTL exceeded
        }

        // Look up path
        if let Some(path) = self.path_table.get(&packet.destination_hash) {
            let target_iface = path.interface_index;
            self.stats.packets_forwarded += 1;
            return self.send_packet_on_interface(target_iface, &packet);
        }

        // No path, drop silently
        self.stats.packets_dropped += 1;
        Ok(())
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

    fn calculate_retransmit_delay(&self, hops: u8) -> u64 {
        // Longer delay for closer announces (they spread faster naturally)
        ((hops as u64) + 1) * MS_PER_SECOND
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

        fn make_transport() -> Transport<MockClock, NoStorage> {
            let clock = MockClock::new(1_000_000);
            let identity = Identity::generate_with_rng(&mut OsRng);
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
                    expires_ms: now + 3600_000,
                    interface_index: 0,
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
            let identity = Identity::generate_with_rng(&mut OsRng);
            let dest = Destination::new(
                Some(identity),
                Direction::In,
                DestinationType::Single,
                "testapp",
                &["echo"],
            );

            let id = dest.identity().unwrap();
            let random_hash = [0x42u8; crate::constants::RANDOM_HASHBYTES];

            let mut payload = Vec::new();
            payload.extend_from_slice(&id.public_key_bytes());
            payload.extend_from_slice(dest.name_hash());
            payload.extend_from_slice(&random_hash);

            let app_data = b"test.data";

            // Sign
            let mut signed_data = Vec::new();
            signed_data.extend_from_slice(dest.hash());
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
                destination_hash: *dest.hash(),
                context: PacketContext::None,
                data: PacketData::Owned(payload),
            };

            let mut buf = [0u8; 500];
            let len = packet.pack(&mut buf).unwrap();

            transport.process_incoming(0, &buf[..len]).unwrap();

            // Should have path now
            assert!(transport.has_path(dest.hash()));
            assert_eq!(transport.hops_to(dest.hash()), Some(2));
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
    }
}
