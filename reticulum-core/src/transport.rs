//! Routing and path discovery
//!
//! The Transport layer handles:
//! - Packet routing based on destination hash
//! - Path discovery via announces
//! - Link table management
//! - Interface coordination
//! - Duplicate detection

use crate::constants::{
    PATHFINDER_EXPIRY_SECS, PATHFINDER_MAX_HOPS, TRUNCATED_HASHBYTES,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Path table entry
#[derive(Debug, Clone)]
pub struct PathEntry {
    /// When this path was learned
    pub timestamp: u64,
    /// Hash of the interface that told us about this path
    pub received_from: [u8; TRUNCATED_HASHBYTES],
    /// Number of hops to destination
    pub hops: u8,
    /// When this path expires
    pub expires: u64,
    /// Interface index where we learned this path
    pub interface_index: usize,
    /// Hash of the announce packet
    pub packet_hash: [u8; TRUNCATED_HASHBYTES],
}

/// Link table entry (for active links through this node)
#[derive(Debug, Clone)]
pub struct LinkEntry {
    /// Number of hops
    pub hops: u8,
    /// When this was learned
    pub timestamp: u64,
    /// Interface index
    pub interface_index: usize,
}

/// Reverse table entry (for routing replies back)
#[derive(Debug, Clone)]
pub struct ReverseEntry {
    /// When this was learned
    pub timestamp: u64,
    /// Who sent this to us
    pub received_from: [u8; TRUNCATED_HASHBYTES],
    /// Interface index
    pub interface_index: usize,
}

/// Announce table entry (for rebroadcast tracking)
#[derive(Debug, Clone)]
pub struct AnnounceEntry {
    /// When we received this announce
    pub timestamp: u64,
    /// Who sent it to us
    pub received_from: [u8; TRUNCATED_HASHBYTES],
    /// Number of retransmit attempts
    pub retries: u8,
    /// Interface indices to rebroadcast on
    #[cfg(feature = "alloc")]
    pub interfaces: Vec<usize>,
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
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            enable_transport: false,
            max_hops: PATHFINDER_MAX_HOPS,
            path_expiry_secs: PATHFINDER_EXPIRY_SECS,
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
    /// Packets forwarded
    pub packets_forwarded: u64,
    /// Announces processed
    pub announces_processed: u64,
    /// Path requests sent
    pub path_requests_sent: u64,
    /// Path requests received
    pub path_requests_received: u64,
}

// The actual Transport implementation will be in reticulum-std
// since it needs async runtime, interfaces, etc.
// This module defines the data structures and traits.

/// Trait for transport layer implementations
pub trait TransportLayer {
    /// Register a destination to receive packets
    fn register_destination(&mut self, hash: [u8; TRUNCATED_HASHBYTES]);

    /// Unregister a destination
    fn unregister_destination(&mut self, hash: &[u8; TRUNCATED_HASHBYTES]);

    /// Check if a path exists to a destination
    fn has_path(&self, destination: &[u8; TRUNCATED_HASHBYTES]) -> bool;

    /// Get the hop count to a destination
    fn hops_to(&self, destination: &[u8; TRUNCATED_HASHBYTES]) -> Option<u8>;

    /// Request a path to a destination
    fn request_path(&mut self, destination: [u8; TRUNCATED_HASHBYTES]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TransportConfig::default();
        assert!(!config.enable_transport);
        assert_eq!(config.max_hops, PATHFINDER_MAX_HOPS);
    }
}
