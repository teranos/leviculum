//! Resource protocol for reliable transfer of large data over a [`Link`](crate::Link).
//!
//! While [`Channel`](crate::Channel) handles small messages (up to ~400 bytes
//! per envelope), resources transfer kilobytes to megabytes by segmenting data
//! into parts and using a sliding window for throughput.
//!
//! # Transfer Flow
//!
//! 1. Sender creates a resource from raw data and a link
//! 2. Sender advertises the resource to the remote peer
//! 3. Receiver accepts (or rejects) the advertisement
//! 4. Parts are sent using a sliding window with automatic retransmission
//! 5. Receiver verifies the reassembled data against a hash
//! 6. Receiver sends a completion proof back to the sender
//!
//! # State Machine
//!
//! ```text
//! None → Queued → Advertised → Transferring → AwaitingProof → Complete
//!                                    ↓
//!                              Failed / Corrupt
//! ```
//!
//! # Current Status
//!
//! This module provides data structures and configuration for the resource
//! protocol. The full transfer implementation is planned for Phase 3
//! (version 0.3.0).

use crate::constants::{
    RESOURCE_HASHMAP_LEN, RESOURCE_WINDOW_INITIAL, RESOURCE_WINDOW_MAX_FAST,
    RESOURCE_WINDOW_MAX_SLOW, RESOURCE_WINDOW_MIN,
};

/// Resource state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceState {
    /// Not yet started
    None,
    /// Waiting to be advertised
    Queued,
    /// Advertised, waiting for acceptance
    Advertised,
    /// Actively transferring parts
    Transferring,
    /// Waiting for completion proof
    AwaitingProof,
    /// Receiver assembling parts
    Assembling,
    /// Transfer complete
    Complete,
    /// Transfer failed
    Failed,
    /// Data integrity error
    Corrupt,
}

/// Resource transfer error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceError {
    /// Resource too large
    TooLarge,
    /// Invalid state for operation
    InvalidState,
    /// Transfer timeout
    Timeout,
    /// Hash verification failed
    HashMismatch,
    /// Link not available
    NoLink,
    /// Rejected by receiver
    Rejected,
    /// Cancelled
    Cancelled,
}

/// Resource configuration
#[derive(Debug, Clone)]
pub struct ResourceConfig {
    /// Initial window size
    pub window_initial: usize,
    /// Minimum window size
    pub window_min: usize,
    /// Maximum window size for slow links
    pub window_max_slow: usize,
    /// Maximum window size for fast links
    pub window_max_fast: usize,
    /// Hash map entry length
    pub hashmap_len: usize,
    /// Enable compression
    pub compress: bool,
    /// Maximum retries per part
    pub max_retries: u8,
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            window_initial: RESOURCE_WINDOW_INITIAL,
            window_min: RESOURCE_WINDOW_MIN,
            window_max_slow: RESOURCE_WINDOW_MAX_SLOW,
            window_max_fast: RESOURCE_WINDOW_MAX_FAST,
            hashmap_len: RESOURCE_HASHMAP_LEN,
            compress: true,
            max_retries: 16,
        }
    }
}

/// Resource transfer statistics
#[derive(Debug, Default, Clone)]
pub struct ResourceStats {
    /// Total size in bytes
    pub total_size: usize,
    /// Bytes transferred
    pub bytes_transferred: usize,
    /// Total parts
    pub total_parts: usize,
    /// Parts transferred
    pub parts_transferred: usize,
    /// Parts retransmitted
    pub parts_retransmitted: usize,
    /// Current window size
    pub current_window: usize,
    /// Transfer rate (bytes per second)
    pub transfer_rate: f64,
}

/// Part hash for verification
pub type PartHash = [u8; RESOURCE_HASHMAP_LEN];

/// Resource part metadata
#[derive(Debug, Clone)]
pub struct ResourcePart {
    /// Part index
    pub index: usize,
    /// Part hash
    pub hash: PartHash,
    /// Part data offset in resource
    pub offset: usize,
    /// Part data length
    pub length: usize,
    /// Whether this part has been received/sent
    pub transferred: bool,
    /// Retry count
    pub retries: u8,
}

// Resource transfer protocol logic belongs here in reticulum-core.
// Only the async driver (scheduling, I/O) belongs in reticulum-std.
// This module currently defines the data structures.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ResourceConfig::default();
        assert_eq!(config.window_initial, RESOURCE_WINDOW_INITIAL);
        assert!(config.compress);
    }

    #[test]
    fn test_resource_state_transitions() {
        // Document valid state transitions
        let valid_transitions = [
            (ResourceState::None, ResourceState::Queued),
            (ResourceState::Queued, ResourceState::Advertised),
            (ResourceState::Advertised, ResourceState::Transferring),
            (ResourceState::Transferring, ResourceState::AwaitingProof),
            (ResourceState::AwaitingProof, ResourceState::Complete),
            (ResourceState::Transferring, ResourceState::Failed),
        ];

        // This test documents expected behavior
        assert!(!valid_transitions.is_empty());
    }
}
