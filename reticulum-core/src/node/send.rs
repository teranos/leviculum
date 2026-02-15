//! Smart send logic for automatic routing decisions
//!
//! This module provides the logic for automatically choosing the best
//! transport method based on send options and network state.

use alloc::vec::Vec;

use crate::constants::TRUNCATED_HASHBYTES;
use crate::link::LinkId;

/// Handle for tracking a sent message
///
/// The handle contains information about how the message was sent
/// and can be used to check delivery status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendHandle {
    /// The packet hash (for tracking proofs/delivery)
    pub packet_hash: [u8; TRUNCATED_HASHBYTES],
    /// How the message was sent
    pub method: SendMethod,
}

impl SendHandle {
    /// Create a new send handle
    pub fn new(packet_hash: [u8; TRUNCATED_HASHBYTES], method: SendMethod) -> Self {
        Self {
            packet_hash,
            method,
        }
    }
}

/// The method used to send a message
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendMethod {
    /// Sent as a single unreliable packet
    SinglePacket,
    /// Sent via an existing Link
    ExistingLink(LinkId),
    /// Sent via a newly established Link
    NewLink(LinkId),
    /// Sent via Channel (reliable, ordered)
    Channel(LinkId),
}

/// Error type for send operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// No path to the destination
    NoPath,
    /// Data too large for single packet (use Link/Channel instead)
    TooLarge,
    /// No existing connection and couldn't establish one
    NoConnection,
    /// Connection/link failed
    ConnectionFailed,
    /// Channel window is full (mirrors [`ChannelError::WindowFull`])
    WindowFull,
    /// Channel is pacing sends — retry at the given time (mirrors [`ChannelError::PacingDelay`])
    PacingDelay { ready_at_ms: u64 },
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SendError::NoPath => write!(f, "no path to destination"),
            SendError::TooLarge => write!(f, "data too large for single packet"),
            SendError::NoConnection => write!(f, "no connection available"),
            SendError::ConnectionFailed => write!(f, "connection failed"),
            SendError::WindowFull => write!(f, "channel window full"),
            SendError::PacingDelay { ready_at_ms } => {
                write!(f, "pacing delay until {}ms", ready_at_ms)
            }
        }
    }
}

/// Routing decision for a send operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Send as a single unreliable packet
    SinglePacket,
    /// Use an existing connection
    UseExistingConnection(LinkId),
    /// Establish a new connection
    EstablishConnection,
    /// Cannot send (no path available)
    CannotSend,
}

/// Determine the best routing method for a message
///
/// # Arguments
/// * `data_len` - Length of the data to send
/// * `reliable` - Whether reliable delivery is required
/// * `prefer_existing` - Whether to prefer existing connections
/// * `has_path` - Whether a path to the destination is known
/// * `existing_connection` - ID of an existing active connection, if any
/// * `max_single_packet_size` - Maximum size for single-packet delivery
///
/// # Returns
/// The routing decision to use
pub(super) fn decide_routing(
    data_len: usize,
    reliable: bool,
    prefer_existing: bool,
    has_path: bool,
    existing_connection: Option<LinkId>,
    max_single_packet_size: usize,
) -> RoutingDecision {
    // If we have an existing connection and prefer it, use it
    if prefer_existing {
        if let Some(link_id) = existing_connection {
            return RoutingDecision::UseExistingConnection(link_id);
        }
    }

    // If reliable delivery is required, we need a connection
    if reliable {
        if let Some(link_id) = existing_connection {
            return RoutingDecision::UseExistingConnection(link_id);
        }
        // Need to establish a new connection
        if has_path {
            return RoutingDecision::EstablishConnection;
        } else {
            return RoutingDecision::CannotSend;
        }
    }

    // Unreliable delivery - prefer single packet if possible
    if data_len <= max_single_packet_size && has_path {
        return RoutingDecision::SinglePacket;
    }

    // Data too large for single packet - need connection
    if let Some(link_id) = existing_connection {
        return RoutingDecision::UseExistingConnection(link_id);
    }

    if has_path {
        return RoutingDecision::EstablishConnection;
    }

    RoutingDecision::CannotSend
}

/// Result of a send operation
#[derive(Debug)]
pub struct SendResult {
    /// Handle for tracking the sent message
    pub handle: SendHandle,
    /// Packet data to transmit (if any)
    pub packet_data: Option<Vec<u8>>,
    /// Whether a connection needs to be established
    pub needs_connection: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routing_unreliable_small_with_path() {
        let decision = decide_routing(
            100,   // data_len
            false, // reliable
            true,  // prefer_existing
            true,  // has_path
            None,  // existing_connection
            500,   // max_single_packet_size
        );
        assert_eq!(decision, RoutingDecision::SinglePacket);
    }

    #[test]
    fn test_routing_unreliable_small_no_path() {
        let decision = decide_routing(
            100,   // data_len
            false, // reliable
            true,  // prefer_existing
            false, // has_path
            None,  // existing_connection
            500,   // max_single_packet_size
        );
        assert_eq!(decision, RoutingDecision::CannotSend);
    }

    #[test]
    fn test_routing_unreliable_prefers_existing() {
        let link_id = LinkId::new([0x42; 16]);
        let decision = decide_routing(
            100,           // data_len
            false,         // reliable
            true,          // prefer_existing
            true,          // has_path
            Some(link_id), // existing_connection
            500,           // max_single_packet_size
        );
        assert_eq!(decision, RoutingDecision::UseExistingConnection(link_id));
    }

    #[test]
    fn test_routing_unreliable_large_needs_connection() {
        let decision = decide_routing(
            1000,  // data_len (larger than max)
            false, // reliable
            true,  // prefer_existing
            true,  // has_path
            None,  // existing_connection
            500,   // max_single_packet_size
        );
        assert_eq!(decision, RoutingDecision::EstablishConnection);
    }

    #[test]
    fn test_routing_reliable_with_existing() {
        let link_id = LinkId::new([0x42; 16]);
        let decision = decide_routing(
            100,           // data_len
            true,          // reliable
            true,          // prefer_existing
            true,          // has_path
            Some(link_id), // existing_connection
            500,           // max_single_packet_size
        );
        assert_eq!(decision, RoutingDecision::UseExistingConnection(link_id));
    }

    #[test]
    fn test_routing_reliable_no_existing_with_path() {
        let decision = decide_routing(
            100,  // data_len
            true, // reliable
            true, // prefer_existing
            true, // has_path
            None, // existing_connection
            500,  // max_single_packet_size
        );
        assert_eq!(decision, RoutingDecision::EstablishConnection);
    }

    #[test]
    fn test_routing_reliable_no_existing_no_path() {
        let decision = decide_routing(
            100,   // data_len
            true,  // reliable
            true,  // prefer_existing
            false, // has_path
            None,  // existing_connection
            500,   // max_single_packet_size
        );
        assert_eq!(decision, RoutingDecision::CannotSend);
    }

    #[test]
    fn test_send_handle_creation() {
        let packet_hash = [0x42; 16];
        let method = SendMethod::SinglePacket;
        let handle = SendHandle::new(packet_hash, method);

        assert_eq!(handle.packet_hash, packet_hash);
        assert_eq!(handle.method, SendMethod::SinglePacket);
    }

    #[test]
    fn test_send_method_variants() {
        let link_id = LinkId::new([0x33; 16]);

        // Test all variants are distinct
        assert_ne!(SendMethod::SinglePacket, SendMethod::ExistingLink(link_id));
        assert_ne!(SendMethod::NewLink(link_id), SendMethod::Channel(link_id));

        // Test equality
        assert_eq!(SendMethod::SinglePacket, SendMethod::SinglePacket);
        assert_eq!(
            SendMethod::ExistingLink(link_id),
            SendMethod::ExistingLink(link_id)
        );
    }
}
