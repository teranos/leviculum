//! Node events - unified event system for all node operations
//!
//! This module provides a unified [`NodeEvent`] enum that combines events from
//! transport, link management, and channels into a single stream, simplifying
//! event handling for application developers.

use alloc::vec::Vec;

use crate::announce::ReceivedAnnounce;
use crate::constants::TRUNCATED_HASHBYTES;
use crate::destination::DestinationHash;
use crate::link::{LinkCloseReason, LinkId, PeerKeys};

/// Unified event enum for all node operations
///
/// This combines events from transport, link management, and channels into a
/// single stream that applications can handle uniformly.
#[derive(Debug)]
pub enum NodeEvent {
    // ─── Path Discovery Events ─────────────────────────────────────────────────
    /// A new announce was received and validated
    AnnounceReceived {
        /// Parsed announce data
        announce: ReceivedAnnounce,
        /// Interface it arrived on
        interface_index: usize,
    },

    /// Path to a destination was found (from announce)
    PathFound {
        /// Destination hash
        destination_hash: DestinationHash,
        /// Number of hops
        hops: u8,
        /// Interface index
        interface_index: usize,
    },

    /// A remote node requested the path to one of our local destinations
    ///
    /// This is informational — the transport layer already handles
    /// auto-re-announce internally (Transport.py:1843-1853).
    /// No application action is required.
    PathRequestReceived {
        /// The destination hash that was requested
        destination_hash: DestinationHash,
    },

    /// Path to a destination expired
    PathLost {
        /// Destination hash
        destination_hash: DestinationHash,
    },

    // ─── Single-Packet Events ──────────────────────────────────────────────────
    /// Incoming single-packet data (not via a Link)
    PacketReceived {
        /// The destination hash that received this packet
        destination: DestinationHash,
        /// The decrypted data
        data: Vec<u8>,
        /// Interface it arrived on
        interface_index: usize,
    },

    /// Delivery confirmation for a sent packet
    PacketDeliveryConfirmed {
        /// The packet hash identifying the sent packet
        packet_hash: [u8; TRUNCATED_HASHBYTES],
    },

    /// Delivery failed for a sent packet
    DeliveryFailed {
        /// The packet hash identifying the sent packet
        packet_hash: [u8; TRUNCATED_HASHBYTES],
        /// The error that occurred
        error: DeliveryError,
    },

    // ─── Link Events ──────────────────────────────────────────────────────────
    /// Incoming link request (Link establishment request)
    LinkRequest {
        /// The link ID
        link_id: LinkId,
        /// The destination that received the request
        destination_hash: DestinationHash,
        /// Peer's public keys
        peer_keys: PeerKeys,
    },

    /// Link established (handshake completed)
    LinkEstablished {
        /// The link ID
        link_id: LinkId,
        /// Whether we initiated this link
        is_initiator: bool,
    },

    /// Message received on a link (via Channel)
    MessageReceived {
        /// The link ID
        link_id: LinkId,
        /// Message type identifier
        msgtype: u16,
        /// Message sequence number
        sequence: u16,
        /// The message data
        data: Vec<u8>,
    },

    /// Raw data received on a link (without Channel framing)
    LinkDataReceived {
        /// The link ID
        link_id: LinkId,
        /// The decrypted data
        data: Vec<u8>,
    },

    /// Link became stale (no activity for too long)
    LinkStale {
        /// The link ID
        link_id: LinkId,
    },

    /// Link recovered from stale state (traffic resumed)
    LinkRecovered {
        /// The link ID
        link_id: LinkId,
    },

    /// Observability event — a channel message was retransmitted due to timeout.
    ///
    /// No application action is required. Useful for logging and diagnostics.
    ChannelRetransmit {
        /// The link ID
        link_id: LinkId,
        /// Message sequence number
        sequence: u16,
        /// Retry attempt number (2 = first retry, etc.)
        tries: u8,
    },

    /// Link closed
    LinkClosed {
        /// The link ID
        link_id: LinkId,
        /// Why the link was closed
        reason: LinkCloseReason,
        /// Whether we initiated this link
        is_initiator: bool,
        /// The destination hash this link was to
        destination_hash: DestinationHash,
    },

    // ─── Proof Events ──────────────────────────────────────────────────────────
    /// Application should decide whether to prove this packet
    ///
    /// Emitted when a packet is received at a destination with `ProofStrategy::App`.
    /// Call `NodeCore::send_proof()` if the application decides to prove delivery.
    /// Not emitted for `ProofStrategy::All` (handled automatically by the library).
    PacketProofRequested {
        /// Full SHA256 hash of the packet to potentially prove
        packet_hash: [u8; 32],
        /// Destination that received the packet
        destination_hash: DestinationHash,
    },

    /// Application should decide whether to prove this link data packet
    ///
    /// Emitted when data is received on a link whose destination has
    /// `ProofStrategy::App`. Call `send_data_proof()` to confirm delivery.
    LinkProofRequested {
        /// The link that received the data
        link_id: LinkId,
        /// Full SHA256 hash of the packet to potentially prove
        packet_hash: [u8; 32],
    },

    /// Delivery confirmation for a link data packet (PROVE_ALL)
    ///
    /// Emitted when a proof is received for a data packet sent on a link.
    /// This confirms the peer received and decrypted the data.
    LinkDeliveryConfirmed {
        /// The link that sent the data
        link_id: LinkId,
        /// Full SHA256 hash of the delivered packet
        packet_hash: [u8; 32],
    },

    // ─── Interface Events ──────────────────────────────────────────────────────
    /// An interface went offline
    InterfaceDown(usize),
}

/// Reason why a delivery failed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryError {
    /// Delivery timed out without proof
    Timeout,
    /// Link failed during delivery
    LinkFailed,
}

impl core::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DeliveryError::Timeout => write!(f, "delivery timed out"),
            DeliveryError::LinkFailed => write!(f, "link failed during delivery"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delivery_error_variants() {
        // Ensure all variants are copyable
        let err = DeliveryError::Timeout;
        let err2 = err;
        assert_eq!(err, err2);
    }
}
