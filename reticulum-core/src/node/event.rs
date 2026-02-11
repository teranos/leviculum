//! Node events - unified event system for all node operations
//!
//! This module provides a unified [`NodeEvent`] enum that combines events from
//! Transport and LinkManager into a single stream, simplifying event handling
//! for application developers.

use alloc::vec::Vec;

use crate::announce::ReceivedAnnounce;
use crate::constants::TRUNCATED_HASHBYTES;
use crate::destination::DestinationHash;
use crate::link::{LinkCloseReason, LinkId, PeerKeys};

/// Unified event enum for all node operations
///
/// This combines events from Transport, LinkManager, and Channel into a single
/// stream that applications can handle uniformly.
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
    /// auto-re-announce internally (Transport.py:1843-1853). The application
    /// does not need to take action.
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
        /// Source destination hash (if known)
        from: DestinationHash,
        /// The decrypted data
        data: Vec<u8>,
        /// Interface it arrived on
        interface_index: usize,
    },

    /// Delivery confirmation for a sent packet
    DeliveryConfirmed {
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

    // ─── Connection Events ─────────────────────────────────────────────────────
    /// Incoming connection request (Link establishment request)
    ConnectionRequest {
        /// The link/connection ID
        link_id: LinkId,
        /// The destination that received the request
        destination_hash: DestinationHash,
        /// Peer's public keys
        peer_keys: PeerKeys,
    },

    /// Connection established (Link handshake completed)
    ConnectionEstablished {
        /// The link/connection ID
        link_id: LinkId,
        /// Whether we initiated this connection
        is_initiator: bool,
    },

    /// Message received on a connection (via Channel)
    MessageReceived {
        /// The link/connection ID
        link_id: LinkId,
        /// Message type identifier
        msgtype: u16,
        /// Message sequence number
        sequence: u16,
        /// The message data
        data: Vec<u8>,
    },

    /// Raw data received on a connection (without Channel framing)
    DataReceived {
        /// The link/connection ID
        link_id: LinkId,
        /// The decrypted data
        data: Vec<u8>,
    },

    /// Connection became stale (no activity for too long)
    ConnectionStale {
        /// The link/connection ID
        link_id: LinkId,
    },

    /// Connection closed
    ConnectionClosed {
        /// The link/connection ID
        link_id: LinkId,
        /// Why the connection was closed
        reason: CloseReason,
    },

    // ─── Proof Events ──────────────────────────────────────────────────────────
    /// Application should decide whether to prove this packet
    ///
    /// Emitted when a packet is received at a destination with `ProofStrategy::App`.
    ProofRequested {
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
    /// No path to the destination
    NoPath,
    /// Delivery timed out without proof
    Timeout,
    /// Connection/link failed during delivery
    ConnectionFailed,
}

impl core::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DeliveryError::NoPath => write!(f, "no path to destination"),
            DeliveryError::Timeout => write!(f, "delivery timed out"),
            DeliveryError::ConnectionFailed => write!(f, "connection failed during delivery"),
        }
    }
}

/// Reason why a connection was closed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Normal close requested by application
    Normal,
    /// Handshake timed out
    Timeout,
    /// Invalid proof received during handshake
    InvalidProof,
    /// Peer closed the connection
    PeerClosed,
    /// Connection became stale (no activity)
    Stale,
}

impl From<LinkCloseReason> for CloseReason {
    fn from(reason: LinkCloseReason) -> Self {
        match reason {
            LinkCloseReason::Normal => CloseReason::Normal,
            LinkCloseReason::Timeout => CloseReason::Timeout,
            LinkCloseReason::InvalidProof => CloseReason::InvalidProof,
            LinkCloseReason::PeerClosed => CloseReason::PeerClosed,
            LinkCloseReason::Stale => CloseReason::Stale,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_close_reason_from_link_close_reason() {
        assert_eq!(
            CloseReason::from(LinkCloseReason::Normal),
            CloseReason::Normal
        );
        assert_eq!(
            CloseReason::from(LinkCloseReason::Timeout),
            CloseReason::Timeout
        );
        assert_eq!(
            CloseReason::from(LinkCloseReason::InvalidProof),
            CloseReason::InvalidProof
        );
        assert_eq!(
            CloseReason::from(LinkCloseReason::PeerClosed),
            CloseReason::PeerClosed
        );
        assert_eq!(
            CloseReason::from(LinkCloseReason::Stale),
            CloseReason::Stale
        );
    }

    #[test]
    fn test_delivery_error_variants() {
        // Ensure all variants are copyable
        let err = DeliveryError::NoPath;
        let err2 = err;
        assert_eq!(err, err2);
    }
}
