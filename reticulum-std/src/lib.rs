//! reticulum-std: Standard library extensions for reticulum
//!
//! This crate provides std-dependent functionality:
//! - Network interfaces (TCP, UDP, Local/IPC)
//! - Serial interfaces (KISS, RNode)
//! - Configuration loading and persistence
//! - File-based storage
//! - Async runtime integration (tokio)
//!
//! Use reticulum-core for the no_std compatible core functionality,
//! including the buffer system types (RawChannelReader, RawChannelWriter).

#![warn(unreachable_pub)]

pub(crate) mod clock;
pub mod config;
pub mod driver;
pub mod file_identity_store;
pub mod error;
pub(crate) mod ini_config;
pub mod interfaces;
pub(crate) mod known_destinations;
pub(crate) mod packet_hashlist;
pub mod reticulum;
pub(crate) mod rpc;
pub(crate) mod storage;

// Re-export commonly used core types for the high-level API
pub use reticulum_core::node::{DeliveryError, LinkStats, NodeEvent};
pub use reticulum_core::{
    AnnounceError, Destination, DestinationHash, DestinationType, Direction, Identity,
    LinkCloseReason, LinkError, LinkId, PeerKeys, ProofStrategy, ReceivedAnnounce, SendError,
    TransportStats,
};

/// Generate a new random identity using the system RNG.
///
/// Convenience wrapper around `Identity::generate(&mut OsRng)` for std apps.
/// Embedded code should use `Identity::generate()` with a platform-specific RNG.
pub fn generate_identity() -> Identity {
    Identity::generate(&mut rand_core::OsRng)
}

pub use config::Config;
pub use driver::{LinkHandle, PacketSender, ReticulumNode, ReticulumNodeBuilder};
pub use error::{Error, Result};
pub use reticulum::Reticulum;
