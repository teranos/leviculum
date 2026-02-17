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
pub mod error;
pub mod interfaces;
pub mod reticulum;
pub(crate) mod storage;

// Re-export commonly used core types for the high-level API
pub use reticulum_core::node::NodeEvent;
pub use reticulum_core::{
    Destination, DestinationHash, DestinationType, Direction, Identity, ProofStrategy,
};

pub use config::Config;
pub use driver::{LinkHandle, PacketSender, ReticulumNode, ReticulumNodeBuilder};
pub use error::{Error, Result};
pub use reticulum::Reticulum;
