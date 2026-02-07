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

pub mod clock;
pub mod config;
pub mod error;
pub mod interfaces;
pub mod node;
pub mod reticulum;
pub mod storage;

// Re-export all core types and modules
pub use reticulum_core::*;

pub use clock::SystemClock;
pub use config::{Config, InterfaceConfig, ReticulumConfig};
pub use error::{Error, Result};
pub use interfaces::TcpClientInterface;
pub use node::{ConnectionStream, ReticulumNode, ReticulumNodeBuilder, StdNodeCore};
pub use reticulum::Reticulum;
pub use storage::Storage;
