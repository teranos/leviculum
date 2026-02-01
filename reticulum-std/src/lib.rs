//! reticulum-std: Standard library extensions for reticulum
//!
//! This crate provides std-dependent functionality:
//! - Network interfaces (TCP, UDP, Local/IPC)
//! - Serial interfaces (KISS, RNode)
//! - Configuration loading and persistence
//! - File-based storage
//! - Async runtime integration (tokio)
//! - BZ2 compression for buffer system (via `compression` feature)
//!
//! Use reticulum-core for the no_std compatible core functionality,
//! including the buffer system types (RawChannelReader, RawChannelWriter).

pub mod buffer;
pub mod clock;
pub mod config;
pub mod error;
pub mod interfaces;
pub mod reticulum;
pub mod runtime;
pub mod storage;

// Re-export all core types and modules
pub use reticulum_core::*;

// Re-export buffer types (from core) and compression extensions
#[cfg(feature = "compression")]
pub use buffer::{compress_bz2, decompress_bz2, CompressingWriter, RawChannelReaderExt};
pub use buffer::{BufferedChannelWriter, RawChannelReader, RawChannelWriter};
pub use clock::SystemClock;
pub use config::{Config, InterfaceConfig, ReticulumConfig};
pub use error::{Error, Result};
pub use interfaces::TcpClientInterface;
pub use reticulum::Reticulum;
pub use runtime::{StdTransport, TransportRunner};
pub use storage::Storage;
