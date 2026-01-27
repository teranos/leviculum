//! reticulum-std: Standard library extensions for reticulum
//!
//! This crate provides std-dependent functionality:
//! - Network interfaces (TCP, UDP, Local/IPC)
//! - Serial interfaces (KISS, RNode)
//! - Configuration loading and persistence
//! - File-based storage
//! - Async runtime integration (tokio)
//!
//! Use reticulum-core for the no_std compatible core functionality.

pub mod clock;
pub mod config;
pub mod error;
pub mod interfaces;
pub mod reticulum;
pub mod runtime;
pub mod storage;

// Re-export core types
pub use reticulum_core::*;

// Re-export main types
pub use clock::SystemClock;
pub use reticulum::Reticulum;
