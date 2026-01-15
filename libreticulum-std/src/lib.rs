//! leviculum-std: Standard library extensions for leviculum
//!
//! This crate provides std-dependent functionality:
//! - Network interfaces (TCP, UDP, Local/IPC)
//! - Serial interfaces (KISS, RNode)
//! - Configuration loading and persistence
//! - File-based storage
//! - Async runtime integration (tokio)
//!
//! Use leviculum-core for the no_std compatible core functionality.

pub mod config;
pub mod error;
pub mod interfaces;
pub mod reticulum;
pub mod storage;

// Re-export core types
pub use leviculum_core::*;

// Re-export main instance
pub use reticulum::Reticulum;
