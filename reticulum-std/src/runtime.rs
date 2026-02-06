//! Async runtime types for Reticulum
//!
//! This module previously contained `TransportRunner`, which has been superseded
//! by the sans-I/O architecture. All event loop functionality now lives in
//! `ReticulumNode` (see [`crate::node`]), which wraps `NodeCore` and drives
//! it via `handle_packet()` / `handle_timeout()`.
//!
//! The `Reticulum` type in [`crate::reticulum`] provides the high-level daemon
//! entry point and uses `ReticulumNode` internally.

// Type aliases kept for backwards compatibility with existing code
use reticulum_core::transport::Transport;

use crate::clock::SystemClock;
use crate::storage::Storage;

/// Type alias for the concrete Transport used by std platforms
pub type StdTransport = Transport<SystemClock, Storage>;
