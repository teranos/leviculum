//! HDLC framing for stream-based interfaces
//!
//! This module re-exports the HDLC implementation from `reticulum-core::framing::hdlc`.
//! All framing logic lives in core for no_std compatibility.

pub use reticulum_core::framing::hdlc::*;
