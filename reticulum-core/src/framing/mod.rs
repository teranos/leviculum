//! Packet framing for stream-based interfaces
//!
//! This module provides framing implementations for protocols
//! that need to delimit packets on byte streams (TCP, Serial).
//!
//! # Available Framers
//!
//! - [`hdlc`] - HDLC-style framing with byte stuffing (used by Reticulum)

pub mod hdlc;

// Re-export commonly used items
pub use hdlc::{crc16, frame_to_slice, max_framed_size, needs_escape, ESCAPE, ESCAPE_XOR, FLAG};
pub use hdlc::{frame, frame_with_crc, Deframer, DeframeResult};
