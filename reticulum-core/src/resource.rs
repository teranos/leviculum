//! Resource protocol for reliable transfer of large data over a [`Link`](crate::Link).
//!
//! While [`Channel`](crate::Channel) handles small messages (up to ~400 bytes
//! per envelope), resources transfer kilobytes to megabytes by segmenting data
//! into parts and using a sliding window for throughput.
//!
//! # Transfer Flow
//!
//! 1. Sender creates a resource from raw data and a link
//! 2. Sender advertises the resource to the remote peer
//! 3. Receiver accepts (or rejects) the advertisement
//! 4. Parts are sent using a sliding window with automatic retransmission
//! 5. Receiver verifies the reassembled data against a hash
//! 6. Receiver sends a completion proof back to the sender
//!
//! # State Machine
//!
//! ```text
//! None → Queued → Advertised → Transferring → AwaitingProof → Complete
//!                                    ↓
//!                              Failed / Corrupt
//! ```
//!
//! # Current Status
//!
//! This module provides data structures and configuration for the resource
//! protocol. The full transfer implementation is planned for Phase 3
//! (version 0.3.0).

// Resource transfer protocol logic belongs here in reticulum-core.
// Only the async driver (scheduling, I/O) belongs in reticulum-std.
