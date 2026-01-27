//! reticulum-core: Core library for Reticulum network stack
//!
//! This crate provides the fundamental building blocks for the Reticulum
//! protocol implementation. It is designed to be no_std compatible for
//! embedded systems support.
//!
//! # Architecture
//!
//! The core library contains all protocol logic and is platform-independent.
//! Platform-specific I/O is abstracted via traits in the `traits` module:
//!
//! - `Interface`: Network interface (TCP, UDP, LoRa, BLE)
//! - `Clock`: Time source for timeouts and RTT
//! - `Storage`: Persistent storage for identities and paths
//! - `Rng`: Cryptographic random number generator
//!
//! # Modules
//!
//! - `traits`: Platform abstraction traits (Interface, Clock, Storage, Rng)
//! - `crypto`: Cryptographic primitives (X25519, Ed25519, AES, HKDF)
//! - `framing`: Packet framing for streams (HDLC)
//! - `identity`: Cryptographic identity management
//! - `destination`: Network endpoint addressing
//! - `packet`: Packet structure and serialization
//! - `link`: Point-to-point verified connections
//! - `transport`: Routing and path discovery (data structures)
//! - `resource`: Large data transfer protocol
//!
//! # Features
//!
//! - `std` (default): Enable standard library support
//! - `alloc`: Enable heap allocation (Vec, String) without full std

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod announce;
pub mod constants;
pub mod crypto;
pub mod destination;
pub mod framing;
pub mod identity;
pub mod link;
pub mod packet;
pub mod resource;
pub mod traits;
pub mod transport;

// Re-export key types
#[cfg(feature = "alloc")]
pub use announce::{AnnounceError, ReceivedAnnounce};
pub use destination::Destination;
pub use identity::Identity;
pub use link::Link;
pub use packet::Packet;

// Re-export traits
#[cfg(feature = "alloc")]
pub use traits::{Clock, Interface, InterfaceError, InterfaceMode, NoStorage, Rng, Storage, StorageError};
