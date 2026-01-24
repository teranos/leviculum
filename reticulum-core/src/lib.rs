//! reticulum-core: Core library for Reticulum network stack
//!
//! This crate provides the fundamental building blocks for the Reticulum
//! protocol implementation. It is designed to be no_std compatible for
//! embedded systems support.
//!
//! # Modules
//!
//! - `crypto`: Cryptographic primitives (X25519, Ed25519, AES, HKDF)
//! - `identity`: Cryptographic identity management
//! - `destination`: Network endpoint addressing
//! - `packet`: Packet structure and serialization
//! - `link`: Point-to-point verified connections
//! - `transport`: Routing and path discovery
//! - `resource`: Large data transfer protocol
//! - `channel`: Stream abstraction over links

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod constants;
pub mod crypto;
pub mod destination;
pub mod identity;
pub mod link;
pub mod packet;
pub mod resource;
pub mod transport;

// Re-export key types
pub use destination::Destination;
pub use identity::Identity;
pub use link::Link;
pub use packet::Packet;
