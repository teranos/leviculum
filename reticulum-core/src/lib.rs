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
//! - `CryptoRngCore`: Cryptographic random number generator
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
//! # no_std
//!
//! This crate is fully `no_std` compatible with `alloc`. It has no optional
//! `std` feature - all functionality works on embedded systems without an OS.

#![no_std]

extern crate alloc;

pub mod announce;
pub mod constants;
pub mod crypto;
pub mod destination;
pub mod framing;
pub mod identity;
pub mod ifac;
pub mod link;
pub mod packet;
pub mod ratchet;
pub mod receipt;
pub mod resource;
pub mod traits;
pub mod transport;

// Re-export key types
pub use announce::{generate_random_hash, AnnounceError, ReceivedAnnounce};
pub use destination::{Destination, ProofStrategy};
pub use identity::Identity;
pub use ifac::{IfacConfig, IfacError};
pub use link::channel::{Channel, ChannelAction, ChannelError, Envelope, Message, MessageState};
pub use link::{
    Link, LinkCloseReason, LinkError, LinkEvent, LinkId, LinkManager, LinkState, PeerKeys,
};
pub use packet::Packet;
pub use ratchet::{KnownRatchets, Ratchet, RatchetError};
pub use receipt::{PacketReceipt, ReceiptStatus};

// Re-export traits
pub use traits::{
    Clock, Context, Interface, InterfaceError, InterfaceMode, NoStorage, PlatformContext, Storage,
    StorageError,
};
