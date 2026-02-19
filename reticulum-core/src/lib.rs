//! Cryptographic mesh networking protocol for resilient communication over any
//! medium.
//!
//! `reticulum-core` implements all protocol logic as `no_std + alloc`, making it
//! suitable for both full operating systems (Linux, macOS, Windows) and bare-metal
//! embedded targets (ESP32, nRF52, STM32). Platform-specific I/O is injected via
//! the [`Clock`] and [`Storage`] traits — see the [`traits`] module.
//!
//! # Core Concepts
//!
//! | Concept | Type | Purpose |
//! |---------|------|---------|
//! | Identity | [`Identity`] | Dual keypair (X25519 + Ed25519) for encryption and signing |
//! | Destination | [`Destination`] | Addressable endpoint identified by a 16-byte hash |
//! | Announce | [`ReceivedAnnounce`] | Broadcast presence notification with public keys |
//! | Transport | [`transport`] | Routing, path discovery, and packet forwarding |
//! | NodeCore | [`NodeCore`] | High-level unified API that ties everything together |
//!
//! # Typical Usage Flow
//!
//! 1. Create an [`Identity`] (or load an existing one)
//! 2. Register a [`Destination`] on a [`NodeCore`]
//! 3. Send an announce so the network learns about this destination
//! 4. Receive announces from peers and open links to them
//! 5. Exchange messages over established links
//!
//! # Platform Dependencies
//!
//! Functions that need platform services take explicit parameters:
//! - `rng: &mut impl CryptoRngCore` - for randomness
//! - `now_ms: u64` - for timestamps
//! - `storage: &mut impl Storage` - for persistence
//!
//! ```
//! use rand_core::OsRng;
//! use reticulum_core::identity::Identity;
//!
//! let identity = Identity::generate(&mut OsRng);
//! ```
//!
//! # Crate Hierarchy
//!
//! ```text
//! reticulum-core   (no_std + alloc)  — all protocol logic
//!     │
//!     ▼
//! reticulum-std    (std)             — platform impls: SystemClock, TcpInterface, FileStorage
//!     │
//!     ▼
//! reticulum-cli / reticulum-ffi     — binaries and C-API
//! ```
//!
//! # Feature Flags
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `compression` | off | BZ2 compression via `libbz2-rs-sys` (pure-Rust) |

#![no_std]
#![warn(unreachable_pub)]

extern crate alloc;

pub(crate) mod announce;
#[cfg(feature = "compression")]
pub mod compression;
pub mod constants;
pub mod crypto;
pub(crate) mod destination;
pub mod framing;
mod hex_fmt;
pub mod identity;
pub mod ifac;
pub mod link;
pub mod node;
pub mod packet;
pub(crate) mod ratchet;
pub(crate) mod receipt;
mod resource;
pub mod storage_types;
#[cfg(test)]
pub(crate) mod test_utils;
pub mod traits;
pub mod transport;

// Re-export key types
pub use announce::{AnnounceError, ReceivedAnnounce};
pub use destination::{
    Destination, DestinationError, DestinationHash, DestinationType, Direction, ProofStrategy,
};
pub use identity::Identity;
pub use link::{LinkCloseReason, LinkError, LinkId, PeerKeys};
pub use node::{DeliveryError, LinkStats, NodeCore, NodeCoreBuilder, NodeEvent, SendError};
pub use transport::{Action, InterfaceId, TickOutput, TransportStats};

// Re-export traits
pub use traits::{
    Clock, Interface, InterfaceError, InterfaceMode, NoStorage, Storage, StorageError,
};
