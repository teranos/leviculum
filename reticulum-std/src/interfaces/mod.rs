//! Network interfaces
//!
//! Interfaces handle the physical layer communication for Reticulum.
//! Each interface type handles a specific transport medium.
//!
//! All interfaces implement `reticulum_core::traits::Interface` so they
//! can be registered with the core `Transport`.

pub mod hdlc;
pub mod tcp;
mod traits;

pub use tcp::TcpClientInterface;
pub use traits::{Interface, InterfaceMode, InterfaceStats};

// Future interface implementations:
// - local.rs - Local IPC (Unix sockets)
// - serial.rs - Serial port (KISS protocol)
// - rnode.rs - RNode LoRa modules
