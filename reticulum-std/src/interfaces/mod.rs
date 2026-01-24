//! Network interfaces
//!
//! Interfaces handle the physical layer communication for Reticulum.
//! Each interface type handles a specific transport medium.

pub mod hdlc;
mod traits;

pub use traits::{Interface, InterfaceMode, InterfaceStats};

// Interface implementations will be added as separate modules:
// - tcp.rs - TCP client/server
// - udp.rs - UDP broadcast
// - local.rs - Local IPC (Unix sockets)
// - serial.rs - Serial port (KISS protocol)
// - rnode.rs - RNode LoRa modules
