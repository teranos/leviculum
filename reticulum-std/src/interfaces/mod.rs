//! Network interfaces
//!
//! Interfaces handle the physical layer communication for Reticulum.
//! Each interface type handles a specific transport medium.
//!
//! All interfaces implement `reticulum_core::traits::Interface` so they
//! can be registered with the core `Transport`.

pub mod hdlc;
pub mod tcp;

pub use tcp::TcpClientInterface;
