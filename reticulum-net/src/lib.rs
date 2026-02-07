//! Shared data types for Reticulum network interfaces
//!
//! This `no_std + alloc` crate defines the data structures exchanged between
//! interface tasks and the event loop. It contains no traits, channels, or
//! async code — only plain data types that work on both std and embedded
//! platforms.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use reticulum_core::InterfaceId;

/// Packet received from an interface, ready for the event loop
pub struct IncomingPacket {
    pub data: Vec<u8>,
}

/// Packet to send out through an interface
pub struct OutgoingPacket {
    pub data: Vec<u8>,
}

/// Metadata describing a registered interface
pub struct InterfaceInfo {
    pub id: InterfaceId,
    pub name: String,
    pub kind: InterfaceKind,
}

/// The transport medium of an interface
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceKind {
    Tcp,
    Udp,
    LoRa,
    Ble,
    Serial,
    Pipe,
    Other,
}
