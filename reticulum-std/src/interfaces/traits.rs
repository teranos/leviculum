//! Interface traits and common types

use std::future::Future;
use std::pin::Pin;

use reticulum_core::constants::MTU;

/// Interface operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceMode {
    /// Full duplex
    Full,
    /// Point-to-point only
    PointToPoint,
    /// Hub/star topology (access point)
    AccessPoint,
    /// Roaming client mode
    Roaming,
    /// Network boundary
    Boundary,
    /// Gateway to other networks
    Gateway,
}

/// Interface statistics
#[derive(Debug, Default, Clone)]
pub struct InterfaceStats {
    /// Bytes received
    pub rx_bytes: u64,
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Packets received
    pub rx_packets: u64,
    /// Packets transmitted
    pub tx_packets: u64,
    /// Receive errors
    pub rx_errors: u64,
    /// Transmit errors
    pub tx_errors: u64,
}

/// Result type for interface operations
pub type InterfaceResult<T> = Result<T, InterfaceError>;

/// Interface error type
#[derive(Debug)]
pub enum InterfaceError {
    /// I/O error
    Io(std::io::Error),
    /// Interface not connected
    NotConnected,
    /// Send buffer full
    BufferFull,
    /// Packet too large
    PacketTooLarge,
    /// Interface is offline
    Offline,
    /// Configuration error
    Config(String),
}

impl From<std::io::Error> for InterfaceError {
    fn from(e: std::io::Error) -> Self {
        InterfaceError::Io(e)
    }
}

/// Trait for network interfaces
pub trait Interface: Send + Sync {
    /// Get the interface name
    fn name(&self) -> &str;

    /// Get the interface mode
    fn mode(&self) -> InterfaceMode;

    /// Get the interface bitrate in bits per second
    fn bitrate(&self) -> u64;

    /// Get the MTU (usually 500 bytes)
    fn mtu(&self) -> usize {
        MTU
    }

    /// Check if the interface is online
    fn is_online(&self) -> bool;

    /// Check if the interface can send
    fn can_send(&self) -> bool;

    /// Check if the interface can receive
    fn can_receive(&self) -> bool;

    /// Get interface statistics
    fn stats(&self) -> InterfaceStats;

    /// Send a packet
    fn send(&self, data: &[u8]) -> Pin<Box<dyn Future<Output = InterfaceResult<()>> + Send + '_>>;

    /// Receive a packet (returns None if no packet available)
    fn receive(
        &self,
    ) -> Pin<Box<dyn Future<Output = InterfaceResult<Option<Vec<u8>>>> + Send + '_>>;

    /// Start the interface
    fn start(&self) -> Pin<Box<dyn Future<Output = InterfaceResult<()>> + Send + '_>>;

    /// Stop the interface
    fn stop(&self) -> Pin<Box<dyn Future<Output = InterfaceResult<()>> + Send + '_>>;
}
