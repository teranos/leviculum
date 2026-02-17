//! Platform abstraction traits for `reticulum-core`.
//!
//! These traits decouple all protocol logic from platform I/O, enabling the
//! same code to run on Linux/macOS (via `reticulum-std`) and on bare-metal
//! embedded targets (ESP32, nRF52, STM32).
//!
//! # Traits
//!
//! | Trait | Purpose | `std` example | Embedded example |
//! |-------|---------|---------------|------------------|
//! | [`Clock`] | Monotonic time | `SystemClock` | Hardware timer |
//! | [`Storage`] | Key-value persistence | `FileStorage` | Flash storage |
//! | [`Interface`] | Send-only network interface | `InterfaceHandle` (channel) | LoRa / BLE driver |
//!
//! # Sans-I/O Architecture
//!
//! The core protocol engine (`NodeCore`, `Transport`) never performs I/O
//! directly. Instead, it accepts incoming packets and emits [`Action`](crate::transport::Action)
//! values for the driver to execute.
//!
//! The [`Interface`] trait defines the **send side** of the interface contract:
//! the driver calls [`dispatch_actions()`](crate::transport::dispatch_actions)
//! which routes `Action` values to interfaces via [`Interface::try_send()`].
//! The **receive side** is driver-specific (async channels for tokio, interrupts
//! for embedded) and not part of this trait.
//!
//! # Platform Dependencies
//!
//! Functions that need platform services take explicit parameters:
//! - `rng: &mut impl CryptoRngCore` - for randomness
//! - `now_ms: u64` - for timestamps
//! - `storage: &mut impl Storage` - for persistence
//!
//! For devices that do not need persistence, use [`NoStorage`].

extern crate alloc;

use alloc::vec::Vec;

use crate::transport::InterfaceId;

/// Error type for interface send operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceError {
    /// Outbound buffer full — packet dropped (non-fatal)
    BufferFull,
    /// Interface disconnected — driver must call handle_interface_down()
    Disconnected,
}

impl core::fmt::Display for InterfaceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InterfaceError::BufferFull => write!(f, "buffer full"),
            InterfaceError::Disconnected => write!(f, "disconnected"),
        }
    }
}

/// Interface mode flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InterfaceMode {
    /// Interface uses broadcast (all nodes see all packets)
    pub broadcast: bool,
    /// Interface is local-only (loopback, IPC)
    pub local: bool,
    /// Interface supports multiple access (shared medium)
    pub multiple_access: bool,
}

/// A network interface that can send packets (sync, non-blocking)
///
/// This trait defines the **send side** of the interface contract. The driver
/// implements it on whatever holds the outbound channel (e.g., a tokio mpsc
/// sender, an Embassy SPI handle, a LoRa radio driver).
///
/// The **receive side** is intentionally absent — receiving is async and
/// driver-specific (tokio channels, hardware interrupts, DMA). The driver
/// feeds received packets into core via `handle_packet()`.
///
/// Core's [`dispatch_actions()`](crate::transport::dispatch_actions) calls
/// `try_send()` on interfaces to route `Action` values to the network.
/// This keeps broadcast-exclusion and interface-selection logic in core,
/// so every driver (tokio, Embassy, bare-metal) gets it for free.
///
/// # Error handling
///
/// - `BufferFull`: non-fatal, packet dropped — Reticulum is best-effort
/// - `Disconnected`: driver must call `handle_interface_down()` for cleanup
pub trait Interface {
    /// Opaque identifier used by core for routing tables
    fn id(&self) -> InterfaceId;

    /// Human-readable name for logging
    fn name(&self) -> &str;

    /// Maximum transmission unit (max packet payload size)
    fn mtu(&self) -> usize;

    /// Interface mode flags (broadcast, local, multiple_access)
    fn mode(&self) -> InterfaceMode {
        InterfaceMode::default()
    }

    /// Check if interface is online/connected
    fn is_online(&self) -> bool;

    /// Try to send a packet (non-blocking, fire-and-forget)
    ///
    /// Returns `Ok(())` if the packet was accepted for delivery.
    /// Returns `Err(BufferFull)` if the outbound buffer is full — packet is dropped.
    /// Returns `Err(Disconnected)` if the interface is dead.
    ///
    /// The implementation handles framing internally (e.g., HDLC for TCP).
    fn try_send(&mut self, data: &[u8]) -> Result<(), InterfaceError>;
}

/// Clock for timestamps and timeouts
///
/// Implementations:
/// - `std`: `SystemClock` using `std::time::Instant`
/// - `embedded`: Hardware timer or `embassy::time::Instant`
///
/// The clock must be monotonic (never go backwards).
pub trait Clock {
    /// Milliseconds since some arbitrary epoch (monotonic)
    fn now_ms(&self) -> u64;

    /// Seconds since epoch (convenience method)
    fn now_secs(&self) -> u64 {
        self.now_ms() / 1000
    }

    /// Check if a deadline (in ms) has passed
    fn has_elapsed(&self, deadline_ms: u64) -> bool {
        self.now_ms() >= deadline_ms
    }

    /// Calculate deadline from now + duration_ms
    fn deadline(&self, duration_ms: u64) -> u64 {
        self.now_ms().saturating_add(duration_ms)
    }
}

/// Persistent storage for identities, paths, destinations
///
/// Implementations:
/// - `std`: `FileStorage` using filesystem
/// - `embedded`: `FlashStorage` using NOR flash
/// - `none`: `NoStorage` for stateless operation
///
/// Storage is optional - transport works without it but won't persist
/// identities or learned paths across restarts.
pub trait Storage {
    /// Load data by key from a category
    ///
    /// Categories: "identities", "destinations", "paths", "ratchets"
    fn load(&self, category: &str, key: &[u8]) -> Option<Vec<u8>>;

    /// Store data by key in a category
    fn store(&mut self, category: &str, key: &[u8], value: &[u8]) -> Result<(), StorageError>;

    /// Delete data by key from a category
    fn delete(&mut self, category: &str, key: &[u8]) -> Result<(), StorageError>;

    /// List all keys in a category
    fn list_keys(&self, category: &str) -> Vec<Vec<u8>>;

    /// Check if a key exists
    fn exists(&self, category: &str, key: &[u8]) -> bool {
        self.load(category, key).is_some()
    }
}

/// Storage error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    /// Storage is full
    Full,
    /// Key not found (for delete)
    NotFound,
    /// I/O error
    IoError,
    /// Data corruption
    Corrupted,
}

impl core::fmt::Display for StorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StorageError::Full => write!(f, "storage full"),
            StorageError::NotFound => write!(f, "key not found"),
            StorageError::IoError => write!(f, "I/O error"),
            StorageError::Corrupted => write!(f, "data corrupted"),
        }
    }
}

/// No-op storage for devices without persistence
///
/// All operations succeed but nothing is actually stored.
/// Use this for stateless embedded devices or testing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoStorage;

impl Storage for NoStorage {
    fn load(&self, _category: &str, _key: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn store(&mut self, _category: &str, _key: &[u8], _value: &[u8]) -> Result<(), StorageError> {
        Ok(())
    }

    fn delete(&mut self, _category: &str, _key: &[u8]) -> Result<(), StorageError> {
        Ok(())
    }

    fn list_keys(&self, _category: &str) -> Vec<Vec<u8>> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockClock;

    #[test]
    fn test_no_storage() {
        let mut storage = NoStorage;

        // Store succeeds but doesn't persist
        assert!(storage.store("test", b"key", b"value").is_ok());

        // Load returns None
        assert!(storage.load("test", b"key").is_none());

        // Delete succeeds
        assert!(storage.delete("test", b"key").is_ok());

        // List is empty
        assert!(storage.list_keys("test").is_empty());
    }

    #[test]
    fn test_interface_mode_default() {
        let mode = InterfaceMode::default();
        assert!(!mode.broadcast);
        assert!(!mode.local);
        assert!(!mode.multiple_access);
    }

    #[test]
    fn test_clock_deadline() {
        let clock = MockClock::new(1000);

        assert_eq!(clock.now_secs(), 1);
        assert_eq!(clock.deadline(500), 1500);
        assert!(!clock.has_elapsed(1500));
        assert!(clock.has_elapsed(1000));
        assert!(clock.has_elapsed(500));
    }
}
