//! Platform abstraction traits for reticulum-core
//!
//! These traits allow the protocol logic to run on any platform
//! by abstracting I/O, time, and storage.
//!
//! # Example
//!
//! ```text
//! use reticulum_core::traits::{Interface, Clock, Storage, NoStorage};
//!
//! // Implement these traits for your platform:
//! // - std: TcpInterface, SystemClock, FileStorage
//! // - embedded: LoRaInterface, EmbassyClock, FlashStorage or NoStorage
//! ```

use crate::constants::TRUNCATED_HASHBYTES;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Error type for interface operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceError {
    /// Would block (non-blocking mode)
    WouldBlock,
    /// Connection closed or unavailable
    Disconnected,
    /// Buffer too small for received data
    BufferTooSmall,
    /// Invalid data or framing error
    InvalidData,
    /// Interface not ready
    NotReady,
    /// Other error
    Other,
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

/// A network interface that can send and receive packets
///
/// Implementations provide the actual I/O:
/// - `std`: TCP, UDP, Serial
/// - `embedded`: LoRa (SX1262), BLE, WiFi
///
/// The interface handles framing internally (e.g., HDLC).
pub trait Interface {
    /// Human-readable name for logging
    fn name(&self) -> &str;

    /// Maximum transmission unit (max packet payload size)
    fn mtu(&self) -> usize;

    /// Unique hash identifying this interface (for routing)
    fn hash(&self) -> [u8; TRUNCATED_HASHBYTES];

    /// Send a packet (implementation handles framing)
    fn send(&mut self, data: &[u8]) -> Result<(), InterfaceError>;

    /// Receive a packet into buffer, returns bytes read
    ///
    /// Returns `WouldBlock` if no data available (non-blocking).
    /// The implementation handles deframing internally.
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, InterfaceError>;

    /// Check if interface is online/connected
    fn is_online(&self) -> bool;

    /// Get interface mode flags
    fn mode(&self) -> InterfaceMode {
        InterfaceMode::default()
    }

    /// Bring interface up (connect, start listening)
    fn up(&mut self) -> Result<(), InterfaceError> {
        Ok(())
    }

    /// Bring interface down (disconnect, stop)
    fn down(&mut self) -> Result<(), InterfaceError> {
        Ok(())
    }
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
#[cfg(feature = "alloc")]
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

/// No-op storage for devices without persistence
///
/// All operations succeed but nothing is actually stored.
/// Use this for stateless embedded devices or testing.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Copy, Default)]
pub struct NoStorage;

#[cfg(feature = "alloc")]
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

/// Random number generator trait
///
/// This is a simplified trait that wraps `rand_core::CryptoRngCore`.
/// All implementations must be cryptographically secure.
pub trait Rng {
    /// Fill a buffer with random bytes
    fn fill_bytes(&mut self, dest: &mut [u8]);

    /// Generate a random u64
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    /// Generate a random u32
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
}

// Blanket implementation for rand_core types
impl<T: rand_core::CryptoRngCore> Rng for T {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::RngCore::fill_bytes(self, dest)
    }
}

/// Storage categories used by the protocol
pub mod categories {
    /// Stored identities (private keys)
    pub const IDENTITIES: &str = "identities";
    /// Known destinations (from announces)
    pub const DESTINATIONS: &str = "destinations";
    /// Learned network paths
    pub const PATHS: &str = "paths";
    /// Ratchet keys for forward secrecy
    pub const RATCHETS: &str = "ratchets";
    /// Cached data (packet dedup, etc.)
    pub const CACHE: &str = "cache";
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // Mock clock for testing
    struct MockClock {
        time_ms: u64,
    }

    impl Clock for MockClock {
        fn now_ms(&self) -> u64 {
            self.time_ms
        }
    }

    #[test]
    fn test_clock_deadline() {
        let clock = MockClock { time_ms: 1000 };

        assert_eq!(clock.now_secs(), 1);
        assert_eq!(clock.deadline(500), 1500);
        assert!(!clock.has_elapsed(1500));
        assert!(clock.has_elapsed(1000));
        assert!(clock.has_elapsed(500));
    }
}
