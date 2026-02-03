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
//! | [`Interface`] | Network I/O | `TcpInterface` | LoRa / BLE driver |
//! | [`Clock`] | Monotonic time | `SystemClock` | Hardware timer |
//! | [`Storage`] | Key-value persistence | `FileStorage` | Flash storage |
//! | [`Context`] | Bundles RNG + Clock + Storage | `PlatformContext<OsRng, ..>` | `PlatformContext<HwRng, ..>` |
//!
//! # The Context Pattern
//!
//! Instead of passing three separate parameters for RNG, clock, and storage,
//! protocol functions accept a single `&mut impl Context`. The concrete type
//! [`PlatformContext`] provides this by composing any implementations of the
//! three underlying traits. For devices that do not need persistence, use
//! [`NoStorage`].

use crate::constants::TRUNCATED_HASHBYTES;
use rand_core::CryptoRngCore;

extern crate alloc;

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

/// Platform context trait that bundles all platform-specific dependencies
///
/// This is the central abstraction that allows protocol code to run
/// on any platform. Functions that need platform services take
/// `ctx: &mut impl Context`.
///
/// The trait is stable: new capabilities can be added without
/// breaking existing function signatures.
pub trait Context {
    type Rng: CryptoRngCore;
    type Clock: Clock;
    type Storage: Storage;

    fn rng(&mut self) -> &mut Self::Rng;
    fn clock(&self) -> &Self::Clock;
    fn storage(&mut self) -> &mut Self::Storage;
}

/// Standard implementation of [`Context`]
///
/// # Example
/// ```
/// use rand_core::OsRng;
/// use reticulum_core::identity::Identity;
/// use reticulum_core::traits::{Clock, PlatformContext, NoStorage};
///
/// // Define a simple clock (in practice, use your platform's clock)
/// struct SimpleClock;
/// impl Clock for SimpleClock {
///     fn now_ms(&self) -> u64 { 0 }
/// }
///
/// let mut ctx = PlatformContext {
///     rng: OsRng,
///     clock: SimpleClock,
///     storage: NoStorage,
/// };
/// let identity = Identity::generate(&mut ctx);
/// ```
///
/// # Embedded Example
///
/// On embedded platforms, provide platform-specific implementations:
///
/// ```text
/// let mut ctx = PlatformContext {
///     rng: Stm32Rng::new(),      // Hardware RNG
///     clock: Tim2Clock::new(),   // Timer-based clock
///     storage: FlashStorage::new(),
/// };
/// ```
pub struct PlatformContext<R: CryptoRngCore, C: Clock, S: Storage> {
    pub rng: R,
    pub clock: C,
    pub storage: S,
}

impl<R: CryptoRngCore, C: Clock, S: Storage> Context for PlatformContext<R, C, S> {
    type Rng = R;
    type Clock = C;
    type Storage = S;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }
    fn clock(&self) -> &Self::Clock {
        &self.clock
    }
    fn storage(&mut self) -> &mut Self::Storage {
        &mut self.storage
    }
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
