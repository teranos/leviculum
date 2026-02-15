//! Shared test utilities for reticulum-core.
//!
//! Provides deterministic clocks, mock interfaces, and transport helpers
//! to eliminate duplication across test modules.

use core::cell::Cell;

use alloc::vec::Vec;
use rand_core::OsRng;

use crate::constants::TRUNCATED_HASHBYTES;
use crate::identity::Identity;
use crate::traits::{Clock, Interface, InterfaceError, NoStorage};
use crate::transport::{Transport, TransportConfig};

/// Standard initial time for deterministic tests (1 second in ms).
pub(crate) const TEST_TIME_MS: u64 = 1_000_000;

/// Deterministic clock for tests — supports interior mutability via Cell.
pub(crate) struct MockClock(Cell<u64>);

impl MockClock {
    pub(crate) fn new(ms: u64) -> Self {
        Self(Cell::new(ms))
    }

    /// Advance time by the given number of milliseconds.
    pub(crate) fn advance(&self, ms: u64) {
        self.0.set(self.0.get() + ms);
    }

    /// Set time to an absolute value.
    pub(crate) fn set(&self, ms: u64) {
        self.0.set(ms);
    }
}

impl Clock for MockClock {
    fn now_ms(&self) -> u64 {
        self.0.get()
    }
}

/// Mock interface for testing — records sent packets.
pub(crate) struct MockInterface {
    name: &'static str,
    hash: [u8; TRUNCATED_HASHBYTES],
    pub(crate) sent: Vec<Vec<u8>>,
    pub(crate) online: bool,
}

impl MockInterface {
    pub(crate) fn new(name: &'static str, id: u8) -> Self {
        let mut hash = [0u8; TRUNCATED_HASHBYTES];
        hash[0] = id;
        Self {
            name,
            hash,
            sent: Vec::new(),
            online: true,
        }
    }
}

impl Interface for MockInterface {
    fn name(&self) -> &str {
        self.name
    }
    fn mtu(&self) -> usize {
        500
    }
    fn hash(&self) -> [u8; TRUNCATED_HASHBYTES] {
        self.hash
    }
    fn send(&mut self, data: &[u8]) -> Result<(), InterfaceError> {
        self.sent.push(data.to_vec());
        Ok(())
    }
    fn recv(&mut self, _buf: &mut [u8]) -> Result<usize, InterfaceError> {
        Err(InterfaceError::WouldBlock)
    }
    fn is_online(&self) -> bool {
        self.online
    }
}

/// Bare Transport with MockClock at TEST_TIME_MS, no interfaces.
pub(crate) fn test_transport() -> Transport<MockClock, NoStorage> {
    let clock = MockClock::new(TEST_TIME_MS);
    let identity = Identity::generate(&mut OsRng);
    Transport::new(TransportConfig::default(), clock, NoStorage, identity)
}
