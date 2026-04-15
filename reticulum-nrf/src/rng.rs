//! Hardware RNG access for NodeCore when the embassy Rng peripheral
//! is consumed by the BLE SoftDevice Controller.
//!
//! The nRF52840 RNG is a simple TRNG: write TASKS_START, poll EVENTS_VALRDY,
//! read VALUE. This works regardless of which code "owns" the peripheral
//! token ; the hardware is always accessible via its register address.
//!
//! The SDC owns the embassy `Rng` peripheral token and uses it for
//! BLE address randomization and crypto. NodeCore uses this `RawHwRng`
//! for identity generation, signing nonces, and announce random hashes.
//! Both are safe because: (a) the hardware RNG is stateless ; reading VALUE
//! consumes the value atomically, (b) the Embassy executor is single-threaded,
//! so NodeCore and SDC never access the RNG simultaneously.

use rand_core::{CryptoRng, RngCore};

/// nRF52840 RNG register base address
const RNG_BASE: u32 = 0x4000_D000;
const RNG_TASKS_START: *mut u32 = (RNG_BASE + 0x000) as *mut u32;
const RNG_TASKS_STOP: *mut u32 = (RNG_BASE + 0x004) as *mut u32;
const RNG_EVENTS_VALRDY: *mut u32 = (RNG_BASE + 0x100) as *mut u32;
const RNG_VALUE: *const u32 = (RNG_BASE + 0x508) as *const u32;
const RNG_CONFIG: *mut u32 = (RNG_BASE + 0x504) as *mut u32;

/// Hardware RNG that reads the nRF52840 RNG register directly.
pub struct RawHwRng;

impl RawHwRng {
    pub fn new() -> Self {
        // Enable bias correction for better randomness
        unsafe { core::ptr::write_volatile(RNG_CONFIG, 1) };
        Self
    }

    fn next_byte(&mut self) -> u8 {
        unsafe {
            // Clear event, start generation
            core::ptr::write_volatile(RNG_EVENTS_VALRDY, 0);
            core::ptr::write_volatile(RNG_TASKS_START, 1);
            // Poll until value is ready
            while core::ptr::read_volatile(RNG_EVENTS_VALRDY) == 0 {}
            // Read value and stop
            let val = core::ptr::read_volatile(RNG_VALUE) as u8;
            core::ptr::write_volatile(RNG_TASKS_STOP, 1);
            val
        }
    }
}

impl RngCore for RawHwRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = self.next_byte();
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// The nRF52840 hardware RNG is a TRNG with bias correction ; cryptographically secure.
impl CryptoRng for RawHwRng {}
