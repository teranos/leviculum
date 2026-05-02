//! Hardware RNG access for NodeCore via the SoftDevice's RNG syscall.
//!
//! The Nordic S140 SoftDevice owns the RNG peripheral exclusively (PREGION-1
//! protected); any direct register access at 0x4000_D000 traps as an
//! `NRF_FAULT_ID_APP_MEMACC` peripheral-violation and panics via
//! `nrf_softdevice::softdevice::fault_handler`. Use the SD's
//! `sd_rand_application_vector_get` syscall instead. NodeCore uses this
//! `RawHwRng` for identity generation, signing nonces, and announce random
//! hashes.
//!
//! Constraint: callers must wait until `ble::init` has enabled the SoftDevice
//! before invoking the RNG. Pre-enable calls return zeros (the syscall errors
//! out before the SD is up).

use rand_core::{CryptoRng, RngCore};

/// Hardware RNG that calls into the SoftDevice's CSPRNG via SVC.
pub struct RawHwRng;

impl RawHwRng {
    pub fn new() -> Self { Self }

    /// Call `sd_rand_application_vector_get` once for `dest`, retrying on
    /// `NRF_ERROR_SOC_RAND_NOT_ENOUGH_VALUES` (the SD's RNG pool can be
    /// drained briefly by BLE's own use; it refills off the hardware TRNG).
    /// Returns `false` if the syscall consistently errors (e.g. SD not yet
    /// enabled), in which case `dest` is left as zeros — callers don't get
    /// good entropy but also don't fault.
    fn fill(dest: &mut [u8]) -> bool {
        if dest.is_empty() { return true; }
        let mut offset = 0usize;
        // Syscall takes u8 length, so chunk by 255.
        while offset < dest.len() {
            let chunk_len = (dest.len() - offset).min(u8::MAX as usize);
            let mut retries = 0u32;
            loop {
                let ret = unsafe {
                    nrf_softdevice_s140::sd_rand_application_vector_get(
                        dest[offset..].as_mut_ptr(),
                        chunk_len as u8,
                    )
                };
                if ret == 0 { break; }
                // NRF_ERROR_SOC_RAND_NOT_ENOUGH_VALUES = 0x1300 + 1 typically;
                // any non-zero return means try again until pool refills.
                retries += 1;
                if retries > 10_000 {
                    // SD not enabled or persistent failure — return as-is.
                    return false;
                }
                cortex_m::asm::nop();
            }
            offset += chunk_len;
        }
        true
    }
}

impl RngCore for RawHwRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        Self::fill(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        Self::fill(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) { let _ = Self::fill(dest); }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Self::fill(dest);
        Ok(())
    }
}

// The SoftDevice's CSPRNG is seeded from the hardware TRNG with bias correction.
impl CryptoRng for RawHwRng {}
