//! Identity persistence via internal flash (NVMC) for nRF52840.
//!
//! Implements [`IdentityStore`] using the nRF52840's internal flash.
//! The wire format (magic, version, checksum) is defined in
//! `reticulum_core::identity_store` and shared across all targets.

use embassy_nrf::nvmc::Nvmc;
use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};
use reticulum_core::identity::Identity;
use reticulum_core::identity_store::{self, IdentityStore, ENCODED_SIZE_ALIGNED};

/// Internal flash page reserved for identity storage.
/// Just below Heltec's reserved area (0xED000).
/// Protected from linker by reducing FLASH length in memory.x.
const IDENTITY_PAGE: u32 = 0xEC000;

/// NVMC-backed identity store for the T114.
pub struct NvmcIdentityStore<'d> {
    nvmc: Nvmc<'d>,
}

impl<'d> NvmcIdentityStore<'d> {
    pub fn new(nvmc: Nvmc<'d>) -> Self {
        Self { nvmc }
    }
}

impl IdentityStore for NvmcIdentityStore<'_> {
    type Error = embassy_nrf::nvmc::Error;

    fn load(&mut self) -> Result<Option<Identity>, Self::Error> {
        let mut buf = [0u8; ENCODED_SIZE_ALIGNED];
        self.nvmc.read(IDENTITY_PAGE, &mut buf)?;
        Ok(identity_store::decode_identity(&buf))
    }

    fn save(&mut self, identity: &Identity) -> Result<(), Self::Error> {
        let buf = match identity_store::encode_identity(identity) {
            Some(b) => b,
            None => return Ok(()),
        };
        self.nvmc.erase(IDENTITY_PAGE, IDENTITY_PAGE + 4096)?;
        self.nvmc.write(IDENTITY_PAGE, &buf)?;
        Ok(())
    }
}
