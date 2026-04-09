//! Identity persistence via internal flash (NVMC).
//!
//! Stores the 64-byte Reticulum private key at a fixed page in internal flash.
//! On first boot, the identity is generated and saved. On subsequent boots,
//! it's loaded — the node keeps the same identity across reboots.
//!
//! The identity page (0xEC000) is reserved by reducing FLASH length in memory.x
//! so the linker never places code there.

use embassy_nrf::nvmc::Nvmc;
use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};
use reticulum_core::identity::Identity;

/// Internal flash page reserved for identity storage.
/// Just below Heltec's reserved area (0xED000).
const IDENTITY_PAGE: u32 = 0xEC000;

const MAGIC: [u8; 4] = [0x52, 0x54, 0x49, 0x43]; // "RTIC"
const VERSION: u8 = 0x01;
const HEADER_SIZE: usize = 5;
const KEY_SIZE: usize = 64;
const CHECKSUM_SIZE: usize = 2;
const RECORD_SIZE: usize = HEADER_SIZE + KEY_SIZE + CHECKSUM_SIZE; // 71

// NVMC write must be 4-byte aligned
const BUF_SIZE: usize = (RECORD_SIZE + 3) & !3; // 72

fn checksum(data: &[u8]) -> [u8; 2] {
    let mut a: u8 = 0;
    let mut b: u8 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i % 2 == 0 { a ^= byte; } else { b ^= byte; }
    }
    [a, b]
}

/// Try to load an identity from internal flash.
pub fn load_identity(nvmc: &mut Nvmc<'_>) -> Option<Identity> {
    let mut buf = [0u8; BUF_SIZE];
    if nvmc.read(IDENTITY_PAGE, &mut buf).is_err() {
        return None;
    }

    // Erased flash reads as 0xFF — no valid data
    if buf[0] == 0xFF {
        return None;
    }

    if buf[0..4] != MAGIC { return None; }
    if buf[4] != VERSION { return None; }

    let key = &buf[HEADER_SIZE..HEADER_SIZE + KEY_SIZE];
    let stored = [buf[HEADER_SIZE + KEY_SIZE], buf[HEADER_SIZE + KEY_SIZE + 1]];
    if stored != checksum(&buf[..HEADER_SIZE + KEY_SIZE]) { return None; }

    Identity::from_private_key_bytes(key).ok()
}

/// Save an identity to internal flash.
///
/// Erases the page first (~85ms CPU stall), then writes the identity record.
/// Should only be called once per device lifetime (first boot).
pub fn save_identity(nvmc: &mut Nvmc<'_>, identity: &Identity) {
    let key = match identity.private_key_bytes() {
        Ok(k) => k,
        Err(_) => return,
    };

    let mut buf = [0u8; BUF_SIZE];
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4] = VERSION;
    buf[HEADER_SIZE..HEADER_SIZE + KEY_SIZE].copy_from_slice(&key);
    let cs = checksum(&buf[..HEADER_SIZE + KEY_SIZE]);
    buf[HEADER_SIZE + KEY_SIZE] = cs[0];
    buf[HEADER_SIZE + KEY_SIZE + 1] = cs[1];

    // Erase page (4 KB, sets all bytes to 0xFF)
    let _ = nvmc.erase(IDENTITY_PAGE, IDENTITY_PAGE + 4096);

    // Write record (4-byte aligned)
    let _ = nvmc.write(IDENTITY_PAGE, &buf);
}
