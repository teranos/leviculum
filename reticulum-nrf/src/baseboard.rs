//! Shared state for RAK19026 baseboard peripherals (display + GNSS + battery).
//!
//! This module is the rendezvous point between the producer tasks (GNSS,
//! battery) and the consumer task (display). It is compiled whenever any
//! one of the three feature flags is enabled; each individual `Watch` /
//! struct definition is then gated on the producing peripheral's feature.

#![allow(dead_code)]

#[cfg(feature = "gnss")]
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
#[cfg(feature = "gnss")]
use embassy_sync::watch::Watch;

/// Compact GNSS fix snapshot — what the display task needs and nothing
/// more. Updated by `gnss::gnss_task` when an RMC or GGA sentence parses
/// cleanly. `valid` is the receiver's own validity flag (RMC `Mode::is_valid`
/// or GGA quality != NoFix), not a project-wide policy.
///
/// `latitude` / `longitude` are decimal degrees with sign (negative = S/W,
/// positive = N/E). They keep their last good values across non-valid
/// sentences so the display has something to render even briefly during
/// a fix dip.
#[cfg(feature = "gnss")]
#[derive(Clone, Copy, Debug)]
pub struct GnssFix {
    /// True when the receiver reports a usable fix.
    pub valid: bool,
    /// Number of satellites in use, from the latest GGA.
    pub sat_in_use: u8,
    /// Latitude in decimal degrees (signed). `None` until the first valid
    /// sentence carries position data.
    pub latitude: Option<f64>,
    /// Longitude in decimal degrees (signed). Same convention as latitude.
    pub longitude: Option<f64>,
}

#[cfg(feature = "gnss")]
impl GnssFix {
    pub const fn empty() -> Self {
        Self { valid: false, sat_in_use: 0, latitude: None, longitude: None }
    }
}

/// Latest GNSS fix snapshot. Capacity-2 watch: one slot for the producer,
/// one for the display consumer.
#[cfg(feature = "gnss")]
pub static GNSS_FIX: Watch<CriticalSectionRawMutex, GnssFix, 2> = Watch::new();
