//! Shared state for RAK19026 baseboard peripherals (display + GNSS + battery).
//!
//! This module is the rendezvous point between the producer tasks (GNSS,
//! battery) and the consumer task (display). It is compiled whenever any
//! one of the three feature flags is enabled; each individual `Watch` /
//! struct definition is then gated on the producing peripheral's feature.
//!
//! Phase 3 commit 1 (display) only ships the empty shell — `BatteryState`
//! and `GnssFix` join the file in commits 2 and 3. The display task
//! tolerates absent producers (renders "—" placeholders).

#![allow(dead_code)]
