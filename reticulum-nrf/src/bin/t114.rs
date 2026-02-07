//! Firmware entry point for Heltec Mesh Node T114
//!
//! Heartbeat blink loop — proves the board boots, heap works, and
//! Embassy task scheduling is functional.

#![no_std]
#![no_main]

extern crate alloc;

use defmt::info;
use embassy_executor::Spawner;
use embassy_nrf::gpio::{Level, Output};
use embassy_time::Timer;
use {defmt_rtt as _, panic_probe as _};

use reticulum_nrf::boards::t114;
use reticulum_nrf::init_heap;

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let p = embassy_nrf::init(Default::default());

    init_heap();

    info!("Heltec Mesh Node T114 — leviculum firmware");

    // Prove heap works
    let v: alloc::vec::Vec<u8> = alloc::vec![1, 2, 3];
    info!("Heap OK: allocated {} bytes", v.len());

    // Disable VEXT power rail — cuts power to NeoPixel LEDs and external peripherals
    let _vext = Output::new(p.P0_21, Level::Low, embassy_nrf::gpio::OutputDrive::Standard);

    let mut led = t114::led(p.P1_03);

    loop {
        // LED is active low: Level::Low = on, Level::High = off
        led.set_level(Level::Low);
        Timer::after_millis(100).await;
        led.set_level(Level::High);
        Timer::after_millis(500).await;
    }
}
