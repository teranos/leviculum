//! Firmware entry point for Heltec Mesh Node T114
//!
//! Heartbeat blink loop — proves the board boots, heap works, USB CDC-ACM
//! debug logging is functional, and Embassy task scheduling works.

#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_time::Timer;

use reticulum_nrf::boards::t114;
use reticulum_nrf::{info, init_heap};

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    let p = embassy_nrf::init(config);

    init_heap();

    // Initialize USB composite device (debug + reticulum CDC-ACM ports)
    reticulum_nrf::usb::init(&spawner, p.USBD);

    info!("leviculum T114 booting");

    // Disable VEXT power rail — cuts power to NeoPixel LEDs and external peripherals
    let _vext = Output::new(p.P0_21, Level::Low, OutputDrive::Standard);

    let mut led = t114::led(p.P1_03);
    let mut counter: u32 = 0;

    loop {
        // LED is active low: Level::Low = on, Level::High = off
        led.set_level(Level::Low);
        Timer::after_millis(100).await;
        led.set_level(Level::High);
        Timer::after_millis(900).await;
        counter = counter.wrapping_add(1);
        info!("heartbeat {}", counter);
    }
}
