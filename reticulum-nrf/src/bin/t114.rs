//! Firmware entry point for Heltec Mesh Node T114
//!
//! Runs a Reticulum endpoint node with a serial interface over USB CDC-ACM.
//! The host connects via SerialInterface (HDLC framing) on /dev/ttyACM1.
//! Debug log output appears on /dev/ttyACM0.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::BTreeMap;
use embassy_executor::Spawner;
use embassy_futures::select::{select, Either};
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::rng::Rng;
use embassy_time::{Instant, Timer};

use reticulum_core::embedded_storage::EmbeddedStorage;
use reticulum_core::node::NodeCoreBuilder;
use reticulum_core::traits::Interface;
use reticulum_core::transport::dispatch_actions;
use reticulum_core::InterfaceId;

use reticulum_nrf::boards::t114;
use reticulum_nrf::clock::EmbassyClock;
use reticulum_nrf::interface::EmbeddedInterface;
use reticulum_nrf::{info, init_heap};

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    let p = embassy_nrf::init(config);

    init_heap();

    // Initialize USB composite device and get serial channel endpoints
    let serial = reticulum_nrf::usb::init(&spawner, p.USBD);

    info!("leviculum T114 booting");

    // Disable VEXT power rail — cuts power to NeoPixel LEDs and external peripherals
    let _vext = Output::new(p.P0_21, Level::Low, OutputDrive::Standard);

    // Heartbeat LED (active low)
    let mut led = t114::led(p.P1_03);

    // Hardware RNG (blocking mode — no interrupt binding needed)
    let rng = Rng::new_blocking(p.RNG);

    // Build NodeCore with embedded-optimized limits
    let mut node = NodeCoreBuilder::new()
        .max_incoming_resource_size(8 * 1024)
        .max_queued_announces(32)
        .max_random_blobs(8)
        .build(rng, EmbassyClock, EmbeddedStorage::new());

    // Log identity hash
    let hash = node.identity().hash();
    info!(
        "LNode started -- identity: {:02X}{:02X}{:02X}{:02X}{:02X}",
        hash[0], hash[1], hash[2], hash[3], hash[4]
    );
    info!("Serial interface online on USB port 1");

    // Interface adapter for dispatch_actions()
    let mut iface = EmbeddedInterface::new(serial.outgoing_tx);
    let ifac_configs = BTreeMap::new(); // no IFAC on serial

    // Blink once to signal boot complete
    led.set_level(Level::Low);
    Timer::after_millis(200).await;
    led.set_level(Level::High);

    // Event-driven main loop
    loop {
        // Compute next NodeCore deadline
        let deadline = node
            .next_deadline()
            .map(Instant::from_millis)
            .unwrap_or(Instant::MAX);

        match select(serial.incoming_rx.receive(), Timer::at(deadline)).await {
            // Incoming packet from USB serial
            Either::First(data) => {
                let output = node.handle_packet(InterfaceId(0), &data);
                let mut ifaces: [&mut dyn Interface; 1] = [&mut iface];
                dispatch_actions(&mut ifaces, output.actions, &ifac_configs);
            }
            // Timer deadline reached — run periodic tasks
            Either::Second(()) => {
                let output = node.handle_timeout();
                let mut ifaces: [&mut dyn Interface; 1] = [&mut iface];
                dispatch_actions(&mut ifaces, output.actions, &ifac_configs);
            }
        }
    }
}
