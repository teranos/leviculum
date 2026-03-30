//! Firmware entry point for Heltec Mesh Node T114
//!
//! Runs a Reticulum endpoint node with a serial interface over USB CDC-ACM.
//! The host connects via SerialInterface (HDLC framing) on the transport port.
//! Debug log output appears on the debug port.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use embassy_executor::Spawner;
use embassy_futures::select::{select, Either};
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::rng::Rng;
use embassy_time::{Instant, Timer};

use reticulum_core::embedded_storage::EmbeddedStorage;
use reticulum_core::ifac::IfacConfig;
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
    // SAFETY: called once before any complex work or concurrent tasks
    unsafe { reticulum_nrf::paint_stack(); }

    // Initialize USB composite device and get serial channel endpoints
    let serial = reticulum_nrf::usb::init(&spawner, p.USBD);

    info!("leviculum T114 booting");

    // Disable VEXT power rail — cuts power to NeoPixel LEDs and external peripherals
    let _vext = Output::new(p.P0_21, Level::Low, OutputDrive::Standard);

    // Heartbeat LED (active low)
    let mut led = t114::led(p.P1_03);

    // Hardware RNG (blocking mode — no interrupt binding needed)
    let rng = Rng::new_blocking(p.RNG);

    // Build NodeCore on the heap — the async frame is too large for the stack
    // when NodeCore (~40 KB with EmbeddedStorage) lives inline. Boxing moves it
    // to the heap (89 KB free), freeing ~40 KB of stack for the Ed25519 signing
    // call chain in management announces.
    let mut node = Box::new(
        NodeCoreBuilder::new()
            .enable_transport(true)
            .max_incoming_resource_size(8 * 1024)
            .max_queued_announces(32)
            .max_random_blobs(8)
            .respond_to_probes(true)
            .build(rng, EmbassyClock, EmbeddedStorage::new()),
    );

    // Register interface with NodeCore for routing decisions
    node.set_interface_name(0, alloc::string::String::from("serial_usb"));
    node.set_interface_hw_mtu(0, 564);

    // Log identity hash
    let hash = node.identity().hash();
    info!(
        "LNode started -- identity: {:02X}{:02X}{:02X}{:02X}{:02X}",
        hash[0], hash[1], hash[2], hash[3], hash[4]
    );
    info!("Serial interface online on USB port 1");

    let (hu, hf) = reticulum_nrf::heap_stats();
    let sf = reticulum_nrf::stack_free();
    info!("heap u={} f={} stack f={}", hu, hf, sf);

    // Interface adapter and IFAC config for dispatch_actions()
    let mut iface = EmbeddedInterface::new(serial.outgoing_tx);
    let ifac_configs: BTreeMap<usize, IfacConfig> = BTreeMap::new();

    // Boot blink
    led.set_level(Level::Low);
    for _ in 0..12_000_000u32 {
        cortex_m::asm::nop();
    }
    led.set_level(Level::High);

    // Event-driven main loop
    loop {
        let node_deadline = node
            .next_deadline()
            .map(Instant::from_millis)
            .unwrap_or(Instant::MAX);
        let heartbeat = Instant::now() + embassy_time::Duration::from_secs(5);
        let deadline = if node_deadline < heartbeat {
            node_deadline
        } else {
            heartbeat
        };

        match select(serial.incoming_rx.receive(), Timer::at(deadline)).await {
            Either::First(data) => {
                info!("RX {} bytes", data.len());
                let output = node.handle_packet(InterfaceId(0), &data);
                if !output.actions.is_empty() {
                    info!("TX {} actions", output.actions.len());
                }
                let mut ifaces: [&mut dyn Interface; 1] = [&mut iface];
                dispatch_actions(&mut ifaces, output.actions, &ifac_configs);
            }
            Either::Second(()) => {
                let output = node.handle_timeout();
                if !output.actions.is_empty() {
                    info!("timeout: {} actions", output.actions.len());
                }
                // Heartbeat blink
                led.set_level(Level::Low);
                Timer::after_millis(50).await;
                led.set_level(Level::High);
                let mut ifaces: [&mut dyn Interface; 1] = [&mut iface];
                dispatch_actions(&mut ifaces, output.actions, &ifac_configs);
            }
        }
    }
}
