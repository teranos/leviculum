//! Firmware entry point for RAKwireless WisMesh Pocket V2 (RAK4631 module).
//!
//! Phase 1 skeleton: USB CDC-ACM serial up, LED1 (P1.03, active high) heartbeat,
//! identity loaded/persisted in internal flash, no LoRa, no BLE, no baseboard
//! peripherals. Tracked under Codeberg #42.
//!
//! The board exposes one Reticulum interface in this build:
//! - Interface 0: USB CDC-ACM serial (HDLC framing) to host
//!
//! LoRa (Phase 2) and OLED/GNSS/battery (Phase 3) will hook in here.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use embassy_executor::Spawner;
use embassy_futures::select::{select, Either};
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_time::{Duration, Instant, Timer};

use reticulum_core::embedded_storage::EmbeddedStorage;
use reticulum_core::ifac::IfacConfig;
use reticulum_core::node::NodeCoreBuilder;
use reticulum_core::traits::Interface;
use reticulum_core::transport::dispatch_actions;
use reticulum_core::InterfaceId;

use reticulum_nrf::boards::rak4631;
use reticulum_nrf::clock::EmbassyClock;
use reticulum_nrf::interface::EmbeddedInterface;
use reticulum_nrf::{info, init_heap};

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    config.gpiote_interrupt_priority = embassy_nrf::interrupt::Priority::P2;
    config.time_interrupt_priority = embassy_nrf::interrupt::Priority::P2;
    let p = embassy_nrf::init(config);

    init_heap();
    reticulum_nrf::init_tracing();
    // SAFETY: called once before any complex work or concurrent tasks
    unsafe { reticulum_nrf::paint_stack(); }

    reticulum_nrf::set_panic_led(rak4631::PANIC_LED_PORT, rak4631::PANIC_LED_PIN, rak4631::PANIC_LED_ACTIVE_LOW);

    let serial = reticulum_nrf::usb::init(&spawner, p.USBD, &rak4631::CONFIG);

    info!("leviculum RAK4631 booting");

    // Phase 1: keep the baseboard 3V3-S rail OFF (no OLED/GNSS/sensors yet).
    // Phase 2 will drive this HIGH before powering up the LoRa front-end.
    let _periph_3v3 = Output::new(p.P1_02, Level::Low, OutputDrive::Standard);
    let led = rak4631::led(p.P1_03);

    let rng = reticulum_nrf::rng::RawHwRng::new();

    // Load or generate persistent identity from internal flash
    let mut id_store = reticulum_nrf::flash::NvmcIdentityStore::new(
        embassy_nrf::nvmc::Nvmc::new(p.NVMC),
        rak4631::CONFIG.identity_flash_page,
    );

    let mut builder = NodeCoreBuilder::new()
        .enable_transport(true)
        .max_incoming_resource_size(8 * 1024)
        .max_queued_announces(32)
        .max_random_blobs(8)
        .respond_to_probes(true);

    let identity_loaded = {
        use reticulum_core::identity_store::IdentityStore;
        if let Ok(Some(identity)) = id_store.load() {
            info!("Identity loaded from flash");
            builder = builder.identity(identity);
            true
        } else {
            info!("No identity in flash, generating new");
            false
        }
    };

    let mut node = Box::new(builder.build(rng, EmbassyClock, EmbeddedStorage::new()));

    let initial_path_len = node.path_count();
    info!("[BOOT] path_table_initial_len={}", initial_path_len);
    spawner.must_spawn(boot_log_repeater(initial_path_len));

    if !identity_loaded {
        use reticulum_core::identity_store::IdentityStore;
        let _ = id_store.save(node.identity());
        info!("Identity saved to flash");
    }

    // Register the serial interface only — Phase 1 is a single-interface skeleton.
    node.set_interface_name(0, alloc::string::String::from("serial_usb"));
    node.set_interface_hw_mtu(0, 564);

    let hash = node.identity().hash();
    info!(
        "LNode started -- identity: {:02X}{:02X}{:02X}{:02X}{:02X}",
        hash[0], hash[1], hash[2], hash[3], hash[4]
    );
    // Full identity hash for benchmark trace correlation
    reticulum_nrf::log::log_fmt("[IDENTITY] ", format_args!(
        "rak_node={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]
    ));
    if let Some(probe_hash) = node.probe_dest_hash() {
        let ph = probe_hash.as_bytes();
        reticulum_nrf::log::log_fmt("[IDENTITY] ", format_args!(
            "rak_probe={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            ph[0], ph[1], ph[2], ph[3], ph[4], ph[5], ph[6], ph[7],
            ph[8], ph[9], ph[10], ph[11], ph[12], ph[13], ph[14], ph[15]
        ));
    }

    let (hu, hf) = reticulum_nrf::heap_stats();
    let sf = reticulum_nrf::stack_free();
    info!("heap u={} f={} stack f={}", hu, hf, sf);

    // Interface adapters
    let mut serial_iface = EmbeddedInterface::new(serial.outgoing_tx);
    let ifac_configs: BTreeMap<usize, IfacConfig> = BTreeMap::new();

    // Heartbeat task — visible "alive" indicator on LED1.
    spawner.must_spawn(led_heartbeat(led));

    // Event-driven main loop, two event sources:
    // 1. Serial incoming (USB)
    // 2. Timer deadline (protocol maintenance, announces)
    loop {
        let deadline = node
            .next_deadline()
            .map(Instant::from_millis)
            .unwrap_or(Instant::MAX);

        match select(serial.incoming_rx.receive(), Timer::at(deadline)).await {
            Either::First(data) => {
                info!("SER RX {} bytes", data.len());
                let output = node.handle_packet(InterfaceId(0), &data);
                info!("SER RX -> {} actions", output.actions.len());
                let mut ifaces: [&mut dyn Interface; 1] = [&mut serial_iface];
                dispatch_actions(&mut ifaces, output.actions, &ifac_configs);
            }
            Either::Second(()) => {
                let output = node.handle_timeout();
                if !output.actions.is_empty() {
                    info!("timeout: {} actions", output.actions.len());
                }
                let mut ifaces: [&mut dyn Interface; 1] = [&mut serial_iface];
                dispatch_actions(&mut ifaces, output.actions, &ifac_configs);
            }
        }
    }
}

#[embassy_executor::task]
async fn boot_log_repeater(initial_len: usize) {
    for _ in 0..6 {
        Timer::after(Duration::from_secs(10)).await;
        info!("[BOOT] path_table_initial_len={}", initial_len);
    }
}

#[embassy_executor::task]
async fn led_heartbeat(mut led: Output<'static>) {
    loop {
        led.set_high();
        Timer::after(Duration::from_millis(500)).await;
        led.set_low();
        Timer::after(Duration::from_millis(500)).await;
    }
}
