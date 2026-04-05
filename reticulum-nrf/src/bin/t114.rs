//! Firmware entry point for Heltec Mesh Node T114
//!
//! Runs a Reticulum transport node with two interfaces:
//! - Interface 0: USB CDC-ACM serial (HDLC framing) to host
//! - Interface 1: SX1262 LoRa radio
//!
//! The transport engine routes packets between interfaces.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use embassy_executor::Spawner;
use embassy_futures::select::{select3, Either3};
use embassy_nrf::gpio::{Level, Output, OutputDrive};
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
use reticulum_nrf::lora::LoRaInterface;
use reticulum_nrf::{info, init_heap};

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    let p = embassy_nrf::init(config);

    init_heap();
    reticulum_nrf::init_tracing();
    // SAFETY: called once before any complex work or concurrent tasks
    unsafe { reticulum_nrf::paint_stack(); }

    // Initialize USB composite device and get serial channel endpoints
    let serial = reticulum_nrf::usb::init(&spawner, p.USBD);

    info!("leviculum T114 booting");

    // Disable VEXT power rail — cuts power to NeoPixel LEDs and external peripherals
    let _vext = Output::new(p.P0_21, Level::Low, OutputDrive::Standard);

    // Boot blink LED (active low)
    let mut led = t114::led(p.P1_03);

    // Hardware RNG via direct register access — the embassy Rng peripheral
    // token (p.RNG) is reserved for the BLE SoftDevice Controller.
    let rng = reticulum_nrf::rng::RawHwRng::new();

    // Build NodeCore on the heap
    let mut node = Box::new(
        NodeCoreBuilder::new()
            .enable_transport(true)
            .max_incoming_resource_size(8 * 1024)
            .max_queued_announces(32)
            .max_random_blobs(8)
            .respond_to_probes(true)
            .build(rng, EmbassyClock, EmbeddedStorage::new()),
    );

    // Register interfaces with NodeCore
    node.set_interface_name(0, alloc::string::String::from("serial_usb"));
    node.set_interface_hw_mtu(0, 564);
    node.set_interface_name(1, alloc::string::String::from("lora_sx1262"));
    node.set_interface_hw_mtu(1, 255);

    let hash = node.identity().hash();
    info!(
        "LNode started -- identity: {:02X}{:02X}{:02X}{:02X}{:02X}",
        hash[0], hash[1], hash[2], hash[3], hash[4]
    );
    info!("Serial interface online on USB port 1");

    // Initialize SX1262 LoRa radio
    let lora = reticulum_nrf::lora::init(
        p.SPI3, p.P0_19, p.P0_22, p.P0_23, p.P0_24, p.P0_25, p.P0_17, p.P0_20,
    )
    .await;
    info!("SX1262 ready");

    // Configure and spawn LoRa task
    let radio_cfg = reticulum_nrf::lora::RadioConfig::eu_medium();
    info!(
        "LoRa: {}Hz BW={:?} SF={:?} preamble={}",
        radio_cfg.frequency_hz,
        radio_cfg.bandwidth,
        radio_cfg.spreading_factor,
        radio_cfg.preamble_symbols()
    );

    let lora_channels = reticulum_nrf::lora::channels();
    spawner.must_spawn(reticulum_nrf::lora::lora_task(lora, radio_cfg));

    // Initialize BLE peripheral (spawns MPSL + BLE tasks, returns immediately)
    info!("BLE init starting");
    let identity_hash = *node.identity().hash();
    reticulum_nrf::ble::init(
        &spawner, identity_hash,
        // MPSL peripherals
        p.RTC0, p.TIMER0, p.TEMP, p.PPI_CH19, p.PPI_CH30, p.PPI_CH31,
        // SDC peripherals
        p.PPI_CH17, p.PPI_CH18, p.PPI_CH20, p.PPI_CH21, p.PPI_CH22, p.PPI_CH23,
        p.PPI_CH24, p.PPI_CH25, p.PPI_CH26, p.PPI_CH27, p.PPI_CH28, p.PPI_CH29,
        // RNG for SDC crypto
        p.RNG,
    );

    info!("BLE init done");
    let (hu, hf) = reticulum_nrf::heap_stats();
    let sf = reticulum_nrf::stack_free();
    info!("heap u={} f={} stack f={}", hu, hf, sf);

    // Interface adapters for dispatch_actions()
    let mut serial_iface = EmbeddedInterface::new(serial.outgoing_tx);
    let mut lora_iface = LoRaInterface::new(lora_channels.outgoing_tx);
    let ifac_configs: BTreeMap<usize, IfacConfig> = BTreeMap::new();

    // Boot blink
    led.set_level(Level::Low);
    for _ in 0..12_000_000u32 {
        cortex_m::asm::nop();
    }
    led.set_level(Level::High);

    // Event-driven main loop — three event sources:
    // 1. Serial incoming packet (from host via USB)
    // 2. LoRa incoming packet (from radio)
    // 3. Timer deadline (protocol maintenance, announces)
    loop {
        let deadline = node
            .next_deadline()
            .map(Instant::from_millis)
            .unwrap_or(Instant::MAX);

        match select3(
            serial.incoming_rx.receive(),
            lora_channels.incoming_rx.receive(),
            Timer::at(deadline),
        )
        .await
        {
            Either3::First(data) => {
                info!("SER RX {} bytes", data.len());
                let output = node.handle_packet(InterfaceId(0), &data);
                if !output.actions.is_empty() {
                    info!("SER RX -> {} actions", output.actions.len());
                }
                let mut ifaces: [&mut dyn Interface; 2] =
                    [&mut serial_iface, &mut lora_iface];
                dispatch_actions(&mut ifaces, output.actions, &ifac_configs);
            }
            Either3::Second(data) => {
                info!("LORA RX {} bytes", data.len());
                let output = node.handle_packet(InterfaceId(1), &data);
                if !output.actions.is_empty() {
                    info!("LORA RX -> {} actions", output.actions.len());
                }
                let mut ifaces: [&mut dyn Interface; 2] =
                    [&mut serial_iface, &mut lora_iface];
                dispatch_actions(&mut ifaces, output.actions, &ifac_configs);
            }
            Either3::Third(()) => {
                let output = node.handle_timeout();
                if !output.actions.is_empty() {
                    info!("timeout: {} actions", output.actions.len());
                }
                let mut ifaces: [&mut dyn Interface; 2] =
                    [&mut serial_iface, &mut lora_iface];
                dispatch_actions(&mut ifaces, output.actions, &ifac_configs);
            }
        }
    }
}
