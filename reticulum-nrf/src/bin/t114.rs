//! Firmware entry point for Heltec Mesh Node T114
//!
//! Runs a Reticulum transport node with three interfaces:
//! - Interface 0: USB CDC-ACM serial (HDLC framing) to host
//! - Interface 1: SX1262 LoRa radio
//! - Interface 2: BLE peripheral (Columba v2.2 protocol)
//!
//! The transport engine routes packets between all interfaces.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use embassy_executor::Spawner;
use embassy_futures::select::{select4, Either4};
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_time::{Instant, Timer};

use reticulum_core::embedded_storage::EmbeddedStorage;
use reticulum_core::ifac::IfacConfig;
use reticulum_core::node::NodeCoreBuilder;
use reticulum_core::traits::Interface;
use reticulum_core::transport::dispatch_actions;
use reticulum_core::InterfaceId;

use reticulum_nrf::ble::BleInterface;
use reticulum_nrf::boards::t114;
use reticulum_nrf::clock::EmbassyClock;
use reticulum_nrf::interface::EmbeddedInterface;
use reticulum_nrf::lora::LoRaInterface;
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

    let serial = reticulum_nrf::usb::init(&spawner, p.USBD);

    info!("leviculum T114 booting");

    let _vext = Output::new(p.P0_21, Level::Low, OutputDrive::Standard);
    let mut led = t114::led(p.P1_03);

    let rng = reticulum_nrf::rng::RawHwRng::new();

    let mut node = Box::new(
        NodeCoreBuilder::new()
            .enable_transport(true)
            .max_incoming_resource_size(8 * 1024)
            .max_queued_announces(32)
            .max_random_blobs(8)
            .respond_to_probes(true)
            .build(rng, EmbassyClock, EmbeddedStorage::new()),
    );

    // Register all three interfaces
    node.set_interface_name(0, alloc::string::String::from("serial_usb"));
    node.set_interface_hw_mtu(0, 564);
    node.set_interface_name(1, alloc::string::String::from("lora_sx1262"));
    node.set_interface_hw_mtu(1, 255);
    node.set_interface_name(2, alloc::string::String::from("ble"));
    node.set_interface_hw_mtu(2, 564);

    let hash = node.identity().hash();
    info!(
        "LNode started -- identity: {:02X}{:02X}{:02X}{:02X}{:02X}",
        hash[0], hash[1], hash[2], hash[3], hash[4]
    );

    // LoRa
    let lora = reticulum_nrf::lora::init(
        p.SPI3, p.P0_19, p.P0_22, p.P0_23, p.P0_24, p.P0_25, p.P0_17, p.P0_20,
    )
    .await;
    info!("SX1262 ready");

    let radio_cfg = reticulum_nrf::lora::RadioConfig::eu_medium();
    let lora_channels = reticulum_nrf::lora::channels();
    spawner.must_spawn(reticulum_nrf::lora::lora_task(lora, radio_cfg));

    // BLE
    let identity_hash = *node.identity().hash();
    reticulum_nrf::ble::init(
        &spawner, identity_hash,
        p.RTC0, p.TIMER0, p.TEMP, p.PPI_CH19, p.PPI_CH30, p.PPI_CH31,
        p.PPI_CH17, p.PPI_CH18, p.PPI_CH20, p.PPI_CH21, p.PPI_CH22, p.PPI_CH23,
        p.PPI_CH24, p.PPI_CH25, p.PPI_CH26, p.PPI_CH27, p.PPI_CH28, p.PPI_CH29,
        p.RNG,
    );
    let ble_channels = reticulum_nrf::ble::channels();
    info!("BLE ready");

    let (hu, hf) = reticulum_nrf::heap_stats();
    let sf = reticulum_nrf::stack_free();
    info!("heap u={} f={} stack f={}", hu, hf, sf);

    // Interface adapters
    let mut serial_iface = EmbeddedInterface::new(serial.outgoing_tx);
    let mut lora_iface = LoRaInterface::new(lora_channels.outgoing_tx);
    let mut ble_iface = BleInterface::new(ble_channels.outgoing_tx);
    let ifac_configs: BTreeMap<usize, IfacConfig> = BTreeMap::new();

    // Boot blink
    led.set_level(Level::Low);
    for _ in 0..12_000_000u32 {
        cortex_m::asm::nop();
    }
    led.set_level(Level::High);

    // Event-driven main loop — four event sources:
    // 1. Serial incoming (USB)
    // 2. LoRa incoming (radio)
    // 3. BLE incoming (defragmented Reticulum packets from phone)
    // 4. Timer deadline (protocol maintenance, announces)
    loop {
        let deadline = node
            .next_deadline()
            .map(Instant::from_millis)
            .unwrap_or(Instant::MAX);

        match select4(
            serial.incoming_rx.receive(),
            lora_channels.incoming_rx.receive(),
            ble_channels.incoming_rx.receive(),
            Timer::at(deadline),
        )
        .await
        {
            Either4::First(data) => {
                let output = node.handle_packet(InterfaceId(0), &data);
                if !output.actions.is_empty() {
                    info!("SER RX -> {} actions", output.actions.len());
                }
                let mut ifaces: [&mut dyn Interface; 3] =
                    [&mut serial_iface, &mut lora_iface, &mut ble_iface];
                dispatch_actions(&mut ifaces, output.actions, &ifac_configs);
            }
            Either4::Second(data) => {
                let output = node.handle_packet(InterfaceId(1), &data);
                if !output.actions.is_empty() {
                    info!("LORA RX -> {} actions", output.actions.len());
                }
                let mut ifaces: [&mut dyn Interface; 3] =
                    [&mut serial_iface, &mut lora_iface, &mut ble_iface];
                dispatch_actions(&mut ifaces, output.actions, &ifac_configs);
            }
            Either4::Third(data) => {
                info!("BLE RX {} bytes", data.len());
                let output = node.handle_packet(InterfaceId(2), &data);
                if !output.actions.is_empty() {
                    info!("BLE RX -> {} actions", output.actions.len());
                }
                let mut ifaces: [&mut dyn Interface; 3] =
                    [&mut serial_iface, &mut lora_iface, &mut ble_iface];
                dispatch_actions(&mut ifaces, output.actions, &ifac_configs);
            }
            Either4::Fourth(()) => {
                let output = node.handle_timeout();
                if !output.actions.is_empty() {
                    info!("timeout: {} actions", output.actions.len());
                }
                let mut ifaces: [&mut dyn Interface; 3] =
                    [&mut serial_iface, &mut lora_iface, &mut ble_iface];
                dispatch_actions(&mut ifaces, output.actions, &ifac_configs);
            }
        }
    }
}
