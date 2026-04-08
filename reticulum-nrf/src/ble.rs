//! BLE Peripheral interface for T114 using trouble-host + nrf-sdc.
//!
//! Phase A: GATT service, advertising, connection handling, identity read.
//! No data pipeline — just prove the BLE stack works.

extern crate alloc;

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_nrf::peripherals;
use embassy_nrf::{bind_interrupts, rng, Peri};
use nrf_sdc::mpsl::MultiprotocolServiceLayer;
use nrf_sdc::{self as sdc, mpsl};
use static_cell::StaticCell;
use trouble_host::prelude::*;

// ─── Interrupt bindings (matches trouble nrf52 example) ────────────────────

// All interrupt bindings in one place — MPSL, SDC, USB, and RNG share
// some interrupts (CLOCK_POWER is used by both MPSL and USB VBUS detect).
bind_interrupts!(pub struct Irqs {
    RNG => rng::InterruptHandler<peripherals::RNG>;
    USBD => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
    EGU0_SWI0 => mpsl::LowPrioInterruptHandler;
    CLOCK_POWER => mpsl::ClockInterruptHandler, embassy_nrf::usb::vbus_detect::InterruptHandler;
    RADIO => mpsl::HighPrioInterruptHandler;
    TIMER0 => mpsl::HighPrioInterruptHandler;
    RTC0 => mpsl::HighPrioInterruptHandler;
});

// ─── GATT service (Columba v2.2) ──────────────────────────────────────────

#[gatt_server]
struct ReticulumServer {
    reticulum_service: ReticulumService,
}

#[gatt_service(uuid = "37145b00-442d-4a94-917f-8f42c5da28e3")]
struct ReticulumService {
    /// RX: peer writes data to us
    #[characteristic(uuid = "37145b00-442d-4a94-917f-8f42c5da28e5", write, write_without_response)]
    rx: [u8; 32],

    /// TX: we send data to peer via notify
    #[characteristic(uuid = "37145b00-442d-4a94-917f-8f42c5da28e4", read, notify)]
    tx: [u8; 32],

    /// Identity: static 16-byte transport identity hash
    #[characteristic(uuid = "37145b00-442d-4a94-917f-8f42c5da28e6", read)]
    identity: [u8; 16],
}

// ─── SDC builder ───────────────────────────────────────────────────────────

const L2CAP_TXQ: u8 = 3;
const L2CAP_RXQ: u8 = 3;

fn build_sdc<'d, const N: usize>(
    p: sdc::Peripherals<'d>,
    rng: &'d mut rng::Rng<'static, embassy_nrf::mode::Async>,
    mpsl: &'d MultiprotocolServiceLayer,
    mem: &'d mut sdc::Mem<N>,
) -> Result<sdc::SoftdeviceController<'d>, sdc::Error> {
    sdc::Builder::new()?
        .support_adv()
        .support_peripheral()
        .peripheral_count(1)?
        .buffer_cfg(
            DefaultPacketPool::MTU as u16,
            DefaultPacketPool::MTU as u16,
            L2CAP_TXQ,
            L2CAP_RXQ,
        )?
        .build(p, rng, mpsl, mem)
}

// ─── Tasks ─────────────────────────────────────────────────────────────────

#[embassy_executor::task]
async fn mpsl_task(mpsl: &'static MultiprotocolServiceLayer<'static>) -> ! {
    crate::info!("BLE: mpsl_task running");
    mpsl.run().await
}

#[embassy_executor::task]
async fn ble_task(
    sdc: sdc::SoftdeviceController<'static>,
    identity_hash: [u8; 16],
) {
    let address = Address::random([0xDE, 0xAD, 0xBE, 0xEF, 0xBA, 0xD1]);

    static RESOURCES: StaticCell<HostResources<DefaultPacketPool, 1, 2, 1>> = StaticCell::new();
    let resources = RESOURCES.init(HostResources::new());

    let stack = trouble_host::new(sdc, resources).set_random_address(address);
    let Host {
        mut peripheral,
        mut runner,
        ..
    } = stack.build();

    let server = ReticulumServer::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: "leviculum",
        appearance: &appearance::TAG,
    }))
    .expect("GATT server");

    let _ = server.set(&server.reticulum_service.identity, &identity_hash);

    let _ = join(
        // Host runner (processes HCI events)
        async {
            loop {
                match runner.run().await {
                    Err(e) => {
                        crate::log::log_fmt("[BLE ] ", format_args!("runner err: {:?}", e));
                    }
                    Ok(()) => {
                        crate::info!("BLE: runner returned Ok");
                    }
                }
            }
        },
        // Peripheral advertising loop
        async {
            loop {
                match advertise(&mut peripheral, &server).await {
                    Ok(conn) => {
                        gatt_events(&server, &conn).await;
                    }
                    Err(e) => {
                        crate::log::log_fmt("[BLE ] ", format_args!("adv err: {:?}", e));
                        embassy_time::Timer::after_millis(1000).await;
                    }
                }
            }
        },
    )
    .await;
}

// ─── Init ──────────────────────────────────────────────────────────────────

/// Initialize MPSL + SDC and spawn the BLE task.
///
/// Returns immediately after spawning. The BLE task handles advertising,
/// connections, and GATT events in the background.
pub fn init(
    spawner: &Spawner,
    identity_hash: [u8; 16],
    // MPSL peripherals
    rtc0: Peri<'static, peripherals::RTC0>,
    timer0: Peri<'static, peripherals::TIMER0>,
    temp: Peri<'static, peripherals::TEMP>,
    ppi_ch19: Peri<'static, peripherals::PPI_CH19>,
    ppi_ch30: Peri<'static, peripherals::PPI_CH30>,
    ppi_ch31: Peri<'static, peripherals::PPI_CH31>,
    // SDC peripherals
    ppi_ch17: Peri<'static, peripherals::PPI_CH17>,
    ppi_ch18: Peri<'static, peripherals::PPI_CH18>,
    ppi_ch20: Peri<'static, peripherals::PPI_CH20>,
    ppi_ch21: Peri<'static, peripherals::PPI_CH21>,
    ppi_ch22: Peri<'static, peripherals::PPI_CH22>,
    ppi_ch23: Peri<'static, peripherals::PPI_CH23>,
    ppi_ch24: Peri<'static, peripherals::PPI_CH24>,
    ppi_ch25: Peri<'static, peripherals::PPI_CH25>,
    ppi_ch26: Peri<'static, peripherals::PPI_CH26>,
    ppi_ch27: Peri<'static, peripherals::PPI_CH27>,
    ppi_ch28: Peri<'static, peripherals::PPI_CH28>,
    ppi_ch29: Peri<'static, peripherals::PPI_CH29>,
    // RNG
    rng_periph: Peri<'static, peripherals::RNG>,
) {
    // 1. MPSL
    let mpsl_p = mpsl::Peripherals::new(rtc0, timer0, temp, ppi_ch19, ppi_ch30, ppi_ch31);
    // T114 has no 32.768 kHz LFXO crystal — use internal RC oscillator.
    // MPSL calibrates the RC periodically via TEMP sensor.
    let lfclk_cfg = mpsl::raw::mpsl_clock_lfclk_cfg_t {
        source: mpsl::raw::MPSL_CLOCK_LF_SRC_RC as u8,
        rc_ctiv: mpsl::raw::MPSL_RECOMMENDED_RC_CTIV as u8,
        rc_temp_ctiv: mpsl::raw::MPSL_RECOMMENDED_RC_TEMP_CTIV as u8,
        accuracy_ppm: mpsl::raw::MPSL_DEFAULT_CLOCK_ACCURACY_PPM as u16,
        skip_wait_lfclk_started: mpsl::raw::MPSL_DEFAULT_SKIP_WAIT_LFCLK_STARTED != 0,
    };

    static MPSL: StaticCell<MultiprotocolServiceLayer> = StaticCell::new();
    let mpsl = MPSL.init(
        mpsl::MultiprotocolServiceLayer::new(mpsl_p, Irqs, lfclk_cfg)
            .expect("MPSL init"),
    );
    spawner.must_spawn(mpsl_task(mpsl));
    crate::info!("BLE: MPSL ok");

    // 2. SDC
    let sdc_p = sdc::Peripherals::new(
        ppi_ch17, ppi_ch18, ppi_ch20, ppi_ch21, ppi_ch22, ppi_ch23,
        ppi_ch24, ppi_ch25, ppi_ch26, ppi_ch27, ppi_ch28, ppi_ch29,
    );

    static RNG: StaticCell<rng::Rng<'static, embassy_nrf::mode::Async>> = StaticCell::new();
    let rng = RNG.init(rng::Rng::new(rng_periph, Irqs));

    static SDC_MEM: StaticCell<sdc::Mem<4720>> = StaticCell::new();
    let sdc_mem = SDC_MEM.init(sdc::Mem::new());

    let sdc = build_sdc(sdc_p, rng, mpsl, sdc_mem).expect("SDC build");
    crate::info!("BLE: SDC ok");

    // 3. Spawn BLE task (handles host runner + peripheral loop)
    spawner.must_spawn(ble_task(sdc, identity_hash));
}

// ─── Advertising ───────────────────────────────────────────────────────────

async fn advertise<'values, 'server, C: Controller>(
    peripheral: &mut Peripheral<'values, C, DefaultPacketPool>,
    server: &'server ReticulumServer<'values>,
) -> Result<GattConnection<'values, 'server, DefaultPacketPool>, BleHostError<C::Error>> {
    // Advertising data: flags + 128-bit service UUID
    let mut adv_data = [0; 31];
    let uuid_bytes: [u8; 16] = [
        0xe3, 0x28, 0xda, 0xc5, 0x42, 0x8f, 0x7f, 0x91,
        0x94, 0x4a, 0x2d, 0x44, 0x00, 0x5b, 0x14, 0x37,
    ];
    let adv_len = AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::CompleteServiceUuids128(&[uuid_bytes]),
        ],
        &mut adv_data[..],
    )?;

    // Scan response: complete local name (Android sends SCAN_REQ before CONNECT_REQ)
    let mut scan_data = [0; 31];
    let scan_len = AdStructure::encode_slice(
        &[AdStructure::CompleteLocalName(b"leviculum")],
        &mut scan_data[..],
    )?;

    let params = AdvertisementParameters {
        interval_min: embassy_time::Duration::from_millis(100),
        interval_max: embassy_time::Duration::from_millis(200),
        ..Default::default()
    };

    crate::info!("BLE: advertise adv={}B scan={}B", adv_len, scan_len);
    let advertiser = peripheral
        .advertise(
            &params,
            Advertisement::ConnectableScannableUndirected {
                adv_data: &adv_data[..adv_len],
                scan_data: &scan_data[..scan_len],
            },
        )
        .await?;

    crate::info!("BLE: waiting for connection");
    match advertiser.accept().await {
        Ok(conn) => {
            crate::info!("BLE: accepted, setting up GATT");
            let gatt = conn.with_attribute_server(server)?;
            crate::info!("BLE: peer connected");
            Ok(gatt)
        }
        Err(e) => {
            crate::log::log_fmt("[BLE ] ", format_args!("accept err: {:?}", e));
            Err(e.into())
        }
    }
}

// ─── GATT event handling ───────────────────────────────────────────────────

async fn gatt_events(
    server: &ReticulumServer<'_>,
    conn: &GattConnection<'_, '_, DefaultPacketPool>,
) {
    let rx = server.reticulum_service.rx;
    loop {
        match conn.next().await {
            GattConnectionEvent::Disconnected { reason } => {
                crate::log::log_fmt("[BLE ] ", format_args!("disconnected: {:?}", reason));
                break;
            }
            GattConnectionEvent::Gatt { event } => {
                match &event {
                    GattEvent::Write(write) => {
                        crate::info!("BLE: write h={} {}B", write.handle(), write.data().len());
                    }
                    GattEvent::Read(read) => {
                        crate::info!("BLE: read h={}", read.handle());
                    }
                    GattEvent::Other(_) => {
                        crate::info!("BLE: gatt other");
                    }
                    GattEvent::NotAllowed(ref na) => {
                        crate::info!("BLE: gatt not_allowed h={}", na.handle());
                    }
                }
                match event.accept() {
                    Ok(reply) => reply.send().await,
                    Err(_) => {
                        crate::info!("BLE: accept err");
                    }
                }
            }
            GattConnectionEvent::PhyUpdated { .. } => {
                crate::info!("BLE: phy updated");
            }
            GattConnectionEvent::DataLengthUpdated { .. } => {
                crate::info!("BLE: data length updated");
            }
            _ => {
                crate::info!("BLE: other conn event");
            }
        }
    }
}
