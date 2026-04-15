//! BLE Peripheral interface for T114 using trouble-host + nrf-sdc.
//!
//! Implements Columba Protocol v2.2: GATT service with RX/TX/Identity,
//! BLE fragmentation, keepalives, and identity handshake.

extern crate alloc;

use alloc::vec::Vec;
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_futures::select::{select3, Either3};
use embassy_nrf::peripherals;
use embassy_nrf::{bind_interrupts, rng, Peri};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::{Channel, Receiver, Sender};
use embassy_time::{Duration, Instant, Timer};
use nrf_sdc::mpsl::MultiprotocolServiceLayer;
use nrf_sdc::{self as sdc, mpsl};
use reticulum_core::framing::ble::{
    self as ble_framing, BleDefragmenter, DefragResult, FRAGMENT_HEADER_SIZE, KEEPALIVE_BYTE,
    KEEPALIVE_INTERVAL_MS,
};
use reticulum_core::traits::{Interface, InterfaceError};
use reticulum_core::InterfaceId;
use static_cell::StaticCell;
use trouble_host::prelude::*;

// Interrupt bindings
bind_interrupts!(pub struct Irqs {
    RNG => rng::InterruptHandler<peripherals::RNG>;
    USBD => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
    EGU0_SWI0 => mpsl::LowPrioInterruptHandler;
    CLOCK_POWER => mpsl::ClockInterruptHandler, embassy_nrf::usb::vbus_detect::InterruptHandler;
    RADIO => mpsl::HighPrioInterruptHandler;
    TIMER0 => mpsl::HighPrioInterruptHandler;
    RTC0 => mpsl::HighPrioInterruptHandler;
});

// GATT service (Columba v2.2)
#[gatt_server]
struct ReticulumServer {
    reticulum_service: ReticulumService,
}

#[gatt_service(uuid = "37145b00-442d-4a94-917f-8f42c5da28e3")]
struct ReticulumService {
    #[characteristic(uuid = "37145b00-442d-4a94-917f-8f42c5da28e5", write, write_without_response)]
    rx: heapless::Vec<u8, 251>,

    #[characteristic(uuid = "37145b00-442d-4a94-917f-8f42c5da28e4", read, notify)]
    tx: heapless::Vec<u8, 251>,

    #[characteristic(uuid = "37145b00-442d-4a94-917f-8f42c5da28e6", read)]
    identity: [u8; 16],
}

// Channels
static BLE_INCOMING: Channel<CriticalSectionRawMutex, Vec<u8>, 4> = Channel::new();
static BLE_OUTGOING: Channel<CriticalSectionRawMutex, Vec<u8>, 4> = Channel::new();

pub struct BleChannels {
    pub incoming_rx: Receiver<'static, CriticalSectionRawMutex, Vec<u8>, 4>,
    pub outgoing_tx: Sender<'static, CriticalSectionRawMutex, Vec<u8>, 4>,
}

pub fn channels() -> BleChannels {
    BleChannels {
        incoming_rx: BLE_INCOMING.receiver(),
        outgoing_tx: BLE_OUTGOING.sender(),
    }
}

// BleInterface
pub struct BleInterface {
    sender: Sender<'static, CriticalSectionRawMutex, Vec<u8>, 4>,
}

impl BleInterface {
    pub fn new(sender: Sender<'static, CriticalSectionRawMutex, Vec<u8>, 4>) -> Self {
        Self { sender }
    }
}

impl Interface for BleInterface {
    fn id(&self) -> InterfaceId { InterfaceId(2) }
    fn name(&self) -> &str { "ble" }
    fn mtu(&self) -> usize { 564 }
    fn is_online(&self) -> bool { true }
    fn try_send(&mut self, data: &[u8]) -> Result<(), InterfaceError> {
        self.sender.try_send(data.to_vec()).map_err(|_| InterfaceError::BufferFull)
    }
}

// SDC builder
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
        .buffer_cfg(DefaultPacketPool::MTU as u16, DefaultPacketPool::MTU as u16, 3, 3)?
        .build(p, rng, mpsl, mem)
}

// Tasks
#[embassy_executor::task]
async fn mpsl_task(mpsl: &'static MultiprotocolServiceLayer<'static>) -> ! {
    mpsl.run().await
}

#[embassy_executor::task]
async fn ble_task(sdc: sdc::SoftdeviceController<'static>, identity_hash: [u8; 16]) {
    // Derive BLE address from identity hash ; new identity per flash = new address
    // = clean GATT discovery on Android (no stale cache from previous firmware)
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&identity_hash[2..8]);
    addr[5] |= 0xC0; // bits 7:6 = 11 → valid random static address
    let address = Address::random(addr);

    static RESOURCES: StaticCell<HostResources<DefaultPacketPool, 1, 2, 1>> = StaticCell::new();
    let resources = RESOURCES.init(HostResources::new());

    let stack = trouble_host::new(sdc, resources).set_random_address(address);
    let Host { mut peripheral, mut runner, .. } = stack.build();

    let server = ReticulumServer::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: "leviculum",
        appearance: &appearance::TAG,
    })).expect("GATT server");

    let _ = server.set(&server.reticulum_service.identity, &identity_hash);

    let outgoing_rx = BLE_OUTGOING.receiver();
    let incoming_tx = BLE_INCOMING.sender();

    let _ = join(
        async { loop { let _ = runner.run().await; } },
        async {
            loop {
                match advertise(&mut peripheral, &server).await {
                    Ok(conn) => {
                        gatt_events(&server, &conn, &incoming_tx, &outgoing_rx).await;
                    }
                    Err(_) => {
                        Timer::after_millis(1000).await;
                    }
                }
            }
        },
    ).await;
}

// Init
pub fn init(
    spawner: &Spawner, identity_hash: [u8; 16],
    rtc0: Peri<'static, peripherals::RTC0>, timer0: Peri<'static, peripherals::TIMER0>,
    temp: Peri<'static, peripherals::TEMP>,
    ppi_ch19: Peri<'static, peripherals::PPI_CH19>, ppi_ch30: Peri<'static, peripherals::PPI_CH30>,
    ppi_ch31: Peri<'static, peripherals::PPI_CH31>,
    ppi_ch17: Peri<'static, peripherals::PPI_CH17>, ppi_ch18: Peri<'static, peripherals::PPI_CH18>,
    ppi_ch20: Peri<'static, peripherals::PPI_CH20>, ppi_ch21: Peri<'static, peripherals::PPI_CH21>,
    ppi_ch22: Peri<'static, peripherals::PPI_CH22>, ppi_ch23: Peri<'static, peripherals::PPI_CH23>,
    ppi_ch24: Peri<'static, peripherals::PPI_CH24>, ppi_ch25: Peri<'static, peripherals::PPI_CH25>,
    ppi_ch26: Peri<'static, peripherals::PPI_CH26>, ppi_ch27: Peri<'static, peripherals::PPI_CH27>,
    ppi_ch28: Peri<'static, peripherals::PPI_CH28>, ppi_ch29: Peri<'static, peripherals::PPI_CH29>,
    rng_periph: Peri<'static, peripherals::RNG>,
) {
    let mpsl_p = mpsl::Peripherals::new(rtc0, timer0, temp, ppi_ch19, ppi_ch30, ppi_ch31);
    let lfclk_cfg = mpsl::raw::mpsl_clock_lfclk_cfg_t {
        source: mpsl::raw::MPSL_CLOCK_LF_SRC_RC as u8,
        rc_ctiv: mpsl::raw::MPSL_RECOMMENDED_RC_CTIV as u8,
        rc_temp_ctiv: mpsl::raw::MPSL_RECOMMENDED_RC_TEMP_CTIV as u8,
        accuracy_ppm: mpsl::raw::MPSL_DEFAULT_CLOCK_ACCURACY_PPM as u16,
        skip_wait_lfclk_started: mpsl::raw::MPSL_DEFAULT_SKIP_WAIT_LFCLK_STARTED != 0,
    };
    static MPSL: StaticCell<MultiprotocolServiceLayer> = StaticCell::new();
    let mpsl = MPSL.init(mpsl::MultiprotocolServiceLayer::new(mpsl_p, Irqs, lfclk_cfg).expect("MPSL"));
    spawner.must_spawn(mpsl_task(mpsl));
    crate::info!("BLE: MPSL ok");

    let sdc_p = sdc::Peripherals::new(
        ppi_ch17, ppi_ch18, ppi_ch20, ppi_ch21, ppi_ch22, ppi_ch23,
        ppi_ch24, ppi_ch25, ppi_ch26, ppi_ch27, ppi_ch28, ppi_ch29,
    );
    static RNG: StaticCell<rng::Rng<'static, embassy_nrf::mode::Async>> = StaticCell::new();
    let rng = RNG.init(rng::Rng::new(rng_periph, Irqs));
    static SDC_MEM: StaticCell<sdc::Mem<4720>> = StaticCell::new();
    let sdc = build_sdc(sdc_p, rng, mpsl, SDC_MEM.init(sdc::Mem::new())).expect("SDC");
    crate::info!("BLE: SDC ok");

    spawner.must_spawn(ble_task(sdc, identity_hash));
}

// Advertising
async fn advertise<'v, 's, C: Controller>(
    peripheral: &mut Peripheral<'v, C, DefaultPacketPool>,
    server: &'s ReticulumServer<'v>,
) -> Result<GattConnection<'v, 's, DefaultPacketPool>, BleHostError<C::Error>> {
    let mut adv_data = [0; 31];
    let uuid_le: [u8; 16] = [
        0xe3, 0x28, 0xda, 0xc5, 0x42, 0x8f, 0x7f, 0x91,
        0x94, 0x4a, 0x2d, 0x44, 0x00, 0x5b, 0x14, 0x37,
    ];
    let adv_len = AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::CompleteServiceUuids128(&[uuid_le]),
        ],
        &mut adv_data[..],
    )?;
    let mut scan_data = [0; 31];
    let scan_len = AdStructure::encode_slice(
        &[AdStructure::CompleteLocalName(b"leviculum")],
        &mut scan_data[..],
    )?;

    let advertiser = peripheral.advertise(
        &AdvertisementParameters {
            interval_min: embassy_time::Duration::from_millis(100),
            interval_max: embassy_time::Duration::from_millis(200),
            ..Default::default()
        },
        Advertisement::ConnectableScannableUndirected {
            adv_data: &adv_data[..adv_len],
            scan_data: &scan_data[..scan_len],
        },
    ).await?;

    crate::info!("BLE: advertising");
    let conn = advertiser.accept().await?.with_attribute_server(server)?;
    crate::info!("BLE: connected");
    Ok(conn)
}

// GATT event loop with data pipeline
async fn gatt_events(
    server: &ReticulumServer<'_>,
    conn: &GattConnection<'_, '_, DefaultPacketPool>,
    incoming_tx: &Sender<'static, CriticalSectionRawMutex, Vec<u8>, 4>,
    outgoing_rx: &Receiver<'static, CriticalSectionRawMutex, Vec<u8>, 4>,
) {
    let rx_handle = server.reticulum_service.rx.handle;
    let mut defrag = BleDefragmenter::new();
    let mut handshake_done = false;
    let mut last_keepalive = Instant::now();

    // Drain stale outgoing packets from before this connection
    while outgoing_rx.try_receive().is_ok() {}

    loop {
        let keepalive_deadline = if handshake_done {
            Timer::at(last_keepalive + Duration::from_millis(KEEPALIVE_INTERVAL_MS))
        } else {
            Timer::at(Instant::MAX) // never fires before handshake
        };

        match select3(conn.next(), outgoing_rx.receive(), keepalive_deadline).await {
            Either3::First(event) => {
                // GATT event
                match event {
                    GattConnectionEvent::Disconnected { .. } => {
                        crate::info!("BLE: disconnected");
                        break;
                    }
                    GattConnectionEvent::Gatt { event } => {
                        if let GattEvent::Write(ref write) = event {
                            if write.handle() == rx_handle {
                                let data = write.data();

                                if !handshake_done && data.len() == 16 {
                                    // Identity handshake
                                    crate::log::log_fmt("[BLE ] ", format_args!(
                                        "peer id: {:02x}{:02x}{:02x}{:02x}",
                                        data[0], data[1], data[2], data[3]
                                    ));
                                    handshake_done = true;
                                    last_keepalive = Instant::now();
                                    match event.accept() {
                                        Ok(reply) => reply.send().await,
                                        Err(_) => {}
                                    }
                                    // Don't send keepalive immediately ; Columba needs
                                    // time to finish its handshake. The keepalive timer
                                    // will fire after KEEPALIVE_INTERVAL_MS.
                                    continue;
                                } else if data.len() < FRAGMENT_HEADER_SIZE {
                                    // Keepalive (1-byte 0x00) ; accept and skip
                                } else {
                                    // Data fragment
                                    let now = Instant::now().as_millis();
                                    match defrag.process(data, now) {
                                        DefragResult::Complete(packet) => {
                                            crate::info!("BLE: RX {}B", packet.len());
                                            incoming_tx.send(packet).await;
                                        }
                                        DefragResult::NeedMore => {}
                                        DefragResult::Error => { defrag.reset(); }
                                    }
                                }
                            }
                        }
                        match event.accept() {
                            Ok(reply) => reply.send().await,
                            Err(_) => {}
                        }
                    }
                    _ => {}
                }
            }
            Either3::Second(packet) => {
                // Outgoing packet ; fragment and notify
                let fragments = ble_framing::fragment_packet(&packet, ble_framing::DEFAULT_MTU);
                for frag in &fragments {
                    if let Ok(hv) = heapless::Vec::<u8, 251>::from_slice(frag) {
                        let _ = server.reticulum_service.tx.notify(conn, &hv).await;
                    }
                }
            }
            Either3::Third(()) => {
                // Keepalive timer fired
                let mut kv = heapless::Vec::<u8, 251>::new();
                let _ = kv.push(KEEPALIVE_BYTE);
                let _ = server.reticulum_service.tx.notify(conn, &kv).await;
                last_keepalive = Instant::now();
            }
        }
    }
}
