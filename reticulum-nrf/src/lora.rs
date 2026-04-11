//! SX1262 LoRa radio initialization, configuration, and async task for T114.
//!
//! Uses the custom sx1262 driver on SPIM2 (SPIM3 has a MISO read bug on T114).
//! Provides an `Interface` impl for NodeCore dispatch and an async task that
//! handles half-duplex TX/RX on the radio.

extern crate alloc;

use alloc::vec::Vec;
use embassy_embedded_hal::shared_bus::asynch::spi::SpiDevice;
use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
use embassy_nrf::spim::{self, Spim};
use embassy_nrf::{bind_interrupts, peripherals, Peri};
use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, NoopRawMutex};
use embassy_sync::channel::{Channel, Receiver, Sender};
use embassy_sync::mutex::Mutex;
use reticulum_core::traits::{Interface, InterfaceError};
use reticulum_core::InterfaceId;
use static_cell::StaticCell;

use crate::boards::t114;
use crate::sx1262::Sx1262;

// SPIM2 — works on T114 (SPIM3 has a MISO read bug)
bind_interrupts!(pub struct SpiIrqs {
    SPI2 => spim::InterruptHandler<peripherals::SPI2>;
});

type SpiBus = Mutex<NoopRawMutex, Spim<'static>>;
type Spi = SpiDevice<'static, NoopRawMutex, Spim<'static>, Output<'static>>;

/// LoRa radio instance type
pub type Radio = Sx1262<Spi>;

// ─── Channels between LoRa task and main loop ──────────────────────────────

static LORA_INCOMING: Channel<CriticalSectionRawMutex, Vec<u8>, 4> = Channel::new();
static LORA_OUTGOING: Channel<CriticalSectionRawMutex, Vec<u8>, 4> = Channel::new();

pub struct LoRaChannels {
    pub incoming_rx: Receiver<'static, CriticalSectionRawMutex, Vec<u8>, 4>,
    pub outgoing_tx: Sender<'static, CriticalSectionRawMutex, Vec<u8>, 4>,
}

pub fn channels() -> LoRaChannels {
    LoRaChannels {
        incoming_rx: LORA_INCOMING.receiver(),
        outgoing_tx: LORA_OUTGOING.sender(),
    }
}

// ─── LoRaInterface for NodeCore dispatch ───────────────────────────────────

pub struct LoRaInterface {
    sender: Sender<'static, CriticalSectionRawMutex, Vec<u8>, 4>,
}

impl LoRaInterface {
    pub fn new(sender: Sender<'static, CriticalSectionRawMutex, Vec<u8>, 4>) -> Self {
        Self { sender }
    }
}

impl Interface for LoRaInterface {
    fn id(&self) -> InterfaceId { InterfaceId(1) }
    fn name(&self) -> &str { "lora_sx1262" }
    fn mtu(&self) -> usize { 255 }
    fn is_online(&self) -> bool { true }
    fn try_send(&mut self, data: &[u8]) -> Result<(), InterfaceError> {
        self.sender.try_send(data.to_vec()).map_err(|_| InterfaceError::BufferFull)
    }
}

// ─── Radio configuration ───────────────────────────────────────────────────

pub struct RadioConfig {
    pub frequency_hz: u32,
    pub sf: u8,
    pub bw: u8,       // SX1262 bandwidth code: 0x04 = 125kHz
    pub cr: u8,       // SX1262 coding rate code: 0x01 = 4/5
    pub tx_power_dbm: i8,
    pub preamble_len: u16,
}

impl RadioConfig {
    /// EU medium profile: 869.525 MHz, SF7, BW125, CR4/5, 17 dBm, preamble 24.
    pub fn eu_medium() -> Self {
        Self {
            frequency_hz: 869_525_000,
            sf: 7,
            bw: 0x04,       // 125 kHz
            cr: 0x01,       // 4/5
            tx_power_dbm: 17,
            preamble_len: 24,
        }
    }
}

// ─── Init ──────────────────────────────────────────────────────────────────

pub async fn init(
    spi_periph: Peri<'static, peripherals::SPI2>,
    sck: Peri<'static, t114::LoRaSck>,
    mosi: Peri<'static, t114::LoRaMosi>,
    miso: Peri<'static, t114::LoRaMiso>,
    cs: Peri<'static, t114::LoRaCs>,
    reset: Peri<'static, t114::LoRaReset>,
    busy: Peri<'static, t114::LoRaBusy>,
    dio1: Peri<'static, t114::LoRaDio1>,
) -> Radio {
    let mut spi_config = spim::Config::default();
    spi_config.frequency = spim::Frequency::M4;

    let spi = Spim::new(spi_periph, SpiIrqs, sck, miso, mosi, spi_config);

    static SPI_BUS: StaticCell<SpiBus> = StaticCell::new();
    let spi_bus = SPI_BUS.init(Mutex::new(spi));

    let cs_pin = Output::new(cs, Level::High, OutputDrive::Standard);
    let spi_device = SpiDevice::new(spi_bus, cs_pin);

    let reset_pin = Output::new(reset, Level::High, OutputDrive::Standard);
    let busy_pin = Input::new(busy, Pull::None);
    let dio1_pin = Input::new(dio1, Pull::Down);

    Sx1262::new(spi_device, reset_pin, busy_pin, dio1_pin)
}

// ─── LoRa async task ───────────────────────────────────────────────────────

#[embassy_executor::task]
pub async fn lora_task(mut radio: Radio, config: RadioConfig) {
    let outgoing_rx = LORA_OUTGOING.receiver();
    let incoming_tx = LORA_INCOMING.sender();

    // Init radio
    radio.reset().await;
    let _ = radio.wait_busy().await;

    match radio.init_radio(config.frequency_hz).await {
        Ok(s) => crate::log::log_fmt("[LORA] ", format_args!(
            "init ok, status=0x{:02X}", s.raw
        )),
        Err(e) => {
            crate::log::log_fmt("[LORA] ", format_args!("init FAILED: {:?}", e));
            return; // Can't continue without radio
        }
    }

    match radio.configure_lora(
        config.frequency_hz, config.sf, config.bw, config.cr,
        config.tx_power_dbm, config.preamble_len,
    ).await {
        Ok(()) => crate::log::log_fmt("[LORA] ", format_args!(
            "configured: {}Hz SF{} BW{} CR{} {}dBm",
            config.frequency_hz, config.sf, config.bw, config.cr, config.tx_power_dbm
        )),
        Err(e) => {
            crate::log::log_fmt("[LORA] ", format_args!("configure FAILED: {:?}", e));
            return;
        }
    }

    crate::log::log_fmt("[LORA] ", format_args!("task started"));

    let mut rx_buf = [0u8; 255];
    let mut rx_timeout_count: u32 = 0;

    // RNode-compatible header: 1-byte prepended to every LoRa frame.
    // Upper nibble = random sequence, bit 0 = split flag.
    // RNode firmware adds this on TX and strips on RX.  We must do the
    // same so T114 and RNode devices can exchange packets.
    let mut rng_state: u32 = 0xDEAD_BEEF; // xorshift32 seed

    loop {
        // Drain outgoing packets (non-blocking)
        while let Ok(data) = outgoing_rx.try_receive() {
            // Prepend 1-byte RNode header (random upper nibble, no split)
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 17;
            rng_state ^= rng_state << 5;
            let header = (rng_state as u8) & 0xF0;
            let mut frame = Vec::with_capacity(1 + data.len());
            frame.push(header);
            frame.extend_from_slice(&data);
            crate::log::log_fmt("[LORA] ", format_args!("TX {} bytes", data.len()));
            match radio.transmit(&frame, 5000).await {
                Ok(()) => {
                    crate::log::log_fmt("[LORA] ", format_args!("TX done"));
                }
                Err(e) => {
                    crate::log::log_fmt("[LORA] ", format_args!("TX err: {:?}", e));
                }
            }
        }

        // RX with 500ms timeout, then loop back to check outgoing
        match radio.receive(&mut rx_buf, 500).await {
            Ok((len, status)) => {
                // Strip 1-byte RNode header
                if len < 2 {
                    crate::log::log_fmt("[LORA] ", format_args!("RX too short ({})", len));
                    continue;
                }
                let payload = &rx_buf[1..len as usize];
                crate::log::log_fmt("[LORA] ", format_args!(
                    "RX {} bytes rssi={} snr={}", payload.len(), status.rssi, status.snr
                ));
                let data = payload.to_vec();
                incoming_tx.send(data).await;
            }
            Err(crate::sx1262::Error::Timeout) => {
                rx_timeout_count += 1;
                if rx_timeout_count % 60 == 0 {
                    crate::log::log_fmt("[LORA] ", format_args!("RX idle ({})", rx_timeout_count));
                }
            }
            Err(e) => {
                crate::log::log_fmt("[LORA] ", format_args!("RX err: {:?}", e));
            }
        }
    }
}
