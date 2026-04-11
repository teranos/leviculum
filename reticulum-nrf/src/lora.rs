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
static LORA_CONFIG: Channel<CriticalSectionRawMutex, RadioConfig, 1> = Channel::new();

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

/// Get the sender for runtime radio config overrides (used by serial task).
pub fn config_sender() -> Sender<'static, CriticalSectionRawMutex, RadioConfig, 1> {
    LORA_CONFIG.sender()
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
    fn mtu(&self) -> usize { 500 }
    fn is_online(&self) -> bool { true }
    fn try_send(&mut self, data: &[u8]) -> Result<(), InterfaceError> {
        self.sender.try_send(data.to_vec()).map_err(|_| InterfaceError::BufferFull)
    }
}

// ─── Radio configuration ───────────────────────────────────────────────────

// Re-export wire protocol constants from core for use by usb.rs
pub use reticulum_core::rnode::{
    RADIO_CONFIG_ACK as CONFIG_ACK,
    RADIO_CONFIG_FRAME_LEN as CONFIG_FRAME_LEN,
    RADIO_CONFIG_MAGIC as CONFIG_MAGIC,
};

pub struct RadioConfig {
    pub frequency_hz: u32,
    pub sf: u8,
    pub bw: u8,           // SX1262 bandwidth register code
    pub cr: u8,           // SX1262 coding rate register code
    pub tx_power_dbm: i8,
    pub preamble_len: u16,
    pub bw_hz: u32,       // human-readable bandwidth in Hz (for logging)
    pub cr_denom: u8,     // human-readable coding rate denominator 5-8 (for logging)
}

impl RadioConfig {
    /// EU medium profile: 869.525 MHz, SF7, BW125, CR4/5, 17 dBm, preamble 24.
    pub fn eu_medium() -> Self {
        Self {
            frequency_hz: 869_525_000,
            sf: 7,
            bw: 0x04,
            cr: 0x01,
            tx_power_dbm: 17,
            preamble_len: 24,
            bw_hz: 125_000,
            cr_denom: 5,
        }
    }

    /// Parse a radio config from wire format (13 bytes, after 2-byte magic stripped).
    ///
    /// Returns `None` for invalid data (wrong length, unknown bandwidth).
    pub fn from_wire(data: &[u8]) -> Option<Self> {
        let wire = reticulum_core::rnode::parse_radio_config(data)?;

        // SX1262 bandwidth register codes (datasheet Table 14-47)
        let bw = match wire.bandwidth_hz {
            7_810 => 0x00,
            10_420 => 0x08,
            15_630 => 0x01,
            20_830 => 0x09,
            31_250 => 0x02,
            41_670 => 0x0A,
            62_500 => 0x03,
            125_000 => 0x04,
            250_000 => 0x05,
            500_000 => 0x06,
            _ => return None,
        };

        // CR denominator (5-8) to SX1262 code (1-4)
        let cr = wire.cr - 4;

        Some(Self {
            frequency_hz: wire.frequency_hz,
            sf: wire.sf,
            bw,
            cr,
            tx_power_dbm: wire.tx_power_dbm,
            preamble_len: wire.preamble_len,
            bw_hz: wire.bandwidth_hz,
            cr_denom: wire.cr,
        })
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
    let config_rx = LORA_CONFIG.receiver();

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
            "active config: freq={} sf={} bw={} cr={} txp={}",
            config.frequency_hz, config.sf, config.bw_hz, config.cr_denom, config.tx_power_dbm
        )),
        Err(e) => {
            crate::log::log_fmt("[LORA] ", format_args!("configure FAILED: {:?}", e));
            return;
        }
    }

    crate::log::log_fmt("[LORA] ", format_args!("task started"));

    let mut rx_buf = [0u8; 255];
    let mut rx_timeout_count: u32 = 0;
    let mut rng_state: u32 = 0xDEAD_BEEF; // xorshift32 seed
    let mut reassembler = reticulum_core::rnode::SplitReassembler::new();

    loop {
        // Check for runtime radio config override (test infrastructure)
        if let Ok(new_cfg) = config_rx.try_receive() {
            match radio.configure_lora(
                new_cfg.frequency_hz, new_cfg.sf, new_cfg.bw, new_cfg.cr,
                new_cfg.tx_power_dbm, new_cfg.preamble_len,
            ).await {
                Ok(()) => crate::log::log_fmt("[LORA] ", format_args!(
                    "active config: freq={} sf={} bw={} cr={} txp={}",
                    new_cfg.frequency_hz, new_cfg.sf, new_cfg.bw_hz,
                    new_cfg.cr_denom, new_cfg.tx_power_dbm
                )),
                Err(e) => crate::log::log_fmt("[LORA] ", format_args!(
                    "reconfig FAILED: {:?}", e
                )),
            }
        }

        // Drain outgoing packets (non-blocking)
        while let Ok(data) = outgoing_rx.try_receive() {
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 17;
            rng_state ^= rng_state << 5;
            let seq_nibble = (rng_state as u8) & 0xF0;
            let frames = reticulum_core::rnode::build_lora_frames(&data, seq_nibble);

            if frames.len() > 1 {
                crate::log::log_fmt("[LORA] ", format_args!(
                    "TX split {} bytes ({}+{})",
                    data.len(), frames[0].len() - 1, frames[1].len() - 1
                ));
            } else {
                crate::log::log_fmt("[LORA] ", format_args!("TX {} bytes", data.len()));
            }

            let mut tx_ok = true;
            for (i, frame) in frames.iter().enumerate() {
                match radio.transmit(frame, 5000).await {
                    Ok(()) => {}
                    Err(e) => {
                        crate::log::log_fmt("[LORA] ", format_args!(
                            "TX err frame {}: {:?}", i, e
                        ));
                        tx_ok = false;
                        break;
                    }
                }
            }
            if tx_ok {
                crate::log::log_fmt("[LORA] ", format_args!("TX done"));
            }
        }

        // Timeout stale split reassembly buffers (10 cycles * 500ms = 5s)
        reassembler.check_timeout(rx_timeout_count, 10);

        // RX with 500ms timeout, then loop back to check outgoing
        match radio.receive(&mut rx_buf, 500).await {
            Ok((len, status)) => {
                let frame = &rx_buf[..len as usize];
                if let Some(data) = reassembler.feed(frame, rx_timeout_count) {
                    crate::log::log_fmt("[LORA] ", format_args!(
                        "RX {} bytes rssi={} snr={}", data.len(), status.rssi, status.snr
                    ));
                    incoming_tx.send(data).await;
                } else if len >= 2 && (rx_buf[0] & reticulum_core::rnode::FLAG_SPLIT) != 0 {
                    crate::log::log_fmt("[LORA] ", format_args!(
                        "RX split part {} bytes seq={} rssi={} snr={}",
                        len - 1, rx_buf[0] >> 4, status.rssi, status.snr
                    ));
                } else if len < 2 {
                    crate::log::log_fmt("[LORA] ", format_args!("RX too short ({})", len));
                }
            }
            Err(crate::sx1262::Error::Timeout) => {
                rx_timeout_count = rx_timeout_count.wrapping_add(1);
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
