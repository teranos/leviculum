//! SX1262 LoRa radio initialization, configuration, and async task for T114
//!
//! Provides the radio driver, an `Interface` impl for NodeCore dispatch,
//! and an async task that handles TX/RX on the radio.

extern crate alloc;

use alloc::vec::Vec;
use embassy_embedded_hal::shared_bus::asynch::spi::SpiDevice;
use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
use embassy_nrf::spim::{self, Spim};
use embassy_nrf::{bind_interrupts, peripherals, Peri};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::{Channel, Receiver, Sender};
use embassy_sync::mutex::Mutex;
use lora_phy::iv::GenericSx126xInterfaceVariant;
use lora_phy::mod_params::{Bandwidth, CodingRate, ModulationParams, PacketParams, SpreadingFactor};
use lora_phy::sx126x::{self, Sx1262, Sx126x, TcxoCtrlVoltage};
use lora_phy::{LoRa, RxMode};
use reticulum_core::traits::{Interface, InterfaceError};
use reticulum_core::InterfaceId;
use static_cell::StaticCell;

use crate::boards::t114;

bind_interrupts!(struct SpiIrqs {
    SPIM3 => spim::InterruptHandler<peripherals::SPI3>;
});

type SpiBus = Mutex<NoopRawMutex, Spim<'static>>;
type Spi = SpiDevice<'static, NoopRawMutex, Spim<'static>, Output<'static>>;
type Iv = GenericSx126xInterfaceVariant<Output<'static>, Input<'static>>;
type RadioKind = Sx126x<Spi, Iv, Sx1262>;

use embassy_sync::blocking_mutex::raw::NoopRawMutex;

/// LoRa radio instance type
pub type Radio = LoRa<RadioKind, embassy_time::Delay>;

// ─── Channels between LoRa task and main loop ──────────────────────────────

/// Packets received from LoRa radio, delivered to main loop
static LORA_INCOMING: Channel<CriticalSectionRawMutex, Vec<u8>, 4> = Channel::new();
/// Packets from NodeCore to transmit on LoRa radio
static LORA_OUTGOING: Channel<CriticalSectionRawMutex, Vec<u8>, 4> = Channel::new();

/// Channel endpoints for the main loop
pub struct LoRaChannels {
    /// Receive packets from LoRa radio (deframed by LoRa task)
    pub incoming_rx: Receiver<'static, CriticalSectionRawMutex, Vec<u8>, 4>,
    /// Send packets to LoRa radio (LoRa task transmits them)
    pub outgoing_tx: Sender<'static, CriticalSectionRawMutex, Vec<u8>, 4>,
}

/// Get the channel endpoints for the LoRa interface.
pub fn channels() -> LoRaChannels {
    LoRaChannels {
        incoming_rx: LORA_INCOMING.receiver(),
        outgoing_tx: LORA_OUTGOING.sender(),
    }
}

// ─── LoRa Interface for NodeCore dispatch ──────────────────────────────────

/// LoRa interface backed by an Embassy channel.
///
/// `try_send()` pushes raw packet data to the outgoing channel.
/// The `lora_task` reads from the other end and transmits via SX1262.
pub struct LoRaInterface {
    sender: Sender<'static, CriticalSectionRawMutex, Vec<u8>, 4>,
}

impl LoRaInterface {
    pub fn new(sender: Sender<'static, CriticalSectionRawMutex, Vec<u8>, 4>) -> Self {
        Self { sender }
    }
}

impl Interface for LoRaInterface {
    fn id(&self) -> InterfaceId {
        InterfaceId(1)
    }

    fn name(&self) -> &str {
        "lora_sx1262"
    }

    fn mtu(&self) -> usize {
        // SX1262 FIFO is 256 bytes. Max usable payload is 255 bytes.
        // dispatch_actions passes raw packets to try_send without
        // fragmentation, so this must reflect the radio's actual limit.
        255
    }

    fn is_online(&self) -> bool {
        true
    }

    fn try_send(&mut self, data: &[u8]) -> Result<(), InterfaceError> {
        self.sender
            .try_send(data.to_vec())
            .map_err(|_| InterfaceError::BufferFull)
    }
}

// ─── Radio configuration ───────────────────────────────────────────────────

/// Radio parameters matching RNode for Reticulum compatibility.
pub struct RadioConfig {
    pub frequency_hz: u32,
    pub bandwidth: Bandwidth,
    pub spreading_factor: SpreadingFactor,
    pub coding_rate: CodingRate,
    pub tx_power_dbm: i32,
}

impl RadioConfig {
    /// EU g3 sub-band medium profile (125 kHz BW, SF7, CR 4/5).
    pub fn eu_medium() -> Self {
        Self {
            frequency_hz: 869_525_000,
            bandwidth: Bandwidth::_125KHz,
            spreading_factor: SpreadingFactor::_7,
            coding_rate: CodingRate::_4_5,
            tx_power_dbm: 17,
        }
    }

    /// Compute preamble length matching RNode's dynamic formula.
    ///
    /// RNode: target 24ms of preamble symbols, minimum 18 symbols.
    /// `preamble = max(ceil(24ms / symbol_time), 18)`
    pub fn preamble_symbols(&self) -> u16 {
        let sf = match self.spreading_factor {
            SpreadingFactor::_5 => 5u64,
            SpreadingFactor::_6 => 6,
            SpreadingFactor::_7 => 7,
            SpreadingFactor::_8 => 8,
            SpreadingFactor::_9 => 9,
            SpreadingFactor::_10 => 10,
            SpreadingFactor::_11 => 11,
            SpreadingFactor::_12 => 12,
        };
        let bw_hz = match self.bandwidth {
            Bandwidth::_7KHz => 7_800u64,
            Bandwidth::_10KHz => 10_400,
            Bandwidth::_15KHz => 15_600,
            Bandwidth::_20KHz => 20_800,
            Bandwidth::_31KHz => 31_250,
            Bandwidth::_41KHz => 41_700,
            Bandwidth::_62KHz => 62_500,
            Bandwidth::_125KHz => 125_000,
            Bandwidth::_250KHz => 250_000,
            Bandwidth::_500KHz => 500_000,
        };
        let symbol_time_us = ((1u64 << sf) * 1_000_000) / bw_hz;
        let target_symbols = (24_000 + symbol_time_us - 1) / symbol_time_us;
        target_symbols.max(18) as u16
    }

    /// Create lora-phy modulation parameters.
    pub fn modulation_params(&self, lora: &mut Radio) -> ModulationParams {
        lora.create_modulation_params(
            self.spreading_factor,
            self.bandwidth,
            self.coding_rate,
            self.frequency_hz,
        )
        .unwrap()
    }

    /// Create lora-phy TX packet parameters.
    pub fn tx_packet_params(&self, lora: &mut Radio, mdltn: &ModulationParams) -> PacketParams {
        lora.create_tx_packet_params(
            self.preamble_symbols(),
            false, // explicit header
            true,  // CRC enabled
            false, // IQ not inverted
            mdltn,
        )
        .unwrap()
    }

    /// Create lora-phy RX packet parameters.
    pub fn rx_packet_params(
        &self,
        lora: &mut Radio,
        mdltn: &ModulationParams,
        max_payload: u8,
    ) -> PacketParams {
        lora.create_rx_packet_params(
            self.preamble_symbols(),
            false,
            max_payload,
            true,
            false,
            mdltn,
        )
        .unwrap()
    }
}

// ─── Radio init ────────────────────────────────────────────────────────────

/// Initialize the SX1262 radio and return a `LoRa` instance.
pub async fn init(
    spi_periph: Peri<'static, peripherals::SPI3>,
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
    let dio1_pin = Input::new(dio1, Pull::Down);
    let busy_pin = Input::new(busy, Pull::None);

    let iv = GenericSx126xInterfaceVariant::new(reset_pin, dio1_pin, busy_pin, None, None)
        .unwrap();

    let config = sx126x::Config {
        chip: Sx1262,
        tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V8),
        use_dcdc: true,
        rx_boost: false,
    };

    let radio_kind = Sx126x::new(spi_device, iv, config);

    // enable_public_network=false → private sync word 0x1424 (matches RNode)
    LoRa::new(radio_kind, false, embassy_time::Delay)
        .await
        .unwrap()
}

// ─── LoRa async task ───────────────────────────────────────────────────────

/// LoRa radio task: half-duplex TX/RX state machine.
///
/// Alternates between RX (listening for incoming packets) and TX (sending
/// packets from the outgoing channel). TX interrupts RX when NodeCore has
/// a packet to send.
///
/// This task owns the radio — no other code touches SPI while this runs.
#[embassy_executor::task]
pub async fn lora_task(
    mut lora: Radio,
    config: RadioConfig,
) {
    let outgoing_rx = LORA_OUTGOING.receiver();
    let incoming_tx = LORA_INCOMING.sender();

    let mdltn = config.modulation_params(&mut lora);
    let mut tx_params = config.tx_packet_params(&mut lora, &mdltn);
    let rx_params = config.rx_packet_params(&mut lora, &mdltn, 255);

    let mut rx_buf = [0u8; 255];

    crate::log::log_fmt("[LORA] ", format_args!("task started"));

    loop {
        // Enter continuous RX mode
        match lora.prepare_for_rx(RxMode::Continuous, &mdltn, &rx_params).await {
            Ok(()) => {}
            Err(e) => {
                crate::log::log_fmt("[LORA] ", format_args!("RX prepare err: {:?}", e));
                embassy_time::Timer::after_millis(1000).await;
                continue;
            }
        }

        // Wait for either: incoming radio packet OR outgoing packet to transmit
        // Use select: lora.rx() vs outgoing_rx.receive()
        //
        // Note: lora.rx() blocks until a packet arrives or timeout. For continuous
        // RX mode, it blocks indefinitely. We use select to interrupt it when
        // NodeCore has a packet to send.
        match embassy_futures::select::select(
            lora.rx(&rx_params, &mut rx_buf),
            outgoing_rx.receive(),
        )
        .await
        {
            // Radio received a packet
            embassy_futures::select::Either::First(rx_result) => {
                match rx_result {
                    Ok((len, status)) => {
                        crate::log::log_fmt(
                            "[LORA] ",
                            format_args!("RX {} bytes rssi={} snr={}", len, status.rssi, status.snr),
                        );
                        let data = rx_buf[..len as usize].to_vec();
                        incoming_tx.send(data).await;
                    }
                    Err(e) => {
                        crate::log::log_fmt("[LORA] ", format_args!("RX err: {:?}", e));
                    }
                }
            }
            // NodeCore wants to transmit a packet
            embassy_futures::select::Either::Second(data) => {
                crate::log::log_fmt("[LORA] ", format_args!("TX {} bytes", data.len()));

                match lora
                    .prepare_for_tx(&mdltn, &mut tx_params, config.tx_power_dbm, &data)
                    .await
                {
                    Ok(()) => match lora.tx().await {
                        Ok(()) => {
                            crate::log::log_fmt("[LORA] ", format_args!("TX done"));
                        }
                        Err(e) => {
                            crate::log::log_fmt("[LORA] ", format_args!("TX err: {:?}", e));
                        }
                    },
                    Err(e) => {
                        crate::log::log_fmt("[LORA] ", format_args!("TX prepare err: {:?}", e));
                    }
                }
                // After TX, loop back to RX
            }
        }
    }
}
