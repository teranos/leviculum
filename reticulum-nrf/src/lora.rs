//! SX1262 LoRa radio initialization for T114
//!
//! Configures the SX1262 via SPI and provides a `LoRa` instance from lora-phy.

use embassy_embedded_hal::shared_bus::asynch::spi::SpiDevice;
use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
use embassy_nrf::spim::{self, Spim};
use embassy_nrf::{bind_interrupts, peripherals, Peri};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use lora_phy::iv::GenericSx126xInterfaceVariant;
use lora_phy::sx126x::{self, Sx1262, Sx126x, TcxoCtrlVoltage};
use lora_phy::LoRa;
use static_cell::StaticCell;

use crate::boards::t114;

bind_interrupts!(struct SpiIrqs {
    SPIM3 => spim::InterruptHandler<peripherals::SPI3>;
});

type SpiBus = Mutex<NoopRawMutex, Spim<'static>>;
type Spi = SpiDevice<'static, NoopRawMutex, Spim<'static>, Output<'static>>;
type Iv = GenericSx126xInterfaceVariant<Output<'static>, Input<'static>>;
type RadioKind = Sx126x<Spi, Iv, Sx1262>;

/// Initialize the SX1262 radio and return a `LoRa` instance.
///
/// Configures SPI3 with the T114 pin mapping, sets up TCXO (DIO3 at 1.8V),
/// and DIO2 as RF switch. Returns the radio ready for configuration.
pub async fn init(
    spi_periph: Peri<'static, peripherals::SPI3>,
    sck: Peri<'static, t114::LoRaSck>,
    mosi: Peri<'static, t114::LoRaMosi>,
    miso: Peri<'static, t114::LoRaMiso>,
    cs: Peri<'static, t114::LoRaCs>,
    reset: Peri<'static, t114::LoRaReset>,
    busy: Peri<'static, t114::LoRaBusy>,
    dio1: Peri<'static, t114::LoRaDio1>,
) -> LoRa<RadioKind, embassy_time::Delay> {
    // SPI bus at 4 MHz (Meshtastic default, conservative)
    let mut spi_config = spim::Config::default();
    spi_config.frequency = spim::Frequency::M4;

    let spi = Spim::new(spi_periph, SpiIrqs, sck, miso, mosi, spi_config);

    static SPI_BUS: StaticCell<SpiBus> = StaticCell::new();
    let spi_bus = SPI_BUS.init(Mutex::new(spi));

    let cs_pin = Output::new(cs, Level::High, OutputDrive::Standard);
    let spi_device = SpiDevice::new(spi_bus, cs_pin);

    // GPIO for radio control — with gpiote feature, Input implements async Wait
    let reset_pin = Output::new(reset, Level::High, OutputDrive::Standard);
    let dio1_pin = Input::new(dio1, Pull::Down);
    let busy_pin = Input::new(busy, Pull::None);

    let iv = GenericSx126xInterfaceVariant::new(
        reset_pin, dio1_pin, busy_pin, None, None,
    )
    .unwrap(); // infallible for this variant

    let config = sx126x::Config {
        chip: Sx1262,
        tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V8),
        use_dcdc: true,
        rx_boost: false,
    };

    let radio_kind = Sx126x::new(spi_device, iv, config);

    // LoRa::new performs radio init: wakeup, TCXO config, calibration
    // enable_public_network=false → private sync word (Reticulum P2P)
    LoRa::new(radio_kind, false, embassy_time::Delay)
        .await
        .unwrap() // Phase A: panic on init failure to see the error
}
