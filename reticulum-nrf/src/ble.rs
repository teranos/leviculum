//! BLE Peripheral interface — Day-2 SANITY-BUILD STUB.
//!
//! On Day 2 of bug32-softdevice-spike this module is a deliberate
//! minimum: it brings up the Nordic S140 SoftDevice via `nrf-softdevice`
//! and runs its event loop, but does not yet expose the Columba v2.2
//! GATT service (RX/TX characteristics, defragmentation, keepalives,
//! identity handshake). The full GATT rewrite happens in Day 3 once
//! we've verified that nrf-softdevice + embassy-nrf 0.9 link cleanly
//! against our existing toolchain.
//!
//! The public API (`init`, `BleChannels`, `BleInterface`) is preserved
//! at the same shape `bin/rak4631.rs` and `bin/t114.rs` currently call,
//! so the binaries don't need a behavior-change diff alongside this
//! library swap. The new `init()` ignores all the peripheral handles
//! the binaries pass in (RTC0/TIMER0/RADIO/PPI/RNG) — those peripherals
//! are owned by the SoftDevice C blob via its own ABI, not via Embassy
//! type-state. Embassy's claim of them at `embassy_nrf::init` is a
//! no-op for this purpose: the SoftDevice never goes through Embassy.

extern crate alloc;

use alloc::vec::Vec;
use core::mem;
use embassy_executor::Spawner;
use embassy_nrf::peripherals;
use embassy_nrf::usb::vbus_detect::SoftwareVbusDetect;
use embassy_nrf::{bind_interrupts, Peri};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::{Channel, Receiver, Sender};
use nrf_softdevice::{raw, SocEvent, Softdevice};
use reticulum_core::traits::{Interface, InterfaceError};
use reticulum_core::InterfaceId;

// Interrupt bindings — only USBD here. The SoftDevice owns RADIO,
// TIMER0, RTC0, EGU0_SWI0, EGU1_SWI1, EGU5_SWI5, CLOCK_POWER and a
// few SPI* / TWI* slots reserved at compile time of S140; we bind
// none of those. CLOCK_POWER's USB-VBUS-detect half is now serviced
// inside the SoftDevice's POWER_CLOCK handler — embassy-nrf-0.9's
// `HardwareVbusDetect` accepts any `Binding`-implementing Irqs, so
// the binding still works through nrf-softdevice's interrupt taps
// once the SoftDevice is enabled.
bind_interrupts!(pub struct Irqs {
    USBD => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
});

// Channels — kept identical to the prior implementation so the
// binaries' `node.set_interface_*` plus `select4` over the BLE channel
// keep working unchanged. They will carry real BLE traffic once Day 3
// adds the GATT layer; for now they receive no producer.
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

/// Reticulum `Interface` adapter for outgoing BLE frames. With the Day-2
/// stub the sink Channel has no consumer task, so packets queued here
/// quietly pile up until the channel is full (4 frames), at which point
/// `try_send` reports `BufferFull`. That's deliberate — the Day-3 GATT
/// layer will plug a real consumer.
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

#[embassy_executor::task]
async fn softdevice_task(sd: &'static Softdevice, vbus: &'static SoftwareVbusDetect) -> ! {
    // run_with_callback runs the BLE event loop AND the SoC event loop;
    // we forward power/USB events to the embassy-nrf SoftwareVbusDetect
    // so the USB driver can enumerate when VBUS appears.
    sd.run_with_callback(|evt| match evt {
        SocEvent::PowerUsbDetected => vbus.detected(true),
        SocEvent::PowerUsbRemoved => vbus.detected(false),
        SocEvent::PowerUsbPowerReady => vbus.ready(),
        _ => {}
    })
    .await
}

/// Bring up S140 with a peripheral-only configuration. No advertising,
/// no GATT in this stub — Day 3 expands the Config and adds the
/// ReticulumService / ReticulumServer pair.
///
/// The peripheral parameters in the signature are left over from the
/// prior MPSL+SDC API for ABI compatibility with the binaries; they are
/// not used here and can be re-claimed for application use once the
/// binaries get cleaned up in Day 3.
#[allow(clippy::too_many_arguments)]
pub fn init(
    spawner: &Spawner,
    identity_hash: [u8; 16],
    vbus: &'static SoftwareVbusDetect,
    _rtc0: Peri<'static, peripherals::RTC0>,
    _timer0: Peri<'static, peripherals::TIMER0>,
    _temp: Peri<'static, peripherals::TEMP>,
    _ppi_ch19: Peri<'static, peripherals::PPI_CH19>,
    _ppi_ch30: Peri<'static, peripherals::PPI_CH30>,
    _ppi_ch31: Peri<'static, peripherals::PPI_CH31>,
    _ppi_ch17: Peri<'static, peripherals::PPI_CH17>,
    _ppi_ch18: Peri<'static, peripherals::PPI_CH18>,
    _ppi_ch20: Peri<'static, peripherals::PPI_CH20>,
    _ppi_ch21: Peri<'static, peripherals::PPI_CH21>,
    _ppi_ch22: Peri<'static, peripherals::PPI_CH22>,
    _ppi_ch23: Peri<'static, peripherals::PPI_CH23>,
    _ppi_ch24: Peri<'static, peripherals::PPI_CH24>,
    _ppi_ch25: Peri<'static, peripherals::PPI_CH25>,
    _ppi_ch26: Peri<'static, peripherals::PPI_CH26>,
    _ppi_ch27: Peri<'static, peripherals::PPI_CH27>,
    _ppi_ch28: Peri<'static, peripherals::PPI_CH28>,
    _ppi_ch29: Peri<'static, peripherals::PPI_CH29>,
    _rng_periph: Peri<'static, peripherals::RNG>,
) {
    let _ = identity_hash; // Day-3 uses this for the BLE address derivation.

    let config = nrf_softdevice::Config {
        clock: Some(raw::nrf_clock_lf_cfg_t {
            // RAK4631 and T114 both have a 32 MHz HF crystal but no
            // separate 32.768 kHz LF crystal — use the synthesized LF
            // clock from the HF crystal (RC-based with periodic re-cal).
            // Same setting Heltec / RAK / Adafruit-Bootloader use.
            source: raw::NRF_CLOCK_LF_SRC_RC as u8,
            rc_ctiv: 16,
            rc_temp_ctiv: 2,
            accuracy: raw::NRF_CLOCK_LF_ACCURACY_500_PPM as u8,
        }),
        conn_gap: Some(raw::ble_gap_conn_cfg_t {
            conn_count: 1,
            event_length: 24,
        }),
        conn_gatt: Some(raw::ble_gatt_conn_cfg_t { att_mtu: 256 }),
        gatts_attr_tab_size: Some(raw::ble_gatts_cfg_attr_tab_size_t {
            attr_tab_size: raw::BLE_GATTS_ATTR_TAB_SIZE_DEFAULT,
        }),
        gap_role_count: Some(raw::ble_gap_cfg_role_count_t {
            adv_set_count: 1,
            periph_role_count: 1,
            central_role_count: 0,
            central_sec_count: 0,
            _bitfield_1: raw::ble_gap_cfg_role_count_t::new_bitfield_1(0),
        }),
        gap_device_name: Some(raw::ble_gap_cfg_device_name_t {
            p_value: b"leviculum" as *const u8 as _,
            current_len: 9,
            max_len: 9,
            write_perm: unsafe { mem::zeroed() },
            _bitfield_1: raw::ble_gap_cfg_device_name_t::new_bitfield_1(
                raw::BLE_GATTS_VLOC_STACK as u8,
            ),
        }),
        ..Default::default()
    };

    let sd = Softdevice::enable(&config);
    spawner.must_spawn(softdevice_task(sd, vbus));
}
