//! USB composite device with two CDC-ACM serial ports
//!
//! Port 0 (debug): carries human-readable log output from `info!`/`warn!` macros.
//! Port 1 (transport): reserved for Reticulum transport (idle for now).
//!
//! The host sees two `/dev/ttyACM*` devices. The debug port sends log messages
//! formatted with `\r\n` line endings for terminal compatibility.

use embassy_executor::Spawner;
use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
use embassy_nrf::{Peri, bind_interrupts, peripherals, usb};
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::{Builder, Config, UsbDevice};
use static_cell::StaticCell;

use crate::log::LOG_CHANNEL;

bind_interrupts!(struct Irqs {
    USBD => usb::InterruptHandler<peripherals::USBD>;
    CLOCK_POWER => usb::vbus_detect::InterruptHandler;
});

static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
static BOS_DESC: StaticCell<[u8; 256]> = StaticCell::new();
static MSOS_DESC: StaticCell<[u8; 0]> = StaticCell::new();
static CONTROL_BUF: StaticCell<[u8; 128]> = StaticCell::new();
static CDC_DEBUG_STATE: StaticCell<State<'static>> = StaticCell::new();
static CDC_RETIC_STATE: StaticCell<State<'static>> = StaticCell::new();

/// nRF52840 FICR base address
const FICR_BASE: u32 = 0x1000_0000;
/// DEVICEID[0] register offset
const FICR_DEVICEID0_OFFSET: u32 = 0x060;
/// DEVICEID[1] register offset
const FICR_DEVICEID1_OFFSET: u32 = 0x064;

/// Read the nRF52840 factory-programmed unique device ID from FICR registers
/// and format as a 16-character uppercase hex string (static lifetime).
fn serial_number() -> &'static str {
    static SERIAL: StaticCell<[u8; 16]> = StaticCell::new();
    // SAFETY: FICR registers are read-only factory-programmed values, always safe to read
    let id0 = unsafe { core::ptr::read_volatile((FICR_BASE + FICR_DEVICEID0_OFFSET) as *const u32) };
    let id1 = unsafe { core::ptr::read_volatile((FICR_BASE + FICR_DEVICEID1_OFFSET) as *const u32) };
    let buf = SERIAL.init([0u8; 16]);
    hex_u32(&mut buf[0..8], id0);
    hex_u32(&mut buf[8..16], id1);
    // buf contains only ASCII hex digits — always valid UTF-8
    match core::str::from_utf8(buf) {
        Ok(s) => s,
        Err(_) => "0000000000000000",
    }
}

fn hex_u32(buf: &mut [u8], val: u32) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for i in 0..8 {
        buf[i] = HEX[((val >> (28 - i * 4)) & 0xF) as usize];
    }
}

/// Initialize USB composite device and spawn driver tasks.
///
/// Spawns three tasks:
/// - `usb_task`: drives the USB bus state machine
/// - `debug_writer_task`: drains log channel to CDC-ACM port 0
/// - `retic_placeholder_task`: reads and discards data on CDC-ACM port 1
pub fn init(spawner: &Spawner, usbd: Peri<'static, peripherals::USBD>) {
    let driver = usb::Driver::new(usbd, Irqs, HardwareVbusDetect::new(Irqs));

    // TODO: register a proper PID at https://pid.codes/
    let mut config = Config::new(0x1209, 0x0001);
    config.manufacturer = Some("leviculum");
    config.product = Some("leviculum T114");
    config.serial_number = Some(serial_number());
    config.max_power = 100;
    config.composite_with_iads = true;

    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESC.init([0; 256]),
        BOS_DESC.init([0; 256]),
        MSOS_DESC.init([0; 0]),
        CONTROL_BUF.init([0; 128]),
    );

    // CDC-ACM #0: Debug log output (interfaces 00+01)
    let cdc_debug = CdcAcmClass::new(&mut builder, CDC_DEBUG_STATE.init(State::new()), 64);

    // CDC-ACM #1: Reticulum transport placeholder (interfaces 02+03)
    let cdc_retic = CdcAcmClass::new(&mut builder, CDC_RETIC_STATE.init(State::new()), 64);

    let usb_dev = builder.build();

    spawner.must_spawn(usb_task(usb_dev));
    spawner.must_spawn(debug_writer_task(cdc_debug));
    spawner.must_spawn(retic_placeholder_task(cdc_retic));
}

type UsbDriver = usb::Driver<'static, HardwareVbusDetect>;

#[embassy_executor::task]
async fn usb_task(mut usb: UsbDevice<'static, UsbDriver>) {
    usb.run().await;
}

#[embassy_executor::task]
async fn debug_writer_task(mut cdc: CdcAcmClass<'static, UsbDriver>) {
    loop {
        cdc.wait_connection().await;
        loop {
            let msg = LOG_CHANNEL.receive().await;
            let bytes = msg.as_bytes();
            let mut ok = true;
            for chunk in bytes.chunks(64) {
                match cdc.write_packet(chunk).await {
                    Ok(()) => {}
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            // Send ZLP if last chunk was exactly 64 bytes (signals end of transfer)
            if ok && !bytes.is_empty() && bytes.len() % 64 == 0
                && cdc.write_packet(&[]).await.is_err()
            {
                break;
            }
            if !ok {
                break;
            }
        }
    }
}

#[embassy_executor::task]
async fn retic_placeholder_task(mut cdc: CdcAcmClass<'static, UsbDriver>) {
    // TODO: wire to Reticulum transport interface
    let mut buf = [0u8; 64];
    loop {
        cdc.wait_connection().await;
        while cdc.read_packet(&mut buf).await.is_ok() {
            // discard received data
        }
    }
}
