//! USB composite device with two CDC-ACM serial ports
//!
//! Port 0 (debug): carries human-readable log output from `info!`/`warn!` macros.
//! Port 1 (transport): Reticulum serial interface with HDLC framing.
//!
//! The host sees two `/dev/ttyACM*` devices. The debug port sends log messages
//! formatted with `\r\n` line endings for terminal compatibility.

extern crate alloc;

use alloc::vec::Vec;
use embassy_time::Duration;

use embassy_executor::Spawner;
use embassy_futures::select::{select, Either};
use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
use embassy_nrf::{Peri, bind_interrupts, peripherals, usb};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::{Channel, Receiver, Sender};
use embassy_time::with_timeout;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::{Builder, Config, UsbDevice};
use reticulum_core::framing::hdlc::{frame, DeframeResult, Deframer};
use static_cell::StaticCell;

use crate::log::{log_fmt, LOG_CHANNEL};

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

/// Channels for serial interface: NodeCore ↔ USB CDC-ACM
static INCOMING_CHANNEL: Channel<CriticalSectionRawMutex, Vec<u8>, 8> = Channel::new();
static OUTGOING_CHANNEL: Channel<CriticalSectionRawMutex, Vec<u8>, 8> = Channel::new();

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
    let id0 =
        unsafe { core::ptr::read_volatile((FICR_BASE + FICR_DEVICEID0_OFFSET) as *const u32) };
    let id1 =
        unsafe { core::ptr::read_volatile((FICR_BASE + FICR_DEVICEID1_OFFSET) as *const u32) };
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

/// Channel endpoints for the main loop to communicate with the serial task.
pub struct SerialChannels {
    /// Receive packets from USB (deframed by serial task)
    pub incoming_rx: Receiver<'static, CriticalSectionRawMutex, Vec<u8>, 8>,
    /// Send packets to USB (serial task frames and writes)
    pub outgoing_tx: Sender<'static, CriticalSectionRawMutex, Vec<u8>, 8>,
}

/// Initialize USB composite device and spawn driver tasks.
///
/// Returns channel endpoints for the Reticulum serial interface.
///
/// Spawns three tasks:
/// - `usb_task`: drives the USB bus state machine
/// - `debug_writer_task`: drains log channel to CDC-ACM port 0
/// - `retic_serial_task`: HDLC-framed bidirectional I/O on CDC-ACM port 1
pub fn init(
    spawner: &Spawner,
    usbd: Peri<'static, peripherals::USBD>,
) -> SerialChannels {
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

    // CDC-ACM #1: Reticulum serial interface (interfaces 02+03)
    let cdc_retic = CdcAcmClass::new(&mut builder, CDC_RETIC_STATE.init(State::new()), 64);

    let usb_dev = builder.build();

    spawner.must_spawn(usb_task(usb_dev));
    spawner.must_spawn(debug_writer_task(cdc_debug));
    spawner.must_spawn(retic_serial_task(
        cdc_retic,
        INCOMING_CHANNEL.sender(),
        OUTGOING_CHANNEL.receiver(),
    ));

    SerialChannels {
        incoming_rx: INCOMING_CHANNEL.receiver(),
        outgoing_tx: OUTGOING_CHANNEL.sender(),
    }
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
            if ok
                && !bytes.is_empty()
                && bytes.len() % 64 == 0
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

/// Lightweight log helpers for serial task diagnostics (no format_args overhead)
fn log(msg: &str) {
    log_fmt("[SER ] ", format_args!("{}", msg));
}

fn log_u32(msg: &str, val: u32) {
    log_fmt("[SER ] ", format_args!("{} {}", msg, val));
}

/// Serial HW_MTU (matches Python SerialInterface)
const SERIAL_HW_MTU: usize = 564;

/// Incomplete frame timeout — matches Python SerialInterface.timeout = 100ms
const FRAME_TIMEOUT_MS: u64 = 100;

/// Reticulum serial interface task: HDLC-framed bidirectional I/O on USB CDC-ACM.
///
/// Read path: CDC read → HDLC deframe → incoming channel → NodeCore
/// Write path: NodeCore → outgoing channel → HDLC frame → CDC write
#[embassy_executor::task]
async fn retic_serial_task(
    mut cdc: CdcAcmClass<'static, UsbDriver>,
    incoming_tx: Sender<'static, CriticalSectionRawMutex, Vec<u8>, 8>,
    outgoing_rx: Receiver<'static, CriticalSectionRawMutex, Vec<u8>, 8>,
) {
    let mut deframer = Deframer::new();
    let mut read_buf = [0u8; 64];
    let mut frame_buf = Vec::with_capacity(1200);

    loop {
        log("SER: wait_connection");
        cdc.wait_connection().await;
        log("SER: connected");
        deframer.reset();

        loop {
            // Conditional timeout: 100ms when mid-frame, ~infinite when idle
            let timeout_dur = if deframer.is_in_frame() {
                Duration::from_millis(FRAME_TIMEOUT_MS)
            } else {
                Duration::from_secs(3600)
            };

            match select(
                with_timeout(timeout_dur, cdc.read_packet(&mut read_buf)),
                outgoing_rx.receive(),
            )
            .await
            {
                // Read succeeded within timeout
                Either::First(Ok(Ok(n))) => {
                    log_u32("SER: USB read", n as u32);
                    let results = deframer.process(&read_buf[..n]);
                    for r in results {
                        if let DeframeResult::Frame(ref data) = r {
                            log_u32("SER: frame complete", data.len() as u32);
                            incoming_tx.send(data.clone()).await;
                        }
                    }
                    // HW_MTU enforcement
                    if deframer.buffer_len() > SERIAL_HW_MTU {
                        log("SER: HW_MTU exceeded, reset");
                        deframer.reset();
                    }
                }
                // USB disconnect
                Either::First(Ok(Err(_))) => {
                    log("SER: USB disconnect");
                    break;
                }
                // Frame timeout
                Either::First(Err(_)) => {
                    if deframer.is_in_frame() {
                        log("SER: frame timeout, reset");
                        deframer.reset();
                    }
                }
                // Outgoing packet to send
                Either::Second(data) => {
                    log_u32("SER: TX", data.len() as u32);
                    frame(&data, &mut frame_buf);
                    log_u32("SER: HDLC framed", frame_buf.len() as u32);
                    let mut write_ok = true;
                    for chunk in frame_buf.chunks(64) {
                        if cdc.write_packet(chunk).await.is_err() {
                            log("SER: write_packet failed");
                            write_ok = false;
                            break;
                        }
                    }
                    // ZLP if last chunk was exactly 64 bytes
                    if write_ok && !frame_buf.is_empty() && frame_buf.len() % 64 == 0 {
                        let _ = cdc.write_packet(&[]).await;
                    }
                }
            }
        }
    }
}
