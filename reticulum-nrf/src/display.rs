//! 1.3" OLED status display on the WisMesh Pocket V2 (RAK19026 VC baseboard).
//!
//! Builds an I²C bus on TWISPI0 with SDA on P0.13 / SCL on P0.14, runtime-
//! probes for an OLED at 0x3C (and 0x3D as fallback), and drives an SSD1306
//! status screen at ~1 Hz.
//!
//! Chip-detection follows Meshtastic's `src/detect/ScanI2CTwoWire.cpp:52-87`
//! exactly: send register address `0x00`, read one byte, mask the lower
//! nibble, and classify per the lookup table. SH1106 detection is logged
//! but not currently rendered; the only sh1106 crate on crates.io still
//! pins embedded-hal 0.2.3 which is not directly usable with embassy-nrf
//! 0.9's TWIM. SH1106 hardware is uncommon on RAK19026 VC and adding it
//! is a follow-up.

extern crate alloc;

use core::sync::atomic::Ordering;

use embassy_executor::Spawner;
use embassy_nrf::peripherals;
use embassy_nrf::twim::{self, Twim};
use embassy_nrf::{bind_interrupts, Peri};
use embassy_time::{Duration, Timer};

use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyleBuilder},
    pixelcolor::BinaryColor,
    prelude::*,
    text::{Baseline, Text},
};
use ssd1306::{prelude::*, I2CDisplayInterface, Ssd1306};

bind_interrupts!(pub struct DisplayIrqs {
    TWISPI0 => twim::InterruptHandler<peripherals::TWISPI0>;
});

/// I²C addresses Meshtastic probes for an OLED. Order matters — 0x3C first.
const PROBE_ADDRS: [u8; 2] = [0x3C, 0x3D];

/// What the chip-probe found. Only the first variant is renderable today.
#[derive(Clone, Copy, Debug)]
enum DetectedKind {
    Ssd1306,
    Sh1106,
    None,
}

#[derive(Clone, Copy, Debug)]
struct Detected {
    kind: DetectedKind,
    addr: u8,
}

/// Address-only ACK probe — matches Meshtastic's `scanPort` quick-test
/// (`beginTransmission(addr); endTransmission()` with no payload). A
/// SSD1306/SH1106 in display-off mode will still ACK its own address even
/// when it would NACK a register read; using `write_read` for the probe
/// (as we did initially) loses those slaves.
async fn ack_probe(twim: &mut Twim<'_>, addr: u8) -> bool {
    twim.write(addr, &[]).await.is_ok()
}

/// Read the SSD1306/SH1106 status byte at register 0x00 with the
/// stabilization loop from `meshtastic/src/detect/ScanI2CTwoWire.cpp:52-87`.
/// Only called after `ack_probe` confirmed the slave is alive.
async fn classify(twim: &mut Twim<'_>, addr: u8) -> DetectedKind {
    let mut r: u8 = 0;
    let mut prev: u8 = 0xFF;
    let mut tries: u8 = 0;
    while r != prev && tries < 4 {
        prev = r;
        let mut buf = [0u8; 1];
        if twim.write_read(addr, &[0x00], &mut buf).await.is_err() {
            return DetectedKind::None;
        }
        r = buf[0] & 0x0F;
        tries += 1;
    }
    match r {
        0x00 | 0x08 => DetectedKind::Sh1106,
        0x03 | 0x04 | 0x05 | 0x06 | 0x07 => DetectedKind::Ssd1306,
        _ => DetectedKind::None,
    }
}

/// Probe both standard addresses; the first hit wins.
///
/// If the slave ACKs its address but `classify()` returns `None` (typical
/// when an SSD1306 is in display-off and won't honour a status read), we
/// default to SSD1306. The RAK19026 VC's RAK-vendor sample driver hard-
/// codes SSD1306, so this is the correct default for this carrier; SH1106
/// detection is best-effort and currently not rendered anyway.
async fn detect(twim: &mut Twim<'_>) -> Detected {
    for &addr in &PROBE_ADDRS {
        if ack_probe(twim, addr).await {
            let kind = classify(twim, addr).await;
            let kind = match kind {
                DetectedKind::None => DetectedKind::Ssd1306,
                k => k,
            };
            return Detected { kind, addr };
        }
    }
    Detected { kind: DetectedKind::None, addr: 0 }
}

/// Format the identity hash as 10 hex chars (5 bytes).
fn ident_short(hash: &[u8; 16]) -> heapless::String<10> {
    let mut s: heapless::String<10> = heapless::String::new();
    let hex = b"0123456789abcdef";
    for b in &hash[..5] {
        let _ = s.push(hex[(*b >> 4) as usize] as char);
        let _ = s.push(hex[(*b & 0x0F) as usize] as char);
    }
    s
}

#[embassy_executor::task]
pub async fn display_task(
    twispi0: Peri<'static, peripherals::TWISPI0>,
    sda: Peri<'static, peripherals::P0_13>,
    scl: Peri<'static, peripherals::P0_14>,
    identity_hash: [u8; 16],
) {
    static mut TX_BUF: [u8; 64] = [0u8; 64];

    let mut config = twim::Config::default();
    config.frequency = twim::Frequency::K400;
    // The RAK19026 VC baseboard exposes I²C1 (SDA P0.13 / SCL P0.14) without
    // external pull-up resistors — internal nRF52840 pull-ups are required.
    config.sda_pullup = true;
    config.scl_pullup = true;

    // SAFETY: TX_BUF is owned exclusively by this single, never-respawned
    // task. We hand it to Twim by `&mut` for the lifetime of the task.
    let tx_buf: &'static mut [u8] = unsafe { &mut *core::ptr::addr_of_mut!(TX_BUF) };
    let mut twim = Twim::new(twispi0, DisplayIrqs, sda, scl, config, tx_buf);

    // OLEDs (and several baseboard sensors) need a few hundred ms after the
    // 3V3-S rail comes up before they ACK on I²C. Give the bus 500 ms quiet
    // time so the very first probe doesn't see a still-resetting chip.
    Timer::after(Duration::from_millis(500)).await;

    let detected = detect(&mut twim).await;
    crate::log::log_fmt("[DISP] ", format_args!(
        "OLED probe: {:?} at 0x{:02X}", detected.kind, detected.addr
    ));

    let mut display = match detected.kind {
        DetectedKind::Ssd1306 => {
            let interface = I2CDisplayInterface::new_custom_address(twim, detected.addr);
            let mut d = Ssd1306::new(interface, DisplaySize128x64, DisplayRotation::Rotate0)
                .into_buffered_graphics_mode();
            if let Err(e) = d.init() {
                crate::log::log_fmt("[DISP] ", format_args!("init failed: {:?}", e));
                return;
            }
            crate::log::log_fmt("[DISP] ", format_args!("SSD1306 init ok"));
            d
        }
        DetectedKind::Sh1106 => {
            crate::log::log_fmt("[DISP] ", format_args!(
                "SH1106 detected — not rendered (driver pending)"
            ));
            return;
        }
        DetectedKind::None => {
            crate::log::log_fmt("[DISP] ", format_args!(
                "no OLED found on TWISPI0 — display task exiting"
            ));
            return;
        }
    };

    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();
    let id_short = ident_short(&identity_hash);

    loop {
        let rx = crate::lora::LORA_RX_COUNT.load(Ordering::Relaxed);
        let tx = crate::lora::LORA_TX_COUNT.load(Ordering::Relaxed);

        // Five-line status. FONT_6X10 → ~10 px/line, 64 px tall = up to 6
        // lines; we render 5 with one blank for breathing room.
        let _ = display.clear(BinaryColor::Off);

        let mut line2 = heapless::String::<22>::new();
        let _ = core::fmt::write(&mut line2, format_args!("ID: {}", id_short));

        let mut line3 = heapless::String::<22>::new();
        let _ = core::fmt::write(&mut line3, format_args!("RX: {:<5} TX: {:<5}", rx, tx));

        let line4 = "Bat: -- (pending D5)";
        let line5 = "GPS: -- (pending D4)";

        let lines: [&str; 5] = ["leviculum RAK4631", line2.as_str(), line3.as_str(), line4, line5];
        for (i, s) in lines.iter().enumerate() {
            let y = (i as i32) * 12;
            let _ = Text::with_baseline(s, Point::new(0, y), text_style, Baseline::Top)
                .draw(&mut display);
        }

        if let Err(e) = display.flush() {
            crate::log::log_fmt("[DISP] ", format_args!("flush failed: {:?}", e));
        }

        Timer::after(Duration::from_secs(1)).await;
    }
}

/// Convenience wrapper invoked from the bin file.
pub fn init(
    spawner: &Spawner,
    twispi0: Peri<'static, peripherals::TWISPI0>,
    sda: Peri<'static, peripherals::P0_13>,
    scl: Peri<'static, peripherals::P0_14>,
    identity_hash: [u8; 16],
) {
    spawner.must_spawn(display_task(twispi0, sda, scl, identity_hash));
}
