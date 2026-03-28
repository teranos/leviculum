//! Reticulum firmware support for nRF52840-based boards
//!
//! Provides heap allocator setup, board-specific pin mappings,
//! USB CDC-ACM debug logging, and Reticulum transport interface.

#![no_std]

extern crate alloc;

pub mod boards;
pub mod clock;
pub mod interface;
pub mod log;
pub mod usb;

use core::mem::MaybeUninit;
use embedded_alloc::LlffHeap as Heap;

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// Heap size in bytes (96 KiB — leaves ~136 KiB of 232 KiB app RAM for stack + BSS)
const HEAP_SIZE: usize = 96 * 1024;

/// Initialize the heap allocator
///
/// Must be called once before any `alloc` usage (Vec, String, etc.).
/// Typically called at the start of the firmware entry point.
pub fn init_heap() {
    static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    // SAFETY: Called once at startup before any concurrent access.
    // Use addr_of! to avoid creating a reference to the static mut.
    unsafe {
        let heap_start = core::ptr::addr_of!(HEAP_MEM) as usize;
        HEAP.init(heap_start, HEAP_SIZE);
    }
}

#[cfg(not(test))]
mod panic_handler {
    use core::panic::PanicInfo;

    /// Format panic info into a static buffer. Returns the used slice.
    fn format_panic(info: &PanicInfo, buf: &mut [u8]) -> usize {
        struct BufWriter<'a> {
            buf: &'a mut [u8],
            pos: usize,
        }
        impl core::fmt::Write for BufWriter<'_> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                let remaining = self.buf.len() - self.pos;
                let to_copy = bytes.len().min(remaining);
                self.buf[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
                self.pos += to_copy;
                Ok(())
            }
        }
        let mut w = BufWriter { buf, pos: 0 };
        let _ = core::fmt::Write::write_fmt(&mut w, format_args!("[PANIC] {}\r\n", info));
        w.pos
    }

    #[panic_handler]
    fn panic(info: &PanicInfo) -> ! {
        // Best-effort: write panic info to LOG_CHANNEL. The Embassy
        // executor is dead so debug_writer_task won't drain it, but
        // the message is preserved in channel memory for post-mortem.
        crate::log::log_fmt("[PANIC] ", format_args!("{}", info));

        // Also try: toggle LED rapidly as visual indicator.
        // P1.03 is the T114 LED (active low).
        // Write directly to GPIO registers to avoid any alloc.
        const P1_BASE: u32 = 0x5000_0300;
        const PIN03: u32 = 1 << 3;
        const DIRSET: u32 = P1_BASE + 0x518;
        const OUTSET: u32 = P1_BASE + 0x508;
        const OUTCLR: u32 = P1_BASE + 0x50C;

        unsafe {
            // Set P1.03 as output
            core::ptr::write_volatile(DIRSET as *mut u32, PIN03);
        }

        // Rapid blink loop — visible panic indicator
        loop {
            unsafe {
                core::ptr::write_volatile(OUTCLR as *mut u32, PIN03); // LED on
            }
            for _ in 0..2_000_000u32 {
                cortex_m::asm::nop();
            }
            unsafe {
                core::ptr::write_volatile(OUTSET as *mut u32, PIN03); // LED off
            }
            for _ in 0..2_000_000u32 {
                cortex_m::asm::nop();
            }
        }
    }
}
