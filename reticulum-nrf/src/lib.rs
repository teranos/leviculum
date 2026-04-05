//! Reticulum firmware support for nRF52840-based boards
//!
//! Provides heap allocator setup, board-specific pin mappings,
//! USB CDC-ACM debug logging, and Reticulum transport interface.

#![no_std]

extern crate alloc;

pub mod ble;
pub mod boards;
pub mod clock;
pub mod interface;
pub mod log;
pub mod lora;
pub mod rng;
pub mod usb;

/// Install the tracing subscriber that routes `reticulum-core` log events
/// to the CDC-ACM debug port via LOG_CHANNEL.
///
/// Call once at startup before any tracing macros fire. Without this,
/// all `tracing::debug!()` / `tracing::info!()` etc. from reticulum-core
/// are silently dropped (no subscriber registered).
pub fn init_tracing() {
    use tracing_core::dispatcher;
    let subscriber = log::TracingSubscriber;
    let dispatch = dispatcher::Dispatch::new(subscriber);
    let _ = dispatcher::set_global_default(dispatch);
}

// No-op defmt logger — required by lora-phy but we use our own CDC-ACM logging.
// defmt log calls from lora-phy are silently discarded.
mod defmt_stub {
    #[defmt::global_logger]
    struct StubLogger;
    unsafe impl defmt::Logger for StubLogger {
        fn acquire() {}
        unsafe fn flush() {}
        unsafe fn release() {}
        unsafe fn write(_bytes: &[u8]) {}
    }
}

use core::mem::MaybeUninit;
use embedded_alloc::LlffHeap as Heap;

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// Heap size in bytes (96 KiB — leaves ~136 KiB of 232 KiB app RAM for stack + BSS)
const HEAP_SIZE: usize = 96 * 1024;

/// Return (used, free) heap bytes at this instant.
pub fn heap_stats() -> (usize, usize) {
    (HEAP.used(), HEAP.free())
}

/// Returns approximate unused stack bytes.
/// Requires `paint_stack()` to have been called at boot.
pub fn stack_free() -> usize {
    extern "C" {
        static __ebss: u8;
    }
    let stack_bottom = core::ptr::addr_of!(__ebss) as *const u32;
    let stack_top = 0x2004_0000 as *const u32; // RAM end
    let mut untouched = 0usize;
    let mut p = stack_bottom;
    while (p as usize) < (stack_top as usize) {
        if unsafe { core::ptr::read_volatile(p) } != 0xDEAD_BEEF {
            break;
        }
        untouched += 1;
        p = unsafe { p.add(1) };
    }
    untouched * 4
}

/// Paint stack with canary pattern. Call once at start of main, before heavy work.
///
/// # Safety
/// Must be called before any concurrent tasks or interrupts use the stack.
pub unsafe fn paint_stack() {
    extern "C" {
        static mut __ebss: u8;
    }
    let stack_bottom = core::ptr::addr_of_mut!(__ebss) as *mut u32;
    let current_sp: u32;
    core::arch::asm!("mov {}, sp", out(reg) current_sp);
    // Paint up to 1 KB below current SP (leave headroom for this function)
    let safe_limit = ((current_sp as usize).saturating_sub(1024)) as *mut u32;
    let mut p = stack_bottom;
    while (p as usize) < (safe_limit as usize) {
        core::ptr::write_volatile(p, 0xDEAD_BEEF);
        p = p.add(1);
    }
}

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
