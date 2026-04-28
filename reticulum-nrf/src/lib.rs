//! Reticulum firmware support for nRF52840-based boards
//!
//! Provides heap allocator setup, board-specific pin mappings,
//! USB CDC-ACM debug logging, and Reticulum transport interface.

#![no_std]

extern crate alloc;

pub mod ble;
pub mod boards;
pub mod clock;
pub mod flash;
pub mod interface;
pub mod log;
pub mod lora;
pub mod rng;
pub mod sx1262;
pub mod usb;

// RAK19026 baseboard peripherals — each gated on its own feature so the
// bare nRF52840 + SX1262 build (T114, RAK4631 module without baseboard)
// stays unchanged.
#[cfg(any(feature = "display", feature = "gnss", feature = "battery"))]
pub mod baseboard;
#[cfg(feature = "display")]
pub mod display;

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

use core::mem::MaybeUninit;
use embedded_alloc::LlffHeap as Heap;

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// Heap size in bytes (96 KiB, leaves ~136 KiB of 232 KiB app RAM for stack + BSS)
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

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

static PANIC_LED_ARMED: AtomicBool = AtomicBool::new(false);
static PANIC_LED_PORT: AtomicU8 = AtomicU8::new(0);
static PANIC_LED_PIN: AtomicU8 = AtomicU8::new(0);
static PANIC_LED_ACTIVE_LOW: AtomicBool = AtomicBool::new(false);

/// Arm the panic-handler LED. Until this is called, a panic skips GPIO
/// and just halts.
///
/// `port` is 0 (P0) or 1 (P1). `pin` is 0..=31. `active_low` is true if
/// the LED lights when the GPIO is driven low.
pub fn set_panic_led(port: u8, pin: u8, active_low: bool) {
    PANIC_LED_PORT.store(port, Ordering::Relaxed);
    PANIC_LED_PIN.store(pin, Ordering::Relaxed);
    PANIC_LED_ACTIVE_LOW.store(active_low, Ordering::Relaxed);
    PANIC_LED_ARMED.store(true, Ordering::Relaxed);
}

#[cfg(not(test))]
mod panic_handler {
    use core::panic::PanicInfo;
    use core::sync::atomic::Ordering;

    #[panic_handler]
    fn panic(info: &PanicInfo) -> ! {
        // Best-effort: write panic info to LOG_CHANNEL. The Embassy
        // executor is dead so debug_writer_task won't drain it, but
        // the message is preserved in channel memory for post-mortem.
        crate::log::log_fmt("[PANIC] ", format_args!("{}", info));

        if !super::PANIC_LED_ARMED.load(Ordering::Relaxed) {
            // No LED configured — nothing to blink, just halt.
            loop {
                cortex_m::asm::wfi();
            }
        }

        // Direct register pokes to avoid any allocation or HAL state.
        // P0_BASE = 0x5000_0000, P1_BASE = 0x5000_0300.
        let port = super::PANIC_LED_PORT.load(Ordering::Relaxed);
        let pin = super::PANIC_LED_PIN.load(Ordering::Relaxed);
        let active_low = super::PANIC_LED_ACTIVE_LOW.load(Ordering::Relaxed);
        let port_base: u32 = if port == 1 { 0x5000_0300 } else { 0x5000_0000 };
        let pin_mask: u32 = 1u32 << (pin & 31);
        let dirset = port_base + 0x518;
        let outset = port_base + 0x508;
        let outclr = port_base + 0x50C;
        // (set_on, set_off): write to OUTCLR to drive low, OUTSET to drive high
        let (reg_on, reg_off) = if active_low { (outclr, outset) } else { (outset, outclr) };

        unsafe {
            core::ptr::write_volatile(dirset as *mut u32, pin_mask);
        }

        loop {
            unsafe {
                core::ptr::write_volatile(reg_on as *mut u32, pin_mask);
            }
            for _ in 0..2_000_000u32 {
                cortex_m::asm::nop();
            }
            unsafe {
                core::ptr::write_volatile(reg_off as *mut u32, pin_mask);
            }
            for _ in 0..2_000_000u32 {
                cortex_m::asm::nop();
            }
        }
    }
}
