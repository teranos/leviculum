//! Reticulum firmware support for nRF52840-based boards
//!
//! Provides heap allocator setup, board-specific pin mappings,
//! USB CDC-ACM debug logging, and Reticulum transport interface.

#![no_std]

extern crate alloc;

// Bug #32 spike: exactly one BSP feature must be enabled. Mutex
// enforced at compile time so any binary forgets-to-select-a-BSP or
// sets-both fails fast at `cargo build`, not at link or runtime.
#[cfg(all(feature = "bsp-rak4631", feature = "bsp-t114"))]
compile_error!("`bsp-rak4631` and `bsp-t114` are mutually exclusive — pick exactly one");

#[cfg(not(any(feature = "bsp-rak4631", feature = "bsp-t114")))]
compile_error!("must enable exactly one of `bsp-rak4631` or `bsp-t114`");

#[cfg(feature = "bsp-rak4631")]
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
#[cfg(feature = "battery")]
pub mod battery;
#[cfg(feature = "display")]
pub mod button;
#[cfg(feature = "display")]
pub mod display;
#[cfg(feature = "display")]
pub mod led;
#[cfg(feature = "gnss")]
pub mod gnss;

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

static HARDFAULT_LED_ARMED: AtomicBool = AtomicBool::new(false);
static HARDFAULT_LED_PORT: AtomicU8 = AtomicU8::new(0);
static HARDFAULT_LED_PIN: AtomicU8 = AtomicU8::new(0);
static HARDFAULT_LED_ACTIVE_LOW: AtomicBool = AtomicBool::new(false);

/// Arm the HardFault-handler LED. Same pattern as `set_panic_led` but
/// for the cortex-m HardFault exception path. Picking a different LED
/// (e.g. blue while panic uses green) lets the operator distinguish a
/// `panic!()` from a HardFault at a glance: blue blink ≈ HardFault,
/// green blink ≈ panic, all dark ≈ async deadlock or DefaultHandler
/// halt with no LED armed.
pub fn set_hardfault_led(port: u8, pin: u8, active_low: bool) {
    HARDFAULT_LED_PORT.store(port, Ordering::Relaxed);
    HARDFAULT_LED_PIN.store(pin, Ordering::Relaxed);
    HARDFAULT_LED_ACTIVE_LOW.store(active_low, Ordering::Relaxed);
    HARDFAULT_LED_ARMED.store(true, Ordering::Relaxed);
}

/// Maximum bytes of panic message preserved across the post-mortem soft-reset.
pub const PANIC_MSG_MAX: usize = 256;

/// Snapshot returned by `take_panic_postmortem()`.
#[derive(Clone, Copy)]
pub struct PanicPostMortem {
    pub len: usize,
    pub bytes: [u8; PANIC_MSG_MAX],
}

#[repr(C)]
struct PanicPmRaw {
    magic: u32,
    len: u32,
    bytes: [u8; PANIC_MSG_MAX],
}

const PANIC_PM_MAGIC: u32 = 0xBADD_CAFE;

#[link_section = ".uninit"]
static mut PANIC_PM: core::mem::MaybeUninit<PanicPmRaw> =
    core::mem::MaybeUninit::uninit();

/// Read and clear the panic message captured before the last soft-reset.
/// Returns `Some(_)` exactly once after a panic, `None` otherwise.
pub fn take_panic_postmortem() -> Option<PanicPostMortem> {
    unsafe {
        let p = core::ptr::addr_of_mut!(PANIC_PM).cast::<PanicPmRaw>();
        let magic = core::ptr::read_volatile(core::ptr::addr_of!((*p).magic));
        if magic != PANIC_PM_MAGIC {
            return None;
        }
        let raw_len = core::ptr::read_volatile(core::ptr::addr_of!((*p).len)) as usize;
        let len = raw_len.min(PANIC_MSG_MAX);
        let mut bytes = [0u8; PANIC_MSG_MAX];
        let src = core::ptr::addr_of!((*p).bytes).cast::<u8>();
        for i in 0..len {
            bytes[i] = core::ptr::read_volatile(src.add(i));
        }
        // Clear magic so subsequent boots don't re-log.
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*p).magic), 0);
        Some(PanicPostMortem { len, bytes })
    }
}

#[cfg(not(test))]
mod panic_handler {
    use core::panic::PanicInfo;
    use core::sync::atomic::Ordering;

    /// Slice writer for `core::fmt::write` — pushes bytes into a caller-
    /// supplied buffer, silently truncating on overflow. Used inside the
    /// panic handler where allocation must not happen.
    struct ByteWriter<'a> {
        buf: &'a mut [u8],
        pos: usize,
    }
    impl core::fmt::Write for ByteWriter<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            for &b in s.as_bytes() {
                if self.pos >= self.buf.len() {
                    return Ok(());
                }
                self.buf[self.pos] = b;
                self.pos += 1;
            }
            Ok(())
        }
    }

    #[panic_handler]
    fn panic(info: &PanicInfo) -> ! {
        // Capture the panic message into `.uninit` so the next boot can
        // log it. LOG_CHANNEL is unusable here — the executor is dead
        // and would never drain it.
        unsafe {
            let p = core::ptr::addr_of_mut!(super::PANIC_PM).cast::<super::PanicPmRaw>();
            let buf_ptr = core::ptr::addr_of_mut!((*p).bytes).cast::<u8>();
            let buf_slice = core::slice::from_raw_parts_mut(buf_ptr, super::PANIC_MSG_MAX);
            let mut writer = ByteWriter { buf: buf_slice, pos: 0 };
            let _ = core::fmt::write(&mut writer, format_args!("{}", info));
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*p).len),
                writer.pos as u32,
            );
            // Magic last — partial write must not appear valid.
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*p).magic),
                super::PANIC_PM_MAGIC,
            );
        }

        if !super::PANIC_LED_ARMED.load(Ordering::Relaxed) {
            // No LED configured — reset immediately so the next boot
            // logs the post-mortem.
            cortex_m::peripheral::SCB::sys_reset();
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

        // Blink ~25 cycles (~5 s of visual indication), then reset so the
        // next boot can log the captured panic message.
        for _ in 0..25u32 {
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
        cortex_m::peripheral::SCB::sys_reset();
    }
}

/// HardFault post-mortem snapshot saved into a `.uninit` static so it
/// survives `sys_reset()`. The next boot reads it via
/// `take_hardfault_postmortem()` to log the faulting PC and the
/// register set, allowing post-hoc address-to-source resolution with
/// `arm-none-eabi-addr2line`.
#[repr(C)]
pub struct HardfaultPostMortem {
    /// `PM_MAGIC` when valid. Set on fault, cleared after one successful read.
    magic: u32,
    pub pc: u32,
    pub lr: u32,
    pub r0: u32,
    pub r1: u32,
    pub r2: u32,
    pub r3: u32,
    pub r12: u32,
    pub xpsr: u32,
}

/// Distinct from `paint_stack`'s `0xDEADBEEF` canary so a post-paint read
/// of `.uninit` (which the canary fills) cannot masquerade as a valid PM.
const HARDFAULT_PM_MAGIC: u32 = 0xC0FF_EE12;

/// Survives `sys_reset` because `.uninit` is `NOLOAD` in cortex-m-rt's
/// link.x — values in RAM are not zeroed by the runtime startup.
#[link_section = ".uninit"]
static mut HARDFAULT_PM: core::mem::MaybeUninit<HardfaultPostMortem> =
    core::mem::MaybeUninit::uninit();

/// Read and clear the HardFault post-mortem captured before the last
/// soft-reset. Returns `Some(_)` once after a HardFault, `None`
/// otherwise (and `None` on every subsequent call until the next fault).
pub fn take_hardfault_postmortem() -> Option<HardfaultPostMortem> {
    unsafe {
        let p = core::ptr::addr_of_mut!(HARDFAULT_PM).cast::<HardfaultPostMortem>();
        let magic = core::ptr::read_volatile(core::ptr::addr_of!((*p).magic));
        if magic != HARDFAULT_PM_MAGIC {
            return None;
        }
        let pm = HardfaultPostMortem {
            magic: 0,
            pc:   core::ptr::read_volatile(core::ptr::addr_of!((*p).pc)),
            lr:   core::ptr::read_volatile(core::ptr::addr_of!((*p).lr)),
            r0:   core::ptr::read_volatile(core::ptr::addr_of!((*p).r0)),
            r1:   core::ptr::read_volatile(core::ptr::addr_of!((*p).r1)),
            r2:   core::ptr::read_volatile(core::ptr::addr_of!((*p).r2)),
            r3:   core::ptr::read_volatile(core::ptr::addr_of!((*p).r3)),
            r12:  core::ptr::read_volatile(core::ptr::addr_of!((*p).r12)),
            xpsr: core::ptr::read_volatile(core::ptr::addr_of!((*p).xpsr)),
        };
        // Invalidate so we don't re-log on subsequent boots.
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*p).magic), 0);
        Some(pm)
    }
}

/// Cortex-M HardFault handler — overrides the cortex-m-rt default which
/// would just `wfi` forever and leave us with no visual cue. If a board
/// armed `set_hardfault_led`, blink that LED briefly so the operator
/// sees the fault in real time, capture an `ExceptionFrame` snapshot to
/// `.uninit` RAM that survives the soft-reset, then `sys_reset` so the
/// next boot can log the post-mortem from a working executor.
#[cfg(not(test))]
#[cortex_m_rt::exception]
unsafe fn HardFault(ef: &cortex_m_rt::ExceptionFrame) -> ! {
    // Save register snapshot first — even if the LED arming is absent
    // (unlikely on a configured board), the post-mortem is the
    // diagnostic of record.
    let p = core::ptr::addr_of_mut!(HARDFAULT_PM).cast::<HardfaultPostMortem>();
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*p).pc),   ef.pc());
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*p).lr),   ef.lr());
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*p).r0),   ef.r0());
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*p).r1),   ef.r1());
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*p).r2),   ef.r2());
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*p).r3),   ef.r3());
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*p).r12),  ef.r12());
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*p).xpsr), ef.xpsr());
    // Magic last so a partial write can't masquerade as a valid PM.
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*p).magic), HARDFAULT_PM_MAGIC);

    if !HARDFAULT_LED_ARMED.load(Ordering::Relaxed) {
        // No LED configured — reset immediately so the next boot can
        // log the post-mortem.
        cortex_m::peripheral::SCB::sys_reset();
    }

    let port = HARDFAULT_LED_PORT.load(Ordering::Relaxed);
    let pin = HARDFAULT_LED_PIN.load(Ordering::Relaxed);
    let active_low = HARDFAULT_LED_ACTIVE_LOW.load(Ordering::Relaxed);
    let port_base: u32 = if port == 1 { 0x5000_0300 } else { 0x5000_0000 };
    let pin_mask: u32 = 1u32 << (pin & 31);
    let dirset = port_base + 0x518;
    let outset = port_base + 0x508;
    let outclr = port_base + 0x50C;
    let (reg_on, reg_off) = if active_low { (outclr, outset) } else { (outset, outclr) };

    core::ptr::write_volatile(dirset as *mut u32, pin_mask);

    // Blink ~25 cycles for ~5 s of visual indication, then reset so the
    // next boot can log the captured post-mortem.
    for _ in 0..25u32 {
        core::ptr::write_volatile(reg_on as *mut u32, pin_mask);
        for _ in 0..2_000_000u32 {
            cortex_m::asm::nop();
        }
        core::ptr::write_volatile(reg_off as *mut u32, pin_mask);
        for _ in 0..2_000_000u32 {
            cortex_m::asm::nop();
        }
    }
    cortex_m::peripheral::SCB::sys_reset();
}
