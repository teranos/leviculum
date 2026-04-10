//! Debug logging via USB CDC-ACM
//!
//! All log output goes into a static ring buffer (`LOG_RING`). The USB debug
//! writer task drains the ring buffer to the host when DTR is asserted.
//!
//! This design never blocks, never drops messages for the reader, and works
//! regardless of when the host opens the port. Old data is overwritten when
//! the ring buffer is full (like Linux `dmesg` / `printk`).

use core::sync::atomic::{AtomicUsize, Ordering};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;

// ─── Ring buffer ───────────────────────────────────────────────────────────

const LOG_RING_SIZE: usize = 4096; // 4 KB — fits ~15-20 log lines

/// Lock-free ring buffer for log output.
/// Single producer (log_fmt / tracing subscriber), single consumer (USB debug writer).
pub struct LogRing {
    buf: core::cell::UnsafeCell<[u8; LOG_RING_SIZE]>,
    write_pos: AtomicUsize,
    read_pos: AtomicUsize,
}

// Safety: Embassy is single-threaded (cooperative executor on one core).
// One producer (log_fmt, called from any task), one consumer (debug_writer_task).
unsafe impl Sync for LogRing {}

impl LogRing {
    pub const fn new() -> Self {
        Self {
            buf: core::cell::UnsafeCell::new([0u8; LOG_RING_SIZE]),
            write_pos: AtomicUsize::new(0),
            read_pos: AtomicUsize::new(0),
        }
    }

    /// Write bytes into the ring buffer. Overwrites oldest data if full.
    pub fn write(&self, data: &[u8]) {
        let buf = unsafe { &mut *self.buf.get() };
        let mut wp = self.write_pos.load(Ordering::Relaxed);
        for &byte in data {
            buf[wp % LOG_RING_SIZE] = byte;
            wp = wp.wrapping_add(1);
        }
        self.write_pos.store(wp, Ordering::Release);

        // If writer has lapped reader, advance reader to oldest available data
        let rp = self.read_pos.load(Ordering::Relaxed);
        if wp.wrapping_sub(rp) > LOG_RING_SIZE {
            self.read_pos.store(wp - LOG_RING_SIZE, Ordering::Release);
        }
    }

    /// Read up to `out.len()` bytes. Returns number of bytes read.
    pub fn read(&self, out: &mut [u8]) -> usize {
        let buf = unsafe { &*self.buf.get() };
        let wp = self.write_pos.load(Ordering::Acquire);
        let mut rp = self.read_pos.load(Ordering::Relaxed);
        let avail = wp.wrapping_sub(rp);
        let to_read = avail.min(out.len());
        for i in 0..to_read {
            out[i] = buf[rp % LOG_RING_SIZE];
            rp = rp.wrapping_add(1);
        }
        self.read_pos.store(rp, Ordering::Release);
        to_read
    }
}

/// Global ring buffer for all log output.
pub static LOG_RING: LogRing = LogRing::new();

/// Signal to wake the USB debug writer when new data is available.
pub static LOG_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();

// ─── Log formatting ────────────────────────────────────────────────────────

/// Format and write a log message to the ring buffer. Never blocks.
pub fn log_fmt(prefix: &str, args: core::fmt::Arguments) {
    let mut buf = [0u8; 256];
    let mut len = 0usize;

    // Format prefix + message + \r\n into stack buffer
    struct BufWriter<'a> { buf: &'a mut [u8], len: &'a mut usize }
    impl core::fmt::Write for BufWriter<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let remaining = self.buf.len() - *self.len;
            let to_copy = s.len().min(remaining);
            self.buf[*self.len..*self.len + to_copy].copy_from_slice(&s.as_bytes()[..to_copy]);
            *self.len += to_copy;
            Ok(())
        }
    }

    let mut w = BufWriter { buf: &mut buf, len: &mut len };
    let _ = core::fmt::Write::write_str(&mut w, prefix);
    let _ = core::fmt::Write::write_fmt(&mut w, args);
    let _ = core::fmt::Write::write_str(&mut w, "\r\n");

    LOG_RING.write(&buf[..len]);
    LOG_SIGNAL.signal(());
}

// ─── Macros ────────────────────────────────────────────────────────────────

/// Log an informational message over USB CDC-ACM debug port.
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        $crate::log::log_fmt("[INFO] ", core::format_args!($($arg)*))
    };
}

/// Log a warning message over USB CDC-ACM debug port.
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::log::log_fmt("[WARN] ", core::format_args!($($arg)*))
    };
}

// ─── Tracing subscriber ───────────────────────────────────────────────────

/// Minimal tracing subscriber that routes `reticulum-core` log events
/// to the ring buffer via log_fmt.
pub struct TracingSubscriber;

impl tracing_core::Subscriber for TracingSubscriber {
    fn enabled(&self, metadata: &tracing_core::Metadata<'_>) -> bool {
        metadata.level() <= &tracing_core::Level::DEBUG
    }

    fn new_span(&self, _: &tracing_core::span::Attributes<'_>) -> tracing_core::span::Id {
        tracing_core::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing_core::span::Id, _: &tracing_core::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing_core::span::Id, _: &tracing_core::span::Id) {}
    fn enter(&self, _: &tracing_core::span::Id) {}
    fn exit(&self, _: &tracing_core::span::Id) {}

    fn event(&self, event: &tracing_core::Event<'_>) {
        let metadata = event.metadata();
        let level = match *metadata.level() {
            tracing_core::Level::ERROR => "ERROR",
            tracing_core::Level::WARN => " WARN",
            tracing_core::Level::INFO => " INFO",
            tracing_core::Level::DEBUG => "DEBUG",
            tracing_core::Level::TRACE => "TRACE",
        };

        let mut buf = [0u8; 256];
        let mut len = 0usize;

        struct BufWriter<'a> { buf: &'a mut [u8], len: &'a mut usize }
        impl core::fmt::Write for BufWriter<'_> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let remaining = self.buf.len() - *self.len;
                let to_copy = s.len().min(remaining);
                self.buf[*self.len..*self.len + to_copy].copy_from_slice(&s.as_bytes()[..to_copy]);
                *self.len += to_copy;
                Ok(())
            }
        }

        {
            let mut w = BufWriter { buf: &mut buf, len: &mut len };
            let _ = core::fmt::Write::write_fmt(
                &mut w,
                format_args!("[{}] {}: ", level, metadata.target()),
            );
        }
        event.record(&mut TracingVisitor { buf: &mut buf, len: &mut len });
        {
            let mut w = BufWriter { buf: &mut buf, len: &mut len };
            let _ = core::fmt::Write::write_str(&mut w, "\r\n");
        }

        LOG_RING.write(&buf[..len]);
        LOG_SIGNAL.signal(());
    }
}

/// Visitor that formats tracing event fields into a buffer.
struct TracingVisitor<'a> {
    buf: &'a mut [u8],
    len: &'a mut usize,
}

impl tracing_core::field::Visit for TracingVisitor<'_> {
    fn record_debug(&mut self, field: &tracing_core::field::Field, value: &dyn core::fmt::Debug) {
        struct BufWriter<'a> { buf: &'a mut [u8], len: &'a mut usize }
        impl core::fmt::Write for BufWriter<'_> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let remaining = self.buf.len() - *self.len;
                let to_copy = s.len().min(remaining);
                self.buf[*self.len..*self.len + to_copy].copy_from_slice(&s.as_bytes()[..to_copy]);
                *self.len += to_copy;
                Ok(())
            }
        }
        let mut w = BufWriter { buf: self.buf, len: self.len };
        if field.name() == "message" {
            let _ = core::fmt::Write::write_fmt(&mut w, format_args!("{:?}", value));
        } else {
            let _ = core::fmt::Write::write_fmt(
                &mut w,
                format_args!(" {}={:?}", field.name(), value),
            );
        }
    }
}
