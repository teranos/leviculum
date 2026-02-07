//! Debug logging via USB CDC-ACM
//!
//! Provides `info!` and `warn!` macros that format messages into a fixed-size
//! buffer and send them over a bounded channel. The USB debug writer task
//! drains this channel and sends messages to the host.
//!
//! Messages are silently dropped if the channel is full (host not reading).

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;

/// Fixed-size log message buffer (no heap allocation in log path).
pub struct LogMessage {
    buf: [u8; 256],
    len: usize,
}

impl LogMessage {
    /// Return the formatted message bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Bounded channel for log messages. Capacity 16 — if full, messages are dropped.
pub static LOG_CHANNEL: Channel<CriticalSectionRawMutex, LogMessage, 16> = Channel::new();

/// Format and enqueue a log message. Non-blocking: drops if channel is full.
pub fn log_fmt(prefix: &str, args: core::fmt::Arguments) {
    let mut msg = LogMessage {
        buf: [0u8; 256],
        len: 0,
    };
    let mut writer = LogWriter(&mut msg);
    let _ = core::fmt::Write::write_str(&mut writer, prefix);
    let _ = core::fmt::Write::write_fmt(&mut writer, args);
    let _ = core::fmt::Write::write_str(&mut writer, "\r\n");

    // Non-blocking send — silently drop if channel is full
    let _ = LOG_CHANNEL.try_send(msg);
}

struct LogWriter<'a>(&'a mut LogMessage);

impl core::fmt::Write for LogWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let remaining = 256 - self.0.len;
        let to_copy = s.len().min(remaining);
        self.0.buf[self.0.len..self.0.len + to_copy].copy_from_slice(&s.as_bytes()[..to_copy]);
        self.0.len += to_copy;
        Ok(())
    }
}

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
