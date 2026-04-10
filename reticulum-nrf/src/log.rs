//! Debug logging via USB CDC-ACM
//!
//! Provides `info!` and `warn!` macros that format messages into a fixed-size
//! buffer and send them over a bounded channel. The USB debug writer task
//! drains this channel and sends messages to the host.
//!
//! Messages are silently dropped if the channel is full (host not reading).

use core::sync::atomic::{AtomicU32, Ordering};
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

/// Bounded channel for log messages. Capacity 32 (8 KB RAM).
pub static LOG_CHANNEL: Channel<CriticalSectionRawMutex, LogMessage, 32> = Channel::new();

/// Count of messages dropped due to full channel.
static LOG_DROPPED: AtomicU32 = AtomicU32::new(0);

/// Format and enqueue a log message. Non-blocking: drops if channel is full.
pub fn log_fmt(prefix: &str, args: core::fmt::Arguments) {
    let mut msg = LogMessage {
        buf: [0u8; 256],
        len: 0,
    };

    // If messages were dropped, prepend a warning
    let dropped = LOG_DROPPED.swap(0, Ordering::Relaxed);
    if dropped > 0 {
        let mut writer = LogWriter(&mut msg);
        let _ = core::fmt::Write::write_fmt(
            &mut writer,
            format_args!("[!!! {} log messages dropped !!!]\r\n", dropped),
        );
    }

    let mut writer = LogWriter(&mut msg);
    let _ = core::fmt::Write::write_str(&mut writer, prefix);
    let _ = core::fmt::Write::write_fmt(&mut writer, args);
    let _ = core::fmt::Write::write_str(&mut writer, "\r\n");

    if LOG_CHANNEL.try_send(msg).is_err() {
        LOG_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
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

/// Minimal tracing subscriber that routes `reticulum-core` log events
/// to the CDC-ACM debug port via LOG_CHANNEL.
///
/// Only processes events (not spans). Formats each event as:
/// `[LEVEL] message key=value key=value...\r\n`
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

        let mut msg = LogMessage {
            buf: [0u8; 256],
            len: 0,
        };

        // Format prefix, then visit fields, then append \r\n — all on msg directly
        {
            let mut writer = LogWriter(&mut msg);
            let _ = core::fmt::Write::write_fmt(
                &mut writer,
                format_args!("[{}] {}: ", level, metadata.target()),
            );
        }
        event.record(&mut TracingVisitor(&mut msg));
        {
            let mut writer = LogWriter(&mut msg);
            let _ = core::fmt::Write::write_str(&mut writer, "\r\n");
        }

        if LOG_CHANNEL.try_send(msg).is_err() {
            LOG_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Visitor that formats tracing event fields into the LogMessage buffer.
struct TracingVisitor<'a>(&'a mut LogMessage);

impl tracing_core::field::Visit for TracingVisitor<'_> {
    fn record_debug(&mut self, field: &tracing_core::field::Field, value: &dyn core::fmt::Debug) {
        let mut writer = LogWriter(self.0);
        if field.name() == "message" {
            let _ = core::fmt::Write::write_fmt(&mut writer, format_args!("{:?}", value));
        } else {
            let _ = core::fmt::Write::write_fmt(
                &mut writer,
                format_args!(" {}={:?}", field.name(), value),
            );
        }
    }
}
