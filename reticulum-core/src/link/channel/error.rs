//! Channel error types

/// Errors that can occur during channel operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    /// Invalid message type (>= 0xf000 reserved)
    InvalidMsgType,
    /// Message too large for link MDU
    TooLarge,
    /// Envelope header is incomplete (< 6 bytes)
    EnvelopeTooShort,
    /// Envelope data is shorter than the declared length
    EnvelopeTruncated,
    /// Invalid stream_id (> STREAM_ID_MAX)
    InvalidStreamId,
    /// Channel window is full
    WindowFull,
}
