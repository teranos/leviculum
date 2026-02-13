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
    /// Receive ring is full (message dropped)
    RxRingFull,
}

impl core::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChannelError::InvalidMsgType => write!(f, "invalid message type"),
            ChannelError::TooLarge => write!(f, "message too large for link MDU"),
            ChannelError::EnvelopeTooShort => write!(f, "envelope header too short"),
            ChannelError::EnvelopeTruncated => write!(f, "envelope data truncated"),
            ChannelError::InvalidStreamId => write!(f, "invalid stream ID"),
            ChannelError::WindowFull => write!(f, "channel window full"),
            ChannelError::RxRingFull => write!(f, "receive ring full"),
        }
    }
}
