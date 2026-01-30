//! Channel error types

/// Errors that can occur during channel operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    /// Invalid message type (>= 0xf000 reserved)
    InvalidMsgType,
    /// Message too large for link MDU
    TooLarge,
    /// Invalid envelope format
    InvalidEnvelope,
    /// Channel window is full
    WindowFull,
}
