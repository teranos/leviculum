//! Connection abstraction - wraps a Link for data transfer
//!
//! A [`Connection`] represents an established, verified communication session
//! between two nodes. Channel-based reliable messaging is handled by the
//! unified Channel in [`LinkManager`](crate::link::LinkManager).

use crate::destination::DestinationHash;
use crate::link::channel::ChannelError;
use crate::link::{LinkError, LinkId};

/// Error type for connection operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionError {
    /// Connection is not in a valid state for this operation
    InvalidState,
    /// Link-level error occurred
    LinkError(LinkError),
    /// Channel-level error occurred
    ChannelError(ChannelError),
    /// Data too large for connection MDU
    TooLarge,
    /// Connection not found
    NotFound,
    /// Destination identity not found (destination not registered or has no identity)
    IdentityNotFound,
}

impl core::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConnectionError::InvalidState => write!(f, "invalid connection state"),
            ConnectionError::LinkError(e) => write!(f, "link error: {}", e),
            ConnectionError::ChannelError(e) => write!(f, "channel error: {}", e),
            ConnectionError::TooLarge => write!(f, "data too large for connection MDU"),
            ConnectionError::NotFound => write!(f, "connection not found"),
            ConnectionError::IdentityNotFound => {
                write!(f, "destination identity not found")
            }
        }
    }
}

impl From<LinkError> for ConnectionError {
    fn from(e: LinkError) -> Self {
        ConnectionError::LinkError(e)
    }
}

impl From<ChannelError> for ConnectionError {
    fn from(e: ChannelError) -> Self {
        ConnectionError::ChannelError(e)
    }
}

/// A connection represents an established Link
///
/// Connections track metadata about an established link (destination,
/// initiator role, compression). Reliable channel messaging is handled
/// by the unified Channel in LinkManager.
///
/// # Example
///
/// ```
/// use reticulum_core::node::Connection;
/// use reticulum_core::link::LinkId;
/// use reticulum_core::destination::DestinationHash;
///
/// let link_id = LinkId::new([0x42; 16]);
/// let dest_hash = DestinationHash::new([0x33; 16]);
/// let connection = Connection::new(link_id, dest_hash, true);
///
/// assert!(connection.is_initiator());
/// ```
pub struct Connection {
    /// The underlying link ID
    link_id: LinkId,
    /// The destination hash this connection is to
    destination_hash: DestinationHash,
    /// Whether we initiated this connection
    is_initiator: bool,
    /// Whether compression is enabled for this connection
    compression_enabled: bool,
}

impl Connection {
    /// Create a new connection wrapper around a link
    ///
    /// # Arguments
    /// * `link_id` - The ID of the underlying link
    /// * `destination_hash` - The destination this connection is to
    /// * `is_initiator` - Whether we initiated this connection
    pub fn new(link_id: LinkId, destination_hash: DestinationHash, is_initiator: bool) -> Self {
        Self {
            link_id,
            destination_hash,
            is_initiator,
            compression_enabled: false,
        }
    }

    /// Get the connection/link ID
    pub fn id(&self) -> &LinkId {
        &self.link_id
    }

    /// Get the destination hash
    pub fn destination_hash(&self) -> &DestinationHash {
        &self.destination_hash
    }

    /// Check if we initiated this connection
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Check if compression is enabled
    pub fn compression_enabled(&self) -> bool {
        self.compression_enabled
    }

    /// Enable or disable compression for this connection
    pub fn set_compression(&mut self, enabled: bool) {
        self.compression_enabled = enabled;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_new() {
        let link_id = LinkId::new([0x42; 16]);
        let dest_hash = DestinationHash::new([0x33; 16]);

        let conn = Connection::new(link_id, dest_hash, true);

        assert_eq!(*conn.id(), link_id);
        assert_eq!(*conn.destination_hash(), dest_hash);
        assert!(conn.is_initiator());
        assert!(!conn.compression_enabled());
    }

    #[test]
    fn test_connection_compression_toggle() {
        let mut conn = Connection::new(LinkId::new([0; 16]), DestinationHash::new([0; 16]), false);

        assert!(!conn.compression_enabled());

        conn.set_compression(true);
        assert!(conn.compression_enabled());

        conn.set_compression(false);
        assert!(!conn.compression_enabled());
    }

    #[test]
    fn test_connection_error_from_link_error() {
        let err: ConnectionError = LinkError::InvalidState.into();
        assert_eq!(err, ConnectionError::LinkError(LinkError::InvalidState));
    }

    #[test]
    fn test_connection_error_from_channel_error() {
        let err: ConnectionError = ChannelError::WindowFull.into();
        assert_eq!(err, ConnectionError::ChannelError(ChannelError::WindowFull));
    }
}
