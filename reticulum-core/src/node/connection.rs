//! Connection abstraction - wraps Link + Channel for unified data transfer
//!
//! A [`Connection`] represents an established, verified communication channel
//! between two nodes. It provides a higher-level API over the raw Link and
//! Channel primitives.

use alloc::vec::Vec;

use crate::destination::DestinationHash;
use crate::link::channel::{Channel, ChannelError, Message};
use crate::link::{Link, LinkError, LinkId, LinkState};
use crate::packet::PacketContext;
use crate::traits::{Clock, Context};

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

/// A connection represents an established Link with optional Channel
///
/// Connections provide a unified interface for sending and receiving data
/// over verified, encrypted links. They can operate in two modes:
///
/// 1. **Raw mode**: Direct Link data transfer (unreliable, unordered)
/// 2. **Channel mode**: Reliable, ordered message delivery with automatic retries
///
/// # Example
///
/// ```ignore
/// // Send a message on a connection
/// let packet_data = connection.send(&mut ctx, b"Hello!")?;
/// // Send packet_data over the network...
///
/// // Send a typed message via Channel
/// let packet_data = connection.send_message(&mut ctx, &my_message)?;
/// ```
pub struct Connection {
    /// The underlying link ID
    link_id: LinkId,
    /// The destination hash this connection is to
    destination_hash: DestinationHash,
    /// Whether we initiated this connection
    is_initiator: bool,
    /// Optional channel for reliable messaging (lazily created)
    channel: Option<Channel>,
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
    pub fn new(
        link_id: LinkId,
        destination_hash: DestinationHash,
        is_initiator: bool,
    ) -> Self {
        Self {
            link_id,
            destination_hash,
            is_initiator,
            channel: None,
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

    /// Check if this connection has an active channel
    pub fn has_channel(&self) -> bool {
        self.channel.is_some()
    }

    /// Get the channel, creating it if necessary
    ///
    /// # Arguments
    /// * `rtt_ms` - The link's round-trip time in milliseconds (for window sizing)
    pub fn get_or_create_channel(&mut self, rtt_ms: u64) -> &mut Channel {
        self.channel.get_or_insert_with(|| {
            let mut channel = Channel::new();
            channel.update_window_for_rtt(rtt_ms);
            channel
        })
    }

    /// Get a mutable reference to the channel if it exists
    pub fn channel_mut(&mut self) -> Option<&mut Channel> {
        self.channel.as_mut()
    }

    /// Send raw data on this connection (without Channel framing)
    ///
    /// This encrypts the data and returns the packet bytes to send.
    /// The data is sent without reliability guarantees.
    ///
    /// # Arguments
    /// * `link` - The underlying link (for encryption)
    /// * `data` - The plaintext data to send
    /// * `ctx` - Platform context for RNG
    ///
    /// # Returns
    /// The encrypted packet bytes ready for transmission
    pub fn send_raw(
        &self,
        link: &Link,
        data: &[u8],
        ctx: &mut impl Context,
    ) -> Result<Vec<u8>, ConnectionError> {
        if link.state() != LinkState::Active {
            return Err(ConnectionError::InvalidState);
        }
        link.build_data_packet(data, ctx).map_err(Into::into)
    }

    /// Send a typed message on this connection via Channel
    ///
    /// This provides reliable, ordered delivery with automatic retries.
    ///
    /// # Arguments
    /// * `link` - The underlying link (for encryption and MDU)
    /// * `message` - The message to send
    /// * `ctx` - Platform context
    ///
    /// # Returns
    /// The encrypted packet bytes ready for transmission
    pub fn send_message<M: Message>(
        &mut self,
        link: &Link,
        message: &M,
        ctx: &mut impl Context,
    ) -> Result<Vec<u8>, ConnectionError> {
        if link.state() != LinkState::Active {
            return Err(ConnectionError::InvalidState);
        }

        let link_mdu = link.mdu();
        let rtt_ms = link.rtt_ms();
        let now_ms = ctx.clock().now_ms();

        // Get or create channel
        let channel = self.get_or_create_channel(rtt_ms);

        // Send through channel to get envelope data
        let envelope_data = channel.send(message, link_mdu, now_ms, rtt_ms)?;

        // Build data packet with Channel context
        link.build_data_packet_with_context(&envelope_data, PacketContext::Channel, ctx)
            .map_err(Into::into)
    }

    /// Send raw bytes as a channel message
    ///
    /// This wraps raw bytes in a simple message type for reliable delivery.
    ///
    /// # Arguments
    /// * `link` - The underlying link
    /// * `data` - The raw bytes to send
    /// * `ctx` - Platform context
    pub fn send_bytes(
        &mut self,
        link: &Link,
        data: &[u8],
        ctx: &mut impl Context,
    ) -> Result<Vec<u8>, ConnectionError> {
        self.send_message(link, &RawBytesMessage(data.to_vec()), ctx)
    }

    /// Check if the channel is ready to send more messages
    ///
    /// Returns false if the send window is full.
    pub fn is_ready_to_send(&self) -> bool {
        self.channel
            .as_ref()
            .map(|c| c.is_ready_to_send())
            .unwrap_or(true)
    }

    /// Get the number of outstanding (unacknowledged) messages
    pub fn outstanding_messages(&self) -> usize {
        self.channel.as_ref().map(|c| c.outstanding()).unwrap_or(0)
    }

    /// Receive a typed message from decrypted channel data
    ///
    /// This is the symmetric counterpart to `send_message<M>()`.
    ///
    /// # Arguments
    /// * `rtt_ms` - The link's round-trip time (for channel window sizing)
    /// * `decrypted_data` - The decrypted envelope data from the link
    ///
    /// # Returns
    /// - `Ok(Some(msg))` if a message was received in sequence
    /// - `Ok(None)` if the message was buffered or was a different type
    /// - `Err(...)` if unpacking failed
    pub fn receive_message<M: Message>(
        &mut self,
        rtt_ms: u64,
        decrypted_data: &[u8],
    ) -> Result<Option<M>, ConnectionError> {
        let channel = self.get_or_create_channel(rtt_ms);
        channel.receive_message::<M>(decrypted_data).map_err(Into::into)
    }

    /// Receive raw bytes from decrypted channel data
    ///
    /// This is the symmetric counterpart to `send_bytes()`.
    ///
    /// # Arguments
    /// * `rtt_ms` - The link's round-trip time
    /// * `decrypted_data` - The decrypted envelope data
    ///
    /// # Returns
    /// The raw bytes if a message was received, or None if buffered
    pub fn receive_bytes(
        &mut self,
        rtt_ms: u64,
        decrypted_data: &[u8],
    ) -> Result<Option<Vec<u8>>, ConnectionError> {
        match self.receive_message::<RawBytesMessage>(rtt_ms, decrypted_data)? {
            Some(msg) => Ok(Some(msg.0)),
            None => Ok(None),
        }
    }

    /// Receive an envelope (for cases where you need to check the message type)
    ///
    /// # Arguments
    /// * `rtt_ms` - The link's round-trip time
    /// * `decrypted_data` - The decrypted envelope data
    ///
    /// # Returns
    /// The envelope if received in sequence, or None if buffered
    pub fn receive_envelope(
        &mut self,
        rtt_ms: u64,
        decrypted_data: &[u8],
    ) -> Result<Option<crate::link::channel::Envelope>, ConnectionError> {
        let channel = self.get_or_create_channel(rtt_ms);
        channel.receive(decrypted_data).map_err(Into::into)
    }
}

/// Simple message type for sending raw bytes over a channel
struct RawBytesMessage(Vec<u8>);

impl Message for RawBytesMessage {
    const MSGTYPE: u16 = 0x0000;

    fn pack(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn unpack(data: &[u8]) -> Result<Self, ChannelError> {
        Ok(Self(data.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_connection_new() {
        let link_id = LinkId::new([0x42; 16]);
        let dest_hash = DestinationHash::new([0x33; 16]);

        let conn = Connection::new(link_id, dest_hash, true);

        assert_eq!(*conn.id(), link_id);
        assert_eq!(*conn.destination_hash(), dest_hash);
        assert!(conn.is_initiator());
        assert!(!conn.has_channel());
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
    fn test_connection_channel_creation() {
        let mut conn = Connection::new(LinkId::new([0; 16]), DestinationHash::new([0; 16]), false);

        assert!(!conn.has_channel());
        assert!(conn.is_ready_to_send());
        assert_eq!(conn.outstanding_messages(), 0);

        // Get or create channel
        let _channel = conn.get_or_create_channel(100);
        assert!(conn.has_channel());
    }

    #[test]
    fn test_raw_bytes_message() {
        let data = vec![1, 2, 3, 4, 5];
        let msg = RawBytesMessage(data.clone());

        assert_eq!(msg.pack(), data);

        let unpacked = RawBytesMessage::unpack(&data).unwrap();
        assert_eq!(unpacked.0, data);
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
