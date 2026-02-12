//! Send-only async stream wrapper for Connections
//!
//! Provides AsyncWrite implementation for Connection. Data received on a
//! connection is delivered exclusively via `NodeEvent` (DataReceived /
//! MessageReceived) on the event channel — there is no per-stream incoming
//! path.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;
use tokio::sync::mpsc;

use reticulum_core::link::LinkId;

/// Async stream wrapper around a Connection (send-only)
///
/// ConnectionStream provides async write operations for a connection.
/// It implements tokio's AsyncWrite trait.
///
/// All outgoing data is tagged with the stream's `LinkId` and sent through
/// a shared channel back to the event loop, which dispatches it to the
/// appropriate link via `NodeCore::send_on_connection()`.
///
/// Incoming data is delivered via `NodeEvent::DataReceived` /
/// `NodeEvent::MessageReceived` on the node's event channel.
///
/// # Example
///
/// ```no_run
/// # use reticulum_std::driver::{ReticulumNodeBuilder, ConnectionStream};
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let node = ReticulumNodeBuilder::new().build().await?;
/// # let dest_hash = reticulum_core::DestinationHash::new([0; 16]);
/// # let signing_key = [0u8; 32];
/// let stream = node.connect(&dest_hash, &signing_key).await?;
///
/// // Write data
/// stream.send(b"Hello!").await?;
///
/// // Read responses via node.take_event_receiver()
/// # Ok(())
/// # }
/// ```
pub struct ConnectionStream {
    /// Link ID for this connection
    link_id: LinkId,
    /// Channel for outgoing data (shared, tagged with LinkId)
    outgoing_tx: mpsc::Sender<(LinkId, Vec<u8>)>,
    /// Whether the stream is closed
    closed: bool,
}

impl ConnectionStream {
    /// Create a new ConnectionStream
    pub(crate) fn new(link_id: LinkId, outgoing_tx: mpsc::Sender<(LinkId, Vec<u8>)>) -> Self {
        Self {
            link_id,
            outgoing_tx,
            closed: false,
        }
    }

    /// Get the link ID for this connection
    pub fn link_id(&self) -> &LinkId {
        &self.link_id
    }

    /// Check if the stream is closed
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Send data on this connection
    ///
    /// This is a convenience method that doesn't require polling.
    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream closed"));
        }

        self.outgoing_tx
            .send((self.link_id, data.to_vec()))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "send channel closed"))
    }

    /// Close the stream gracefully, sending LINKCLOSE to the peer
    pub async fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        // Signal close through outgoing channel (empty data = close)
        let _ = self.outgoing_tx.send((self.link_id, vec![])).await;
        Ok(())
    }
}

impl AsyncWrite for ConnectionStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }

        // Check if the channel is ready to send
        match self.outgoing_tx.capacity() {
            0 => {
                // Channel full, need to wait
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            _ => {
                // Try to send (tagged with LinkId)
                match self.outgoing_tx.try_send((self.link_id, buf.to_vec())) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "send channel closed",
                    ))),
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // No buffering at this level - data is sent immediately
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_stream_send() {
        let link_id = [0u8; 16];
        let (out_tx, mut out_rx) = mpsc::channel(16);

        let stream = ConnectionStream::new(link_id.into(), out_tx);

        // Test send
        stream.send(b"hello").await.unwrap();
        let (recv_link_id, sent) = out_rx.recv().await.unwrap();
        assert_eq!(recv_link_id, LinkId::from(link_id));
        assert_eq!(sent, b"hello");
    }

    #[tokio::test]
    async fn test_connection_stream_close() {
        let link_id = [0u8; 16];
        let (out_tx, mut out_rx) = mpsc::channel(16);

        let mut stream = ConnectionStream::new(link_id.into(), out_tx);

        assert!(!stream.is_closed());
        stream.close().await.unwrap();
        assert!(stream.is_closed());

        // Close should have sent an empty-data sentinel
        let (recv_link_id, data) = out_rx.recv().await.unwrap();
        assert_eq!(recv_link_id, LinkId::from(link_id));
        assert!(data.is_empty());

        // Send should fail after close
        let result = stream.send(b"test").await;
        assert!(result.is_err());
    }
}
