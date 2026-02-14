//! Send-only async stream wrapper for Connections
//!
//! Locks the core directly and dispatches actions through the event loop,
//! matching the pattern used by `PacketEndpoint`. This ensures that
//! `send()` returns the real result from `send_on_connection()` — including
//! `WindowFull` — instead of silently buffering through an mpsc channel.

use std::io;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use reticulum_core::link::LinkId;
use reticulum_core::transport::TickOutput;
use reticulum_core::SendError;

use super::StdNodeCore;

/// Async stream wrapper around a Connection (send-only)
///
/// `ConnectionStream` provides async write operations for a connection.
/// It locks the core directly for each send, ensuring the caller sees
/// the real result (including `WindowFull` mapped to `WouldBlock`).
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
    /// Shared handle to the core node
    inner: Arc<Mutex<StdNodeCore>>,
    /// Channel for dispatching actions to the event loop
    action_dispatch_tx: mpsc::Sender<TickOutput>,
    /// Whether the stream is closed
    closed: bool,
}

impl ConnectionStream {
    /// Create a new ConnectionStream
    pub(crate) fn new(
        link_id: LinkId,
        inner: Arc<Mutex<StdNodeCore>>,
        action_dispatch_tx: mpsc::Sender<TickOutput>,
    ) -> Self {
        Self {
            link_id,
            inner,
            action_dispatch_tx,
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
    /// Locks the core, calls `send_on_connection()`, and dispatches the
    /// resulting actions. Returns `WouldBlock` if the channel window is full
    /// or pacing delay is active.
    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream closed"));
        }

        let output = {
            let mut core = self.inner.lock().unwrap();
            core.send_on_connection(&self.link_id, data)
                .map_err(|e| match e {
                    SendError::WindowFull => {
                        io::Error::new(io::ErrorKind::WouldBlock, "channel window full")
                    }
                    SendError::PacingDelay { .. } => {
                        io::Error::new(io::ErrorKind::WouldBlock, "channel pacing delay")
                    }
                    SendError::NoConnection => {
                        io::Error::new(io::ErrorKind::NotConnected, "no connection")
                    }
                    other => io::Error::other(other.to_string()),
                })?
        };

        self.action_dispatch_tx
            .send(output)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "event loop shut down"))?;
        Ok(())
    }

    /// Send data on this connection, absorbing pacing delays and window-full
    ///
    /// Unlike `send()`, this method retries automatically when the channel
    /// reports a pacing delay or window-full condition, sleeping until ready.
    /// Only returns an error on fatal conditions (connection lost, stream closed).
    pub async fn send_bytes(&self, data: &[u8]) -> io::Result<()> {
        loop {
            if self.closed {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream closed"));
            }

            let result = {
                let mut core = self.inner.lock().unwrap();
                core.send_on_connection(&self.link_id, data)
            };

            match result {
                Ok(output) => {
                    self.action_dispatch_tx.send(output).await.map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "event loop shut down")
                    })?;
                    return Ok(());
                }
                Err(SendError::PacingDelay { ready_at_ms }) => {
                    let now_ms = self.inner.lock().unwrap().now_ms();
                    let delay = ready_at_ms.saturating_sub(now_ms);
                    if delay > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    }
                }
                Err(SendError::WindowFull) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(SendError::NoConnection) => {
                    return Err(io::Error::new(io::ErrorKind::NotConnected, "no connection"));
                }
                Err(other) => {
                    return Err(io::Error::other(other.to_string()));
                }
            }
        }
    }

    /// Close the stream gracefully, sending LINKCLOSE to the peer
    pub async fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;

        let output = {
            let mut core = self.inner.lock().unwrap();
            core.close_connection(&self.link_id)
        };

        self.action_dispatch_tx
            .send(output)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "event loop shut down"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::ReticulumNodeBuilder;

    fn make_node_and_inner() -> (
        Arc<Mutex<StdNodeCore>>,
        mpsc::Sender<TickOutput>,
        mpsc::Receiver<TickOutput>,
    ) {
        let node = ReticulumNodeBuilder::new()
            .build_sync()
            .expect("build_sync");
        let inner = node.inner();
        let (tx, rx) = mpsc::channel(16);
        (inner, tx, rx)
    }

    #[tokio::test]
    async fn test_connection_stream_send_no_connection() {
        let (inner, tx, _rx) = make_node_and_inner();
        let link_id = LinkId::from([0u8; 16]);

        let stream = ConnectionStream::new(link_id, inner, tx);

        // Sending on a non-existent connection should return NotConnected
        let result = stream.send(b"hello").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotConnected);
    }

    #[tokio::test]
    async fn test_connection_stream_close() {
        let (inner, tx, _rx) = make_node_and_inner();
        let link_id = LinkId::from([0u8; 16]);

        let mut stream = ConnectionStream::new(link_id, inner, tx);

        assert!(!stream.is_closed());
        // close_connection on a non-existent link is harmless (returns empty output)
        stream.close().await.unwrap();
        assert!(stream.is_closed());

        // Send should fail after close
        let result = stream.send(b"test").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn test_connection_stream_close_idempotent() {
        let (inner, tx, _rx) = make_node_and_inner();
        let link_id = LinkId::from([0u8; 16]);

        let mut stream = ConnectionStream::new(link_id, inner, tx);

        stream.close().await.unwrap();
        // Second close is a no-op
        stream.close().await.unwrap();
        assert!(stream.is_closed());
    }

    #[tokio::test]
    async fn test_connection_stream_send_closed_dispatch_channel() {
        let (inner, _, _) = make_node_and_inner();
        let link_id = LinkId::from([0u8; 16]);

        // Create with a channel whose receiver is dropped
        let (tx, rx) = mpsc::channel::<TickOutput>(1);
        drop(rx);

        let stream = ConnectionStream::new(link_id, inner, tx);

        // Send fails because there's no connection, so dispatch channel
        // closure is not reached — but NotConnected is returned first
        let result = stream.send(b"hello").await;
        assert!(result.is_err());
    }
}
