//! Send-only async handle for Links
//!
//! Locks the core directly and dispatches actions through the event loop,
//! matching the pattern used by `PacketSender`. This ensures that
//! `send()` returns the real result from `send_on_link()` — including
//! `WindowFull` — instead of silently buffering through an mpsc channel.

use std::io;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use reticulum_core::link::LinkId;
use reticulum_core::transport::TickOutput;
use reticulum_core::SendError;

use super::StdNodeCore;

/// Async handle for a Link (send-only)
///
/// `LinkHandle` provides async write operations for a link.
/// It locks the core directly for each send, ensuring the caller sees
/// the real result (including `WindowFull` mapped to `WouldBlock`).
///
/// Incoming data is delivered via `NodeEvent::LinkDataReceived` /
/// `NodeEvent::MessageReceived` on the node's event channel.
///
/// # Example
///
/// ```no_run
/// # use reticulum_std::driver::{ReticulumNodeBuilder, LinkHandle};
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let node = ReticulumNodeBuilder::new().build().await?;
/// # let dest_hash = reticulum_core::DestinationHash::new([0; 16]);
/// # let signing_key = [0u8; 32];
/// let handle = node.connect(&dest_hash, &signing_key).await?;
///
/// // Write data
/// handle.send(b"Hello!").await?;
///
/// // Read responses via node.take_event_receiver()
/// # Ok(())
/// # }
/// ```
pub struct LinkHandle {
    /// Link ID for this link
    link_id: LinkId,
    /// Shared handle to the core node
    inner: Arc<Mutex<StdNodeCore>>,
    /// Channel for dispatching actions to the event loop
    action_dispatch_tx: mpsc::Sender<TickOutput>,
    /// Whether the handle is closed
    closed: bool,
}

impl LinkHandle {
    /// Create a new LinkHandle
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

    /// Get the link ID
    pub fn link_id(&self) -> &LinkId {
        &self.link_id
    }

    /// Check if the handle is closed
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Try to send data on this link (non-blocking)
    ///
    /// Locks the core, calls `send_on_link()`, and dispatches the
    /// resulting actions. Returns `WouldBlock` if the channel window is full
    /// or pacing delay is active.
    pub async fn try_send(&self, data: &[u8]) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream closed"));
        }

        let output = {
            let mut core = self.inner.lock().unwrap();
            core.send_on_link(&self.link_id, data)
                .map_err(|e| match e {
                    SendError::WindowFull => {
                        io::Error::new(io::ErrorKind::WouldBlock, "channel window full")
                    }
                    SendError::PacingDelay { .. } => {
                        io::Error::new(io::ErrorKind::WouldBlock, "channel pacing delay")
                    }
                    SendError::NoLink => io::Error::new(io::ErrorKind::NotConnected, "no link"),
                    other => io::Error::other(other.to_string()),
                })?
        };

        self.action_dispatch_tx
            .send(output)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "event loop shut down"))?;
        Ok(())
    }

    /// Send data on this link, absorbing pacing delays and window-full
    ///
    /// Unlike `try_send()`, this method retries automatically when the channel
    /// reports a pacing delay or window-full condition, sleeping until ready.
    /// Only returns an error on fatal conditions (link lost, handle closed).
    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        loop {
            if self.closed {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream closed"));
            }

            let result = {
                let mut core = self.inner.lock().unwrap();
                core.send_on_link(&self.link_id, data)
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
                Err(SendError::NoLink) => {
                    return Err(io::Error::new(io::ErrorKind::NotConnected, "no link"));
                }
                Err(other) => {
                    return Err(io::Error::other(other.to_string()));
                }
            }
        }
    }

    /// Close the link gracefully, sending LINKCLOSE to the peer
    pub async fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;

        let output = {
            let mut core = self.inner.lock().unwrap();
            core.close_link(&self.link_id)
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
    async fn test_link_handle_send_no_link() {
        let (inner, tx, _rx) = make_node_and_inner();
        let link_id = LinkId::from([0u8; 16]);

        let handle = LinkHandle::new(link_id, inner, tx);

        // Sending on a non-existent link should return NotConnected
        let result = handle.try_send(b"hello").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotConnected);
    }

    #[tokio::test]
    async fn test_link_handle_close() {
        let (inner, tx, _rx) = make_node_and_inner();
        let link_id = LinkId::from([0u8; 16]);

        let mut handle = LinkHandle::new(link_id, inner, tx);

        assert!(!handle.is_closed());
        // close_link on a non-existent link is harmless (returns empty output)
        handle.close().await.unwrap();
        assert!(handle.is_closed());

        // Send should fail after close
        let result = handle.try_send(b"test").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn test_link_handle_close_idempotent() {
        let (inner, tx, _rx) = make_node_and_inner();
        let link_id = LinkId::from([0u8; 16]);

        let mut handle = LinkHandle::new(link_id, inner, tx);

        handle.close().await.unwrap();
        // Second close is a no-op
        handle.close().await.unwrap();
        assert!(handle.is_closed());
    }

    #[tokio::test]
    async fn test_link_handle_send_closed_dispatch_channel() {
        let (inner, _, _) = make_node_and_inner();
        let link_id = LinkId::from([0u8; 16]);

        // Create with a channel whose receiver is dropped
        let (tx, rx) = mpsc::channel::<TickOutput>(1);
        drop(rx);

        let handle = LinkHandle::new(link_id, inner, tx);

        // Send fails because there's no link, so dispatch channel
        // closure is not reached — but NotConnected is returned first
        let result = handle.try_send(b"hello").await;
        assert!(result.is_err());
    }
}
