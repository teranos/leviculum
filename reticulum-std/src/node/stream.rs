//! Async stream wrapper for Connections
//!
//! Provides AsyncRead/AsyncWrite implementations for Connection.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use reticulum_core::link::LinkId;

/// Async stream wrapper around a Connection
///
/// ConnectionStream provides async read/write operations for a connection.
/// It implements tokio's AsyncRead and AsyncWrite traits.
///
/// # Example
///
/// ```no_run
/// # use reticulum_std::node::{ReticulumNodeBuilder, ConnectionStream};
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let node = ReticulumNodeBuilder::new().build().await?;
/// # let dest_hash = reticulum_core::DestinationHash::new([0; 16]);
/// # let signing_key = [0u8; 32];
/// let (mut stream, packet) = node.connect(&dest_hash, &signing_key).await?;
///
/// // Write data
/// stream.send(b"Hello!").await?;
///
/// // Read response
/// if let Some(data) = stream.recv().await? {
///     println!("Received {} bytes", data.len());
/// }
/// # Ok(())
/// # }
/// ```
pub struct ConnectionStream {
    /// Link ID for this connection
    link_id: LinkId,
    /// Channel for outgoing data
    outgoing_tx: mpsc::Sender<Vec<u8>>,
    /// Channel for incoming data
    incoming_rx: mpsc::Receiver<Vec<u8>>,
    /// Buffer for partial reads
    read_buffer: Vec<u8>,
    /// Current position in read buffer
    read_pos: usize,
    /// Whether the stream is closed
    closed: bool,
}

impl ConnectionStream {
    /// Create a new ConnectionStream
    pub(crate) fn new(
        link_id: LinkId,
        outgoing_tx: mpsc::Sender<Vec<u8>>,
        incoming_rx: mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            link_id,
            outgoing_tx,
            incoming_rx,
            read_buffer: Vec::new(),
            read_pos: 0,
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
            .send(data.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "send channel closed"))
    }

    /// Receive data from this connection
    ///
    /// This is a convenience method that doesn't require polling.
    /// Returns None if the connection is closed.
    pub async fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.closed {
            return Ok(None);
        }

        match self.incoming_rx.recv().await {
            Some(data) => Ok(Some(data)),
            None => {
                self.closed = true;
                Ok(None)
            }
        }
    }

    /// Close the stream
    pub fn close(&mut self) {
        self.closed = true;
    }
}

impl AsyncRead for ConnectionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // If we have buffered data, return it first
        if self.read_pos < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;

            // Clear buffer if fully consumed
            if self.read_pos >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_pos = 0;
            }

            return Poll::Ready(Ok(()));
        }

        if self.closed {
            return Poll::Ready(Ok(())); // EOF
        }

        // Try to receive more data
        match Pin::new(&mut self.incoming_rx).poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);

                // Buffer remaining if any
                if to_copy < data.len() {
                    self.read_buffer = data;
                    self.read_pos = to_copy;
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                self.closed = true;
                Poll::Ready(Ok(())) // EOF
            }
            Poll::Pending => Poll::Pending,
        }
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
                // Try to send
                match self.outgoing_tx.try_send(buf.to_vec()) {
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
    async fn test_connection_stream_send_recv() {
        let link_id = [0u8; 16];
        let (out_tx, mut out_rx) = mpsc::channel(16);
        let (in_tx, in_rx) = mpsc::channel(16);

        let mut stream = ConnectionStream::new(link_id.into(), out_tx, in_rx);

        // Test send
        stream.send(b"hello").await.unwrap();
        let sent = out_rx.recv().await.unwrap();
        assert_eq!(sent, b"hello");

        // Test recv
        in_tx.send(b"world".to_vec()).await.unwrap();
        let received = stream.recv().await.unwrap().unwrap();
        assert_eq!(received, b"world");
    }

    #[tokio::test]
    async fn test_connection_stream_close() {
        let link_id = [0u8; 16];
        let (out_tx, _out_rx) = mpsc::channel(16);
        let (_in_tx, in_rx) = mpsc::channel(16);

        let mut stream = ConnectionStream::new(link_id.into(), out_tx, in_rx);

        assert!(!stream.is_closed());
        stream.close();
        assert!(stream.is_closed());

        // Send should fail after close
        let result = stream.send(b"test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connection_stream_recv_closed() {
        let link_id = [0u8; 16];
        let (out_tx, _out_rx) = mpsc::channel(16);
        let (in_tx, in_rx) = mpsc::channel(16);

        let mut stream = ConnectionStream::new(link_id.into(), out_tx, in_rx);

        // Drop sender to close channel
        drop(in_tx);

        // Recv should return None
        let result = stream.recv().await.unwrap();
        assert!(result.is_none());
        assert!(stream.is_closed());
    }
}
