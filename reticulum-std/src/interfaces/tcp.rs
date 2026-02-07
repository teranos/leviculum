//! TCP client interface
//!
//! Connects to a Reticulum TCP server (e.g. rnsd TCPServerInterface)
//! and implements the core `Interface` trait for use with Transport.
//!
//! Uses HDLC framing to delimit packets on the TCP stream,
//! matching Python Reticulum's `TCPClientInterface`.

use std::collections::VecDeque;
use std::io;
use std::net::ToSocketAddrs;
use std::task::{Context, Poll};
use std::time::Duration;

use reticulum_core::constants::{MTU, TRUNCATED_HASHBYTES};
use reticulum_core::crypto::truncated_hash;
use reticulum_core::framing::hdlc::{frame, DeframeResult, Deframer};
use reticulum_core::traits::{Interface, InterfaceError, InterfaceMode};

/// Frame buffer multiplier (accounts for HDLC escaping overhead)
const FRAME_BUFFER_MULTIPLIER: usize = 2;

/// Read buffer multiplier (handles multiple packets per read)
const READ_BUFFER_MULTIPLIER: usize = 4;

/// TCP client interface connecting to a Reticulum TCP server
pub struct TcpClientInterface {
    /// Human-readable name
    name: String,
    /// Unique hash for routing
    hash: [u8; TRUNCATED_HASHBYTES],
    /// TCP connection (tokio async stream)
    stream: tokio::net::TcpStream,
    /// HDLC deframer for incoming data
    deframer: Deframer,
    /// Queue of complete deframed packets waiting to be returned by recv()
    recv_queue: VecDeque<Vec<u8>>,
    /// Reusable buffer for framing outgoing data
    frame_buf: Vec<u8>,
    /// Reusable buffer for reading from socket
    read_buf: Vec<u8>,
    /// Whether the connection is alive
    online: bool,
}

impl TcpClientInterface {
    /// Connect to a TCP server
    ///
    /// Uses a synchronous connect with timeout, then converts to tokio TcpStream.
    /// This keeps construction synchronous for compatibility with the existing
    /// `initialize_interfaces` flow and interop tests.
    ///
    /// # Arguments
    /// * `name` - Human-readable name for logging
    /// * `addr` - Socket address to connect to (e.g. "127.0.0.1:4242")
    /// * `connect_timeout` - Timeout for the initial connection
    pub fn connect<A: ToSocketAddrs>(
        name: &str,
        addr: A,
        connect_timeout: Duration,
    ) -> Result<Self, io::Error> {
        // Resolve address
        let addr = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no addresses found"))?;

        // Use std connect_timeout, then convert to tokio
        let std_stream = std::net::TcpStream::connect_timeout(&addr, connect_timeout)?;
        std_stream.set_nonblocking(true)?;
        std_stream.set_nodelay(true)?;
        let stream = tokio::net::TcpStream::from_std(std_stream)?;

        // Compute interface hash from name
        let hash = truncated_hash(name.as_bytes());

        Ok(Self {
            name: name.to_string(),
            hash,
            stream,
            deframer: Deframer::new(),
            recv_queue: VecDeque::new(),
            frame_buf: Vec::with_capacity(MTU * FRAME_BUFFER_MULTIPLIER),
            read_buf: vec![0u8; MTU * READ_BUFFER_MULTIPLIER],
            online: true,
        })
    }

    /// Create from an already-connected TCP stream (e.g. from `TcpListener::accept()`)
    ///
    /// Sets the stream to non-blocking mode and enables TCP_NODELAY,
    /// then converts to a tokio TcpStream.
    ///
    /// # Arguments
    /// * `name` - Human-readable name for logging
    /// * `stream` - An already-connected `std::net::TcpStream`
    pub fn from_stream(name: &str, stream: std::net::TcpStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        stream.set_nodelay(true)?;
        let stream = tokio::net::TcpStream::from_std(stream)?;
        let hash = truncated_hash(name.as_bytes());
        Ok(Self {
            name: name.to_string(),
            hash,
            stream,
            deframer: Deframer::new(),
            recv_queue: VecDeque::new(),
            frame_buf: Vec::with_capacity(MTU * FRAME_BUFFER_MULTIPLIER),
            read_buf: vec![0u8; MTU * READ_BUFFER_MULTIPLIER],
            online: true,
        })
    }

    /// Try to read from the socket using non-blocking try_read and deframe packets
    fn poll_read_sync(&mut self) {
        loop {
            match self.stream.try_read(&mut self.read_buf) {
                Ok(0) => {
                    // Connection closed
                    self.online = false;
                    break;
                }
                Ok(n) => {
                    let results = self.deframer.process(&self.read_buf[..n]);
                    for result in results {
                        if let DeframeResult::Frame(data) = result {
                            self.recv_queue.push_back(data);
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break; // No more data available
                }
                Err(_) => {
                    self.online = false;
                    break;
                }
            }
        }
    }

    /// Poll for the next complete deframed packet (async)
    ///
    /// Registers waker with tokio for socket readability. Returns `Poll::Ready`
    /// when a complete HDLC frame is available, or `Poll::Pending` if the socket
    /// has no data yet.
    pub fn poll_recv_packet(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Vec<u8>, InterfaceError>> {
        // Return queued frame immediately
        if let Some(frame) = self.recv_queue.pop_front() {
            return Poll::Ready(Ok(frame));
        }
        if !self.online {
            return Poll::Ready(Err(InterfaceError::Disconnected));
        }
        // Poll socket readability, read + deframe
        loop {
            match self.stream.poll_read_ready(cx) {
                Poll::Ready(Ok(())) => {
                    match self.stream.try_read(&mut self.read_buf) {
                        Ok(0) => {
                            self.online = false;
                            return Poll::Ready(Err(InterfaceError::Disconnected));
                        }
                        Ok(n) => {
                            let results = self.deframer.process(&self.read_buf[..n]);
                            for r in results {
                                if let DeframeResult::Frame(data) = r {
                                    self.recv_queue.push_back(data);
                                }
                            }
                            if let Some(frame) = self.recv_queue.pop_front() {
                                return Poll::Ready(Ok(frame));
                            }
                            // Got bytes but no complete frame — try reading more
                            continue;
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            // Socket not actually ready — loop back to
                            // poll_read_ready to register waker for next
                            // readiness notification (required by tokio's
                            // edge-triggered I/O model).
                            continue;
                        }
                        Err(_) => {
                            self.online = false;
                            return Poll::Ready(Err(InterfaceError::Disconnected));
                        }
                    }
                }
                Poll::Ready(Err(_)) => {
                    self.online = false;
                    return Poll::Ready(Err(InterfaceError::Disconnected));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Interface for TcpClientInterface {
    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> usize {
        MTU
    }

    fn hash(&self) -> [u8; TRUNCATED_HASHBYTES] {
        self.hash
    }

    fn send(&mut self, data: &[u8]) -> Result<(), InterfaceError> {
        if !self.online {
            return Err(InterfaceError::Disconnected);
        }

        frame(data, &mut self.frame_buf);

        match self.stream.try_write(&self.frame_buf) {
            Ok(n) if n == self.frame_buf.len() => Ok(()),
            Ok(_) => Err(InterfaceError::WouldBlock), // Partial write
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Err(InterfaceError::WouldBlock),
            Err(_) => {
                self.online = false;
                Err(InterfaceError::Disconnected)
            }
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, InterfaceError> {
        if !self.online {
            return Err(InterfaceError::Disconnected);
        }

        // If we have queued packets, return the first one
        if let Some(packet) = self.recv_queue.pop_front() {
            if packet.len() > buf.len() {
                return Err(InterfaceError::BufferTooSmall);
            }
            buf[..packet.len()].copy_from_slice(&packet);
            return Ok(packet.len());
        }

        // Try to read more from the socket (non-blocking)
        self.poll_read_sync();

        // Check again after reading
        if let Some(packet) = self.recv_queue.pop_front() {
            if packet.len() > buf.len() {
                return Err(InterfaceError::BufferTooSmall);
            }
            buf[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        } else {
            Err(InterfaceError::WouldBlock)
        }
    }

    fn is_online(&self) -> bool {
        self.online
    }

    fn mode(&self) -> InterfaceMode {
        InterfaceMode::default()
    }

    fn down(&mut self) -> Result<(), InterfaceError> {
        self.online = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_interface_connect_refused() {
        // Connecting to a port with nothing listening should fail
        let result =
            TcpClientInterface::connect("test", "127.0.0.1:19999", Duration::from_millis(500));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_from_stream() {
        // Start a listener, connect, then wrap the accepted stream
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let client = std::net::TcpStream::connect(addr).unwrap();
        let (server_stream, _peer) = listener.accept().unwrap();

        let iface = TcpClientInterface::from_stream("test_server", server_stream).unwrap();
        assert!(iface.is_online());
        assert_eq!(iface.name(), "test_server");

        // Verify the client connection is alive
        drop(client);
    }

    // Integration tests for TcpClientInterface are in tests/rnsd_interop/
    // using the TestDaemon infrastructure which auto-spawns a Python daemon.
}
