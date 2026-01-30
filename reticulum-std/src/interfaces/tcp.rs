//! TCP client interface
//!
//! Connects to a Reticulum TCP server (e.g. rnsd TCPServerInterface)
//! and implements the core `Interface` trait for use with Transport.
//!
//! Uses HDLC framing to delimit packets on the TCP stream,
//! matching Python Reticulum's `TCPClientInterface`.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use reticulum_core::constants::{MTU, TRUNCATED_HASHBYTES};
use reticulum_core::crypto::truncated_hash;
use reticulum_core::framing::hdlc::{frame, Deframer, DeframeResult};
use reticulum_core::traits::{Interface, InterfaceError, InterfaceMode};

/// TCP client interface connecting to a Reticulum TCP server
pub struct TcpClientInterface {
    /// Human-readable name
    name: String,
    /// Unique hash for routing
    hash: [u8; TRUNCATED_HASHBYTES],
    /// TCP connection
    stream: TcpStream,
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

        let stream = TcpStream::connect_timeout(&addr, connect_timeout)?;
        stream.set_nonblocking(true)?;
        stream.set_nodelay(true)?;

        // Compute interface hash from name
        let hash = truncated_hash(name.as_bytes());

        Ok(Self {
            name: name.to_string(),
            hash,
            stream,
            deframer: Deframer::new(),
            recv_queue: VecDeque::new(),
            frame_buf: Vec::with_capacity(MTU * 2),
            read_buf: vec![0u8; MTU * 4],
            online: true,
        })
    }

    /// Try to dequeue a packet from the receive queue into the provided buffer.
    /// Returns Some(Ok(len)) if a packet was dequeued, Some(Err) on error, None if queue is empty.
    fn try_dequeue(&mut self, buf: &mut [u8]) -> Option<Result<usize, InterfaceError>> {
        let packet = self.recv_queue.pop_front()?;
        if packet.len() > buf.len() {
            return Some(Err(InterfaceError::BufferTooSmall));
        }
        buf[..packet.len()].copy_from_slice(&packet);
        Some(Ok(packet.len()))
    }

    /// Try to read from the socket and deframe any complete packets
    fn poll_read(&mut self) {
        loop {
            match self.stream.read(&mut self.read_buf) {
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

        match self.stream.write_all(&self.frame_buf) {
            Ok(()) => Ok(()),
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
        if let Some(result) = self.try_dequeue(buf) {
            return result;
        }

        // Try to read more from the socket
        self.poll_read();

        // Check again after reading
        self.try_dequeue(buf).unwrap_or(Err(InterfaceError::WouldBlock))
    }

    fn is_online(&self) -> bool {
        self.online
    }

    fn mode(&self) -> InterfaceMode {
        InterfaceMode::default()
    }

    fn down(&mut self) -> Result<(), InterfaceError> {
        self.online = false;
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_interface_connect_refused() {
        // Connecting to a port with nothing listening should fail
        let result = TcpClientInterface::connect(
            "test",
            "127.0.0.1:19999",
            Duration::from_millis(500),
        );
        assert!(result.is_err());
    }

    // Integration tests for TcpClientInterface are in tests/rnsd_interop/
    // using the TestDaemon infrastructure which auto-spawns a Python daemon.
}
