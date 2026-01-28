//! TCP client interface
//!
//! Connects to a Reticulum TCP server (e.g. rnsd TCPServerInterface)
//! and implements the core `Interface` trait for use with Transport.
//!
//! Uses HDLC framing to delimit packets on the TCP stream,
//! matching Python Reticulum's `TCPClientInterface`.

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
    recv_queue: Vec<Vec<u8>>,
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
            recv_queue: Vec::new(),
            frame_buf: Vec::with_capacity(MTU * 2),
            read_buf: vec![0u8; MTU * 4],
            online: true,
        })
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
                            self.recv_queue.push(data);
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
        if !self.recv_queue.is_empty() {
            let packet = self.recv_queue.remove(0);
            if packet.len() > buf.len() {
                return Err(InterfaceError::BufferTooSmall);
            }
            buf[..packet.len()].copy_from_slice(&packet);
            return Ok(packet.len());
        }

        // Try to read more from the socket
        self.poll_read();

        // Check again after reading
        if !self.recv_queue.is_empty() {
            let packet = self.recv_queue.remove(0);
            if packet.len() > buf.len() {
                return Err(InterfaceError::BufferTooSmall);
            }
            buf[..packet.len()].copy_from_slice(&packet);
            return Ok(packet.len());
        }

        Err(InterfaceError::WouldBlock)
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

    #[test]
    #[ignore] // Requires rnsd running on localhost:4242
    fn test_tcp_interface_connect_to_rnsd() {
        let iface = TcpClientInterface::connect(
            "TestTCP",
            "127.0.0.1:4242",
            Duration::from_secs(2),
        )
        .expect("Failed to connect to rnsd");

        assert!(iface.is_online());
        assert_eq!(iface.name(), "TestTCP");
        assert_eq!(iface.mtu(), MTU);
    }

    #[test]
    #[ignore] // Requires rnsd running on localhost:4242
    fn test_tcp_interface_recv_announces() {
        let mut iface = TcpClientInterface::connect(
            "TestTCP",
            "127.0.0.1:4242",
            Duration::from_secs(2),
        )
        .expect("Failed to connect to rnsd");

        // Wait up to 5 seconds for an announce
        let mut buf = [0u8; MTU];
        let start = std::time::Instant::now();
        let mut received = false;

        while start.elapsed() < Duration::from_secs(5) {
            match iface.recv(&mut buf) {
                Ok(len) => {
                    println!("Received {} bytes from rnsd", len);
                    // Parse as packet
                    let packet = reticulum_core::packet::Packet::unpack(&buf[..len]);
                    println!("  Parsed: {:?}", packet.is_ok());
                    received = true;
                    break;
                }
                Err(InterfaceError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    panic!("Unexpected error: {:?}", e);
                }
            }
        }

        assert!(received, "Should have received at least one packet from rnsd");
    }

    #[test]
    #[ignore] // Requires rnsd running on localhost:4242
    fn test_tcp_interface_send_and_receive() {
        use reticulum_core::destination::{Destination, DestinationType, Direction};
        use reticulum_core::packet::{
            HeaderType, PacketContext, PacketData, PacketFlags, PacketType, TransportType,
        };

        let mut iface = TcpClientInterface::connect(
            "TestTCP",
            "127.0.0.1:4242",
            Duration::from_secs(2),
        )
        .expect("Failed to connect to rnsd");

        // Create a valid announce and send it
        let identity = reticulum_core::identity::Identity::generate_with_rng(&mut rand_core::OsRng);
        let dest = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "tcptest",
            &["echo"],
        );

        let id = dest.identity().unwrap();
        let mut random_hash = [0u8; 10];
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(&mut random_hash);

        let mut payload = Vec::new();
        payload.extend_from_slice(&id.public_key_bytes());
        payload.extend_from_slice(dest.name_hash());
        payload.extend_from_slice(&random_hash);

        let app_data = b"tcptest.echo";
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(dest.hash());
        signed_data.extend_from_slice(&id.public_key_bytes());
        signed_data.extend_from_slice(dest.name_hash());
        signed_data.extend_from_slice(&random_hash);
        signed_data.extend_from_slice(app_data);

        let signature = id.sign(&signed_data).unwrap();
        payload.extend_from_slice(&signature);
        payload.extend_from_slice(app_data);

        let packet = reticulum_core::packet::Packet {
            flags: PacketFlags {
                header_type: HeaderType::Type1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                dest_type: DestinationType::Single,
                packet_type: PacketType::Announce,
            },
            hops: 0,
            transport_id: None,
            destination_hash: *dest.hash(),
            context: PacketContext::None,
            data: PacketData::Owned(payload),
        };

        let mut pack_buf = [0u8; MTU];
        let len = packet.pack(&mut pack_buf).unwrap();

        // Send the announce
        iface.send(&pack_buf[..len]).unwrap();
        println!("Sent announce ({} bytes)", len);

        // Wait for rnsd to send us packets (announces from network)
        let mut buf = [0u8; MTU];
        let start = std::time::Instant::now();
        let mut packet_count = 0;

        while start.elapsed() < Duration::from_secs(3) {
            match iface.recv(&mut buf) {
                Ok(len) => {
                    packet_count += 1;
                    println!("Received packet {} ({} bytes)", packet_count, len);
                }
                Err(InterfaceError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    panic!("Unexpected recv error: {:?}", e);
                }
            }
        }

        println!("Total packets received: {}", packet_count);
        assert!(iface.is_online(), "Interface should still be online");
    }
}
