//! TCP client interface
//!
//! Connects to a Reticulum TCP server (e.g. rnsd TCPServerInterface)
//! and runs as a spawned tokio task communicating through channels.
//!
//! Uses HDLC framing to delimit packets on the TCP stream,
//! matching Python Reticulum's `TCPClientInterface`.

use std::io;
use std::net::ToSocketAddrs;
use std::time::Duration;

use rand_core::RngCore;
use reticulum_core::constants::MTU;
use reticulum_core::framing::hdlc::{frame, DeframeResult, Deframer};
use reticulum_core::transport::InterfaceId;
use reticulum_net::{IncomingPacket, InterfaceInfo, InterfaceKind, OutgoingPacket};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use super::{InterfaceHandle, TCP_INCOMING_CAPACITY, TCP_OUTGOING_CAPACITY};

/// Fast non-cryptographic PRNG (xorshift64). Seeded from OsRng once per task.
struct Xorshift64(u64);

impl Xorshift64 {
    fn from_entropy() -> Self {
        Self(rand_core::OsRng.next_u64() | 1) // ensure non-zero seed
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Corrupt bytes in `buf` with probability 1/N per byte.
///
/// Uses a fast inline PRNG (not OsRng) to avoid syscalls per byte.
/// XORs with a random non-zero value to guarantee the byte actually changes.
/// Returns the number of bytes corrupted.
fn maybe_corrupt(buf: &mut [u8], every_n: u64, rng: &mut Xorshift64) -> usize {
    if every_n == 0 {
        return 0;
    }
    let mut corrupted = 0;
    for byte in buf.iter_mut() {
        if rng.next().is_multiple_of(every_n) {
            let flip = loop {
                let v = (rng.next() & 0xFF) as u8;
                if v != 0 {
                    break v;
                }
            };
            *byte ^= flip;
            corrupted += 1;
        }
    }
    corrupted
}

/// Frame buffer multiplier (accounts for HDLC escaping overhead)
const FRAME_BUFFER_MULTIPLIER: usize = 2;

/// Read buffer multiplier (handles multiple packets per read)
const READ_BUFFER_MULTIPLIER: usize = 4;

/// Spawn a TCP client interface task
///
/// Connects to the given address synchronously (with timeout), then spawns
/// a tokio task that handles all I/O through channels. Returns an
/// `InterfaceHandle` for the event loop to use.
///
/// # Arguments
/// * `id` - Interface ID assigned by the driver
/// * `name` - Human-readable name for logging
/// * `addr` - Socket address to connect to (e.g. "127.0.0.1:4242")
/// * `connect_timeout` - Timeout for the initial connection
pub(crate) fn spawn_tcp_interface<A: ToSocketAddrs>(
    id: InterfaceId,
    name: String,
    addr: A,
    connect_timeout: Duration,
    corrupt_every: Option<u64>,
) -> Result<InterfaceHandle, io::Error> {
    // Resolve and connect synchronously (same as old TcpClientInterface::connect)
    let addr = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no addresses found"))?;

    let std_stream = std::net::TcpStream::connect_timeout(&addr, connect_timeout)?;
    std_stream.set_nonblocking(true)?;
    std_stream.set_nodelay(true)?;
    let stream = tokio::net::TcpStream::from_std(std_stream)?;

    // Create channels
    let (incoming_tx, incoming_rx) = mpsc::channel(TCP_INCOMING_CAPACITY);
    let (outgoing_tx, outgoing_rx) = mpsc::channel(TCP_OUTGOING_CAPACITY);

    let task_name = name.clone();

    // Spawn the I/O task
    tokio::spawn(async move {
        tcp_interface_task(task_name, stream, incoming_tx, outgoing_rx, corrupt_every).await;
    });

    Ok(InterfaceHandle {
        info: InterfaceInfo {
            id,
            name,
            kind: InterfaceKind::Tcp,
        },
        incoming: incoming_rx,
        outgoing: outgoing_tx,
    })
}

/// Interface task owning the TCP stream
///
/// Handles bidirectional I/O:
/// - Read path: poll_read_ready → try_read → HDLC deframe → incoming_tx.send()
/// - Write path: outgoing_rx.recv() → HDLC frame → stream.write_all()
///
/// Returns when the connection is lost or channels are dropped, which
/// causes the incoming sender to drop and signals the event loop.
async fn tcp_interface_task(
    name: String,
    stream: tokio::net::TcpStream,
    incoming_tx: mpsc::Sender<IncomingPacket>,
    mut outgoing_rx: mpsc::Receiver<OutgoingPacket>,
    corrupt_every: Option<u64>,
) {
    let (reader, mut writer) = stream.into_split();

    let mut deframer = Deframer::new();
    let mut read_buf = vec![0u8; MTU * READ_BUFFER_MULTIPLIER];
    let mut frame_buf = Vec::with_capacity(MTU * FRAME_BUFFER_MULTIPLIER);
    let mut corrupt_rng = Xorshift64::from_entropy();

    loop {
        tokio::select! {
            // Read path: wait for socket readability, then try_read + deframe
            result = reader.readable() => {
                match result {
                    Ok(()) => {
                        // Drain all available data from the socket
                        loop {
                            match reader.try_read(&mut read_buf) {
                                Ok(0) => {
                                    tracing::debug!("TCP interface {} disconnected (EOF)", name);
                                    return;
                                }
                                Ok(n) => {
                                    let results = deframer.process(&read_buf[..n]);
                                    for r in results {
                                        if let DeframeResult::Frame(data) = r {
                                            if incoming_tx.send(IncomingPacket { data }).await.is_err() {
                                                // Event loop dropped its receiver
                                                return;
                                            }
                                        }
                                    }
                                }
                                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                    // No more data — go back to select!
                                    break;
                                }
                                Err(e) => {
                                    tracing::debug!("TCP interface {} read error: {}", name, e);
                                    return;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("TCP interface {} readability error: {}", name, e);
                        return;
                    }
                }
            }

            // Write path: receive outgoing packets and write to stream
            msg = outgoing_rx.recv() => {
                match msg {
                    Some(pkt) => {
                        frame(&pkt.data, &mut frame_buf);
                        if let Some(n) = corrupt_every {
                            let count = maybe_corrupt(&mut frame_buf, n, &mut corrupt_rng);
                            if count > 0 {
                                tracing::trace!(
                                    "TCP {} corrupted {} byte(s) in {} byte frame",
                                    name, count, frame_buf.len()
                                );
                            }
                        }
                        if let Err(e) = writer.write_all(&frame_buf).await {
                            tracing::debug!("TCP interface {} write error: {}", name, e);
                            return;
                        }
                    }
                    None => {
                        // Event loop dropped its sender — shut down
                        tracing::debug!("TCP interface {} outgoing channel closed", name);
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_interface_connect_refused() {
        // Connecting to a port with nothing listening should fail
        let result = spawn_tcp_interface(
            InterfaceId(0),
            "test".to_string(),
            "127.0.0.1:19999",
            Duration::from_millis(500),
            None,
        );
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_spawn_tcp_interface() {
        // Start a listener, connect via spawn_tcp_interface
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = spawn_tcp_interface(
            InterfaceId(0),
            "test_tcp".to_string(),
            addr,
            Duration::from_secs(2),
            None,
        )
        .unwrap();

        assert_eq!(handle.info.name, "test_tcp");
        assert_eq!(handle.info.id, InterfaceId(0));
        assert_eq!(handle.info.kind, InterfaceKind::Tcp);

        // Accept the connection on the listener side
        let (_server_stream, _peer) = listener.accept().unwrap();

        // The handle is valid and channels are open
        assert!(!handle.outgoing.is_closed());
    }

    #[test]
    fn test_maybe_corrupt_zero_means_no_corruption() {
        let mut buf = vec![0xAA; 100];
        let original = buf.clone();
        let mut rng = Xorshift64::from_entropy();
        let count = maybe_corrupt(&mut buf, 0, &mut rng);
        assert_eq!(count, 0);
        assert_eq!(buf, original);
    }

    #[test]
    fn test_maybe_corrupt_every_one_corrupts_all() {
        let mut buf = vec![0xAA; 500];
        let original = buf.clone();
        let mut rng = Xorshift64::from_entropy();
        let count = maybe_corrupt(&mut buf, 1, &mut rng);
        assert_eq!(count, 500);
        // XOR with non-zero guarantees every byte changed
        for (i, &b) in buf.iter().enumerate() {
            assert_ne!(b, original[i], "byte {i} should have changed");
        }
    }

    #[test]
    fn test_maybe_corrupt_rare_practically_none() {
        let mut buf = vec![0xAA; 500];
        let original = buf.clone();
        let mut rng = Xorshift64::from_entropy();
        let count = maybe_corrupt(&mut buf, 1_000_000, &mut rng);
        // With 500 bytes and 1/1M probability, expect ~0 corruptions
        assert!(count <= 2, "expected near-zero corruption, got {count}");
        // Most bytes should be unchanged
        let unchanged = buf
            .iter()
            .zip(original.iter())
            .filter(|(a, b)| a == b)
            .count();
        assert!(unchanged >= 498);
    }

    #[test]
    fn test_maybe_corrupt_empty_buffer() {
        let mut buf: Vec<u8> = Vec::new();
        let mut rng = Xorshift64::from_entropy();
        let count = maybe_corrupt(&mut buf, 1, &mut rng);
        assert_eq!(count, 0);
    }
}
