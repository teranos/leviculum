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

use reticulum_core::constants::MTU;
use reticulum_core::framing::hdlc::{frame, DeframeResult, Deframer};
use reticulum_core::transport::InterfaceId;
use reticulum_net::{IncomingPacket, InterfaceInfo, InterfaceKind, OutgoingPacket};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use super::{InterfaceHandle, TCP_INCOMING_CAPACITY, TCP_OUTGOING_CAPACITY};

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
        tcp_interface_task(task_name, stream, incoming_tx, outgoing_rx).await;
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
) {
    let (reader, mut writer) = stream.into_split();

    let mut deframer = Deframer::new();
    let mut read_buf = vec![0u8; MTU * READ_BUFFER_MULTIPLIER];
    let mut frame_buf = Vec::with_capacity(MTU * FRAME_BUFFER_MULTIPLIER);

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
}
