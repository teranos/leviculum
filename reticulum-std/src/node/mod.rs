//! High-level async node API for Reticulum
//!
//! This module provides `ReticulumNode`, a high-level async API for interacting
//! with the Reticulum network. It wraps the no_std `NodeCore` from reticulum-core
//! and provides async/await methods for common operations.
//!
//! # Overview
//!
//! `ReticulumNode` simplifies working with Reticulum by:
//! - Managing the event loop internally
//! - Providing async methods for send/receive operations
//! - Handling interface management (TCP, etc.)
//! - Supporting connection streams with AsyncRead/AsyncWrite
//!
//! # Example
//!
//! ```ignore
//! use reticulum_std::node::ReticulumNodeBuilder;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a node with a TCP interface
//!     let mut node = ReticulumNodeBuilder::new()
//!         .add_tcp_client("127.0.0.1:4242".parse()?)
//!         .build()
//!         .await?;
//!
//!     // Start the node
//!     node.start().await?;
//!
//!     // Take event receiver to handle events
//!     let mut events = node.take_event_receiver().unwrap();
//!
//!     // Process events
//!     while let Some(event) = events.recv().await {
//!         println!("Event: {:?}", event);
//!     }
//!
//!     Ok(())
//! }
//! ```

mod builder;
mod stream;

pub use builder::ReticulumNodeBuilder;
pub use stream::ConnectionStream;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};

use reticulum_core::constants::{MTU, TRUNCATED_HASHBYTES};
use reticulum_core::link::LinkId;
use reticulum_core::node::{NodeCore, NodeEvent};
use reticulum_core::traits::{Interface, InterfaceError, NoStorage, PlatformContext};
use reticulum_core::{Destination, DestinationHash};

use crate::clock::SystemClock;
use crate::config::InterfaceConfig;
use crate::error::Error;
use crate::interfaces::TcpClientInterface;
use crate::storage::Storage;

/// Type alias for the concrete NodeCore used by std platforms
pub type StdNodeCore = NodeCore<SystemClock, Storage>;

/// Default poll interval in milliseconds
const DEFAULT_POLL_INTERVAL_MS: u64 = 50;

/// Event channel capacity
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Connection channel capacity
const CONNECTION_CHANNEL_CAPACITY: usize = 64;

/// High-level async Reticulum node
///
/// `ReticulumNode` provides an async API for interacting with the Reticulum network.
/// It manages the internal event loop and provides methods for sending data,
/// establishing connections, and handling incoming messages.
pub struct ReticulumNode {
    /// Handle to the core node
    inner: Arc<Mutex<StdNodeCore>>,
    /// Interface configurations
    interfaces: Vec<InterfaceConfig>,
    /// Whether transport mode is enabled
    #[allow(dead_code)]
    enable_transport: bool,
    /// Event sender for the runner
    event_tx: mpsc::Sender<NodeEvent>,
    /// Event receiver for consuming events
    event_rx: Option<mpsc::Receiver<NodeEvent>>,
    /// Shutdown sender
    shutdown_tx: Option<watch::Sender<bool>>,
    /// Runner task handle
    runner_handle: Option<tokio::task::JoinHandle<()>>,
    /// Active connection streams (link_id -> channels)
    connections: Arc<Mutex<HashMap<LinkId, ConnectionChannels>>>,
    /// Pending connection requests
    pending_connects: Arc<Mutex<HashMap<[u8; TRUNCATED_HASHBYTES], oneshot::Sender<LinkId>>>>,
}

/// Internal channels for a connection
struct ConnectionChannels {
    /// Outgoing data from the stream
    outgoing_rx: mpsc::Receiver<Vec<u8>>,
    /// Incoming data to the stream
    incoming_tx: mpsc::Sender<Vec<u8>>,
}

impl ReticulumNode {
    /// Create a new ReticulumNode (internal use - use ReticulumNodeBuilder)
    pub(crate) fn new(
        core: StdNodeCore,
        interfaces: Vec<InterfaceConfig>,
        enable_transport: bool,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);

        Self {
            inner: Arc::new(Mutex::new(core)),
            interfaces,
            enable_transport,
            event_tx,
            event_rx: Some(event_rx),
            shutdown_tx: None,
            runner_handle: None,
            connections: Arc::new(Mutex::new(HashMap::new())),
            pending_connects: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start the node
    ///
    /// This spawns the internal event loop and initializes interfaces.
    /// The node will process incoming packets and emit events until `stop()` is called.
    pub async fn start(&mut self) -> Result<(), Error> {
        if self.runner_handle.is_some() {
            return Err(Error::Transport("Node already running".to_string()));
        }

        // Initialize interfaces
        let interfaces = self.initialize_interfaces().await?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        // Clone handles for the runner
        let inner = Arc::clone(&self.inner);
        let event_tx = self.event_tx.clone();
        let connections = Arc::clone(&self.connections);
        let pending_connects = Arc::clone(&self.pending_connects);

        // Spawn the runner
        let runner_handle = tokio::spawn(async move {
            run_event_loop(
                inner,
                interfaces,
                event_tx,
                connections,
                pending_connects,
                shutdown_rx,
            )
            .await;
        });

        self.runner_handle = Some(runner_handle);

        Ok(())
    }

    /// Initialize interfaces from configuration
    async fn initialize_interfaces(&self) -> Result<Vec<Box<dyn Interface + Send + Sync>>, Error> {
        let mut interfaces: Vec<Box<dyn Interface + Send + Sync>> = Vec::new();

        for (idx, config) in self.interfaces.iter().enumerate() {
            if !config.enabled {
                continue;
            }

            match config.interface_type.as_str() {
                "TCPClientInterface" => {
                    let target_host = config
                        .target_host
                        .as_ref()
                        .ok_or_else(|| Error::Config("TCPClientInterface requires target_host".to_string()))?;
                    let target_port = config
                        .target_port
                        .ok_or_else(|| Error::Config("TCPClientInterface requires target_port".to_string()))?;

                    let addr = format!("{}:{}", target_host, target_port);
                    let iface_name = format!("tcp_client_{}", idx);

                    match TcpClientInterface::connect(
                        &iface_name,
                        &addr,
                        Duration::from_secs(10),
                    ) {
                        Ok(iface) => {
                            tracing::info!("Connected to TCP interface: {}", addr);
                            interfaces.push(Box::new(iface));
                        }
                        Err(e) => {
                            tracing::warn!("Failed to connect to {}: {:?}", addr, e);
                        }
                    }
                }
                "TCPServerInterface" => {
                    // TCP server interfaces would be handled here
                    // For now, we skip them as they require more complex handling
                    tracing::warn!("TCP server interfaces not yet supported");
                }
                other => {
                    tracing::warn!("Unknown interface type: {}", other);
                }
            }
        }

        Ok(interfaces)
    }

    /// Stop the node
    ///
    /// This signals the event loop to stop and waits for it to complete.
    pub async fn stop(&mut self) -> Result<(), Error> {
        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }

        // Wait for runner to finish
        if let Some(handle) = self.runner_handle.take() {
            handle
                .await
                .map_err(|e| Error::Transport(format!("Runner panicked: {}", e)))?;
        }

        tracing::info!("ReticulumNode stopped");
        Ok(())
    }

    /// Check if the node is running
    pub fn is_running(&self) -> bool {
        self.runner_handle
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or(false)
    }

    /// Register a destination for incoming connections
    pub fn register_destination(&self, destination: Destination) {
        let mut inner = self.inner.lock().unwrap();
        inner.register_destination(destination);
    }

    /// Connect to a remote destination
    ///
    /// Establishes a Link to the destination and returns a ConnectionStream
    /// for async read/write operations.
    ///
    /// # Arguments
    /// * `dest_hash` - The destination hash to connect to
    /// * `dest_signing_key` - The destination's signing key (from announce)
    ///
    /// # Returns
    /// A tuple of (ConnectionStream, packet_to_send). The packet must be sent
    /// via an interface to initiate the connection handshake.
    pub async fn connect(
        &self,
        dest_hash: &DestinationHash,
        dest_signing_key: &[u8; 32],
    ) -> Result<(ConnectionStream, Vec<u8>), Error> {
        // Create oneshot channel to receive notification when connection is established
        let (tx, rx) = oneshot::channel();

        // Register the pending connect
        {
            let mut pending = self.pending_connects.lock().unwrap();
            pending.insert(dest_hash.into_bytes(), tx);
        }

        // Request connection from NodeCore
        let (link_id, packet) = {
            let mut inner = self.inner.lock().unwrap();
            let mut ctx = PlatformContext {
                rng: rand_core::OsRng,
                clock: SystemClock::new(),
                storage: NoStorage,
            };
            inner.connect(*dest_hash, dest_signing_key, &mut ctx)
        };

        // Create channels for the stream
        let (out_tx, out_rx) = mpsc::channel(CONNECTION_CHANNEL_CAPACITY);
        let (in_tx, in_rx) = mpsc::channel(CONNECTION_CHANNEL_CAPACITY);

        // Register the connection channels
        {
            let mut connections = self.connections.lock().unwrap();
            connections.insert(
                link_id,
                ConnectionChannels {
                    outgoing_rx: out_rx,
                    incoming_tx: in_tx,
                },
            );
        }

        // Store the oneshot receiver for when connection completes
        // (In practice, we'd want to track this better and wait for completion)
        tokio::spawn(async move {
            // Wait for connection establishment
            let _ = rx.await;
        });

        Ok((ConnectionStream::new(link_id, out_tx, in_rx), packet))
    }

    /// Take the event receiver
    ///
    /// This allows consuming node events directly. Can only be called once.
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<NodeEvent>> {
        self.event_rx.take()
    }

    /// Get a handle to the inner NodeCore
    ///
    /// Use this for direct access to the core API.
    pub fn inner(&self) -> Arc<Mutex<StdNodeCore>> {
        Arc::clone(&self.inner)
    }
}

/// Run the internal event loop
async fn run_event_loop(
    inner: Arc<Mutex<StdNodeCore>>,
    mut interfaces: Vec<Box<dyn Interface + Send + Sync>>,
    event_tx: mpsc::Sender<NodeEvent>,
    connections: Arc<Mutex<HashMap<LinkId, ConnectionChannels>>>,
    pending_connects: Arc<Mutex<HashMap<[u8; TRUNCATED_HASHBYTES], oneshot::Sender<LinkId>>>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let poll_interval = Duration::from_millis(DEFAULT_POLL_INTERVAL_MS);
    let mut interval = tokio::time::interval(poll_interval);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Poll interfaces for incoming data
                poll_interfaces(&inner, &mut interfaces);

                // Process outgoing data from connections
                process_outgoing(&inner, &connections);

                // Run NodeCore poll and collect events
                let events = {
                    let mut core = inner.lock().unwrap();
                    // Create a platform context for polling
                    let mut ctx = PlatformContext {
                        rng: rand_core::OsRng,
                        clock: SystemClock::new(),
                        storage: NoStorage,
                    };
                    core.poll(&mut ctx);
                    core.drain_events().collect::<Vec<_>>()
                };

                // Handle events
                for event in events {
                    handle_event(
                        &event,
                        &connections,
                        &pending_connects,
                    );

                    // Forward to external receiver
                    if event_tx.try_send(event).is_err() {
                        tracing::warn!("Event channel full, dropping event");
                    }
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("Node shutdown requested");
                    break;
                }
            }
        }
    }
}

/// Poll interfaces for incoming data
fn poll_interfaces(
    inner: &Arc<Mutex<StdNodeCore>>,
    interfaces: &mut [Box<dyn Interface + Send + Sync>],
) {
    let mut recv_buf = [0u8; MTU];

    for (idx, iface) in interfaces.iter_mut().enumerate() {
        loop {
            match iface.recv(&mut recv_buf) {
                Ok(len) if len > 0 => {
                    let data = recv_buf[..len].to_vec();
                    let mut core = inner.lock().unwrap();
                    // Create a platform context for receiving
                    let mut ctx = PlatformContext {
                        rng: rand_core::OsRng,
                        clock: SystemClock::new(),
                        storage: NoStorage,
                    };
                    if let Err(e) = core.receive_packet(idx, &data, &mut ctx) {
                        tracing::debug!("Error processing packet from interface {}: {:?}", idx, e);
                    }
                }
                Ok(_) | Err(InterfaceError::WouldBlock) => break,
                Err(InterfaceError::Disconnected) => {
                    tracing::warn!("Interface {} disconnected", idx);
                    break;
                }
                Err(e) => {
                    tracing::debug!("Interface {} recv error: {:?}", idx, e);
                    break;
                }
            }
        }
    }
}

/// Process outgoing data from connection streams
fn process_outgoing(
    inner: &Arc<Mutex<StdNodeCore>>,
    connections: &Arc<Mutex<HashMap<LinkId, ConnectionChannels>>>,
) {
    let mut conns = connections.lock().unwrap();

    for (link_id, channels) in conns.iter_mut() {
        // Try to receive outgoing data from the stream
        while let Ok(data) = channels.outgoing_rx.try_recv() {
            let mut core = inner.lock().unwrap();
            // Create a platform context for sending
            let mut ctx = PlatformContext {
                rng: rand_core::OsRng,
                clock: SystemClock::new(),
                storage: NoStorage,
            };
            // Send data on the connection
            if let Err(e) = core.send_on_connection(link_id, &data, &mut ctx) {
                tracing::debug!("Error sending on connection {:?}: {:?}", link_id, e);
            }
        }
    }
}

/// Handle a node event
fn handle_event(
    event: &NodeEvent,
    connections: &Arc<Mutex<HashMap<LinkId, ConnectionChannels>>>,
    _pending_connects: &Arc<Mutex<HashMap<[u8; TRUNCATED_HASHBYTES], oneshot::Sender<LinkId>>>>,
) {
    match event {
        NodeEvent::ConnectionEstablished { link_id, .. } => {
            // Note: We can't easily look up the destination hash from just the link_id
            // This would require changes to NodeCore to include destination_hash in the event
            // For now, the connection will be set up when the user explicitly calls connect()
            tracing::debug!("Connection established: {:?}", link_id);
        }
        NodeEvent::DataReceived { link_id, data } => {
            // Forward data to the connection stream
            let conns = connections.lock().unwrap();
            if let Some(channels) = conns.get(link_id) {
                if channels.incoming_tx.try_send(data.clone()).is_err() {
                    tracing::warn!("Connection channel full, dropping data");
                }
            }
        }
        NodeEvent::ConnectionClosed { link_id, .. } => {
            // Remove connection channels
            let mut conns = connections.lock().unwrap();
            conns.remove(link_id);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reticulum_node_builder_creates_node() {
        // This is a basic smoke test
        let _builder = ReticulumNodeBuilder::new();
    }
}
