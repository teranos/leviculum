//! Sans-I/O driver for Reticulum
//!
//! This module provides `ReticulumNode`, the async I/O driver that bridges the
//! pure state machine (`NodeCore` from reticulum-core) with actual network
//! interfaces. It owns the interfaces and dispatches `Action` values.
//!
//! # Architecture (Sans-I/O)
//!
//! `NodeCore` from reticulum-core is a pure state machine that never performs I/O
//! directly. Instead, it returns `Action` values (SendPacket, Broadcast) that this
//! driver dispatches to the actual network interfaces.
//!
//! The event loop awaits interface readability via `select!`:
//! 1. Wakes immediately when any interface has data (no polling delay)
//! 2. Feeds packets to `NodeCore::handle_packet()` → gets `TickOutput`
//! 3. Wakes on outgoing data from `ConnectionStream`s
//! 4. Wakes on timer deadline for periodic maintenance
//! 5. Dispatches `Action`s from `TickOutput` to interfaces
//! 6. Forwards `NodeEvent`s to the application
//!
//! # Example
//!
//! ```no_run
//! use reticulum_std::driver::ReticulumNodeBuilder;
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
use std::task::Poll;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};

use reticulum_core::constants::TRUNCATED_HASHBYTES;
use reticulum_core::link::LinkId;
use reticulum_core::node::{NodeCore, NodeEvent};
use reticulum_core::traits::Clock;
use reticulum_core::transport::{Action, InterfaceId, TickOutput};
use reticulum_core::{Destination, DestinationHash};
use reticulum_net::{IncomingPacket, OutgoingPacket};

use crate::clock::SystemClock;
use crate::config::InterfaceConfig;
use crate::error::Error;
use crate::interfaces::tcp::spawn_tcp_interface;
use crate::interfaces::InterfaceRegistry;
use crate::storage::Storage;

/// Type alias for the concrete NodeCore used by std platforms
pub type StdNodeCore = NodeCore<rand_core::OsRng, SystemClock, Storage>;

/// Alias for `ReticulumNode` (preserves backward compatibility)
pub type ReticulumNode = ReticulumNodeImpl;

/// Event channel capacity
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Connection channel capacity
const CONNECTION_CHANNEL_CAPACITY: usize = 64;

/// Map from link ID to the channel for delivering incoming data to the connection stream
type ConnectionMap = HashMap<LinkId, mpsc::Sender<Vec<u8>>>;

/// Event received from any interface
enum RecvEvent {
    /// A complete packet from an interface
    Packet(InterfaceId, IncomingPacket),
    /// An interface disconnected (its incoming channel closed)
    Disconnected(InterfaceId),
}

/// High-level async Reticulum node
///
/// `ReticulumNodeImpl` provides an async API for interacting with the Reticulum
/// network. It manages the internal event loop and provides methods for sending
/// data, establishing connections, and handling incoming messages.
pub struct ReticulumNodeImpl {
    /// Handle to the core node
    inner: Arc<Mutex<StdNodeCore>>,
    /// Interface configurations
    interfaces: Vec<InterfaceConfig>,
    /// Event sender for the runner
    event_tx: mpsc::Sender<NodeEvent>,
    /// Event receiver for consuming events
    event_rx: Option<mpsc::Receiver<NodeEvent>>,
    /// Shutdown sender
    shutdown_tx: Option<watch::Sender<bool>>,
    /// Runner task handle
    runner_handle: Option<tokio::task::JoinHandle<()>>,
    /// Active connection streams (link_id -> incoming data sender)
    connections: Arc<Mutex<ConnectionMap>>,
    /// Pending connection requests
    pending_connects: Arc<Mutex<HashMap<[u8; TRUNCATED_HASHBYTES], oneshot::Sender<LinkId>>>>,
    /// Shared outgoing channel sender (cloned to each ConnectionStream)
    outgoing_tx: mpsc::Sender<(LinkId, Vec<u8>)>,
    /// Channel for dispatching TickOutput from outside the event loop
    /// (used by connect() and announce_destination())
    action_dispatch_tx: mpsc::Sender<TickOutput>,
}

impl ReticulumNodeImpl {
    /// Create a new ReticulumNode (internal use - use ReticulumNodeBuilder)
    pub(crate) fn new(core: StdNodeCore, interfaces: Vec<InterfaceConfig>) -> Self {
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        // Create dummy channels; real ones are created in start()
        let (outgoing_tx, _) = mpsc::channel(1);
        let (action_dispatch_tx, _) = mpsc::channel(1);

        Self {
            inner: Arc::new(Mutex::new(core)),
            interfaces,
            event_tx,
            event_rx: Some(event_rx),
            shutdown_tx: None,
            runner_handle: None,
            connections: Arc::new(Mutex::new(HashMap::new())),
            pending_connects: Arc::new(Mutex::new(HashMap::new())),
            outgoing_tx,
            action_dispatch_tx,
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

        // Initialize interfaces — the driver owns them, NOT NodeCore
        let registry = self.initialize_interfaces()?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        // Create the shared outgoing channel
        let (outgoing_tx, outgoing_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        self.outgoing_tx = outgoing_tx;

        // Channel for dispatching TickOutput from outside the event loop.
        // connect() and announce_destination() produce actions that must reach
        // the event loop for interface dispatch.  Capacity 256 is generous —
        // each call produces exactly one TickOutput, and the event loop drains
        // them on every iteration, so the queue only backs up if the event
        // loop is blocked (which also stalls all other I/O).
        let (action_dispatch_tx, action_dispatch_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        self.action_dispatch_tx = action_dispatch_tx;

        // Clone handles for the runner
        let inner = Arc::clone(&self.inner);
        let event_tx = self.event_tx.clone();
        let connections = Arc::clone(&self.connections);
        let pending_connects = Arc::clone(&self.pending_connects);

        // Spawn the runner
        let runner_handle = tokio::spawn(async move {
            run_event_loop(
                inner,
                registry,
                event_tx,
                connections,
                pending_connects,
                outgoing_rx,
                action_dispatch_rx,
                shutdown_rx,
            )
            .await;
        });

        self.runner_handle = Some(runner_handle);

        Ok(())
    }

    /// Initialize interfaces from configuration
    fn initialize_interfaces(&self) -> Result<InterfaceRegistry, Error> {
        let mut registry = InterfaceRegistry::new();

        for (idx, config) in self.interfaces.iter().enumerate() {
            if !config.enabled {
                continue;
            }

            match config.interface_type.as_str() {
                "TCPClientInterface" => {
                    let target_host = config.target_host.as_ref().ok_or_else(|| {
                        Error::Config("TCPClientInterface requires target_host".to_string())
                    })?;
                    let target_port = config.target_port.ok_or_else(|| {
                        Error::Config("TCPClientInterface requires target_port".to_string())
                    })?;

                    let addr = format!("{}:{}", target_host, target_port);
                    let iface_name = format!("tcp_client_{}", idx);
                    let id = InterfaceId(idx);

                    match spawn_tcp_interface(
                        id,
                        iface_name,
                        &addr as &str,
                        Duration::from_secs(10),
                    ) {
                        Ok(handle) => {
                            tracing::info!("Connected to TCP interface: {}", addr);
                            registry.register(handle);
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

        Ok(registry)
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
    /// for async read/write operations. The link request packet is queued
    /// internally and dispatched by the event loop.
    ///
    /// # Arguments
    /// * `dest_hash` - The destination hash to connect to
    /// * `dest_signing_key` - The destination's signing key (from announce)
    pub async fn connect(
        &self,
        dest_hash: &DestinationHash,
        dest_signing_key: &[u8; 32],
    ) -> Result<ConnectionStream, Error> {
        // Create oneshot channel to receive notification when connection is established
        let (tx, rx) = oneshot::channel();

        // Register the pending connect
        {
            let mut pending = self.pending_connects.lock().unwrap();
            pending.insert(dest_hash.into_bytes(), tx);
        }

        // Request connection from NodeCore
        let (link_id, output) = {
            let mut inner = self.inner.lock().unwrap();
            inner.connect(*dest_hash, dest_signing_key)
        };
        // Send output to event loop for dispatch (backpressure — waits if full)
        self.action_dispatch_tx
            .send(output)
            .await
            .map_err(|_| Error::Transport("event loop shut down".to_string()))?;

        // Create incoming channel (per-connection)
        let (in_tx, in_rx) = mpsc::channel(CONNECTION_CHANNEL_CAPACITY);

        // Register the connection channels
        {
            let mut connections = self.connections.lock().unwrap();
            connections.insert(link_id, in_tx);
        }

        // Store the oneshot receiver for when connection completes
        // (In practice, we'd want to track this better and wait for completion)
        tokio::spawn(async move {
            // Wait for connection establishment
            let _ = rx.await;
        });

        Ok(ConnectionStream::new(
            link_id,
            self.outgoing_tx.clone(),
            in_rx,
        ))
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

    /// Check if a path to a destination is known
    pub fn has_path(&self, dest_hash: &reticulum_core::DestinationHash) -> bool {
        self.inner.lock().unwrap().has_path(dest_hash)
    }

    /// Get hop count to a destination
    pub fn hops_to(&self, dest_hash: &reticulum_core::DestinationHash) -> Option<u8> {
        self.inner.lock().unwrap().hops_to(dest_hash)
    }

    /// Get the number of known paths
    pub fn path_count(&self) -> usize {
        self.inner.lock().unwrap().path_count()
    }

    /// Get transport statistics (packets sent, received, forwarded, dropped)
    pub fn transport_stats(&self) -> reticulum_core::transport::TransportStats {
        self.inner.lock().unwrap().transport_stats()
    }

    /// Announce a registered destination on all interfaces
    ///
    /// Builds the announce packet and queues it as a Broadcast action.
    /// The event loop dispatches the action on the next iteration.
    ///
    /// # Arguments
    /// * `dest_hash` - Hash of the registered destination to announce
    /// * `app_data` - Optional application data to include in the announce
    pub fn announce_destination(
        &self,
        dest_hash: &reticulum_core::DestinationHash,
        app_data: Option<&[u8]>,
    ) -> Result<(), Error> {
        let output = self
            .inner
            .lock()
            .unwrap()
            .announce_destination(dest_hash, app_data)
            .map_err(|e| Error::Transport(e.to_string()))?;
        // Send output to event loop for dispatch.
        // try_send fails only if the channel is full (event loop stalled)
        // or closed (event loop shut down). Either way, the caller must know.
        self.action_dispatch_tx
            .try_send(output)
            .map_err(|_| Error::Transport("action dispatch channel full or closed".to_string()))?;
        Ok(())
    }

    /// Check if transport mode (relay/routing) is enabled
    pub fn is_transport_enabled(&self) -> bool {
        self.inner
            .lock()
            .unwrap()
            .transport_config()
            .enable_transport
    }
}

// ─── Sans-I/O Event Loop ────────────────────────────────────────────────────

/// Poll all interface channels with round-robin fairness
///
/// Returns `RecvEvent::Packet` when a complete packet is available, or
/// `RecvEvent::Disconnected` when an interface's incoming channel closes.
/// Returns `Poll::Pending` when no interface has data ready.
async fn recv_any(registry: &mut InterfaceRegistry) -> RecvEvent {
    if registry.is_empty() {
        // No interfaces — pend forever (timer branch will still fire)
        std::future::pending().await
    } else {
        std::future::poll_fn(|cx| {
            let (handles, poll_start) = registry.handles_mut();
            let len = handles.len();

            for offset in 0..len {
                let idx = (*poll_start + offset) % len;
                let handle = &mut handles[idx];
                let id = handle.info.id;

                match handle.incoming.poll_recv(cx) {
                    Poll::Ready(Some(pkt)) => {
                        *poll_start = (idx + 1) % len;
                        return Poll::Ready(RecvEvent::Packet(id, pkt));
                    }
                    Poll::Ready(None) => {
                        *poll_start = (idx + 1) % len;
                        return Poll::Ready(RecvEvent::Disconnected(id));
                    }
                    Poll::Pending => {}
                }
            }
            Poll::Pending
        })
        .await
    }
}

/// Run the internal event loop (sans-I/O architecture)
///
/// The driver owns the interfaces and acts as the I/O bridge between the
/// pure state machine (`NodeCore`) and the actual network. Uses `select!`
/// to wake immediately on socket readability, outgoing data, or timer expiry.
#[allow(clippy::too_many_arguments)]
async fn run_event_loop(
    inner: Arc<Mutex<StdNodeCore>>,
    mut registry: InterfaceRegistry,
    event_tx: mpsc::Sender<NodeEvent>,
    connections: Arc<Mutex<ConnectionMap>>,
    pending_connects: Arc<Mutex<HashMap<[u8; TRUNCATED_HASHBYTES], oneshot::Sender<LinkId>>>>,
    mut outgoing_rx: mpsc::Receiver<(LinkId, Vec<u8>)>,
    mut action_dispatch_rx: mpsc::Receiver<TickOutput>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        // Compute deadline for timer branch
        let deadline = {
            let core = inner.lock().unwrap();
            match core.next_deadline() {
                Some(deadline_ms) => {
                    let now_ms = core.transport().clock().now_ms();
                    if deadline_ms <= now_ms {
                        tokio::time::Instant::now()
                    } else {
                        tokio::time::Instant::now() + Duration::from_millis(deadline_ms - now_ms)
                    }
                }
                None => tokio::time::Instant::now() + Duration::from_secs(1),
            }
        };

        tokio::select! {
            // Branch 1: Packet from any interface
            event = recv_any(&mut registry) => {
                match event {
                    RecvEvent::Packet(iface_id, pkt) => {
                        let output = {
                            let mut core = inner.lock().unwrap();
                            core.handle_packet(iface_id, &pkt.data)
                        };
                        dispatch_output(
                            output,
                            &registry,
                            &event_tx,
                            &connections,
                            &pending_connects,
                        );
                    }
                    RecvEvent::Disconnected(iface_id) => {
                        tracing::warn!("Interface {} ({}) disconnected", iface_id, registry.name_of(iface_id));
                        let output = {
                            let mut core = inner.lock().unwrap();
                            core.handle_interface_down(iface_id)
                        };
                        dispatch_output(
                            output,
                            &registry,
                            &event_tx,
                            &connections,
                            &pending_connects,
                        );
                        registry.remove(iface_id);
                    }
                }
            }

            // Branch 2: Outgoing data from ConnectionStreams
            Some((link_id, data)) = outgoing_rx.recv() => {
                let mut combined = TickOutput::default();
                {
                    let mut core = inner.lock().unwrap();
                    match core.send_on_connection(&link_id, &data) {
                        Ok(output) => combined.merge(output),
                        Err(e) => tracing::debug!("send_on_connection failed for {:?}: {}", link_id, e),
                    }
                    // Drain any more queued messages before dispatching
                    while let Ok((lid, d)) = outgoing_rx.try_recv() {
                        match core.send_on_connection(&lid, &d) {
                            Ok(output) => combined.merge(output),
                            Err(e) => tracing::debug!("send_on_connection failed for {:?}: {}", lid, e),
                        }
                    }
                };
                dispatch_output(
                    combined,
                    &registry,
                    &event_tx,
                    &connections,
                    &pending_connects,
                );
            }

            // Branch 3: Dispatch TickOutput from outside the event loop
            // (connect() and announce_destination() send their output here)
            Some(output) = action_dispatch_rx.recv() => {
                dispatch_output(
                    output,
                    &registry,
                    &event_tx,
                    &connections,
                    &pending_connects,
                );
            }

            // Branch 4: Timer deadline
            _ = tokio::time::sleep_until(deadline) => {
                let output = {
                    let mut core = inner.lock().unwrap();
                    core.handle_timeout()
                };
                dispatch_output(
                    output,
                    &registry,
                    &event_tx,
                    &connections,
                    &pending_connects,
                );
            }

            // Branch 5: Shutdown
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("Node shutdown requested");
                    break;
                }
            }
        }
    }
}

/// Dispatch a TickOutput: execute Actions on interface channels and forward Events
fn dispatch_output(
    output: TickOutput,
    registry: &InterfaceRegistry,
    event_tx: &mpsc::Sender<NodeEvent>,
    connections: &Arc<Mutex<ConnectionMap>>,
    pending_connects: &Arc<Mutex<HashMap<[u8; TRUNCATED_HASHBYTES], oneshot::Sender<LinkId>>>>,
) {
    // Execute I/O actions
    for action in &output.actions {
        match action {
            Action::SendPacket { iface, data } => {
                if let Some(sender) = registry.get_sender(*iface) {
                    if let Err(e) = sender.try_send(OutgoingPacket { data: data.clone() }) {
                        tracing::debug!("Send error on {}: {:?}", iface, e);
                    }
                } else {
                    tracing::debug!("No interface {} for SendPacket", iface);
                }
            }
            Action::Broadcast {
                data,
                exclude_iface,
            } => {
                for (id, sender) in registry.senders() {
                    if Some(id) == *exclude_iface {
                        continue;
                    }
                    let _ = sender.try_send(OutgoingPacket { data: data.clone() });
                }
            }
        }
    }

    // Forward events: handle internal routing and send to application
    for event in output.events {
        handle_event(&event, connections, pending_connects);
        // Forward to external event receiver (best effort — drop if full)
        let _ = event_tx.try_send(event);
    }
}

/// Handle a node event
fn handle_event(
    event: &NodeEvent,
    connections: &Arc<Mutex<ConnectionMap>>,
    _pending_connects: &Arc<Mutex<HashMap<[u8; TRUNCATED_HASHBYTES], oneshot::Sender<LinkId>>>>,
) {
    match event {
        NodeEvent::ConnectionEstablished { link_id, .. } => {
            tracing::debug!("Connection established: {:?}", link_id);
        }
        NodeEvent::DataReceived { link_id, data } => {
            // Forward data to the connection stream
            let conns = connections.lock().unwrap();
            if let Some(tx) = conns.get(link_id) {
                if tx.try_send(data.clone()).is_err() {
                    tracing::warn!(
                        "Connection channel full for {:?}, dropping {} bytes",
                        link_id,
                        data.len()
                    );
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
