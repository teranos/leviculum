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
//! 3. Dispatches `TickOutput` from external callers (connect, send, close)
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
mod sender;
mod stream;

pub use builder::ReticulumNodeBuilder;
pub use sender::PacketSender;
pub use stream::LinkHandle;

use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use crate::interfaces::IncomingPacket;
use reticulum_core::constants::TRUNCATED_HASHBYTES;
use reticulum_core::link::LinkId;
use reticulum_core::node::{NodeCore, NodeEvent};
use reticulum_core::traits::InterfaceError;
use reticulum_core::transport::{InterfaceId, TickOutput};
use reticulum_core::{Destination, DestinationHash};

use crate::clock::SystemClock;
use crate::config::InterfaceConfig;
use crate::error::Error;
use crate::interfaces::tcp::{
    spawn_tcp_client_with_reconnect, spawn_tcp_server, TCP_DEFAULT_BUFFER_SIZE,
};
use crate::interfaces::udp::spawn_udp_interface;
use crate::interfaces::{InterfaceHandle, InterfaceRegistry};
use crate::storage::Storage;

/// Type alias for the concrete NodeCore used by std platforms
pub(crate) type StdNodeCore = NodeCore<rand_core::OsRng, SystemClock, Storage>;

/// Event channel capacity for NodeEvent delivery to the application.
/// Must be large enough that slow consumers don't block the event loop.
/// Not yet tuned — chosen empirically during initial development.
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Interval between periodic storage flushes (seconds).
/// Crash protection only — normal shutdown calls flush() via signal handler.
/// Lost data from a crash is recovered via fresh announces.
/// Hardcoded — see E12 for making this configurable.
const FLUSH_INTERVAL_SECS: u64 = 3600;

/// Event received from any interface
enum RecvEvent {
    /// A complete packet from an interface
    Packet(InterfaceId, IncomingPacket),
    /// An interface disconnected (its incoming channel closed)
    Disconnected(InterfaceId),
}

/// High-level async Reticulum node
///
/// `ReticulumNode` provides an async API for interacting with the Reticulum
/// network. It manages the internal event loop and provides methods for sending
/// data, establishing links, and handling incoming messages.
pub struct ReticulumNode {
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
    /// Channel for dispatching TickOutput from outside the event loop
    /// (used by connect, send_on_link, close_link, announce)
    action_dispatch_tx: mpsc::Sender<TickOutput>,
    /// Fault injection: corrupt ~1 byte per N bytes on TCP write
    corrupt_every: Option<u64>,
}

impl ReticulumNode {
    /// Create a new ReticulumNode (internal use - use ReticulumNodeBuilder)
    pub(crate) fn new(
        core: StdNodeCore,
        interfaces: Vec<InterfaceConfig>,
        corrupt_every: Option<u64>,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        // Create dummy channel; real one is created in start()
        let (action_dispatch_tx, _) = mpsc::channel(1);

        Self {
            inner: Arc::new(Mutex::new(core)),
            interfaces,
            event_tx,
            event_rx: Some(event_rx),
            shutdown_tx: None,
            runner_handle: None,
            action_dispatch_tx,
            corrupt_every,
        }
    }

    /// Start the node
    ///
    /// This spawns the internal event loop and initializes interfaces.
    /// The node will process incoming packets and emit events until `stop()` is called.
    pub async fn start(&mut self) -> Result<(), Error> {
        if self.runner_handle.is_some() {
            return Err(Error::Config("node already running".to_string()));
        }

        // Shared monotonic counter for interface IDs.
        // Initialized at interfaces.len() so static and dynamic IDs never collide.
        let next_id = Arc::new(AtomicUsize::new(self.interfaces.len()));

        // Channel for dynamically registering interfaces (e.g. from TCP server accept loop)
        let (new_iface_tx, new_iface_rx) = mpsc::channel::<InterfaceHandle>(32);

        // Initialize interfaces — the driver owns them, NOT NodeCore
        let registry = self.initialize_interfaces(&next_id, &new_iface_tx)?;

        {
            let mut core = self.inner.lock().unwrap();

            // Register human-readable interface names with core for log messages
            for handle in registry.handles() {
                core.set_interface_name(handle.info.id.0, handle.info.name.clone());
            }

            let transport_enabled = core.transport_config().enable_transport;
            let iface_count = self.interfaces.iter().filter(|c| c.enabled).count();
            tracing::info!(
                "Node started with {} interface(s), transport {}",
                iface_count,
                if transport_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        // Channel for dispatching TickOutput from outside the event loop.
        // connect(), send_on_link(), close_link(), and
        // announce_destination() produce actions that must reach the event loop
        // for interface dispatch.  Capacity 256 is generous — each call
        // produces exactly one TickOutput, and the event loop drains them on
        // every iteration, so the queue only backs up if the event loop is
        // blocked (which also stalls all other I/O).
        let (action_dispatch_tx, action_dispatch_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        self.action_dispatch_tx = action_dispatch_tx;

        // Clone handles for the runner
        let inner = Arc::clone(&self.inner);
        let event_tx = self.event_tx.clone();

        // Spawn the runner
        let runner_handle = tokio::spawn(async move {
            run_event_loop(
                inner,
                registry,
                event_tx,
                action_dispatch_rx,
                new_iface_rx,
                shutdown_rx,
            )
            .await;
        });

        self.runner_handle = Some(runner_handle);

        Ok(())
    }

    /// Initialize interfaces from configuration
    ///
    /// Static interfaces (TCP clients) are connected and registered directly.
    /// Server listeners spawn accept loops that send new handles via `new_iface_tx`.
    fn initialize_interfaces(
        &self,
        next_id: &Arc<AtomicUsize>,
        new_iface_tx: &mpsc::Sender<InterfaceHandle>,
    ) -> Result<InterfaceRegistry, Error> {
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

                    let addr_str = format!("{}:{}", target_host, target_port);
                    let addr: SocketAddr = addr_str
                        .as_str()
                        .to_socket_addrs()
                        .map_err(|e| Error::Config(format!("cannot resolve {}: {}", addr_str, e)))?
                        .next()
                        .ok_or_else(|| Error::Config(format!("no addresses for {}", addr_str)))?;

                    let iface_name = format!("tcp_client_{}", idx);
                    let id = InterfaceId(idx);
                    let buffer_size = config.buffer_size.unwrap_or(TCP_DEFAULT_BUFFER_SIZE);
                    let reconnect_interval =
                        Duration::from_secs(config.reconnect_interval_secs.unwrap_or(5));

                    // NOTE: TCP interfaces don't register a bitrate cap
                    // (bitrate=0 means unlimited). Future LoRa/serial interfaces
                    // should call transport.register_interface_bitrate(id, bitrate)
                    // after registration to enable per-interface announce caps.
                    let handle = spawn_tcp_client_with_reconnect(
                        id,
                        iface_name,
                        addr,
                        buffer_size,
                        self.corrupt_every,
                        reconnect_interval,
                        config.max_reconnect_tries,
                    );
                    tracing::info!("TCP client interface for {} (reconnect enabled)", addr);
                    registry.register(handle);
                }
                "TCPServerInterface" => {
                    let listen_ip = config.listen_ip.as_deref().unwrap_or("0.0.0.0");
                    let listen_port = config.listen_port.ok_or_else(|| {
                        Error::Config("TCPServerInterface requires listen_port".to_string())
                    })?;

                    let addr: SocketAddr = format!("{}:{}", listen_ip, listen_port)
                        .parse()
                        .map_err(|e| Error::Config(format!("invalid listen address: {}", e)))?;

                    let buffer_size = config.buffer_size.unwrap_or(TCP_DEFAULT_BUFFER_SIZE);
                    spawn_tcp_server(
                        addr,
                        next_id.clone(),
                        new_iface_tx.clone(),
                        buffer_size,
                        self.corrupt_every,
                    )?;
                }
                "UDPInterface" => {
                    let listen_ip = config.listen_ip.as_deref().unwrap_or("0.0.0.0");
                    let listen_port = config.listen_port.ok_or_else(|| {
                        Error::Config("UDPInterface requires listen_port".to_string())
                    })?;
                    let forward_ip = config.forward_ip.as_ref().ok_or_else(|| {
                        Error::Config("UDPInterface requires forward_ip".to_string())
                    })?;
                    let forward_port = config.forward_port.ok_or_else(|| {
                        Error::Config("UDPInterface requires forward_port".to_string())
                    })?;

                    let listen_addr: SocketAddr = format!("{}:{}", listen_ip, listen_port)
                        .parse()
                        .map_err(|e| {
                            Error::Config(format!("UDPInterface invalid listen address: {}", e))
                        })?;
                    let forward_addr: SocketAddr = format!("{}:{}", forward_ip, forward_port)
                        .parse()
                        .map_err(|e| {
                            Error::Config(format!("UDPInterface invalid forward address: {}", e))
                        })?;

                    let iface_name = format!("udp_{}", idx);
                    let id = InterfaceId(idx);
                    let handle = spawn_udp_interface(id, iface_name, listen_addr, forward_addr)?;
                    tracing::info!(
                        "UDP interface listening on {}, forwarding to {}",
                        listen_addr,
                        forward_addr
                    );
                    registry.register(handle);
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
    /// This signals the event loop to stop, waits for completion, and persists
    /// known destinations to disk.
    pub async fn stop(&mut self) -> Result<(), Error> {
        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }

        // Wait for runner to finish
        if let Some(handle) = self.runner_handle.take() {
            handle
                .await
                .map_err(|e| Error::Config(format!("runner panicked: {}", e)))?;
        }

        // Persist state to disk
        self.save_persistent_state();

        tracing::info!("ReticulumNode stopped");
        Ok(())
    }

    /// Persist all state to disk on shutdown.
    ///
    /// Delegates to `Storage::flush()` which saves known_destinations
    /// and packet_hashlist in Python-compatible formats.
    fn save_persistent_state(&self) {
        use reticulum_core::traits::Storage as _;
        let mut core = self.inner.lock().unwrap();
        core.storage_mut().flush();
    }

    /// Check if the node is running
    pub fn is_running(&self) -> bool {
        self.runner_handle
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or(false)
    }

    /// Register a destination for incoming links
    pub fn register_destination(&self, destination: Destination) {
        let mut inner = self.inner.lock().unwrap();
        inner.register_destination(destination);
    }

    /// Connect to a remote destination
    ///
    /// Sends a link request to the destination and returns a `LinkHandle`
    /// for async read/write operations. The returned handle is usable
    /// immediately, but the link is not yet established — watch for
    /// `NodeEvent::LinkEstablished` on the event channel before sending data.
    ///
    /// Returns `Err` only if the event loop is down (the request could not
    /// be dispatched). Link-level failures arrive as `NodeEvent::LinkClosed`.
    ///
    /// # Arguments
    /// * `dest_hash` - The destination hash to connect to
    /// * `dest_signing_key` - The destination's signing key (from announce)
    pub async fn connect(
        &self,
        dest_hash: &DestinationHash,
        dest_signing_key: &[u8; 32],
    ) -> Result<LinkHandle, Error> {
        // Request link from NodeCore
        let (link_id, _was_routed, output) = {
            let mut inner = self.inner.lock().unwrap();
            inner.connect(*dest_hash, dest_signing_key)
        };
        // Send output to event loop for dispatch (backpressure — waits if full)
        self.action_dispatch_tx
            .send(output)
            .await
            .map_err(|_| Error::NotRunning)?;

        Ok(LinkHandle::new(
            link_id,
            Arc::clone(&self.inner),
            self.action_dispatch_tx.clone(),
        ))
    }

    /// Accept an incoming link request
    ///
    /// Accepts a link request identified by `link_id` (from a `LinkRequest`
    /// event) and returns a `LinkHandle` for async read/write operations.
    /// The link proof packet is queued and dispatched by the event loop.
    ///
    /// # Arguments
    /// * `link_id` - The link ID from the `LinkRequest` event
    pub async fn accept_link(&self, link_id: &LinkId) -> Result<LinkHandle, Error> {
        let output = {
            let mut inner = self.inner.lock().unwrap();
            inner.accept_link(link_id)?
        };

        self.action_dispatch_tx
            .send(output)
            .await
            .map_err(|_| Error::NotRunning)?;

        Ok(LinkHandle::new(
            *link_id,
            Arc::clone(&self.inner),
            self.action_dispatch_tx.clone(),
        ))
    }

    /// Take the event receiver
    ///
    /// This allows consuming node events directly. Can only be called once.
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<NodeEvent>> {
        self.event_rx.take()
    }

    /// Get the number of active (established) links
    pub fn active_link_count(&self) -> usize {
        self.inner.lock().unwrap().active_link_count()
    }

    /// Get the number of pending (not yet established) links
    pub fn pending_link_count(&self) -> usize {
        self.inner.lock().unwrap().pending_link_count()
    }

    /// Get the node's identity hash (16 bytes)
    pub fn identity_hash(&self) -> [u8; 16] {
        *self.inner.lock().unwrap().identity().hash()
    }

    /// Register a known identity for a destination
    ///
    /// Identities learned from received announces are cached automatically —
    /// call this only for out-of-band identity registration or testing.
    pub fn remember_identity(
        &self,
        dest_hash: DestinationHash,
        identity: reticulum_core::Identity,
    ) {
        self.inner
            .lock()
            .unwrap()
            .remember_identity(dest_hash, identity);
    }

    /// Get a handle to the inner NodeCore
    ///
    /// Use this for direct access to the core API.
    #[cfg(test)]
    pub(crate) fn inner(&self) -> Arc<Mutex<StdNodeCore>> {
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

    /// Get link statistics for a link
    pub fn link_stats(
        &self,
        link_id: &reticulum_core::link::LinkId,
    ) -> Option<reticulum_core::node::LinkStats> {
        self.inner.lock().unwrap().link_stats(link_id)
    }

    /// Announce a registered destination on all interfaces
    ///
    /// Builds the announce packet and queues it as a Broadcast action.
    /// The event loop dispatches the action on the next iteration.
    ///
    /// # Arguments
    /// * `dest_hash` - Hash of the registered destination to announce
    /// * `app_data` - Optional application data to include in the announce
    pub async fn announce_destination(
        &self,
        dest_hash: &reticulum_core::DestinationHash,
        app_data: Option<&[u8]>,
    ) -> Result<(), Error> {
        let output = self
            .inner
            .lock()
            .unwrap()
            .announce_destination(dest_hash, app_data)?;
        // Send output to event loop for dispatch (backpressure — waits if full)
        self.action_dispatch_tx
            .send(output)
            .await
            .map_err(|_| Error::NotRunning)?;
        Ok(())
    }

    /// Close a link gracefully
    ///
    /// Sends a LINKCLOSE packet to the peer and removes the link.
    ///
    /// # Arguments
    /// * `link_id` - The link ID of the link to close
    pub async fn close_link(&self, link_id: &LinkId) -> Result<(), Error> {
        let output = {
            let mut inner = self.inner.lock().unwrap();
            inner.close_link(link_id)
        };
        self.action_dispatch_tx
            .send(output)
            .await
            .map_err(|_| Error::NotRunning)?;
        Ok(())
    }

    /// Send a single (fire-and-forget) packet to a destination
    ///
    /// Builds an unreliable data packet addressed to `dest_hash` and queues it
    /// for dispatch. A path to the destination must already be known.
    ///
    /// # Arguments
    /// * `dest_hash` - The destination hash to send to
    /// * `data` - The data to send (must fit in a single packet)
    ///
    /// # Returns
    /// The truncated packet hash, usable for tracking delivery proofs.
    pub async fn send_single_packet(
        &self,
        dest_hash: &DestinationHash,
        data: &[u8],
    ) -> Result<[u8; TRUNCATED_HASHBYTES], Error> {
        let (packet_hash, output) = {
            let mut inner = self.inner.lock().unwrap();
            inner.send_single_packet(dest_hash, data)?
        };
        self.action_dispatch_tx
            .send(output)
            .await
            .map_err(|_| Error::NotRunning)?;
        Ok(packet_hash)
    }

    /// Create a PacketSender for a destination
    ///
    /// Returns a self-contained handle for sending single packets.
    /// No path or destination validation — errors are reported on send().
    pub fn packet_sender(&self, dest_hash: &DestinationHash) -> PacketSender {
        PacketSender::new(
            *dest_hash,
            Arc::clone(&self.inner),
            self.action_dispatch_tx.clone(),
        )
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
async fn run_event_loop(
    inner: Arc<Mutex<StdNodeCore>>,
    mut registry: InterfaceRegistry,
    event_tx: mpsc::Sender<NodeEvent>,
    mut action_dispatch_rx: mpsc::Receiver<TickOutput>,
    mut new_interface_rx: mpsc::Receiver<InterfaceHandle>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut next_poll = tokio::time::Instant::now();
    let mut next_flush = tokio::time::Instant::now() + Duration::from_secs(FLUSH_INTERVAL_SECS);

    loop {
        tokio::select! {
            // Branch 1: Packet from any interface
            event = recv_any(&mut registry) => {
                match event {
                    RecvEvent::Packet(iface_id, pkt) => {
                        let (output, now_ms) = {
                            let mut core = inner.lock().unwrap();
                            let output = core.handle_packet(iface_id, &pkt.data);
                            let now_ms = core.now_ms();
                            (output, now_ms)
                        };
                        // Packet handling may schedule new deadlines (e.g. announce
                        // rebroadcast retries) — advance next_poll if sooner.
                        if let Some(deadline_ms) = output.next_deadline_ms {
                            let delta = deadline_ms.saturating_sub(now_ms);
                            let wake_at = tokio::time::Instant::now()
                                + Duration::from_millis(delta);
                            if wake_at < next_poll {
                                next_poll = wake_at;
                            }
                        }
                        dispatch_output(
                            output,
                            &mut registry,
                            &event_tx,
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
                            &mut registry,
                            &event_tx,
                        );
                        registry.remove(iface_id);
                    }
                }
            }

            // Branch 2: Dispatch TickOutput from outside the event loop
            // (connect, send_on_link, close_link, announce send here)
            Some(output) = action_dispatch_rx.recv() => {
                dispatch_output(
                    output,
                    &mut registry,
                    &event_tx,
                );
            }

            // Branch 3: Timer — persistent deadline, not recomputed per iteration
            _ = tokio::time::sleep_until(next_poll) => {
                let (output, now_ms) = {
                    let mut core = inner.lock().unwrap();
                    let output = core.handle_timeout();
                    let now_ms = core.now_ms();
                    (output, now_ms)
                };
                let next = output.next_deadline_ms;
                dispatch_output(
                    output,
                    &mut registry,
                    &event_tx,
                );

                // Advance next_poll based on next_deadline_ms
                let interval = match next {
                    Some(deadline_ms) => {
                        let delta = deadline_ms.saturating_sub(now_ms);
                        debug_assert!(delta > 0, "next_deadline() returned zero — would cause spin loop");
                        Duration::from_millis(delta.clamp(1, 1000))
                    }
                    None => Duration::from_secs(1),
                };
                next_poll = tokio::time::Instant::now() + interval;
            }

            // Branch 4: Shutdown
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("Node shutdown requested");
                    break;
                }
            }

            // Branch 5: Dynamic interface registration (TCP server accept loop)
            Some(handle) = new_interface_rx.recv() => {
                tracing::info!("New connection: {} ({})", handle.info.name, handle.info.id);
                {
                    let mut core = inner.lock().unwrap();
                    core.set_interface_name(handle.info.id.0, handle.info.name.clone());
                }
                registry.register(handle);
            }

            // Branch 6: Periodic storage flush (persist identities + packet hashes)
            _ = tokio::time::sleep_until(next_flush) => {
                {
                    use reticulum_core::traits::Storage as _;
                    let mut core = inner.lock().unwrap();
                    core.storage_mut().flush();
                }
                next_flush = tokio::time::Instant::now() + Duration::from_secs(FLUSH_INTERVAL_SECS);
            }
        }
    }
}

/// Dispatch a TickOutput: route Actions to interfaces via core, forward Events
fn dispatch_output(
    output: TickOutput,
    registry: &mut InterfaceRegistry,
    event_tx: &mpsc::Sender<NodeEvent>,
) {
    // 1. Dispatch actions to interfaces (protocol logic in core)
    let mut ifaces: Vec<&mut dyn reticulum_core::traits::Interface> = registry
        .handles_mut_slice()
        .iter_mut()
        .map(|h| h as &mut dyn reticulum_core::traits::Interface)
        .collect();
    let errors = reticulum_core::transport::dispatch_actions(&mut ifaces, &output.actions);

    // 2. React to dispatch errors
    for (iface_id, error) in &errors {
        match error {
            InterfaceError::BufferFull => {
                tracing::warn!("Interface {} buffer full, packet dropped", iface_id);
            }
            InterfaceError::Disconnected => {
                tracing::warn!("Interface {} disconnected during dispatch", iface_id);
                // Actual cleanup happens when recv_any() detects channel closure
                // and triggers handle_interface_down(). This is a secondary signal.
            }
        }
    }

    // 3. Forward events to application (best effort — drop if full)
    for event in output.events {
        if let NodeEvent::LinkEstablished { link_id, .. } = &event {
            tracing::debug!("Link established: {:?}", link_id);
        }
        let _ = event_tx.try_send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reticulum_node_builder_creates_node() {
        let node = ReticulumNodeBuilder::new()
            .enable_transport(true)
            .build_sync()
            .expect("build_sync failed");

        assert!(node.is_transport_enabled());
        assert!(!node.is_running());
        assert_eq!(node.path_count(), 0);

        let fake_hash = reticulum_core::DestinationHash::new([0xFF; 16]);
        assert!(!node.has_path(&fake_hash));
        assert!(node.hops_to(&fake_hash).is_none());
    }
}
