//! Network interfaces
//!
//! Interfaces handle the physical layer communication for Reticulum.
//! Each interface type runs as a spawned tokio task communicating through
//! channels. `InterfaceHandle` represents the event loop's end of the
//! channel pair, and `InterfaceRegistry` manages all active handles.
//!
//! `InterfaceHandle` implements [`reticulum_core::traits::Interface`] so that
//! core's [`dispatch_actions()`](reticulum_core::transport::dispatch_actions)
//! can route packets to interfaces directly.

pub(crate) mod airtime;
pub mod auto_interface;
pub mod hdlc;
pub(crate) mod local;
pub(crate) mod rnode;
pub(crate) mod serial;
pub(crate) mod tcp;
pub(crate) mod udp;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use reticulum_core::traits::{InterfaceError, InterfaceMode};
use reticulum_core::transport::InterfaceId;
use tokio::sync::mpsc;

/// Speed sampling state, updated every second by the traffic counter task.
struct SpeedState {
    prev_rx: u64,
    prev_tx: u64,
    prev_time: Instant,
    cached_rxs: f64,
    cached_txs: f64,
}

/// Shared I/O counters for an interface, readable from the RPC handler.
///
/// Created by each interface spawn function, cloned into the I/O task.
/// The RPC handler reads these via `InterfaceStatsMap`.
///
/// `rx_bytes`/`tx_bytes` are written by I/O tasks (lock-free atomics).
/// `speed` is updated every second by a background task (see
/// `spawn_traffic_counter`) and read by the RPC handler.
pub(crate) struct InterfaceCounters {
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    speed: std::sync::Mutex<SpeedState>,
}

impl InterfaceCounters {
    pub(crate) fn new() -> Self {
        Self {
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            speed: std::sync::Mutex::new(SpeedState {
                prev_rx: 0,
                prev_tx: 0,
                prev_time: Instant::now(),
                cached_rxs: 0.0,
                cached_txs: 0.0,
            }),
        }
    }

    /// Sample current byte counters and recompute cached speeds.
    ///
    /// Called every second by the traffic counter task. Formula matches
    /// Python's `count_traffic_loop`: `(byte_diff * 8) / time_diff`.
    pub(crate) fn update_speed(&self) {
        let mut state = self.speed.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(state.prev_time).as_secs_f64();
        if elapsed > 0.0 {
            let rx = self.rx_bytes.load(Ordering::Relaxed);
            let tx = self.tx_bytes.load(Ordering::Relaxed);
            state.cached_rxs = (rx.saturating_sub(state.prev_rx) as f64 * 8.0) / elapsed;
            state.cached_txs = (tx.saturating_sub(state.prev_tx) as f64 * 8.0) / elapsed;
            state.prev_rx = rx;
            state.prev_tx = tx;
            state.prev_time = now;
        }
    }

    /// Return the cached rx/tx speeds in bits per second.
    ///
    /// Returns the values last computed by `update_speed()`.
    pub(crate) fn speeds(&self) -> (f64, f64) {
        let state = self.speed.lock().unwrap();
        (state.cached_rxs, state.cached_txs)
    }
}

/// Spawn a background task that samples interface byte counters every second
/// and updates cached speeds. Mirrors Python's `Transport.count_traffic_loop()`.
pub(crate) fn spawn_traffic_counter(iface_stats_map: InterfaceStatsMap) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            let map = iface_stats_map.lock().unwrap();
            for counters in map.values() {
                counters.update_speed();
            }
        }
    });
}

/// Shared map of interface counters, keyed by interface ID index.
///
/// Populated by the event loop when handles are registered.
/// Read by the RPC handler for byte counter reporting.
pub(crate) type InterfaceStatsMap =
    Arc<std::sync::Mutex<std::collections::BTreeMap<usize, Arc<InterfaceCounters>>>>;

/// Packet received from an interface, ready for the event loop
pub(crate) struct IncomingPacket {
    pub data: Vec<u8>,
}

/// Packet to send out through an interface
pub(crate) struct OutgoingPacket {
    pub data: Vec<u8>,
    /// High-priority packets (link requests, proofs, channel data) are sent
    /// before normal-priority packets (announce rebroadcasts) on constrained
    /// interfaces like LoRa. Read by RNode send queue (behind `serial` feature).
    pub high_priority: bool,
}

/// Metadata describing a registered interface
pub(crate) struct InterfaceInfo {
    pub id: InterfaceId,
    pub name: String,
    /// Hardware MTU for link MTU negotiation (e.g., TCP=262144, UDP=1064).
    /// `None` means the interface uses the base protocol MTU (500).
    pub hw_mtu: Option<u32>,
    /// Whether this interface is a local IPC client (shared instance).
    /// Local clients receive announce forwarding and path request routing.
    pub is_local_client: bool,
    /// On-air bitrate in bits/sec (e.g., LoRa ~5468 bps for SF7/CR5/BW125kHz).
    /// `None` for interfaces without a fixed bitrate (TCP, UDP).
    pub bitrate: Option<u32>,
    /// IFAC config inherited from the parent interface (e.g., TCP server listener).
    /// When a TCP server accepts a connection, the child interface inherits the
    /// parent's IFAC config so that IFAC verification/application works on the
    /// dynamically-created interface.
    pub ifac: Option<reticulum_core::ifac::IfacConfig>,
}

/// Event loop's handle to a spawned interface task
pub(crate) struct InterfaceHandle {
    pub info: InterfaceInfo,
    pub incoming: mpsc::Receiver<IncomingPacket>,
    pub outgoing: mpsc::Sender<OutgoingPacket>,
    pub counters: Arc<InterfaceCounters>,
}

impl reticulum_core::traits::Interface for InterfaceHandle {
    fn id(&self) -> InterfaceId {
        self.info.id
    }
    fn name(&self) -> &str {
        &self.info.name
    }
    fn mtu(&self) -> usize {
        reticulum_core::constants::MTU
    }
    fn mode(&self) -> InterfaceMode {
        InterfaceMode::default()
    }
    fn is_online(&self) -> bool {
        !self.outgoing.is_closed()
    }
    fn try_send(&mut self, data: &[u8]) -> Result<(), InterfaceError> {
        self.try_send_prioritized(data, false)
    }
    fn try_send_prioritized(
        &mut self,
        data: &[u8],
        high_priority: bool,
    ) -> Result<(), InterfaceError> {
        match self.outgoing.try_send(OutgoingPacket {
            data: data.to_vec(),
            high_priority,
        }) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Err(InterfaceError::BufferFull),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                Err(InterfaceError::Disconnected)
            }
        }
    }
}

/// Registry of active interface handles with round-robin polling
pub(crate) struct InterfaceRegistry {
    handles: Vec<InterfaceHandle>,
    /// Round-robin start index to prevent busy interfaces from starving others
    poll_start: usize,
}

impl InterfaceRegistry {
    /// Create an empty registry
    pub(crate) fn new() -> Self {
        Self {
            handles: Vec::new(),
            poll_start: 0,
        }
    }

    /// Register a new interface handle
    pub(crate) fn register(&mut self, handle: InterfaceHandle) {
        self.handles.push(handle);
    }

    /// Remove an interface by ID, returns true if found
    pub(crate) fn remove(&mut self, id: InterfaceId) -> bool {
        let before = self.handles.len();
        self.handles.retain(|h| h.info.id != id);
        let removed = self.handles.len() < before;
        if removed && !self.handles.is_empty() {
            self.poll_start %= self.handles.len();
        } else if self.handles.is_empty() {
            self.poll_start = 0;
        }
        removed
    }

    /// Whether the registry has no interfaces
    pub(crate) fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// Get the name of an interface by ID
    pub(crate) fn name_of(&self, id: InterfaceId) -> &str {
        self.handles
            .iter()
            .find(|h| h.info.id == id)
            .map(|h| h.info.name.as_str())
            .unwrap_or("unknown")
    }

    /// Immutable slice of all handles
    pub(crate) fn handles(&self) -> &[InterfaceHandle] {
        &self.handles
    }

    /// Mutable access to handles and poll_start for recv_any
    pub(crate) fn handles_mut(&mut self) -> (&mut Vec<InterfaceHandle>, &mut usize) {
        (&mut self.handles, &mut self.poll_start)
    }

    /// Mutable slice of all handles for dispatch_actions()
    pub(crate) fn handles_mut_slice(&mut self) -> &mut [InterfaceHandle] {
        &mut self.handles
    }
}
