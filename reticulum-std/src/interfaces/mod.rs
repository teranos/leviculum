//! Network interfaces
//!
//! Interfaces handle the physical layer communication for Reticulum.
//! Each interface type runs as a spawned tokio task communicating through
//! channels. `InterfaceHandle` represents the event loop's end of the
//! channel pair, and `InterfaceRegistry` manages all active handles.

pub mod hdlc;
pub(crate) mod tcp;

use reticulum_core::transport::InterfaceId;
use reticulum_net::{IncomingPacket, InterfaceInfo, OutgoingPacket};
use tokio::sync::mpsc;

/// Incoming channel capacity for TCP interfaces
pub(crate) const TCP_INCOMING_CAPACITY: usize = 32;

/// Outgoing channel capacity for TCP interfaces
pub(crate) const TCP_OUTGOING_CAPACITY: usize = 16;

/// Event loop's handle to a spawned interface task
pub(crate) struct InterfaceHandle {
    pub info: InterfaceInfo,
    pub incoming: mpsc::Receiver<IncomingPacket>,
    pub outgoing: mpsc::Sender<OutgoingPacket>,
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

    /// Get the outgoing sender for a specific interface
    pub(crate) fn get_sender(&self, id: InterfaceId) -> Option<&mpsc::Sender<OutgoingPacket>> {
        self.handles
            .iter()
            .find(|h| h.info.id == id)
            .map(|h| &h.outgoing)
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

    /// Iterator over all interface IDs and their outgoing senders (for broadcast)
    pub(crate) fn senders(
        &self,
    ) -> impl Iterator<Item = (InterfaceId, &mpsc::Sender<OutgoingPacket>)> {
        self.handles.iter().map(|h| (h.info.id, &h.outgoing))
    }

    /// Mutable access to handles and poll_start for recv_any
    pub(crate) fn handles_mut(&mut self) -> (&mut Vec<InterfaceHandle>, &mut usize) {
        (&mut self.handles, &mut self.poll_start)
    }
}
