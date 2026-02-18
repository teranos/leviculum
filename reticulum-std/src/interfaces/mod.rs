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

pub mod hdlc;
pub(crate) mod tcp;

use reticulum_core::traits::{InterfaceError, InterfaceMode};
use reticulum_core::transport::InterfaceId;
use tokio::sync::mpsc;

/// Packet received from an interface, ready for the event loop
pub(crate) struct IncomingPacket {
    pub data: Vec<u8>,
}

/// Packet to send out through an interface
pub(crate) struct OutgoingPacket {
    pub data: Vec<u8>,
}

/// Metadata describing a registered interface
pub(crate) struct InterfaceInfo {
    pub id: InterfaceId,
    pub name: String,
}

/// Event loop's handle to a spawned interface task
pub(crate) struct InterfaceHandle {
    pub info: InterfaceInfo,
    pub incoming: mpsc::Receiver<IncomingPacket>,
    pub outgoing: mpsc::Sender<OutgoingPacket>,
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
        match self.outgoing.try_send(OutgoingPacket {
            data: data.to_vec(),
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

    /// Mutable access to handles and poll_start for recv_any
    pub(crate) fn handles_mut(&mut self) -> (&mut Vec<InterfaceHandle>, &mut usize) {
        (&mut self.handles, &mut self.poll_start)
    }

    /// Mutable slice of all handles for dispatch_actions()
    pub(crate) fn handles_mut_slice(&mut self) -> &mut [InterfaceHandle] {
        &mut self.handles
    }
}
