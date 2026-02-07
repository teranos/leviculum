//! Network interfaces
//!
//! Interfaces handle the physical layer communication for Reticulum.
//! Each interface type handles a specific transport medium.
//!
//! `AnyInterface` is an enum over all concrete interface types, and
//! `InterfaceSet` manages a collection of interfaces with async readability
//! notification via `next_packet()`.

pub mod hdlc;
pub mod tcp;

pub use tcp::TcpClientInterface;

use std::task::{Context, Poll};

use reticulum_core::traits::{Interface, InterfaceError};
use reticulum_core::transport::InterfaceId;

/// Enum over all concrete interface types
///
/// Avoids trait objects and enables the event loop to poll for async
/// readability via `poll_recv_packet()`.
pub enum AnyInterface {
    Tcp(TcpClientInterface),
}

impl AnyInterface {
    /// Poll for the next deframed packet (async waker registration)
    pub fn poll_recv_packet(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Vec<u8>, InterfaceError>> {
        match self {
            AnyInterface::Tcp(tcp) => tcp.poll_recv_packet(cx),
        }
    }

    /// Send a framed packet (non-blocking try_write)
    pub fn send(&mut self, data: &[u8]) -> Result<(), InterfaceError> {
        match self {
            AnyInterface::Tcp(tcp) => tcp.send(data),
        }
    }

    /// Check if the interface is online
    pub fn is_online(&self) -> bool {
        match self {
            AnyInterface::Tcp(tcp) => tcp.is_online(),
        }
    }

    /// Get the interface name
    pub fn name(&self) -> &str {
        match self {
            AnyInterface::Tcp(tcp) => tcp.name(),
        }
    }
}

/// Collection of interfaces with round-robin async packet polling
pub struct InterfaceSet {
    interfaces: Vec<(InterfaceId, AnyInterface)>,
    /// Round-robin start index to prevent busy interfaces from starving others
    poll_start: usize,
}

impl Default for InterfaceSet {
    fn default() -> Self {
        Self::new()
    }
}

impl InterfaceSet {
    /// Create an empty interface set
    pub fn new() -> Self {
        Self {
            interfaces: Vec::new(),
            poll_start: 0,
        }
    }

    /// Add an interface and return its assigned ID
    pub fn add(&mut self, iface: AnyInterface) -> InterfaceId {
        let id = InterfaceId(self.interfaces.len());
        self.interfaces.push((id, iface));
        id
    }

    /// Number of interfaces
    pub fn len(&self) -> usize {
        self.interfaces.len()
    }

    /// Whether the set is empty
    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
    }

    /// Await until any interface has a packet ready
    ///
    /// Returns `(InterfaceId, Ok(data))` for a complete packet, or
    /// `(InterfaceId, Err(Disconnected))` when an interface goes down.
    ///
    /// Uses round-robin polling to prevent busy interfaces from starving others.
    /// If all interfaces are offline, returns `Poll::Pending` forever (the event
    /// loop timer branch will still fire).
    pub async fn next_packet(&mut self) -> (InterfaceId, Result<Vec<u8>, InterfaceError>) {
        let len = self.interfaces.len();
        std::future::poll_fn(|cx| {
            for offset in 0..len {
                let idx = (self.poll_start + offset) % len;
                let (id, iface) = &mut self.interfaces[idx];
                if !iface.is_online() {
                    continue;
                }
                match iface.poll_recv_packet(cx) {
                    Poll::Ready(result) => {
                        self.poll_start = (idx + 1) % len;
                        return Poll::Ready((*id, result));
                    }
                    Poll::Pending => {}
                }
            }
            Poll::Pending
        })
        .await
    }

    /// Send on a specific interface (synchronous try_write)
    pub fn send(&mut self, iface: InterfaceId, data: &[u8]) -> Result<(), InterfaceError> {
        if let Some((_, iface_obj)) = self.interfaces.get_mut(iface.0) {
            if iface_obj.is_online() {
                iface_obj.send(data)
            } else {
                Err(InterfaceError::Disconnected)
            }
        } else {
            Err(InterfaceError::Other)
        }
    }

    /// Get the name of an interface by ID, or "unknown" if not found
    pub fn name_of(&self, iface: InterfaceId) -> &str {
        self.interfaces
            .get(iface.0)
            .map(|(_, i)| i.name())
            .unwrap_or("unknown")
    }

    /// Broadcast on all interfaces except excluded (best effort)
    pub fn broadcast(&mut self, data: &[u8], exclude: Option<InterfaceId>) {
        for (id, iface) in self.interfaces.iter_mut() {
            if Some(*id) == exclude {
                continue;
            }
            if iface.is_online() {
                let _ = iface.send(data);
            }
        }
    }
}
