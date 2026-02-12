//! Send-only async handle for single-packet destinations
//!
//! Provides a self-contained handle for fire-and-forget packet delivery
//! to a specific destination. The single-packet analog of ConnectionStream.

use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use reticulum_core::constants::TRUNCATED_HASHBYTES;
use reticulum_core::transport::TickOutput;
use reticulum_core::DestinationHash;

use super::StdNodeCore;
use crate::error::Error;

/// Async handle for sending single packets to a destination
///
/// `PacketEndpoint` provides a self-contained handle for fire-and-forget
/// packet delivery to a specific destination hash. It is the single-packet
/// analog of [`super::ConnectionStream`].
///
/// Created via [`super::ReticulumNodeImpl::packet_endpoint()`]. The handle
/// locks the core to build the packet and dispatches the resulting actions
/// through the event loop.
///
/// # Example
///
/// ```no_run
/// # use reticulum_std::driver::{ReticulumNodeBuilder, PacketEndpoint};
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let node = ReticulumNodeBuilder::new().build().await?;
/// # let dest_hash = reticulum_core::DestinationHash::new([0; 16]);
/// let endpoint = node.packet_endpoint(&dest_hash);
///
/// // Send a single packet
/// let _hash = endpoint.send(b"Hello!").await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct PacketEndpoint {
    dest_hash: DestinationHash,
    inner: Arc<Mutex<StdNodeCore>>,
    action_dispatch_tx: mpsc::Sender<TickOutput>,
}

impl PacketEndpoint {
    /// Create a new PacketEndpoint (crate-private, like ConnectionStream)
    pub(crate) fn new(
        dest_hash: DestinationHash,
        inner: Arc<Mutex<StdNodeCore>>,
        action_dispatch_tx: mpsc::Sender<TickOutput>,
    ) -> Self {
        Self {
            dest_hash,
            inner,
            action_dispatch_tx,
        }
    }

    /// Get the destination hash for this endpoint
    pub fn dest_hash(&self) -> &DestinationHash {
        &self.dest_hash
    }

    /// Send a single packet to the destination
    ///
    /// Builds an unreliable data packet and queues it for dispatch.
    /// A path to the destination must already be known.
    ///
    /// # Returns
    /// The truncated packet hash, usable for tracking delivery proofs.
    pub async fn send(&self, data: &[u8]) -> Result<[u8; TRUNCATED_HASHBYTES], Error> {
        let (packet_hash, output) = {
            let mut core = self.inner.lock().unwrap();
            core.send_single_packet(&self.dest_hash, data)
                .map_err(|e| Error::Transport(e.to_string()))?
        };
        self.action_dispatch_tx
            .send(output)
            .await
            .map_err(|_| Error::Transport("event loop shut down".to_string()))?;
        Ok(packet_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::ReticulumNodeBuilder;

    fn make_node_and_inner() -> (Arc<Mutex<StdNodeCore>>, mpsc::Sender<TickOutput>) {
        let node = ReticulumNodeBuilder::new()
            .build_sync()
            .expect("build_sync");
        let inner = node.inner();
        let (tx, _rx) = mpsc::channel(16);
        (inner, tx)
    }

    #[tokio::test]
    async fn test_packet_endpoint_dest_hash() {
        let (inner, tx) = make_node_and_inner();
        let dest_hash = DestinationHash::new([0xAB; 16]);
        let ep = PacketEndpoint::new(dest_hash, inner, tx);

        assert_eq!(*ep.dest_hash(), dest_hash);
    }

    #[tokio::test]
    async fn test_packet_endpoint_send_no_path_returns_error() {
        let (inner, tx) = make_node_and_inner();
        let dest_hash = DestinationHash::new([0xAB; 16]);
        let ep = PacketEndpoint::new(dest_hash, inner, tx);

        let result = ep.send(b"hello").await;
        assert!(result.is_err(), "send with no path should fail");
    }

    #[tokio::test]
    async fn test_packet_endpoint_send_closed_channel() {
        let (inner, _) = make_node_and_inner();

        // Register a destination and announce so a path exists
        let id = reticulum_core::Identity::generate(&mut rand_core::OsRng);
        let dest = reticulum_core::Destination::new(
            Some(id),
            reticulum_core::Direction::In,
            reticulum_core::DestinationType::Single,
            "test",
            &["endpoint"],
        )
        .unwrap();
        let dest_hash = *dest.hash();
        inner.lock().unwrap().register_destination(dest);
        // Announce creates a local path entry
        let _ = inner.lock().unwrap().announce_destination(&dest_hash, None);

        // Create endpoint with a closed channel
        let (tx, rx) = mpsc::channel::<TickOutput>(1);
        drop(rx); // close the receiver

        let ep = PacketEndpoint::new(dest_hash, Arc::clone(&inner), tx);
        let result = ep.send(b"hello").await;
        assert!(result.is_err(), "send on closed channel should fail");
    }
}
