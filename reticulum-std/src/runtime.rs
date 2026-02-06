//! Async runtime wrapper for core Transport
//!
//! Bridges the sync/polling `Transport` from core with tokio's async runtime.
//!
//! The runtime:
//! - Polls interfaces for incoming data
//! - Feeds received data to `Transport::process_incoming()`
//! - Runs periodic `Transport::poll()` for housekeeping
//! - Forwards events via a tokio channel
//!
//! # Example
//!
//! ```text
//! use reticulum_std::runtime::TransportRunner;
//! use reticulum_core::transport::{Transport, TransportConfig, TransportEvent};
//!
//! let transport = Transport::new(config, clock, storage, identity);
//! let (runner, mut event_rx) = TransportRunner::new(transport);
//!
//! // Spawn the transport loop
//! tokio::spawn(async move {
//!     runner.run(shutdown_rx).await;
//! });
//!
//! // Consume events
//! while let Some(event) = event_rx.recv().await {
//!     match event {
//!         TransportEvent::AnnounceReceived { .. } => { /* ... */ }
//!         _ => {}
//!     }
//! }
//! ```

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use reticulum_core::constants::MTU;
use reticulum_core::traits::InterfaceError;
use reticulum_core::transport::{Transport, TransportEvent};

use crate::clock::SystemClock;
use crate::storage::Storage;

/// Default poll interval in milliseconds
const DEFAULT_POLL_INTERVAL_MS: u64 = 50;

/// Event channel capacity
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Type alias for the concrete Transport used by std platforms
pub type StdTransport = Transport<SystemClock, Storage>;

/// Async runner for the core Transport
///
/// Wraps a `Transport<SystemClock, Storage>` and drives it with tokio.
pub struct TransportRunner {
    transport: Arc<Mutex<StdTransport>>,
    event_tx: mpsc::Sender<TransportEvent>,
    poll_interval: Duration,
}

impl TransportRunner {
    /// Create a new TransportRunner
    ///
    /// Returns the runner and a channel receiver for transport events.
    pub fn new(transport: StdTransport) -> (Self, mpsc::Receiver<TransportEvent>) {
        Self::with_poll_interval(transport, Duration::from_millis(DEFAULT_POLL_INTERVAL_MS))
    }

    /// Create a new TransportRunner with custom poll interval
    pub fn with_poll_interval(
        transport: StdTransport,
        poll_interval: Duration,
    ) -> (Self, mpsc::Receiver<TransportEvent>) {
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);

        let runner = Self {
            transport: Arc::new(Mutex::new(transport)),
            event_tx,
            poll_interval,
        };

        (runner, event_rx)
    }

    /// Get a handle to the transport for external use (registering destinations, etc.)
    pub fn transport(&self) -> Arc<Mutex<StdTransport>> {
        Arc::clone(&self.transport)
    }

    /// Run the transport loop until shutdown
    ///
    /// This polls interfaces for incoming data, processes packets,
    /// and emits events on the channel.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(self.poll_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.tick();
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Transport shutdown requested");
                        break;
                    }
                }
            }
        }
    }

    /// Run a single tick: poll interfaces, process packets, emit events
    fn tick(&self) {
        let mut transport = self.transport.lock().unwrap();

        // Poll all interfaces for incoming data
        let iface_count = transport.interface_count();
        let mut recv_buf = [0u8; MTU];

        for idx in 0..iface_count {
            // Try to receive from each interface
            while let Some(iface) = transport.interface_mut(idx) {
                match iface.recv(&mut recv_buf) {
                    Ok(len) if len > 0 => {
                        let data = recv_buf[..len].to_vec();
                        // Feed to transport
                        if let Err(e) = transport.process_incoming(idx, &data) {
                            tracing::debug!("Error processing packet from interface {idx}: {e:?}");
                        }
                    }
                    Ok(_) | Err(InterfaceError::WouldBlock) => break, // No data available
                    Err(InterfaceError::Disconnected) => {
                        tracing::warn!("Interface {idx} disconnected");
                        break;
                    }
                    Err(e) => {
                        tracing::debug!("Interface {idx} recv error: {e:?}");
                        break;
                    }
                }
            }
        }

        // Run periodic housekeeping
        transport.poll();

        // Forward events to channel
        for event in transport.drain_events() {
            if self.event_tx.try_send(event).is_err() {
                tracing::warn!("Event channel full, dropping event");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::identity::Identity;
    use reticulum_core::transport::TransportConfig;

    // Note: We can't use NoStorage here because TransportRunner requires Storage.
    // We test with the real StdTransport type via a helper that creates a temp storage.

    #[tokio::test]
    async fn test_transport_runner_creation() {
        let clock = SystemClock::new();
        let storage_path =
            std::env::temp_dir().join(format!("reticulum_runner_test_{}", std::process::id()));
        let storage = Storage::new(&storage_path).unwrap();
        let identity = Identity::generate(&mut rand_core::OsRng);
        let config = TransportConfig::default();

        let transport = Transport::new(config, clock, storage, identity);
        let (runner, _event_rx) = TransportRunner::new(transport);

        let transport_handle = runner.transport();
        let t = transport_handle.lock().unwrap();
        assert_eq!(t.interface_count(), 0);

        // Cleanup
        let _ = std::fs::remove_dir_all(&storage_path);
    }

    #[tokio::test]
    async fn test_transport_runner_shutdown() {
        let clock = SystemClock::new();
        let storage_path =
            std::env::temp_dir().join(format!("reticulum_runner_shutdown_{}", std::process::id()));
        let storage = Storage::new(&storage_path).unwrap();
        let identity = Identity::generate(&mut rand_core::OsRng);
        let config = TransportConfig::default();

        let transport = Transport::new(config, clock, storage, identity);
        let (runner, _event_rx) = TransportRunner::new(transport);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Spawn the runner
        let handle = tokio::spawn(async move {
            runner.run(shutdown_rx).await;
        });

        // Let it run briefly
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Signal shutdown
        shutdown_tx.send(true).unwrap();

        // Should complete quickly
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("Runner should shut down within 2 seconds")
            .expect("Runner task should not panic");

        // Cleanup
        let _ = std::fs::remove_dir_all(&storage_path);
    }
}
