//! Main Reticulum instance
//!
//! High-level entry point that wires together configuration, storage,
//! core Transport, and the async runtime.

use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, watch};

use reticulum_core::identity::Identity;
use reticulum_core::transport::{Transport, TransportConfig, TransportEvent};

use crate::clock::SystemClock;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::runtime::{StdTransport, TransportRunner};
use crate::storage::Storage;

/// Main Reticulum instance
pub struct Reticulum {
    /// Configuration
    config: Config,
    /// Handle to the core transport (shared with the runner)
    transport: Arc<Mutex<StdTransport>>,
    /// Event receiver
    event_rx: Option<mpsc::Receiver<TransportEvent>>,
    /// Shutdown sender
    shutdown_tx: watch::Sender<bool>,
    /// Runner task handle
    runner_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Reticulum {
    /// Create a new Reticulum instance with default configuration
    pub fn new() -> Result<Self> {
        let config_path = Config::default_config_path();
        let config = if config_path.exists() {
            Config::load(&config_path)?
        } else {
            Config::default()
        };

        Self::with_config(config)
    }

    /// Create a new Reticulum instance with custom configuration
    pub fn with_config(config: Config) -> Result<Self> {
        let storage_path = config
            .reticulum
            .storage_path
            .clone()
            .unwrap_or_else(|| Config::default_config_dir().join("storage"));

        let storage = Storage::new(&storage_path)?;
        let clock = SystemClock::new();
        let identity = Identity::generate_with_rng(&mut rand_core::OsRng);

        let transport_config = TransportConfig {
            enable_transport: config.reticulum.enable_transport,
            ..TransportConfig::default()
        };

        let transport = Transport::new(transport_config, clock, storage, identity);
        let (runner, event_rx) = TransportRunner::new(transport);
        let transport_handle = runner.transport();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Spawn the runner
        let runner_handle = tokio::spawn(async move {
            runner.run(shutdown_rx).await;
        });

        Ok(Self {
            config,
            transport: transport_handle,
            event_rx: Some(event_rx),
            shutdown_tx,
            runner_handle: Some(runner_handle),
        })
    }

    /// Stop the Reticulum instance
    pub async fn stop(&mut self) -> Result<()> {
        // Signal shutdown
        let _ = self.shutdown_tx.send(true);

        // Wait for runner to finish
        if let Some(handle) = self.runner_handle.take() {
            handle
                .await
                .map_err(|e| Error::Transport(format!("Runner panicked: {e}")))?;
        }

        tracing::info!("Reticulum stopped");
        Ok(())
    }

    /// Check if the instance is running
    pub fn is_running(&self) -> bool {
        self.runner_handle
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or(false)
    }

    /// Get the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Check if transport mode is enabled
    pub fn is_transport_enabled(&self) -> bool {
        self.config.reticulum.enable_transport
    }

    /// Get a handle to the core transport
    ///
    /// Use this to register interfaces, destinations, query paths, etc.
    pub fn transport(&self) -> Arc<Mutex<StdTransport>> {
        Arc::clone(&self.transport)
    }

    /// Take the event receiver (can only be called once)
    ///
    /// Use this to consume transport events (announces, packets, etc.).
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<TransportEvent>> {
        self.event_rx.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_instance() {
        let config = Config::default();
        let mut rns = Reticulum::with_config(config).unwrap();
        assert!(rns.is_running());
        assert!(!rns.is_transport_enabled());

        // Verify transport is accessible
        {
            let handle = rns.transport();
            let t = handle.lock().unwrap();
            assert_eq!(t.interface_count(), 0);
        }

        // Can take event receiver
        let rx = rns.take_event_receiver();
        assert!(rx.is_some());
        assert!(rns.take_event_receiver().is_none()); // Second call returns None

        rns.stop().await.unwrap();
        assert!(!rns.is_running());
    }
}
