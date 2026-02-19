//! Main Reticulum instance
//!
//! High-level entry point that wires together configuration, storage,
//! core NodeCore, and the async runtime (via `ReticulumNode`).

use reticulum_core::node::NodeEvent;

use tokio::sync::mpsc;

use crate::config::Config;
use crate::driver::{ReticulumNode, ReticulumNodeBuilder};
use crate::error::Result;

/// Main Reticulum instance
///
/// Wraps a `ReticulumNode` with configuration-driven setup.
pub struct Reticulum {
    /// Configuration
    config: Config,
    /// The underlying node
    node: ReticulumNode,
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
    ///
    /// The builder reads enable_transport and interface configurations
    /// from the provided config automatically.
    pub fn with_config(config: Config) -> Result<Self> {
        let builder = ReticulumNodeBuilder::new().config(config.clone());

        Ok(Self {
            config,
            node: builder.build_sync()?,
        })
    }

    /// Start the Reticulum instance (spawns the event loop)
    pub async fn start(&mut self) -> Result<()> {
        self.node.start().await?;
        Ok(())
    }

    /// Stop the Reticulum instance
    pub async fn stop(&mut self) -> Result<()> {
        self.node.stop().await?;
        tracing::info!("Reticulum stopped");
        Ok(())
    }

    /// Check if the instance is running
    pub fn is_running(&self) -> bool {
        self.node.is_running()
    }

    /// Get the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Check if transport mode is enabled
    pub fn is_transport_enabled(&self) -> bool {
        self.node.is_transport_enabled()
    }

    /// Take the event receiver (can only be called once)
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<NodeEvent>> {
        self.node.take_event_receiver()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_instance() {
        let config = Config::default();
        let mut rns = Reticulum::with_config(config).unwrap();

        // Start the node
        rns.start().await.unwrap();
        assert!(rns.is_running());
        assert!(rns.is_transport_enabled());

        // Can take event receiver
        let rx = rns.take_event_receiver();
        assert!(rx.is_some());
        assert!(rns.take_event_receiver().is_none()); // Second call returns None

        rns.stop().await.unwrap();
        assert!(!rns.is_running());
    }

    #[tokio::test]
    async fn test_transport_disabled_via_config() {
        let mut config = Config::default();
        config.reticulum.enable_transport = false;
        let rns = Reticulum::with_config(config).unwrap();
        assert!(!rns.is_transport_enabled());
    }
}
