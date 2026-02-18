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
    pub fn with_config(config: Config) -> Result<Self> {
        let mut builder = ReticulumNodeBuilder::new();

        if config.reticulum.enable_transport {
            builder = builder.enable_transport(true);
        }

        // Wire config interfaces to the builder
        for (name, iface) in &config.interfaces {
            if !iface.enabled {
                continue;
            }
            match iface.interface_type.as_str() {
                "TCPClientInterface" => {
                    let target_host = iface.target_host.as_ref().ok_or_else(|| {
                        crate::error::Error::Config(format!(
                            "interface '{}': TCPClientInterface requires target_host",
                            name
                        ))
                    })?;
                    let target_port = iface.target_port.ok_or_else(|| {
                        crate::error::Error::Config(format!(
                            "interface '{}': TCPClientInterface requires target_port",
                            name
                        ))
                    })?;
                    let addr: std::net::SocketAddr = format!("{}:{}", target_host, target_port)
                        .parse()
                        .map_err(|e| {
                            crate::error::Error::Config(format!(
                                "interface '{}': invalid address: {}",
                                name, e
                            ))
                        })?;
                    builder = builder.add_tcp_client(addr);
                }
                "TCPServerInterface" => {
                    let listen_ip = iface.listen_ip.as_deref().unwrap_or("0.0.0.0");
                    let listen_port = iface.listen_port.ok_or_else(|| {
                        crate::error::Error::Config(format!(
                            "interface '{}': TCPServerInterface requires listen_port",
                            name
                        ))
                    })?;
                    let addr: std::net::SocketAddr = format!("{}:{}", listen_ip, listen_port)
                        .parse()
                        .map_err(|e| {
                            crate::error::Error::Config(format!(
                                "interface '{}': invalid listen address: {}",
                                name, e
                            ))
                        })?;
                    builder = builder.add_tcp_server(addr);
                }
                other => {
                    tracing::warn!(name, r#type = other, "unknown interface type, skipping");
                }
            }
        }

        // Two-phase pattern: sync construction here, async start() later.
        // This allows callers to configure the node synchronously before
        // entering an async runtime.
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
        self.config.reticulum.enable_transport
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
        assert!(!rns.is_transport_enabled());

        // Can take event receiver
        let rx = rns.take_event_receiver();
        assert!(rx.is_some());
        assert!(rns.take_event_receiver().is_none()); // Second call returns None

        rns.stop().await.unwrap();
        assert!(!rns.is_running());
    }
}
