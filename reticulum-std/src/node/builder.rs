//! Builder for ReticulumNode
//!
//! Provides fluent configuration for creating ReticulumNode instances.

use std::net::SocketAddr;
use std::path::PathBuf;

use reticulum_core::identity::Identity;
use reticulum_core::traits::{NoStorage, PlatformContext};
use reticulum_core::ProofStrategy;

use crate::clock::SystemClock;
use crate::config::{Config, InterfaceConfig};
use crate::error::Error;
use crate::storage::Storage;

use super::ReticulumNode;

/// Builder for creating ReticulumNode instances
///
/// # Example
///
/// ```no_run
/// use reticulum_std::node::ReticulumNodeBuilder;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let node = ReticulumNodeBuilder::new()
///     .add_tcp_client("127.0.0.1:4242".parse().unwrap())
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct ReticulumNodeBuilder {
    identity: Option<Identity>,
    proof_strategy: ProofStrategy,
    config_path: Option<PathBuf>,
    storage_path: Option<PathBuf>,
    interfaces: Vec<InterfaceConfig>,
    enable_transport: bool,
}

impl Default for ReticulumNodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ReticulumNodeBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self {
            identity: None,
            proof_strategy: ProofStrategy::default(),
            config_path: None,
            storage_path: None,
            interfaces: Vec::new(),
            enable_transport: false,
        }
    }

    /// Set the identity for the node
    ///
    /// If not set, a random identity will be generated.
    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Set the proof strategy for the node
    pub fn proof_strategy(mut self, strategy: ProofStrategy) -> Self {
        self.proof_strategy = strategy;
        self
    }

    /// Load configuration from a file
    ///
    /// If set, the builder will attempt to load configuration from this path.
    /// Interface configurations from the file will be merged with any
    /// manually added interfaces.
    pub fn config_file(mut self, path: PathBuf) -> Self {
        self.config_path = Some(path);
        self
    }

    /// Set the storage path
    ///
    /// If not set, a default path will be used.
    pub fn storage_path(mut self, path: PathBuf) -> Self {
        self.storage_path = Some(path);
        self
    }

    /// Add a TCP client interface
    ///
    /// This connects to a remote Reticulum node as a client.
    pub fn add_tcp_client(mut self, addr: SocketAddr) -> Self {
        self.interfaces.push(InterfaceConfig {
            interface_type: "TCPClientInterface".to_string(),
            enabled: true,
            outgoing: true,
            bitrate: 62500,
            target_host: Some(addr.ip().to_string()),
            target_port: Some(addr.port()),
            listen_ip: None,
            listen_port: None,
            forward_ip: None,
            forward_port: None,
            port: None,
            speed: None,
            databits: None,
            parity: None,
            stopbits: None,
            frequency: None,
            bandwidth: None,
            spreading_factor: None,
            coding_rate: None,
            tx_power: None,
        });
        self
    }

    /// Add a TCP server interface
    ///
    /// This listens for incoming connections from other Reticulum nodes.
    pub fn add_tcp_server(mut self, addr: SocketAddr) -> Self {
        self.interfaces.push(InterfaceConfig {
            interface_type: "TCPServerInterface".to_string(),
            enabled: true,
            outgoing: true,
            bitrate: 62500,
            listen_ip: Some(addr.ip().to_string()),
            listen_port: Some(addr.port()),
            target_host: None,
            target_port: None,
            forward_ip: None,
            forward_port: None,
            port: None,
            speed: None,
            databits: None,
            parity: None,
            stopbits: None,
            frequency: None,
            bandwidth: None,
            spreading_factor: None,
            coding_rate: None,
            tx_power: None,
        });
        self
    }

    /// Enable transport mode
    ///
    /// When enabled, this node will forward packets between interfaces.
    pub fn enable_transport(mut self, enabled: bool) -> Self {
        self.enable_transport = enabled;
        self
    }

    /// Build the ReticulumNode
    ///
    /// This creates the node, initializes storage, and prepares interfaces.
    /// The node is not yet running after this call - use `start()` to begin.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Configuration file loading fails
    /// - Storage initialization fails
    /// - Identity generation fails
    pub async fn build(self) -> Result<ReticulumNode, Error> {
        // Load config if specified
        let config = if let Some(ref path) = self.config_path {
            if path.exists() {
                Config::load(path)?
            } else {
                Config::default()
            }
        } else {
            Config::default()
        };

        // Determine storage path
        let storage_path = self
            .storage_path
            .or_else(|| config.reticulum.storage_path.clone())
            .unwrap_or_else(|| Config::default_config_dir().join("storage"));

        // Initialize storage
        let storage = Storage::new(&storage_path)?;
        let clock = SystemClock::new();

        // Get or generate identity
        let identity = self
            .identity
            .unwrap_or_else(|| Identity::generate_with_rng(&mut rand_core::OsRng));

        // Merge interface configs from file
        let mut interfaces = config
            .interfaces
            .into_values()
            .collect::<Vec<_>>();
        interfaces.extend(self.interfaces);

        // Build NodeCore with identity
        let mut ctx = PlatformContext {
            rng: rand_core::OsRng,
            clock: SystemClock::new(),
            storage: NoStorage,
        };
        let node_core = reticulum_core::node::NodeCoreBuilder::new()
            .identity(identity)
            .proof_strategy(self.proof_strategy)
            .build(&mut ctx, clock, storage)
            .map_err(|e| Error::Transport(format!("{:?}", e)))?;

        Ok(ReticulumNode::new(node_core, interfaces, self.enable_transport))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_default() {
        let builder = ReticulumNodeBuilder::new();
        assert!(builder.identity.is_none());
        assert!(builder.config_path.is_none());
        assert!(builder.interfaces.is_empty());
        assert!(!builder.enable_transport);
    }

    #[test]
    fn test_builder_with_identity() {
        let identity = Identity::generate_with_rng(&mut rand_core::OsRng);
        let builder = ReticulumNodeBuilder::new().identity(identity);
        assert!(builder.identity.is_some());
    }

    #[test]
    fn test_builder_add_tcp_client() {
        let addr: SocketAddr = "127.0.0.1:4242".parse().unwrap();
        let builder = ReticulumNodeBuilder::new().add_tcp_client(addr);
        assert_eq!(builder.interfaces.len(), 1);
        assert_eq!(builder.interfaces[0].interface_type, "TCPClientInterface");
    }

    #[test]
    fn test_builder_enable_transport() {
        let builder = ReticulumNodeBuilder::new().enable_transport(true);
        assert!(builder.enable_transport);
    }
}
