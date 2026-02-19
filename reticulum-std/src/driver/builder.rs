//! Builder for ReticulumNode
//!
//! Provides fluent configuration for creating ReticulumNode instances.

use std::net::SocketAddr;
use std::path::PathBuf;

use reticulum_core::identity::Identity;
use reticulum_core::node::NodeCoreBuilder;
use reticulum_core::ProofStrategy;

use crate::clock::SystemClock;
use crate::config::{Config, InterfaceConfig, DEFAULT_BITRATE_BPS};
use crate::error::Error;
use crate::storage::Storage;

use super::ReticulumNode;

/// Builder for creating ReticulumNode instances
///
/// # Example
///
/// ```no_run
/// use reticulum_std::driver::ReticulumNodeBuilder;
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
    core_builder: NodeCoreBuilder,
    /// Pre-loaded config (takes priority over config_path)
    loaded_config: Option<Config>,
    config_path: Option<PathBuf>,
    storage_path: Option<PathBuf>,
    interfaces: Vec<InterfaceConfig>,
    corrupt_every: Option<u64>,
    /// Explicit enable_transport override (takes priority over config value)
    enable_transport_explicit: Option<bool>,
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
            core_builder: NodeCoreBuilder::new(),
            loaded_config: None,
            config_path: None,
            storage_path: None,
            interfaces: Vec::new(),
            corrupt_every: None,
            enable_transport_explicit: None,
        }
    }

    /// Set the identity for the node
    ///
    /// If not set, a random identity will be generated.
    pub fn identity(mut self, identity: Identity) -> Self {
        self.core_builder = self.core_builder.identity(identity);
        self
    }

    /// Set the proof strategy for the node
    pub fn proof_strategy(mut self, strategy: ProofStrategy) -> Self {
        self.core_builder = self.core_builder.proof_strategy(strategy);
        self
    }

    /// Use a pre-loaded configuration
    ///
    /// The builder will use this config for storage path, interface
    /// configurations, and transport settings. Takes priority over
    /// `config_file()`.
    pub fn config(mut self, config: Config) -> Self {
        self.loaded_config = Some(config);
        self
    }

    /// Load configuration from a file
    ///
    /// If set, the builder will attempt to load configuration from this path.
    /// Interface configurations from the file will be merged with any
    /// manually added interfaces. Ignored if `config()` was called.
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
            bitrate: DEFAULT_BITRATE_BPS,
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
            buffer_size: None,
            reconnect_interval_secs: None,
            max_reconnect_tries: None,
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
            bitrate: DEFAULT_BITRATE_BPS,
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
            buffer_size: None,
            reconnect_interval_secs: None,
            max_reconnect_tries: None,
            frequency: None,
            bandwidth: None,
            spreading_factor: None,
            coding_rate: None,
            tx_power: None,
        });
        self
    }

    /// Add a UDP interface
    ///
    /// Binds to `listen_addr` for incoming datagrams and sends outgoing
    /// datagrams to `forward_addr`. No framing — each datagram is one packet.
    pub fn add_udp_interface(mut self, listen_addr: SocketAddr, forward_addr: SocketAddr) -> Self {
        self.interfaces.push(InterfaceConfig {
            interface_type: "UDPInterface".to_string(),
            enabled: true,
            outgoing: true,
            bitrate: DEFAULT_BITRATE_BPS,
            listen_ip: Some(listen_addr.ip().to_string()),
            listen_port: Some(listen_addr.port()),
            forward_ip: Some(forward_addr.ip().to_string()),
            forward_port: Some(forward_addr.port()),
            target_host: None,
            target_port: None,
            port: None,
            speed: None,
            databits: None,
            parity: None,
            stopbits: None,
            buffer_size: None,
            reconnect_interval_secs: None,
            max_reconnect_tries: None,
            frequency: None,
            bandwidth: None,
            spreading_factor: None,
            coding_rate: None,
            tx_power: None,
        });
        self
    }

    /// Enable fault injection: corrupt ~1 byte per N bytes on TCP write
    pub fn corrupt_every(mut self, n: Option<u64>) -> Self {
        self.corrupt_every = n;
        self
    }

    /// Enable or disable transport mode
    ///
    /// When enabled, this node will forward packets between interfaces.
    /// If not called, the value from the loaded config is used (default: true).
    pub fn enable_transport(mut self, enabled: bool) -> Self {
        self.enable_transport_explicit = Some(enabled);
        self
    }

    /// Set path expiry duration in seconds.
    ///
    /// Paths not refreshed within this duration will be removed.
    /// Default is 7 days (604800 seconds).
    pub fn path_expiry_secs(mut self, secs: u64) -> Self {
        self.core_builder = self.core_builder.path_expiry_secs(secs);
        self
    }

    /// Resolve config: pre-loaded > loaded from path > default
    fn resolve_config(&self) -> Result<Config, Error> {
        if let Some(ref config) = self.loaded_config {
            return Ok(config.clone());
        }
        if let Some(ref path) = self.config_path {
            if path.exists() {
                return Config::load(path);
            }
        }
        Ok(Config::default())
    }

    /// Build the ReticulumNode synchronously
    ///
    /// Same as `build()` but does not require an async context.
    /// Useful when constructing a node outside of an async runtime.
    pub fn build_sync(self) -> Result<ReticulumNode, Error> {
        // Resolve config: pre-loaded > loaded from path > default
        let config = self.resolve_config()?;

        // Apply enable_transport: explicit override > config value
        let enable_transport = self
            .enable_transport_explicit
            .unwrap_or(config.reticulum.enable_transport);

        // Determine storage path
        let storage_path = self
            .storage_path
            .or_else(|| config.reticulum.storage_path.clone())
            .unwrap_or_else(|| Config::default_config_dir().join("storage"));

        // Storage::new() loads persistent data (known_destinations, packet_hashlist)
        // into its inner MemoryStorage automatically.
        let storage = Storage::new(&storage_path)?;
        let clock = SystemClock::new();

        // Merge interface configs from file
        let mut interfaces = config.interfaces.into_values().collect::<Vec<_>>();
        interfaces.extend(self.interfaces);

        // Load or generate transport identity (unless explicitly set)
        let core_builder = if self.core_builder.identity_ref().is_none() {
            let identity = load_or_generate_transport_identity(&storage)?;
            self.core_builder.identity(identity)
        } else {
            self.core_builder
        };
        let core_builder = core_builder.enable_transport(enable_transport);

        // Build NodeCore (consumes storage — persistent data already loaded)
        let node_core = core_builder.build(rand_core::OsRng, clock, storage);

        Ok(ReticulumNode::new(
            node_core,
            interfaces,
            self.corrupt_every,
        ))
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
        // Async version delegates to build_sync (no async operations needed here)
        self.build_sync()
    }
}

const IDENTITY_FILE: &str = "transport_identity";

/// Load an existing transport identity from storage, or generate and persist a new one.
///
/// The identity is stored as 64 raw bytes (32 X25519 private + 32 Ed25519 private)
/// in the storage root, matching the Python Reticulum format exactly.
fn load_or_generate_transport_identity(storage: &Storage) -> Result<Identity, Error> {
    match storage.read_root(IDENTITY_FILE) {
        Ok(bytes) if bytes.len() == 64 => {
            let id = Identity::from_private_key_bytes(&bytes)
                .map_err(|e| Error::Storage(format!("invalid transport_identity: {e}")))?;
            tracing::info!("Loaded transport identity: {}", hex_short(id.hash()),);
            Ok(id)
        }
        Ok(bytes) => Err(Error::Storage(format!(
            "transport_identity has wrong size: {} (expected 64)",
            bytes.len()
        ))),
        Err(_) => {
            let id = Identity::generate(&mut rand_core::OsRng);
            let bytes = id
                .private_key_bytes()
                .map_err(|e| Error::Storage(format!("failed to serialize identity: {e}")))?;
            storage.write_root(IDENTITY_FILE, &bytes)?;
            tracing::info!("Generated new transport identity: {}", hex_short(id.hash()),);
            Ok(id)
        }
    }
}

/// Format the first 8 bytes of a hash as hex for logging
fn hex_short(hash: &[u8]) -> String {
    use std::fmt::Write;
    let n = hash.len().min(8);
    hash[..n]
        .iter()
        .fold(String::with_capacity(n * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_default() {
        let builder = ReticulumNodeBuilder::new();
        assert!(builder.config_path.is_none());
        assert!(builder.interfaces.is_empty());
    }

    #[test]
    fn test_builder_with_identity() {
        let identity = Identity::generate(&mut rand_core::OsRng);
        let _builder = ReticulumNodeBuilder::new().identity(identity);
        // Identity is consumed by NodeCoreBuilder, verified by the build test
    }

    #[test]
    fn test_builder_add_tcp_client() {
        let addr: SocketAddr = "127.0.0.1:4242".parse().unwrap();
        let builder = ReticulumNodeBuilder::new().add_tcp_client(addr);
        assert_eq!(builder.interfaces.len(), 1);
        assert_eq!(builder.interfaces[0].interface_type, "TCPClientInterface");
    }

    #[test]
    fn test_builder_add_udp_interface() {
        let listen: SocketAddr = "0.0.0.0:4242".parse().unwrap();
        let forward: SocketAddr = "192.168.1.255:4242".parse().unwrap();
        let builder = ReticulumNodeBuilder::new().add_udp_interface(listen, forward);
        assert_eq!(builder.interfaces.len(), 1);
        assert_eq!(builder.interfaces[0].interface_type, "UDPInterface");
        assert_eq!(builder.interfaces[0].listen_ip, Some("0.0.0.0".to_string()));
        assert_eq!(builder.interfaces[0].listen_port, Some(4242));
        assert_eq!(
            builder.interfaces[0].forward_ip,
            Some("192.168.1.255".to_string())
        );
        assert_eq!(builder.interfaces[0].forward_port, Some(4242));
    }

    #[test]
    fn test_builder_enable_transport_explicit_override() {
        let builder = ReticulumNodeBuilder::new().enable_transport(false);
        assert_eq!(builder.enable_transport_explicit, Some(false));
    }

    #[test]
    fn test_builder_defaults_transport_enabled_from_config() {
        // No explicit enable_transport call — should use config default (true)
        let node = ReticulumNodeBuilder::new()
            .build_sync()
            .expect("build_sync failed");
        assert!(
            node.is_transport_enabled(),
            "default config should enable transport"
        );
    }

    #[test]
    fn test_builder_explicit_false_overrides_config() {
        let node = ReticulumNodeBuilder::new()
            .enable_transport(false)
            .build_sync()
            .expect("build_sync failed");
        assert!(
            !node.is_transport_enabled(),
            "explicit false should override config default"
        );
    }

    #[test]
    fn test_builder_config_false_respected() {
        let mut config = Config::default();
        config.reticulum.enable_transport = false;
        let node = ReticulumNodeBuilder::new()
            .config(config)
            .build_sync()
            .expect("build_sync failed");
        assert!(
            !node.is_transport_enabled(),
            "config with enable_transport=false should be respected"
        );
    }

    #[test]
    fn test_builder_explicit_true_overrides_config_false() {
        let mut config = Config::default();
        config.reticulum.enable_transport = false;
        let node = ReticulumNodeBuilder::new()
            .config(config)
            .enable_transport(true)
            .build_sync()
            .expect("build_sync failed");
        assert!(
            node.is_transport_enabled(),
            "explicit true should override config false"
        );
    }

    fn temp_storage_path() -> PathBuf {
        std::env::temp_dir().join(format!("reticulum_test_builder_{}", std::process::id()))
    }

    #[test]
    fn test_identity_round_trip() {
        let path = temp_storage_path().join("rt");
        let _ = std::fs::remove_dir_all(&path);
        let storage = Storage::new(&path).unwrap();

        let id = Identity::generate(&mut rand_core::OsRng);
        let bytes = id.private_key_bytes().unwrap();
        storage.write_root(IDENTITY_FILE, &bytes).unwrap();

        let loaded_bytes = storage.read_root(IDENTITY_FILE).unwrap();
        let loaded = Identity::from_private_key_bytes(&loaded_bytes).unwrap();
        assert_eq!(id.hash(), loaded.hash());

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_first_run_creates_identity_file() {
        let path = temp_storage_path().join("first_run");
        let _ = std::fs::remove_dir_all(&path);
        let storage = Storage::new(&path).unwrap();

        let id = load_or_generate_transport_identity(&storage).unwrap();
        assert!(id.has_private_keys());

        let file_path = path.join(IDENTITY_FILE);
        assert!(file_path.exists(), "identity file should be created");
        let bytes = std::fs::read(&file_path).unwrap();
        assert_eq!(bytes.len(), 64);

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_second_run_loads_same_identity() {
        let path = temp_storage_path().join("second_run");
        let _ = std::fs::remove_dir_all(&path);
        let storage = Storage::new(&path).unwrap();

        let id1 = load_or_generate_transport_identity(&storage).unwrap();
        let id2 = load_or_generate_transport_identity(&storage).unwrap();
        assert_eq!(id1.hash(), id2.hash());

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_explicit_identity_overrides_persistence() {
        let path = temp_storage_path().join("explicit_id");
        let _ = std::fs::remove_dir_all(&path);

        let explicit_id = Identity::generate(&mut rand_core::OsRng);
        let explicit_hash = *explicit_id.hash();

        let node = ReticulumNodeBuilder::new()
            .identity(explicit_id)
            .storage_path(path.clone())
            .build_sync()
            .expect("build_sync failed");

        assert_eq!(node.identity_hash(), explicit_hash);

        // No transport_identity file should exist (explicit identity bypasses persistence)
        assert!(
            !path.join(IDENTITY_FILE).exists(),
            "explicit identity should not create a persistence file"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_build_sync_persists_identity() {
        let path = temp_storage_path().join("build_persist");
        let _ = std::fs::remove_dir_all(&path);

        let node1 = ReticulumNodeBuilder::new()
            .storage_path(path.clone())
            .build_sync()
            .expect("first build_sync failed");
        let hash1 = node1.identity_hash();

        let node2 = ReticulumNodeBuilder::new()
            .storage_path(path.clone())
            .build_sync()
            .expect("second build_sync failed");
        let hash2 = node2.identity_hash();

        assert_eq!(hash1, hash2, "identity should persist across builds");

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_wrong_size_identity_file_errors() {
        let path = temp_storage_path().join("wrong_size");
        let _ = std::fs::remove_dir_all(&path);
        let storage = Storage::new(&path).unwrap();

        storage.write_root(IDENTITY_FILE, b"too_short").unwrap();
        let result = load_or_generate_transport_identity(&storage);
        assert!(result.is_err());
        let err_msg = format!("{}", result.err().expect("should be an error"));
        assert!(
            err_msg.contains("wrong size"),
            "error should mention wrong size: {err_msg}"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_python_transport_identity_compat() {
        // Read the actual Python rnsd transport_identity file if present
        let python_path = dirs::home_dir().map(|h| h.join(".reticulum/storage/transport_identity"));
        let Some(path) = python_path else { return };
        if !path.exists() {
            return; // Skip if Python rnsd hasn't been run on this machine
        }

        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            bytes.len(),
            64,
            "Python transport_identity should be 64 bytes"
        );

        let id = Identity::from_private_key_bytes(&bytes).unwrap();
        assert!(id.has_private_keys());
        // Verify the identity produces a valid hash (16 bytes)
        assert_eq!(id.hash().len(), 16);
        // Verify it can sign and verify
        let msg = b"test message";
        let sig = id.sign(msg).unwrap();
        assert!(id.verify(msg, &sig).unwrap());
    }

    // Reuse the dirs module from config.rs for home dir lookup in tests
    mod dirs {
        use std::path::PathBuf;
        pub(super) fn home_dir() -> Option<PathBuf> {
            std::env::var_os("HOME").map(PathBuf::from)
        }
    }
}
