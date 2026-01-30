//! Test harness for spawning and managing the Python test daemon.
//!
//! This module provides infrastructure for running interop tests without
//! requiring a manually-started rnsd instance. Instead, it spawns a custom
//! Python test daemon that provides:
//!
//! 1. A Reticulum TCPServerInterface for packet exchange
//! 2. A JSON-RPC command interface for querying internal state
//!
//! # Example
//!
//! ```ignore
//! #[tokio::test]
//! async fn test_announce_creates_path() {
//!     let daemon = TestDaemon::start().await.expect("Failed to start daemon");
//!
//!     // Connect to Reticulum interface
//!     let mut stream = TcpStream::connect(daemon.rns_addr()).await.unwrap();
//!
//!     // Send announce
//!     let (raw, dest_hash, _) = build_announce_raw("test", &["echo"], b"data");
//!     send_framed(&mut stream, &raw).await;
//!
//!     // Query state directly
//!     tokio::time::sleep(Duration::from_millis(100)).await;
//!     assert!(daemon.has_path(&dest_hash).await);
//! }
//! ```

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener, TcpStream as StdTcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Error type for test harness operations
#[derive(Debug)]
pub enum HarnessError {
    /// Failed to spawn the daemon process
    SpawnFailed(std::io::Error),
    /// Daemon did not become ready in time
    StartupTimeout,
    /// Failed to parse daemon output
    ParseError(String),
    /// Port is not available
    #[allow(dead_code)] // Reserved for future error handling
    PortUnavailable(u16),
    /// JSON-RPC command failed
    CommandFailed(String),
    /// Connection to daemon failed
    ConnectionFailed(std::io::Error),
    /// Failed to initialize git submodule
    SubmoduleInitFailed(String),
}

impl std::fmt::Display for HarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HarnessError::SpawnFailed(e) => write!(f, "Failed to spawn daemon: {}", e),
            HarnessError::StartupTimeout => write!(f, "Daemon did not become ready in time"),
            HarnessError::ParseError(s) => write!(f, "Failed to parse daemon output: {}", s),
            HarnessError::PortUnavailable(p) => write!(f, "Port {} is not available", p),
            HarnessError::CommandFailed(s) => write!(f, "JSON-RPC command failed: {}", s),
            HarnessError::ConnectionFailed(e) => write!(f, "Connection to daemon failed: {}", e),
            HarnessError::SubmoduleInitFailed(s) => {
                write!(f, "Failed to initialize Reticulum submodule: {}", s)
            }
        }
    }
}

impl std::error::Error for HarnessError {}

/// Ensure the Reticulum submodule is initialized if it exists.
///
/// This checks for the vendor/Reticulum directory and initializes the submodule
/// if it exists but the RNS module is missing (indicating uninitialized state).
fn ensure_reticulum_submodule() -> Result<(), HarnessError> {
    // Skip if RETICULUM_PATH is set (user override)
    if std::env::var("RETICULUM_PATH").is_ok() {
        return Ok(());
    }

    let project_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let vendor_dir = project_root.join("vendor/Reticulum");
    let rns_path = vendor_dir.join("RNS");

    if rns_path.exists() {
        // Already initialized
        return Ok(());
    }

    if vendor_dir.exists() {
        // Directory exists but RNS not present - need to init submodule
        eprintln!("Initializing Reticulum submodule...");
        let output = Command::new("git")
            .current_dir(&project_root)
            .args(["submodule", "update", "--init", "vendor/Reticulum"])
            .output()
            .map_err(|e| HarnessError::SubmoduleInitFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(HarnessError::SubmoduleInitFailed(format!(
                "git submodule update failed: {}",
                stderr
            )));
        }

        // Verify initialization succeeded
        if !rns_path.exists() {
            return Err(HarnessError::SubmoduleInitFailed(
                "Submodule initialized but RNS directory not found".to_string(),
            ));
        }
    }
    // If vendor dir doesn't exist at all, test_daemon.py will handle the error

    Ok(())
}

/// A handle to a running test daemon.
///
/// The daemon is automatically killed when this handle is dropped.
pub struct TestDaemon {
    process: Child,
    rns_port: u16,
    cmd_port: u16,
}

impl TestDaemon {
    /// Path to the test daemon script
    const DAEMON_SCRIPT: &'static str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../scripts/test_daemon.py");

    /// Timeout for daemon startup
    const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

    /// Maximum retries for daemon startup (handles port race conditions)
    const MAX_STARTUP_RETRIES: u32 = 3;

    /// Start a new test daemon instance.
    ///
    /// This spawns the Python test daemon with dynamically allocated ports,
    /// waits for it to signal readiness, and returns a handle for interaction.
    ///
    /// If the Reticulum submodule exists but is not initialized, this will
    /// automatically run `git submodule update --init` first.
    ///
    /// Note: This includes retry logic to handle TOCTOU race conditions where
    /// ports allocated by `find_two_available_ports()` might be grabbed by
    /// another parallel test before the daemon can bind to them.
    pub async fn start() -> Result<Self, HarnessError> {
        ensure_reticulum_submodule()?;

        let mut last_error = HarnessError::StartupTimeout;

        for attempt in 0..Self::MAX_STARTUP_RETRIES {
            let (rns_port, cmd_port) = find_two_available_ports()?;

            match Self::start_with_ports(rns_port, cmd_port).await {
                Ok(daemon) => return Ok(daemon),
                Err(HarnessError::StartupTimeout) => {
                    // Port conflict likely - retry with new ports
                    if attempt + 1 < Self::MAX_STARTUP_RETRIES {
                        // Small delay before retry to let other tests settle
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    last_error = HarnessError::StartupTimeout;
                }
                Err(e) => {
                    // Non-retryable error
                    return Err(e);
                }
            }
        }

        Err(last_error)
    }

    /// Start a daemon with specific ports (useful for debugging).
    pub async fn start_with_ports(rns_port: u16, cmd_port: u16) -> Result<Self, HarnessError> {
        let mut process = Command::new("python3")
            .args([
                Self::DAEMON_SCRIPT,
                "--rns-port",
                &rns_port.to_string(),
                "--cmd-port",
                &cmd_port.to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(HarnessError::SpawnFailed)?;

        // Wait for "READY <rns_port> <cmd_port>" line
        let stdout = process.stdout.take().expect("stdout should be captured");
        let reader = BufReader::new(stdout);

        let ready_result = tokio::task::spawn_blocking(move || {
            for line in reader.lines() {
                match line {
                    Ok(line) if line.starts_with("READY ") => {
                        return Ok(line);
                    }
                    Ok(_) => continue,
                    Err(e) => return Err(HarnessError::ParseError(e.to_string())),
                }
            }
            Err(HarnessError::StartupTimeout)
        });

        let ready_line = timeout(Self::STARTUP_TIMEOUT, ready_result)
            .await
            .map_err(|_| HarnessError::StartupTimeout)?
            .map_err(|_| HarnessError::StartupTimeout)??;

        // Parse the READY line to verify ports
        let parts: Vec<&str> = ready_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(HarnessError::ParseError(format!(
                "Invalid READY line: {}",
                ready_line
            )));
        }

        // Wait briefly for interfaces to fully initialize
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Verify we can connect to the command port
        let daemon = Self {
            process,
            rns_port,
            cmd_port,
        };

        // Ping to verify daemon is responsive
        match daemon.ping().await {
            Ok(_) => Ok(daemon),
            Err(e) => {
                // Daemon didn't respond, clean up
                drop(daemon);
                Err(e)
            }
        }
    }

    /// Get the address for the Reticulum TCP interface.
    pub fn rns_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.rns_port))
    }

    /// Get the address for the JSON-RPC command interface.
    pub fn cmd_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.cmd_port))
    }

    /// Get the RNS port number.
    pub fn rns_port(&self) -> u16 {
        self.rns_port
    }

    /// Get the command port number.
    #[allow(dead_code)] // Reserved for future test scenarios
    pub fn cmd_port(&self) -> u16 {
        self.cmd_port
    }

    /// Send a JSON-RPC command to the daemon and return the result.
    async fn query(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, HarnessError> {
        let mut stream = TcpStream::connect(self.cmd_addr())
            .await
            .map_err(HarnessError::ConnectionFailed)?;

        let cmd = serde_json::json!({
            "method": method,
            "params": params
        });

        stream
            .write_all(cmd.to_string().as_bytes())
            .await
            .map_err(|e| HarnessError::ConnectionFailed(e))?;

        stream
            .shutdown()
            .await
            .map_err(|e| HarnessError::ConnectionFailed(e))?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|e| HarnessError::ConnectionFailed(e))?;

        let response: serde_json::Value = serde_json::from_slice(&response)
            .map_err(|e| HarnessError::ParseError(e.to_string()))?;

        if let Some(error) = response.get("error") {
            return Err(HarnessError::CommandFailed(error.to_string()));
        }

        Ok(response
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }

    /// Ping the daemon to verify it's responsive.
    pub async fn ping(&self) -> Result<(), HarnessError> {
        let result = self.query("ping", serde_json::json!({})).await?;
        if result == "pong" {
            Ok(())
        } else {
            Err(HarnessError::CommandFailed(format!(
                "Unexpected ping response: {}",
                result
            )))
        }
    }

    /// Check if a path exists to a destination.
    pub async fn has_path(&self, dest_hash: &[u8]) -> bool {
        let hex_hash = hex::encode(dest_hash);
        match self
            .query("has_path", serde_json::json!({"hash": hex_hash}))
            .await
        {
            Ok(serde_json::Value::Bool(b)) => b,
            _ => false,
        }
    }

    /// Get the path table from the daemon.
    pub async fn get_path_table(&self) -> Result<HashMap<String, PathEntry>, HarnessError> {
        let result = self.query("get_path_table", serde_json::json!({})).await?;
        let mut paths = HashMap::new();

        if let serde_json::Value::Object(map) = result {
            for (hash, entry) in map {
                let timestamp = entry.get("timestamp").and_then(|v| v.as_f64());
                let hops = entry.get("hops").and_then(|v| v.as_u64()).map(|v| v as u8);
                let expires = entry.get("expires").and_then(|v| v.as_f64());

                paths.insert(
                    hash,
                    PathEntry {
                        timestamp,
                        hops,
                        expires,
                    },
                );
            }
        }

        Ok(paths)
    }

    /// Get pending announces from the daemon.
    #[allow(dead_code)] // Reserved for future test scenarios
    pub async fn get_announces(&self) -> Result<HashMap<String, AnnounceEntry>, HarnessError> {
        let result = self.query("get_announces", serde_json::json!({})).await?;
        let mut announces = HashMap::new();

        if let serde_json::Value::Object(map) = result {
            for (hash, entry) in map {
                let timestamp = entry.get("timestamp").and_then(|v| v.as_f64());
                announces.insert(hash, AnnounceEntry { timestamp });
            }
        }

        Ok(announces)
    }

    /// Get interface information from the daemon.
    pub async fn get_interfaces(&self) -> Result<Vec<InterfaceInfo>, HarnessError> {
        let result = self.query("get_interfaces", serde_json::json!({})).await?;
        let mut interfaces = Vec::new();

        if let serde_json::Value::Array(arr) = result {
            for entry in arr {
                let name = entry
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let online = entry.get("online").and_then(|v| v.as_bool());
                let in_enabled = entry.get("IN").and_then(|v| v.as_bool());
                let out_enabled = entry.get("OUT").and_then(|v| v.as_bool());

                interfaces.push(InterfaceInfo {
                    name,
                    online,
                    in_enabled,
                    out_enabled,
                });
            }
        }

        Ok(interfaces)
    }

    /// Register a destination in the daemon that accepts links.
    ///
    /// Returns the destination hash and signing key.
    pub async fn register_destination(
        &self,
        app_name: &str,
        aspects: &[&str],
    ) -> Result<DestinationInfo, HarnessError> {
        let result = self
            .query(
                "register_destination",
                serde_json::json!({
                    "app_name": app_name,
                    "aspects": aspects,
                }),
            )
            .await?;

        let hash = result
            .get("hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| HarnessError::ParseError("Missing hash".to_string()))?
            .to_string();

        let public_key = result
            .get("public_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| HarnessError::ParseError("Missing public_key".to_string()))?
            .to_string();

        let signing_key = result
            .get("signing_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| HarnessError::ParseError("Missing signing_key".to_string()))?
            .to_string();

        Ok(DestinationInfo {
            hash,
            public_key,
            signing_key,
        })
    }

    /// Announce a registered destination.
    pub async fn announce_destination(
        &self,
        dest_hash: &str,
        app_data: &[u8],
    ) -> Result<(), HarnessError> {
        self.query(
            "announce_destination",
            serde_json::json!({
                "hash": dest_hash,
                "app_data": hex::encode(app_data),
            }),
        )
        .await?;
        Ok(())
    }

    /// Request the daemon to shut down gracefully.
    #[allow(dead_code)] // Reserved for future test scenarios
    pub async fn shutdown(&self) -> Result<(), HarnessError> {
        let _ = self.query("shutdown", serde_json::json!({})).await;
        Ok(())
    }

    /// Get established links from the daemon.
    pub async fn get_links(&self) -> Result<HashMap<String, LinkInfo>, HarnessError> {
        let result = self.query("get_links", serde_json::json!({})).await?;
        let mut links = HashMap::new();

        if let serde_json::Value::Object(map) = result {
            for (hash, entry) in map {
                let status = entry
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let activated_at = entry.get("activated_at").and_then(|v| v.as_f64());

                links.insert(
                    hash,
                    LinkInfo {
                        hash: String::new(), // Will be set from key
                        status,
                        activated_at,
                    },
                );
            }
        }

        // Fill in hashes from keys
        for (hash, info) in links.iter_mut() {
            info.hash = hash.clone();
        }

        Ok(links)
    }

    /// Get packets received over links from the daemon.
    pub async fn get_received_packets(&self) -> Result<Vec<ReceivedPacket>, HarnessError> {
        let result = self
            .query("get_received_packets", serde_json::json!({}))
            .await?;
        let mut packets = Vec::new();

        if let serde_json::Value::Array(arr) = result {
            for entry in arr {
                let timestamp = entry.get("timestamp").and_then(|v| v.as_f64());
                let link_hash = entry
                    .get("link_hash")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let data = entry
                    .get("data")
                    .and_then(|v| v.as_str())
                    .map(|s| hex::decode(s).unwrap_or_default())
                    .unwrap_or_default();

                packets.push(ReceivedPacket {
                    timestamp,
                    link_hash,
                    data,
                });
            }
        }

        Ok(packets)
    }

    /// Send data on an existing link (Python as sender).
    ///
    /// # Arguments
    /// * `link_hash` - The link hash (from create_link)
    /// * `data` - The data to send (will be hex-encoded)
    pub async fn send_on_link(&self, link_hash: &str, data: &[u8]) -> Result<(), HarnessError> {
        self.query(
            "send_on_link",
            serde_json::json!({
                "link_hash": link_hash,
                "data": hex::encode(data),
            }),
        )
        .await?;
        Ok(())
    }

    /// Enable ratchets for a destination (forward secrecy).
    ///
    /// # Arguments
    /// * `dest_hash` - The destination hash to enable ratchets for
    pub async fn enable_ratchets(&self, dest_hash: &str) -> Result<RatchetInfo, HarnessError> {
        let result = self
            .query(
                "enable_ratchets",
                serde_json::json!({
                    "hash": dest_hash,
                }),
            )
            .await?;

        let enabled = result
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let ratchet_dir = result
            .get("ratchet_dir")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(RatchetInfo {
            enabled,
            count: None,
            latest_id: None,
            ratchet_dir,
        })
    }

    /// Get ratchet state for a destination.
    ///
    /// # Arguments
    /// * `dest_hash` - The destination hash to query
    pub async fn get_ratchet_info(&self, dest_hash: &str) -> Result<RatchetInfo, HarnessError> {
        let result = self
            .query(
                "get_ratchet_info",
                serde_json::json!({
                    "hash": dest_hash,
                }),
            )
            .await?;

        let enabled = result
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let count = result
            .get("count")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize);
        let latest_id = result
            .get("latest_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(RatchetInfo {
            enabled,
            count,
            latest_id,
            ratchet_dir: None,
        })
    }

    /// Add a TCPClientInterface to connect to another daemon.
    ///
    /// # Arguments
    /// * `target_ip` - The IP address to connect to
    /// * `target_port` - The port to connect to
    /// * `name` - Optional name for the interface
    pub async fn add_client_interface(
        &self,
        target_ip: &str,
        target_port: u16,
        name: Option<&str>,
    ) -> Result<ClientInterfaceInfo, HarnessError> {
        let mut params = serde_json::json!({
            "target_ip": target_ip,
            "target_port": target_port,
        });

        if let Some(n) = name {
            params["name"] = serde_json::json!(n);
        }

        let result = self.query("add_client_interface", params).await?;

        let iface_name = result
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let online = result
            .get("online")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let ip = result
            .get("target_ip")
            .and_then(|v| v.as_str())
            .unwrap_or(target_ip)
            .to_string();
        let port = result
            .get("target_port")
            .and_then(|v| v.as_u64())
            .unwrap_or(target_port as u64) as u16;

        Ok(ClientInterfaceInfo {
            name: iface_name,
            online,
            target_ip: ip,
            target_port: port,
        })
    }

    /// Get transport/routing status.
    pub async fn get_transport_status(&self) -> Result<TransportStatus, HarnessError> {
        let result = self
            .query("get_transport_status", serde_json::json!({}))
            .await?;

        let enabled = result
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let identity_hash = result
            .get("identity_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let path_table_size = result
            .get("path_table_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let link_table_size = result
            .get("link_table_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let announce_table_size = result
            .get("announce_table_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let interface_count = result
            .get("interface_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;

        Ok(TransportStatus {
            enabled,
            identity_hash,
            path_table_size,
            link_table_size,
            announce_table_size,
            interface_count,
        })
    }

    /// Get the link table from the daemon.
    pub async fn get_link_table(&self) -> Result<HashMap<String, LinkTableEntry>, HarnessError> {
        let result = self.query("get_link_table", serde_json::json!({})).await?;
        let mut link_table = HashMap::new();

        if let serde_json::Value::Object(map) = result {
            for (link_id, entry) in map {
                let timestamp = entry.get("timestamp").and_then(|v| v.as_f64());
                let interface = entry
                    .get("interface")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let hops = entry.get("hops").and_then(|v| v.as_u64()).map(|v| v as u8);

                link_table.insert(
                    link_id,
                    LinkTableEntry {
                        timestamp,
                        interface,
                        hops,
                    },
                );
            }
        }

        Ok(link_table)
    }

    /// Rotate the ratchet for a destination.
    ///
    /// # Arguments
    /// * `dest_hash` - The destination hash to rotate ratchets for
    pub async fn rotate_ratchet(
        &self,
        dest_hash: &str,
    ) -> Result<RatchetRotationResult, HarnessError> {
        let result = self
            .query(
                "rotate_ratchet",
                serde_json::json!({
                    "hash": dest_hash,
                }),
            )
            .await?;

        let rotated = result
            .get("rotated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let ratchet_count = result
            .get("ratchet_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let new_ratchet_id = result
            .get("new_ratchet_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(RatchetRotationResult {
            rotated,
            ratchet_count,
            new_ratchet_id,
        })
    }

    /// Close a link gracefully via RPC.
    ///
    /// # Arguments
    /// * `link_hash` - The link hash (hex string)
    pub async fn close_link(&self, link_hash: &str) -> Result<String, HarnessError> {
        let result = self
            .query(
                "close_link",
                serde_json::json!({
                    "link_hash": link_hash,
                }),
            )
            .await?;

        let status = result
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(status)
    }

    /// Get detailed link status via RPC.
    ///
    /// # Arguments
    /// * `link_hash` - The link hash (hex string)
    pub async fn get_link_status(&self, link_hash: &str) -> Result<LinkStatusInfo, HarnessError> {
        let result = self
            .query(
                "get_link_status",
                serde_json::json!({
                    "link_hash": link_hash,
                }),
            )
            .await?;

        let status = result
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let link_hash_result = result
            .get("link_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let state = result
            .get("state")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let is_initiator = result.get("is_initiator").and_then(|v| v.as_bool());
        let rtt = result.get("rtt").and_then(|v| v.as_f64());
        let established_at = result.get("established_at").and_then(|v| v.as_f64());
        let last_inbound = result.get("last_inbound").and_then(|v| v.as_f64());
        let last_outbound = result.get("last_outbound").and_then(|v| v.as_f64());

        Ok(LinkStatusInfo {
            status,
            link_hash: link_hash_result,
            state,
            is_initiator,
            rtt,
            established_at,
            last_inbound,
            last_outbound,
        })
    }

    /// Wait for a link to reach a specific state.
    ///
    /// # Arguments
    /// * `link_hash` - The link hash (hex string)
    /// * `state` - The expected state (e.g., "ACTIVE", "CLOSED")
    /// * `timeout_secs` - Maximum time to wait
    pub async fn wait_for_link_state(
        &self,
        link_hash: &str,
        state: &str,
        timeout_secs: u64,
    ) -> Result<WaitForLinkStateResult, HarnessError> {
        let result = self
            .query(
                "wait_for_link_state",
                serde_json::json!({
                    "link_hash": link_hash,
                    "state": state,
                    "timeout": timeout_secs,
                }),
            )
            .await?;

        let status = result
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let state_result = result
            .get("state")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let expected = result
            .get("expected")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let current = result
            .get("current")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(WaitForLinkStateResult {
            status,
            state: state_result,
            expected,
            current,
        })
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        // Try graceful shutdown first
        if let Ok(mut stream) = StdTcpStream::connect(self.cmd_addr()) {
            let cmd = r#"{"method":"shutdown"}"#;
            let _ = std::io::Write::write_all(&mut stream, cmd.as_bytes());
        }

        // Give it a moment to shut down
        std::thread::sleep(Duration::from_millis(100));

        // Force kill if still running
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Entry in the path table.
#[derive(Debug, Clone)]
pub struct PathEntry {
    pub timestamp: Option<f64>,
    pub hops: Option<u8>,
    #[allow(dead_code)]
    pub expires: Option<f64>,
}

/// Entry in the announce table.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AnnounceEntry {
    pub timestamp: Option<f64>,
}

/// Information about a Reticulum interface.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub online: Option<bool>,
    pub in_enabled: Option<bool>,
    pub out_enabled: Option<bool>,
}

/// Information about a registered destination.
#[derive(Debug, Clone)]
pub struct DestinationInfo {
    pub hash: String,
    /// Full 64-byte public key (X25519 + Ed25519)
    pub public_key: String,
    /// Ed25519 signing key (last 32 bytes of public_key)
    #[allow(dead_code)]
    pub signing_key: String,
}

/// Information about an established link.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LinkInfo {
    pub hash: String,
    pub status: String,
    pub activated_at: Option<f64>,
}

/// A packet received over a link.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ReceivedPacket {
    pub timestamp: Option<f64>,
    pub link_hash: Option<String>,
    pub data: Vec<u8>,
}

/// Information about ratchet state for a destination.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RatchetInfo {
    pub enabled: bool,
    pub count: Option<usize>,
    pub latest_id: Option<String>,
    pub ratchet_dir: Option<String>,
}

/// Information about transport status.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TransportStatus {
    pub enabled: bool,
    pub identity_hash: Option<String>,
    pub path_table_size: usize,
    pub link_table_size: usize,
    pub announce_table_size: usize,
    pub interface_count: usize,
}

/// Information about a link table entry.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LinkTableEntry {
    pub timestamp: Option<f64>,
    pub interface: Option<String>,
    pub hops: Option<u8>,
}

/// Information about a client interface.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ClientInterfaceInfo {
    pub name: String,
    pub online: bool,
    pub target_ip: String,
    pub target_port: u16,
}

/// Result from rotating a ratchet.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RatchetRotationResult {
    pub rotated: bool,
    pub ratchet_count: usize,
    pub new_ratchet_id: Option<String>,
}

/// Detailed status of a link.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LinkStatusInfo {
    pub status: String,
    pub link_hash: String,
    pub state: Option<String>,
    pub is_initiator: Option<bool>,
    pub rtt: Option<f64>,
    pub established_at: Option<f64>,
    pub last_inbound: Option<f64>,
    pub last_outbound: Option<f64>,
}

/// Result from waiting for a link state.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct WaitForLinkStateResult {
    pub status: String,
    pub state: Option<String>,
    pub expected: Option<String>,
    pub current: Option<String>,
}

/// Find two distinct available TCP ports.
///
/// This function binds to two ports simultaneously before releasing them,
/// ensuring we get two distinct ports that were both available at the same time.
///
/// Prefers high ports (49152-65535) to avoid conflicts with any running rnsd
/// (which typically uses port 4242) or other well-known services.
fn find_two_available_ports() -> Result<(u16, u16), HarnessError> {
    // Bind to two ports at the same time, then return both
    // This ensures we get two distinct ports
    let listener1 = TcpListener::bind("127.0.0.1:0").map_err(|e| HarnessError::SpawnFailed(e))?;
    let port1 = listener1
        .local_addr()
        .map_err(|e| HarnessError::SpawnFailed(e))?
        .port();

    let listener2 = TcpListener::bind("127.0.0.1:0").map_err(|e| HarnessError::SpawnFailed(e))?;
    let port2 = listener2
        .local_addr()
        .map_err(|e| HarnessError::SpawnFailed(e))?
        .port();

    // Drop both listeners to free the ports for the daemon to use
    drop(listener1);
    drop(listener2);

    Ok((port1, port2))
}

// =========================================================================
// DaemonTopology - Manages multiple connected Python daemons
// =========================================================================

/// Manages multiple connected Python daemons for multi-hop testing.
///
/// This struct creates a topology of daemons where each daemon connects
/// to the previous one via TCPClientInterface, forming a linear chain.
///
/// # Example Topology
///
/// For a 3-daemon topology: D0 <- D1 <- D2
/// - D0 is the entry point (only TCPServerInterface)
/// - D1 connects to D0 (TCPClientInterface -> D0's TCPServerInterface)
/// - D2 connects to D1 (TCPClientInterface -> D1's TCPServerInterface)
///
/// # Usage
///
/// ```ignore
/// let topology = DaemonTopology::linear(3).await?;
/// let entry = topology.entry_daemon();  // D0
/// let exit = topology.exit_daemon();    // D2 (or D1 for 2-daemon)
/// ```
pub struct DaemonTopology {
    daemons: Vec<TestDaemon>,
}

impl DaemonTopology {
    /// Create a linear topology with the specified number of daemons.
    ///
    /// The topology forms a chain: D0 <- D1 <- D2 <- ... <- D(n-1)
    /// where each daemon (except D0) connects to the previous daemon's TCPServerInterface.
    ///
    /// # Arguments
    /// * `count` - Number of daemons to create (must be >= 2)
    ///
    /// # Returns
    /// A DaemonTopology with all daemons connected in a linear chain.
    pub async fn linear(count: usize) -> Result<Self, HarnessError> {
        if count < 2 {
            return Err(HarnessError::ParseError(
                "DaemonTopology requires at least 2 daemons".to_string(),
            ));
        }

        let mut daemons = Vec::with_capacity(count);

        // Start the first daemon (entry point)
        let entry_daemon = TestDaemon::start().await?;
        daemons.push(entry_daemon);

        // Start subsequent daemons and connect them to the previous one
        for i in 1..count {
            let daemon = TestDaemon::start().await?;

            // Get the RNS port of the previous daemon
            let prev_rns_port = daemons[i - 1].rns_port();

            // Connect this daemon to the previous daemon's TCPServerInterface
            let interface_name = format!("LinkTo_D{}", i - 1);
            daemon
                .add_client_interface("127.0.0.1", prev_rns_port, Some(&interface_name))
                .await?;

            daemons.push(daemon);
        }

        // Wait for connections to stabilize
        tokio::time::sleep(Duration::from_millis(500)).await;

        Ok(Self { daemons })
    }

    /// Get the entry daemon (first in the chain).
    ///
    /// This is where Rust A would connect to inject packets into the network.
    pub fn entry_daemon(&self) -> &TestDaemon {
        &self.daemons[0]
    }

    /// Get the exit daemon (last in the chain).
    ///
    /// This is where Rust B would connect to receive packets from the network.
    pub fn exit_daemon(&self) -> &TestDaemon {
        &self.daemons[self.daemons.len() - 1]
    }

    /// Get a daemon by index.
    pub fn daemon(&self, index: usize) -> Option<&TestDaemon> {
        self.daemons.get(index)
    }

    /// Get the number of daemons in the topology.
    pub fn len(&self) -> usize {
        self.daemons.len()
    }

    /// Check if the topology is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.daemons.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_daemon_starts_and_responds() {
        let daemon = TestDaemon::start().await.expect("Failed to start daemon");

        // Verify ping works
        daemon.ping().await.expect("Ping failed");

        // Verify we can get interfaces
        let interfaces = daemon
            .get_interfaces()
            .await
            .expect("Failed to get interfaces");
        assert!(!interfaces.is_empty(), "Should have at least one interface");

        // Verify the TCP server interface is present and online
        let tcp_interface = interfaces
            .iter()
            .find(|i| i.name.contains("Test TCP Server"))
            .expect("TCP server interface not found");
        assert_eq!(tcp_interface.online, Some(true));
        assert_eq!(tcp_interface.in_enabled, Some(true));
        assert_eq!(tcp_interface.out_enabled, Some(true));
    }

    #[tokio::test]
    async fn test_register_destination() {
        let daemon = TestDaemon::start().await.expect("Failed to start daemon");

        let dest = daemon
            .register_destination("test", &["echo"])
            .await
            .expect("Failed to register destination");

        assert_eq!(dest.hash.len(), 32, "Hash should be 16 bytes hex-encoded");
        assert_eq!(
            dest.signing_key.len(),
            64,
            "Signing key should be 32 bytes hex-encoded"
        );
    }
}
