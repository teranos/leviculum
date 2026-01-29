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
    /// Port is not available (reserved for future use)
    #[allow(dead_code)]
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
    const DAEMON_SCRIPT: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/../scripts/test_daemon.py");

    /// Timeout for daemon startup
    const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

    /// Start a new test daemon instance.
    ///
    /// This spawns the Python test daemon with dynamically allocated ports,
    /// waits for it to signal readiness, and returns a handle for interaction.
    ///
    /// If the Reticulum submodule exists but is not initialized, this will
    /// automatically run `git submodule update --init` first.
    pub async fn start() -> Result<Self, HarnessError> {
        ensure_reticulum_submodule()?;

        let (rns_port, cmd_port) = find_two_available_ports()?;

        Self::start_with_ports(rns_port, cmd_port).await
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
    #[allow(dead_code)]
    pub fn cmd_port(&self) -> u16 {
        self.cmd_port
    }

    /// Send a JSON-RPC command to the daemon and return the result.
    async fn query(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, HarnessError> {
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

        Ok(response.get("result").cloned().unwrap_or(serde_json::Value::Null))
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
        match self.query("has_path", serde_json::json!({"hash": hex_hash})).await {
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

                paths.insert(hash, PathEntry {
                    timestamp,
                    hops,
                    expires,
                });
            }
        }

        Ok(paths)
    }

    /// Get pending announces from the daemon.
    #[allow(dead_code)]
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
                let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
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
    pub async fn announce_destination(&self, dest_hash: &str, app_data: &[u8]) -> Result<(), HarnessError> {
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
    #[allow(dead_code)]
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
        let result = self.query("get_received_packets", serde_json::json!({})).await?;
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

    /// Create a link from Python daemon to an external destination.
    ///
    /// This allows testing Rust as the link responder (server) side.
    ///
    /// # Arguments
    /// * `dest_hash` - The destination hash to connect to (hex string)
    /// * `dest_key` - The destination's 64-byte public key (hex string)
    /// * `timeout` - Timeout in seconds for link establishment
    ///
    /// # Returns
    /// Information about the established link, or error if failed.
    pub async fn create_link(
        &self,
        dest_hash: &str,
        dest_key: &str,
        timeout: u32,
    ) -> Result<CreatedLinkInfo, HarnessError> {
        let result = self
            .query(
                "create_link",
                serde_json::json!({
                    "dest_hash": dest_hash,
                    "dest_key": dest_key,
                    "timeout": timeout,
                }),
            )
            .await?;

        let link_hash = result
            .get("link_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| HarnessError::ParseError("Missing link_hash".to_string()))?
            .to_string();

        let status = result
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(CreatedLinkInfo { link_hash, status })
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
}

/// Information about a link created by the daemon (Python as initiator).
#[derive(Debug, Clone)]
pub struct CreatedLinkInfo {
    pub link_hash: String,
    pub status: String,
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
    let port1 = listener1.local_addr().map_err(|e| HarnessError::SpawnFailed(e))?.port();

    let listener2 = TcpListener::bind("127.0.0.1:0").map_err(|e| HarnessError::SpawnFailed(e))?;
    let port2 = listener2.local_addr().map_err(|e| HarnessError::SpawnFailed(e))?.port();

    // Drop both listeners to free the ports for the daemon to use
    drop(listener1);
    drop(listener2);

    Ok((port1, port2))
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
        let interfaces = daemon.get_interfaces().await.expect("Failed to get interfaces");
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
        assert_eq!(dest.signing_key.len(), 64, "Signing key should be 32 bytes hex-encoded");
    }
}
