//! Configuration loading and management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Main Reticulum configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Core reticulum settings
    #[serde(default)]
    pub reticulum: ReticulumConfig,
    /// Interface configurations by name
    #[serde(default)]
    pub interfaces: HashMap<String, InterfaceConfig>,
}

/// Core reticulum settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReticulumConfig {
    /// Enable transport mode (routing for others)
    #[serde(default)]
    pub enable_transport: bool,
    /// Use implicit proof for link identification
    #[serde(default = "default_true")]
    pub use_implicit_proof: bool,
    /// Allow sharing instance across processes
    #[serde(default)]
    pub shared_instance: bool,
    /// Enable remote management
    #[serde(default)]
    pub remote_management_enabled: bool,
    /// Storage path (relative to config dir or absolute)
    #[serde(default)]
    pub storage_path: Option<PathBuf>,
}

fn default_true() -> bool {
    true
}

impl Default for ReticulumConfig {
    fn default() -> Self {
        Self {
            enable_transport: false,
            use_implicit_proof: true,
            shared_instance: false,
            remote_management_enabled: false,
            storage_path: None,
        }
    }
}

/// Interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    /// Interface type
    #[serde(rename = "type")]
    pub interface_type: String,
    /// Whether the interface is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Can send outgoing packets
    #[serde(default = "default_true")]
    pub outgoing: bool,
    /// Bitrate in bits per second
    #[serde(default = "default_bitrate")]
    pub bitrate: u64,

    // TCP/UDP specific
    /// Listen IP address
    pub listen_ip: Option<String>,
    /// Listen port
    pub listen_port: Option<u16>,
    /// Target host for client connections
    pub target_host: Option<String>,
    /// Target port for client connections
    pub target_port: Option<u16>,
    /// Forward IP (for UDP broadcast)
    pub forward_ip: Option<String>,
    /// Forward port (for UDP broadcast)
    pub forward_port: Option<u16>,

    // Serial specific
    /// Serial port path
    pub port: Option<String>,
    /// Serial baud rate
    pub speed: Option<u32>,
    /// Data bits
    pub databits: Option<u8>,
    /// Parity (none, even, odd)
    pub parity: Option<String>,
    /// Stop bits
    pub stopbits: Option<u8>,

    // RNode specific
    /// LoRa frequency in Hz
    pub frequency: Option<u64>,
    /// LoRa bandwidth in Hz
    pub bandwidth: Option<u32>,
    /// LoRa spreading factor
    pub spreading_factor: Option<u8>,
    /// LoRa coding rate
    pub coding_rate: Option<u8>,
    /// TX power in dBm
    pub tx_power: Option<i8>,
}

fn default_bitrate() -> u64 {
    62500 // Default Reticulum bitrate
}


impl Config {
    /// Load configuration from a file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| Error::Config(format!("Failed to read config: {e}")))?;

        // Try TOML format
        toml::from_str(&content)
            .map_err(|e| Error::Config(format!("Failed to parse config: {e}")))
    }

    /// Save configuration to a file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| Error::Config(format!("Failed to serialize config: {e}")))?;

        std::fs::write(path.as_ref(), content)
            .map_err(|e| Error::Config(format!("Failed to write config: {e}")))
    }

    /// Get the default config directory path
    pub fn default_config_dir() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".reticulum")
    }

    /// Get the default config file path
    pub fn default_config_path() -> PathBuf {
        Self::default_config_dir().join("config")
    }
}

// Minimal home_dir implementation to avoid dirs crate dependency
mod dirs {
    use std::path::PathBuf;

    pub fn home_dir() -> Option<PathBuf> {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(!config.reticulum.enable_transport);
        assert!(config.reticulum.use_implicit_proof);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(
            parsed.reticulum.enable_transport,
            config.reticulum.enable_transport
        );
    }
}
