//! Main Reticulum instance

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::storage::Storage;

/// Main Reticulum instance
pub struct Reticulum {
    /// Configuration
    config: Config,
    /// Storage manager
    storage: Storage,
    /// Whether transport mode is enabled
    transport_enabled: bool,
    /// Running state
    running: Arc<RwLock<bool>>,
}

impl Reticulum {
    /// Create a new Reticulum instance with default configuration
    pub async fn new() -> Result<Self> {
        let config_path = Config::default_config_path();
        let config = if config_path.exists() {
            Config::load(&config_path)?
        } else {
            Config::default()
        };

        Self::with_config(config).await
    }

    /// Create a new Reticulum instance with custom configuration
    pub async fn with_config(config: Config) -> Result<Self> {
        let storage_path = config
            .reticulum
            .storage_path
            .clone()
            .unwrap_or_else(|| Config::default_config_dir().join("storage"));

        let storage = Storage::new(&storage_path)?;

        Ok(Self {
            transport_enabled: config.reticulum.enable_transport,
            config,
            storage,
            running: Arc::new(RwLock::new(false)),
        })
    }

    /// Create a new Reticulum instance with custom config and storage paths
    pub async fn with_paths(config_path: PathBuf, storage_path: PathBuf) -> Result<Self> {
        let mut config = if config_path.exists() {
            Config::load(&config_path)?
        } else {
            Config::default()
        };

        config.reticulum.storage_path = Some(storage_path.clone());
        let storage = Storage::new(&storage_path)?;

        Ok(Self {
            transport_enabled: config.reticulum.enable_transport,
            config,
            storage,
            running: Arc::new(RwLock::new(false)),
        })
    }

    /// Start the Reticulum instance
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Err(Error::Config("Reticulum already running".into()));
        }

        // TODO: Initialize interfaces from config
        // TODO: Start transport layer
        // TODO: Load persisted state

        *running = true;
        tracing::info!("Reticulum started");

        Ok(())
    }

    /// Stop the Reticulum instance
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }

        // TODO: Stop interfaces
        // TODO: Persist state
        // TODO: Clean up resources

        *running = false;
        tracing::info!("Reticulum stopped");

        Ok(())
    }

    /// Check if the instance is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Get the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get the storage manager
    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    /// Check if transport mode is enabled
    pub fn is_transport_enabled(&self) -> bool {
        self.transport_enabled
    }

    // TODO: Add methods for:
    // - Creating/registering destinations
    // - Creating identities
    // - Establishing links
    // - Sending packets
    // - Path requests
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_instance() {
        let config = Config::default();
        let rns = Reticulum::with_config(config).await.unwrap();
        assert!(!rns.is_running().await);
        assert!(!rns.is_transport_enabled());
    }
}
