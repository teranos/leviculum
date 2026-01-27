//! lrnsd - Reticulum daemon
//!
//! This is the main daemon process that runs the Reticulum network stack.
//! Equivalent to rnsd in the Python implementation.

use std::path::PathBuf;

use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use reticulum_std::config::Config;
use reticulum_std::Reticulum;

#[derive(Parser, Debug)]
#[command(name = "lrnsd")]
#[command(author, version, about = "Reticulum network daemon")]
struct Args {
    /// Configuration file path
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Storage directory path
    #[arg(short, long)]
    storage: Option<PathBuf>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Run in foreground (don't daemonize)
    #[arg(short, long)]
    foreground: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting lrnsd v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config_path = args.config.unwrap_or_else(Config::default_config_path);
    let storage_path = args
        .storage
        .unwrap_or_else(|| Config::default_config_dir().join("storage"));

    info!("Config: {}", config_path.display());
    info!("Storage: {}", storage_path.display());

    // Load and configure Reticulum
    let mut config = if config_path.exists() {
        Config::load(&config_path)?
    } else {
        Config::default()
    };
    config.reticulum.storage_path = Some(storage_path);

    let mut rns = Reticulum::with_config(config).await?;

    info!("Reticulum daemon running");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;

    info!("Shutting down...");
    rns.stop().await?;

    Ok(())
}
