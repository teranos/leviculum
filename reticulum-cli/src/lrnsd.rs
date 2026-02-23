//! lrnsd - Reticulum daemon
//!
//! This is the main daemon process that runs the Reticulum network stack.
//! Equivalent to rnsd in the Python implementation.

use std::path::PathBuf;

use clap::{ArgAction, Parser};
use tracing::info;
use tracing_subscriber::EnvFilter;

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

    /// Increase log verbosity (repeat for more: -v debug, -vv trace)
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,

    /// Decrease log verbosity (repeat for less: -q warn, -qq error)
    #[arg(short, long, action = ArgAction::Count)]
    quiet: u8,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // RUST_LOG env takes precedence; otherwise use -v/-q flags
    let default_filter = match (args.verbose as i8) - (args.quiet as i8) {
        2.. => "trace",
        1 => "debug",
        0 => "info",
        -1 => "warn",
        _ => "error",
    };
    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter)),
        )
        .init();

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

    let mut rns = Reticulum::with_config(config)?;
    rns.start().await?;

    info!("Reticulum daemon running");

    // Wait for shutdown signal (SIGINT or SIGTERM), dump diagnostics on SIGUSR1
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigusr1 = signal(SignalKind::user_defined1())?;
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => { info!("Received SIGINT"); break; }
                _ = sigterm.recv() => { info!("Received SIGTERM"); break; }
                _ = sigusr1.recv() => {
                    let dump = rns.diagnostic_dump();
                    eprint!("{}", dump);
                }
            }
        }
    }

    info!("Shutting down...");
    rns.stop().await?;

    Ok(())
}
