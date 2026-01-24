//! lrns - Leviculum command-line utility
//!
//! This provides various utility commands for interacting with Reticulum.
//! Equivalent to rnstatus, rnpath, etc. in the Python implementation.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(name = "lrns")]
#[command(author, version, about = "Leviculum command-line utility")]
struct Args {
    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show status of the Reticulum network
    Status,

    /// Show or request paths to destinations
    Path {
        /// Destination hash (hex)
        destination: Option<String>,
    },

    /// Identity management
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },

    /// Probe a destination
    Probe {
        /// Destination hash (hex)
        destination: String,
    },

    /// Show interface information
    Interfaces,
}

#[derive(Subcommand, Debug)]
enum IdentityAction {
    /// Generate a new identity
    Generate {
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show identity information
    Show {
        /// Identity file path
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    match args.command {
        Commands::Status => {
            println!("Reticulum Status");
            println!("================");
            println!();
            println!("Status: Not implemented yet");
            // TODO: Connect to running daemon and show status
        }

        Commands::Path { destination } => {
            if let Some(dest) = destination {
                println!("Requesting path to: {}", dest);
                // TODO: Request path via daemon
            } else {
                println!("Known paths:");
                println!("============");
                println!();
                println!("No paths (not implemented yet)");
                // TODO: List known paths from daemon
            }
        }

        Commands::Identity { action } => match action {
            IdentityAction::Generate { output } => {
                use leviculum_core::Identity;

                let identity = Identity::new();
                let hash = identity.hash();
                let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

                println!("Generated new identity");
                println!("Hash: {}", hash_hex);

                if let Some(path) = output {
                    let key_bytes = identity.private_key_bytes()?;
                    std::fs::write(&path, key_bytes)?;
                    println!("Saved to: {}", path.display());
                } else {
                    let pub_key = identity.public_key_bytes();
                    let pub_hex: String = pub_key.iter().map(|b| format!("{:02x}", b)).collect();
                    println!("Public key: {}", pub_hex);
                }
            }

            IdentityAction::Show { path } => {
                use leviculum_core::Identity;

                let key_bytes = std::fs::read(&path)?;
                let identity = Identity::from_private_key_bytes(&key_bytes)?;
                let hash = identity.hash();
                let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
                let pub_key = identity.public_key_bytes();
                let pub_hex: String = pub_key.iter().map(|b| format!("{:02x}", b)).collect();

                println!("Identity: {}", path.display());
                println!("Hash: {}", hash_hex);
                println!("Public key: {}", pub_hex);
            }
        },

        Commands::Probe { destination } => {
            println!("Probing destination: {}", destination);
            println!("Not implemented yet");
            // TODO: Send probe packet via daemon
        }

        Commands::Interfaces => {
            println!("Interfaces");
            println!("==========");
            println!();
            println!("No interfaces (not implemented yet)");
            // TODO: Show interface information from daemon
        }
    }

    Ok(())
}
