//! lrncp - Reticulum File Transfer Utility
//!
//! Standalone binary for sending/receiving files over Reticulum,
//! compatible with Python's rncp. Connects to a running daemon
//! (lrnsd or rnsd) via shared instance IPC.

use std::path::PathBuf;

use clap::{ArgAction, Parser};
use tracing_subscriber::EnvFilter;

use reticulum_std::config::Config;
use reticulum_std::driver::ReticulumNodeBuilder;
use reticulum_std::{Destination, DestinationType, Direction};

mod cp;

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("hex string has odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[derive(Parser, Debug)]
#[command(name = "lrncp", version, about = "Reticulum File Transfer Utility")]
struct Args {
    /// File to send (send mode)
    file: Option<String>,

    /// Destination hash, 32 hex characters (send mode)
    destination: Option<String>,

    /// Path to alternative Reticulum config directory
    #[arg(long)]
    config: Option<PathBuf>,

    /// Increase verbosity
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,

    /// Decrease verbosity
    #[arg(short, long, action = ArgAction::Count)]
    quiet: u8,

    /// Listen for incoming transfer requests
    #[arg(short, long)]
    listen: bool,

    /// Sender timeout before giving up (seconds)
    #[arg(short = 'w', default_value = "15.0")]
    timeout: f64,

    /// Save received files in specified path
    #[arg(short, long)]
    save: Option<PathBuf>,

    /// Allow overwriting received files
    #[arg(short = 'O', long)]
    overwrite: bool,

    /// Accept requests from anyone
    #[arg(short = 'n', long = "no-auth")]
    no_auth: bool,

    /// Announce interval (-1=none, 0=once at startup, N=every N sec)
    #[arg(short = 'b', default_value = "0")]
    announce_interval: i64,

    /// Print identity and destination info and exit
    #[arg(short = 'p', long = "print-identity")]
    print_identity: bool,

    /// Path to identity file to use
    #[arg(short = 'i')]
    identity: Option<PathBuf>,

    // --- Flags accepted but not yet implemented ---
    /// Disable transfer progress output
    #[arg(short = 'S', long)]
    silent: bool,

    /// Disable automatic compression
    #[arg(short = 'C', long = "no-compress")]
    no_compress: bool,

    /// Fetch file from remote listener [not yet implemented]
    #[arg(short = 'f', long, hide = true)]
    fetch: bool,

    /// Allow authenticated clients to fetch files [not yet implemented]
    #[arg(short = 'F', long = "allow-fetch", hide = true)]
    allow_fetch: bool,

    /// Restrict fetch requests to specified path [not yet implemented]
    #[arg(short = 'j', long, hide = true)]
    jail: Option<PathBuf>,

    /// Display physical layer transfer rates [not yet implemented]
    #[arg(short = 'P', long = "phy-rates", hide = true)]
    phy_rates: bool,

    /// Allow this identity hash [not yet implemented]
    #[arg(short = 'a', action = ArgAction::Append, hide = true)]
    allowed: Vec<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Check for unimplemented flags before anything else
    check_unimplemented(&args);

    // RUST_LOG env takes precedence; otherwise use -v/-q flags.
    // Default is "warn" (not "info") — lrncp is a user tool, not a daemon.
    let default_filter = match (args.verbose as i8) - (args.quiet as i8) {
        3.. => "trace",
        2 => "debug",
        1 => "info",
        0 => "warn",
        _ => "error",
    };
    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter)),
        )
        .init();

    if let Err(e) = run(args).await {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let config_dir = args
        .config
        .clone()
        .unwrap_or_else(Config::default_config_dir);

    // Handle -p/--print-identity (no node needed)
    if args.print_identity {
        return print_identity(&config_dir, args.identity.as_deref());
    }

    // Determine instance name from config
    let instance_name = read_instance_name(&config_dir);

    // Connect to daemon
    let mut node = ReticulumNodeBuilder::new()
        .enable_transport(false)
        .connect_to_shared_instance(&instance_name)
        // Safe to share storage path with lrnsd: a client with
        // enable_transport(false) writes no paths, announces, or
        // packet hashes to storage. Identity is loaded separately.
        .storage_path(config_dir.join("storage"))
        .build_sync()
        .map_err(|e| daemon_connect_error(&instance_name, &e, args.verbose))?;
    node.start()
        .await
        .map_err(|e| daemon_connect_error(&instance_name, &e, args.verbose))?;
    let mut events = node.take_event_receiver().ok_or("no event receiver")?;

    // quiet: u8 (count) from CLI, converted to bool for now.
    // TODO(ROADMAP #quiet-levels): differentiate -q / -qq levels in the future.
    let quiet_bool = args.quiet > 0 || args.silent;

    let result = if args.listen {
        let identity_path = args
            .identity
            .unwrap_or_else(|| config_dir.join("identities").join("lrncp"));
        let identity = cp::load_or_generate_identity(&identity_path)?;

        cp::run_listen(
            &node,
            &mut events,
            identity,
            args.save,
            args.overwrite,
            args.no_auth,
            args.announce_interval,
            args.verbose,
            quiet_bool,
        )
        .await
    } else {
        let file = args.file.ok_or("file argument required in send mode")?;
        let dest = args
            .destination
            .ok_or("destination argument required in send mode")?;
        cp::run_send(
            &node,
            &mut events,
            &file,
            &dest,
            args.timeout,
            args.verbose,
            quiet_bool,
            args.no_compress,
        )
        .await
    };

    node.stop().await?;
    result
}

fn daemon_connect_error(instance_name: &str, error: &dyn std::fmt::Display, verbose: u8) -> String {
    format!(
        "Could not connect to a running Reticulum daemon on rns/{}.\n\
         Start lrnsd or rnsd first.{}",
        instance_name,
        if verbose > 0 {
            format!("\nDetail: {}", error)
        } else {
            String::new()
        }
    )
}

fn check_unimplemented(args: &Args) {
    let mut flag = None;
    if args.fetch {
        flag = Some("-f/--fetch");
    }
    if args.allow_fetch {
        flag = Some("-F/--allow-fetch");
    }
    if args.jail.is_some() {
        flag = Some("-j/--jail");
    }
    if args.phy_rates {
        flag = Some("-P/--phy-rates");
    }
    if !args.allowed.is_empty() {
        flag = Some("-a (allowed identity)");
    }
    if let Some(f) = flag {
        eprintln!("lrncp: {} is not yet implemented", f);
        std::process::exit(1);
    }
}

fn read_instance_name(config_dir: &std::path::Path) -> String {
    // Config has `instance_name` field (config.rs:39),
    // INI parser handles it (ini_config.rs:152), default is "default".
    let config_file = config_dir.join("config");
    if config_file.exists() {
        if let Ok(config) = Config::load(&config_file) {
            return config.reticulum.instance_name;
        }
    }
    "default".to_string()
}

fn print_identity(
    config_dir: &std::path::Path,
    identity_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = identity_path
        .map(PathBuf::from)
        .unwrap_or_else(|| config_dir.join("identities").join("lrncp"));
    let identity = cp::load_or_generate_identity(&path)?;
    let dest = Destination::new(
        Some(identity),
        Direction::In,
        DestinationType::Single,
        "rncp",
        &["receive"],
    )
    .map_err(|e| format!("destination error: {e}"))?;
    println!("{}", hex_encode(dest.hash().as_bytes()));
    Ok(())
}
