//! lrns - Reticulum command-line utility
//!
//! This provides various utility commands for interacting with Reticulum.
//! Equivalent to rnstatus, rnpath, etc. in the Python implementation.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use tokio::io::AsyncBufReadExt;

use reticulum_core::destination::{DestinationType, Direction};
use reticulum_core::link::LinkId;
use reticulum_core::node::NodeEvent;
use reticulum_core::{Destination, DestinationHash, Identity};
use reticulum_std::driver::{ConnectionStream, ReticulumNodeBuilder};

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
        return Err("odd length hex string".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[derive(Parser, Debug)]
#[command(name = "lrns")]
#[command(author, version, about = "Reticulum command-line utility")]
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

    /// Interactive session: connect to rnsd and enter command loop
    Connect {
        /// Address of the rnsd to connect to (host:port)
        addr: String,

        /// Path to identity file (default: generate ephemeral)
        #[arg(long)]
        identity: Option<PathBuf>,
    },
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

struct AnnounceInfo {
    app_data: String,
    hops: Option<u8>,
    /// X25519(32) + Ed25519(32), needed for /link
    public_key: [u8; 64],
}

struct SessionState {
    discovered: BTreeMap<String, AnnounceInfo>,
    pending_requests: VecDeque<(LinkId, DestinationHash)>,
    active_link_id: Option<LinkId>,
    show_announces: bool,
}

fn print_prompt() {
    print!("> ");
    let _ = std::io::stdout().flush();
}

fn print_help() {
    println!("Commands:");
    println!("  /peers           List discovered destinations");
    println!("  /link <hash>     Initiate link to destination (32-char hex)");
    println!("  /accept          Accept pending incoming link request");
    println!("  /send <msg>      Send data on active link");
    println!("  /close           Close active link");
    println!("  /announce        Re-announce this destination");
    println!("  /quiet           Hide announce/path messages");
    println!("  /verbose         Show announce/path messages");
    println!("  /status          Show node status");
    println!("  /help            Show this help");
    println!("  /quit            Exit");
    println!("  <bare text>      Send as data if link is active");
}

async fn run_connect(
    addr: String,
    identity_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket_addr: SocketAddr = addr.parse().map_err(|e| format!("invalid address: {e}"))?;

    // Verify TCP connectivity before building the node — the driver silently
    // ignores connection failures, leaving the node running with no interfaces.
    tokio::net::TcpStream::connect(socket_addr)
        .await
        .map_err(|e| format!("cannot connect to {socket_addr}: {e}"))?;

    // Load or generate identity private key bytes, so we can create two Identity
    // instances (one for the builder, one for the destination — Identity is not Clone).
    let private_key_bytes = if let Some(path) = &identity_path {
        let bytes = std::fs::read(path)?;
        let id =
            Identity::from_private_key_bytes(&bytes).map_err(|e| format!("bad identity: {e}"))?;
        id.private_key_bytes().map_err(|e| e.to_string())?
    } else {
        use rand_core::OsRng;
        let id = Identity::generate(&mut OsRng);
        id.private_key_bytes().map_err(|e| e.to_string())?
    };

    let node_identity =
        Identity::from_private_key_bytes(&private_key_bytes).map_err(|e| e.to_string())?;
    let dest_identity =
        Identity::from_private_key_bytes(&private_key_bytes).map_err(|e| e.to_string())?;

    let identity_hash = hex_encode(node_identity.hash());

    // Build and start node
    let mut node = ReticulumNodeBuilder::new()
        .identity(node_identity)
        .enable_transport(false)
        .add_tcp_client(socket_addr)
        .build()
        .await?;

    node.start().await?;

    // Create destination and register it
    let mut dest = Destination::new(
        Some(dest_identity),
        Direction::In,
        DestinationType::Single,
        "lrns",
        &["connect"],
    )
    .map_err(|e| format!("destination error: {e}"))?;
    dest.set_accepts_links(true);
    let dest_hash = *dest.hash();
    let dest_hash_hex = hex_encode(dest_hash.as_bytes());
    node.register_destination(dest);

    // Announce ourselves
    if let Err(e) = node.announce_destination(&dest_hash, Some(b"lrns-cli")) {
        eprintln!("announce failed: {e}");
    }

    println!("Identity: {identity_hash}");
    println!("Destination: {dest_hash_hex}");
    println!("Announced as lrns-cli");
    println!("Type /help for commands.");
    print_prompt();

    // Take event receiver
    let event_rx = node
        .take_event_receiver()
        .ok_or("event receiver already taken")?;

    let state = Arc::new(Mutex::new(SessionState {
        discovered: BTreeMap::new(),
        pending_requests: VecDeque::new(),
        active_link_id: None,
        show_announces: false,
    }));

    // Spawn event task
    let event_state = Arc::clone(&state);
    let event_task = tokio::spawn(event_loop(event_rx, event_state));

    // Input loop (main task)
    let mut stream: Option<ConnectionStream> = None;
    let stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();

    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => break, // EOF
            Err(e) => {
                eprintln!("stdin error: {e}");
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            print_prompt();
            continue;
        }

        if trimmed.starts_with('/') {
            let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
            let cmd = parts[0];
            let arg = parts.get(1).map(|s| s.trim());

            match cmd {
                "/quit" => break,

                "/help" => {
                    print_help();
                }

                "/peers" => {
                    let st = state.lock().expect("lock poisoned");
                    if st.discovered.is_empty() {
                        println!("No peers discovered yet.");
                    } else {
                        for (hash, info) in &st.discovered {
                            let hops = info
                                .hops
                                .map(|h| format!("{h} hops"))
                                .unwrap_or_else(|| "? hops".to_string());
                            println!("  {hash}  {hops}  app_data: {}", info.app_data);
                        }
                    }
                }

                "/link" => {
                    let Some(hash_str) = arg else {
                        eprintln!("usage: /link <32-char hex destination hash>");
                        print_prompt();
                        continue;
                    };

                    if hash_str.len() != 32 {
                        eprintln!("destination hash must be 32 hex characters (16 bytes)");
                        print_prompt();
                        continue;
                    }

                    // Check if we already have an active link
                    {
                        let st = state.lock().expect("lock poisoned");
                        if st.active_link_id.is_some() {
                            eprintln!("close current link first (/close)");
                            print_prompt();
                            continue;
                        }
                    }

                    let hash_bytes = match hex_decode(hash_str) {
                        Ok(b) => b,
                        Err(e) => {
                            eprintln!("invalid hex: {e}");
                            print_prompt();
                            continue;
                        }
                    };

                    let mut dest_bytes = [0u8; 16];
                    dest_bytes.copy_from_slice(&hash_bytes);
                    let target_hash = DestinationHash::new(dest_bytes);

                    // Look up signing key from discovered announces
                    let signing_key = {
                        let st = state.lock().expect("lock poisoned");
                        st.discovered.get(hash_str).map(|info| {
                            let mut key = [0u8; 32];
                            key.copy_from_slice(&info.public_key[32..64]);
                            key
                        })
                    };

                    let Some(signing_key) = signing_key else {
                        eprintln!("destination not found in discovered peers, wait for announce");
                        print_prompt();
                        continue;
                    };

                    match node.connect(&target_hash, &signing_key).await {
                        Ok(s) => {
                            let link_id = *s.link_id();
                            {
                                let mut st = state.lock().expect("lock poisoned");
                                st.active_link_id = Some(link_id);
                            }
                            stream = Some(s);
                            println!("[linking] request sent for {hash_str}");
                        }
                        Err(e) => {
                            eprintln!("connect failed: {e}");
                        }
                    }
                }

                "/accept" => {
                    // Check if we already have an active link
                    {
                        let st = state.lock().expect("lock poisoned");
                        if st.active_link_id.is_some() {
                            eprintln!("close current link first (/close)");
                            print_prompt();
                            continue;
                        }
                    }

                    let pending = {
                        let mut st = state.lock().expect("lock poisoned");
                        st.pending_requests.pop_front()
                    };

                    let Some((link_id, dest_hash_req)) = pending else {
                        eprintln!("no pending link requests");
                        print_prompt();
                        continue;
                    };

                    match node.accept_connection(&link_id).await {
                        Ok(s) => {
                            {
                                let mut st = state.lock().expect("lock poisoned");
                                st.active_link_id = Some(link_id);
                            }
                            stream = Some(s);
                            println!(
                                "[accepting] link {} from {}",
                                link_id,
                                hex_encode(dest_hash_req.as_bytes())
                            );
                        }
                        Err(e) => {
                            eprintln!("accept failed: {e}");
                        }
                    }
                }

                "/send" => {
                    let Some(msg) = arg else {
                        eprintln!("usage: /send <message>");
                        print_prompt();
                        continue;
                    };

                    if let Err(e) = try_send(&state, &stream, msg).await {
                        eprintln!("{e}");
                        if e.contains("closed by peer") {
                            stream = None;
                        }
                    }
                }

                "/close" => {
                    if let Some(mut s) = stream.take() {
                        if let Err(e) = s.close().await {
                            eprintln!("close error: {e}");
                        }
                        let mut st = state.lock().expect("lock poisoned");
                        st.active_link_id = None;
                        println!("[closed] link closed");
                    } else {
                        eprintln!("no active link");
                    }
                }

                "/announce" => match node.announce_destination(&dest_hash, Some(b"lrns-cli")) {
                    Ok(()) => println!("[announced] {dest_hash_hex}"),
                    Err(e) => eprintln!("announce failed: {e}"),
                },

                "/quiet" => {
                    let mut st = state.lock().expect("lock poisoned");
                    st.show_announces = false;
                    println!("Announce/path messages hidden. Use /verbose to restore.");
                }

                "/verbose" => {
                    let mut st = state.lock().expect("lock poisoned");
                    st.show_announces = true;
                    println!("Announce/path messages visible.");
                }

                "/status" => {
                    let st = state.lock().expect("lock poisoned");
                    println!("Identity:    {identity_hash}");
                    println!("Destination: {dest_hash_hex}");
                    println!(
                        "Active link: {}",
                        st.active_link_id
                            .as_ref()
                            .map(|id| format!("{id}"))
                            .unwrap_or_else(|| "none".to_string())
                    );
                    println!("Paths:       {}", node.path_count());
                    println!("Transport:   {}", node.is_transport_enabled());
                    println!("Peers:       {}", st.discovered.len());
                }

                _ => {
                    eprintln!("unknown command: {cmd} (type /help)");
                }
            }
        } else {
            // Bare text → send as data if link is active
            if let Err(e) = try_send(&state, &stream, trimmed).await {
                eprintln!("{e}");
                if e.contains("closed by peer") {
                    stream = None;
                }
            }
        }

        print_prompt();
    }

    // Cleanup
    event_task.abort();
    if let Some(mut s) = stream.take() {
        let _ = s.close().await;
    }
    node.stop().await?;

    Ok(())
}

/// Try to send data on the active connection.
/// Returns Err with a user-facing message on failure.
async fn try_send(
    state: &Arc<Mutex<SessionState>>,
    stream: &Option<ConnectionStream>,
    msg: &str,
) -> Result<(), String> {
    // Check if peer closed the link (event task clears active_link_id)
    let link_alive = {
        let st = state.lock().expect("lock poisoned");
        st.active_link_id.is_some()
    };

    if !link_alive {
        if stream.is_some() {
            // Peer closed but we still hold the stream — signal to caller to drop it
            return Err("[closed] link closed by peer".to_string());
        }
        return Err("no active link, use /link or /accept first".to_string());
    }

    let Some(s) = stream else {
        return Err("no active link, use /link or /accept first".to_string());
    };

    if msg.len() > 458 {
        return Err(format!("message too long ({} bytes, max 458)", msg.len()));
    }

    s.send(msg.as_bytes()).await.map_err(|e| {
        tracing::debug!(error = %e, msg_len = msg.len(), "try_send: stream.send() failed");
        format!("send failed: {e}")
    })
}

/// Event loop task: reads NodeEvents and prints them, updating shared state.
async fn event_loop(
    mut event_rx: tokio::sync::mpsc::Receiver<NodeEvent>,
    state: Arc<Mutex<SessionState>>,
) {
    use tokio::io::AsyncWriteExt;
    let mut stdout = tokio::io::stdout();

    while let Some(event) = event_rx.recv().await {
        // Build output message and state updates for each event
        let msg = match event {
            NodeEvent::AnnounceReceived {
                announce,
                interface_index: _,
            } => {
                let hash = hex_encode(announce.destination_hash().as_bytes());
                let app_data = String::from_utf8_lossy(announce.app_data()).to_string();
                let public_key = *announce.public_key();

                let mut st = state.lock().expect("lock poisoned");
                let entry = st.discovered.entry(hash.clone()).or_insert(AnnounceInfo {
                    app_data: app_data.clone(),
                    hops: None,
                    public_key,
                });
                // Update on re-announce
                entry.app_data = app_data.clone();
                entry.public_key = public_key;

                if !st.show_announces {
                    continue;
                }
                format!("[announce] {hash}  app_data: {app_data}")
            }

            NodeEvent::PathFound {
                destination_hash,
                hops,
                interface_index: _,
            } => {
                let hash = hex_encode(destination_hash.as_bytes());

                let mut st = state.lock().expect("lock poisoned");
                if let Some(info) = st.discovered.get_mut(&hash) {
                    info.hops = Some(hops);
                }

                if !st.show_announces {
                    continue;
                }
                format!("[path] {hash}  {hops} hops")
            }

            NodeEvent::ConnectionRequest {
                link_id,
                destination_hash,
                peer_keys: _,
            } => {
                let hash = hex_encode(destination_hash.as_bytes());
                {
                    let mut st = state.lock().expect("lock poisoned");
                    st.pending_requests.push_back((link_id, destination_hash));
                }
                format!("[link-request] from {hash} — use /accept")
            }

            NodeEvent::ConnectionEstablished {
                link_id,
                is_initiator,
            } => {
                format!("[connected] link {link_id} (initiator: {is_initiator})")
            }

            NodeEvent::DataReceived { link_id: _, data } => {
                // Note: DataReceived is delivered to BOTH event_rx and the
                // ConnectionStream's internal incoming_rx. Since nobody calls
                // stream.recv() in this CLI, the stream's channel (capacity 64)
                // fills up silently. This is acceptable — 64 × ≤458 bytes ≈ 29 KB.
                let text = String::from_utf8_lossy(&data);
                format!("[received] {text}")
            }

            NodeEvent::MessageReceived {
                link_id: _,
                msgtype,
                sequence: _,
                data,
            } => {
                let text = String::from_utf8_lossy(&data);
                format!("[message type={msgtype}] {text}")
            }

            NodeEvent::ConnectionClosed { link_id, reason } => {
                {
                    let mut st = state.lock().expect("lock poisoned");
                    if st.active_link_id == Some(link_id) {
                        st.active_link_id = None;
                    }
                }
                format!("[closed] link {link_id}: {reason:?}")
            }

            NodeEvent::ConnectionStale { link_id } => {
                format!("[stale] link {link_id}")
            }

            NodeEvent::ConnectionRecovered { link_id } => {
                format!("[recovered] link {link_id}")
            }

            _ => continue, // Ignore other events
        };

        // Print the event on its own line, then re-print the prompt
        let output = format!("\r{msg}\n> ");
        let _ = stdout.write_all(output.as_bytes()).await;
        let _ = stdout.flush().await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging: RUST_LOG env takes precedence, then -v flag
    let default_filter = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter)),
        )
        .with_target(true)
        .init();

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
                println!("Requesting path to: {dest}");
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
                use rand_core::OsRng;

                let identity = Identity::generate(&mut OsRng);
                let hash = identity.hash();
                let hash_hex = hex_encode(hash);

                println!("Generated new identity");
                println!("Hash: {hash_hex}");

                if let Some(path) = output {
                    let key_bytes = identity.private_key_bytes().map_err(|e| e.to_string())?;
                    std::fs::write(&path, key_bytes)?;
                    println!("Saved to: {}", path.display());
                } else {
                    let pub_key = identity.public_key_bytes();
                    let pub_hex = hex_encode(&pub_key);
                    println!("Public key: {pub_hex}");
                }
            }

            IdentityAction::Show { path } => {
                let key_bytes = std::fs::read(&path)?;
                let identity =
                    Identity::from_private_key_bytes(&key_bytes).map_err(|e| e.to_string())?;
                let hash = identity.hash();
                let hash_hex = hex_encode(hash);
                let pub_key = identity.public_key_bytes();
                let pub_hex = hex_encode(&pub_key);

                println!("Identity: {}", path.display());
                println!("Hash: {hash_hex}");
                println!("Public key: {pub_hex}");
            }
        },

        Commands::Probe { destination } => {
            println!("Probing destination: {destination}");
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

        Commands::Connect { addr, identity } => {
            run_connect(addr, identity).await?;
        }
    }

    Ok(())
}
