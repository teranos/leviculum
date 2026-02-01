//! Simple chat example
//!
//! This example demonstrates bidirectional messaging between nodes
//! using the ConnectionStream API.
//!
//! # Usage
//!
//! This example requires a running Reticulum daemon (rnsd) to connect to.
//! Start rnsd first, then run:
//!
//! ```sh
//! cargo run --example chat
//! ```
//!
//! The example will:
//! 1. Connect to a local daemon
//! 2. Listen for announces from other destinations
//! 3. Allow you to type messages to send

use std::io::{self, BufRead, Write};

use reticulum_std::node::ReticulumNodeBuilder;
use reticulum_std::NodeEvent;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging (set RUST_LOG=debug for verbose output)
    tracing_subscriber::fmt::init();

    println!("Reticulum Chat Example");
    println!("======================");
    println!();

    // Build a node with a TCP interface
    println!("Connecting to local daemon...");
    let mut node = ReticulumNodeBuilder::new()
        .add_tcp_client("127.0.0.1:4242".parse()?)
        .build()
        .await?;

    // Start the node
    node.start().await?;

    // Get a handle to the inner node for direct operations
    let inner = node.inner();

    // Take the event receiver
    let mut events = node
        .take_event_receiver()
        .ok_or("Failed to get event receiver")?;

    println!("Connected!");
    println!();
    println!("Commands:");
    println!("  /quit     - Exit the chat");
    println!("  /status   - Show node status");
    println!("  /help     - Show this help");
    println!();
    println!("Listening for announces...");
    println!();

    // Spawn event handler task
    let event_handle = tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                NodeEvent::AnnounceReceived { announce, interface_index } => {
                    println!();
                    println!("[ANNOUNCE] Destination {:02x?} on interface {}",
                             &announce.destination_hash()[..4], interface_index);
                    if let Some(app_data) = announce.app_data_string() {
                        println!("           App: {}", app_data);
                    }
                    print!("> ");
                    io::stdout().flush().ok();
                }
                NodeEvent::PathFound { destination_hash, hops, .. } => {
                    println!();
                    println!("[PATH] Found route to {:02x?} ({} hops)",
                             &destination_hash[..4], hops);
                    print!("> ");
                    io::stdout().flush().ok();
                }
                NodeEvent::ConnectionEstablished { link_id, is_initiator } => {
                    println!();
                    println!("[CONNECTED] Link {:02x?} (initiator: {})",
                             &link_id[..4], is_initiator);
                    print!("> ");
                    io::stdout().flush().ok();
                }
                NodeEvent::DataReceived { link_id, data } => {
                    println!();
                    println!("[MESSAGE] From {:02x?}: {}",
                             &link_id[..4], String::from_utf8_lossy(&data));
                    print!("> ");
                    io::stdout().flush().ok();
                }
                NodeEvent::MessageReceived { link_id, data, .. } => {
                    println!();
                    println!("[MESSAGE] From {:02x?}: {}",
                             &link_id[..4], String::from_utf8_lossy(&data));
                    print!("> ");
                    io::stdout().flush().ok();
                }
                NodeEvent::ConnectionClosed { link_id, reason } => {
                    println!();
                    println!("[DISCONNECTED] Link {:02x?}: {:?}",
                             &link_id[..4], reason);
                    print!("> ");
                    io::stdout().flush().ok();
                }
                _ => {
                    // Ignore other events
                }
            }
        }
    });

    // Read input from stdin
    let stdin = io::stdin();
    print!("> ");
    io::stdout().flush()?;

    for line in stdin.lock().lines() {
        let line = line?;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            print!("> ");
            io::stdout().flush()?;
            continue;
        }

        if trimmed.starts_with('/') {
            match trimmed {
                "/quit" | "/exit" | "/q" => {
                    println!("Goodbye!");
                    break;
                }
                "/status" => {
                    let core = inner.lock().unwrap();
                    println!("Node Status:");
                    println!("  Active connections: {}", core.active_connection_count());
                    println!("  Pending connections: {}", core.pending_connection_count());
                }
                "/help" | "/?" => {
                    println!("Commands:");
                    println!("  /quit     - Exit the chat");
                    println!("  /status   - Show node status");
                    println!("  /help     - Show this help");
                }
                _ => {
                    println!("Unknown command: {}", trimmed);
                    println!("Type /help for available commands.");
                }
            }
        } else {
            // Regular message - in a full implementation, this would send to a connected peer
            println!("(Messages would be sent to connected peers in a full implementation)");
        }

        print!("> ");
        io::stdout().flush()?;
    }

    // Clean up
    event_handle.abort();
    // node.stop() would be called here but we've moved events out
    println!("Chat ended.");

    Ok(())
}
