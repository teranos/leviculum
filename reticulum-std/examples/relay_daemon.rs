//! Transport relay daemon example
//!
//! This example demonstrates a Rust Reticulum node acting as a transport relay.
//! It listens for incoming TCP connections and routes traffic between all
//! connected peers.
//!
//! # Usage
//!
//! ```sh
//! # Start the relay daemon on the default port (4242)
//! cargo run --example relay_daemon
//!
//! # Start on a custom port
//! cargo run --example relay_daemon -- 5555
//! ```
//!
//! Then connect Python rnsd instances or other Reticulum nodes to this relay
//! by adding it as a TCPClientInterface target.

use std::net::TcpListener;
use std::time::Duration;

use reticulum_std::node::ReticulumNodeBuilder;
use reticulum_std::TcpClientInterface;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "4242".to_string());
    let addr = format!("0.0.0.0:{}", port);

    // Build a transport-enabled node with no pre-configured interfaces.
    // Interfaces are added dynamically as clients connect.
    let mut node = ReticulumNodeBuilder::new()
        .enable_transport(true)
        .build()
        .await?;

    node.start().await?;

    let listener = TcpListener::bind(&addr)?;
    listener.set_nonblocking(true)?;
    println!("Relay daemon listening on {}", addr);

    let mut client_count = 0u64;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\nShutting down...");
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                match listener.accept() {
                    Ok((stream, peer)) => {
                        client_count += 1;
                        let name = format!("client_{}", client_count);
                        let iface = TcpClientInterface::from_stream(&name, stream)?;
                        let idx = {
                            let inner = node.inner();
                            let mut core = inner.lock().unwrap();
                            core.register_interface(Box::new(iface))
                        };
                        println!("Client connected: {} -> interface {}", peer, idx);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => eprintln!("Accept error: {}", e),
                }
            }
        }
    }

    node.stop().await?;

    let stats = node.transport_stats();
    println!(
        "Stats: received={}, forwarded={}, sent={}",
        stats.packets_received, stats.packets_forwarded, stats.packets_sent
    );
    println!("Relay daemon stopped");

    Ok(())
}
