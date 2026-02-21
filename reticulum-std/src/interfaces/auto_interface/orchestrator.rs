//! AutoInterface orchestrator — manages peer discovery and lifecycle
//!
//! Single tokio task that handles multicast discovery, peer management,
//! and data socket demultiplexing for AutoInterface.

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use tokio::sync::mpsc;

use super::AutoInterfaceConfig;
use crate::interfaces::InterfaceHandle;

/// Spawn the AutoInterface orchestrator as a background tokio task.
///
/// The orchestrator enumerates NICs, binds sockets, and runs the discovery
/// + data forwarding loop. Discovered peers are registered as individual
/// interfaces via `new_iface_tx`.
pub(crate) fn spawn_auto_interface(
    next_id: Arc<AtomicUsize>,
    new_iface_tx: mpsc::Sender<InterfaceHandle>,
    config: AutoInterfaceConfig,
) {
    tokio::spawn(async move {
        if let Err(e) = run_auto_interface(config, next_id, new_iface_tx).await {
            tracing::error!("AutoInterface orchestrator exited with error: {}", e);
        }
    });
}

/// Main orchestrator loop (implementation in commit 3).
async fn run_auto_interface(
    _config: AutoInterfaceConfig,
    _next_id: Arc<AtomicUsize>,
    _new_iface_tx: mpsc::Sender<InterfaceHandle>,
) -> std::io::Result<()> {
    // Full implementation follows in commit 3
    Ok(())
}
