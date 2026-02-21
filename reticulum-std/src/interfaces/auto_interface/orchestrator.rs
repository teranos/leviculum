//! AutoInterface orchestrator — manages peer discovery and lifecycle
//!
//! Single tokio task that handles multicast discovery, peer management,
//! and data socket demultiplexing for AutoInterface.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::{
    bind_data_socket, bind_multicast_socket, bind_outbound_socket, bind_unicast_socket,
    derive_multicast_address, enumerate_nics, make_discovery_token, recv_from_any,
    unicast_discovery_port, verify_discovery_token, AdoptedNic, AutoInterfaceConfig,
    DeduplicationCache, ANNOUNCE_INTERVAL_SECS, AUTO_HW_MTU, MCAST_ECHO_TIMEOUT_SECS,
    PEERING_TIMEOUT_SECS, PEER_JOB_INTERVAL_SECS,
};
use crate::interfaces::{IncomingPacket, InterfaceHandle, InterfaceInfo, OutgoingPacket};
use reticulum_core::transport::InterfaceId;

/// Maximum datagram size for AutoInterface (matches Python HW_MTU = 1196).
const MAX_DATAGRAM_SIZE: usize = 1196;

/// Per-peer channel buffer size
const PEER_CHANNEL_BUFFER: usize = 64;

/// Information about a discovered peer
struct PeerInfo {
    /// NIC name where this peer was discovered
    nic_name: String,
    /// NIC interface index (scope_id for SocketAddrV6)
    scope_id: u32,
    /// Last time we heard from this peer (discovery or data)
    last_heard: Instant,
    /// Last time we sent a reverse peering token to this peer
    last_reverse_peering: Instant,
    /// Channel to push incoming data to the event loop.
    /// Dropping this triggers handle_interface_down cascade.
    incoming_tx: mpsc::Sender<IncomingPacket>,
}

/// Per-NIC multicast echo tracking for carrier detection
struct NicState {
    /// Last time a multicast echo was received on this NIC
    last_echo: Option<Instant>,
    /// Whether the NIC is currently timed out (no carrier)
    timed_out: bool,
}

/// Given all enumerated NICs and per-NIC bind results, return only the NICs
/// that succeeded and pre-compute their discovery tokens.
///
/// Socket vecs (`mcast_sockets`, `unicast_sockets`, `data_sockets`) only contain
/// entries for NICs where all three binds succeeded. This function produces a
/// parallel `active_nics` vec so that `socket_index` maps to the correct NIC.
///
/// Removal path: entries are static for the lifetime of the orchestrator.
pub(crate) fn build_active_nics_and_tokens(
    nics: &[AdoptedNic],
    bind_results: &[bool],
    group_id: &[u8],
) -> (Vec<AdoptedNic>, Vec<([u8; 32], String)>) {
    let active: Vec<AdoptedNic> = nics
        .iter()
        .zip(bind_results.iter())
        .filter(|(_, ok)| **ok)
        .map(|(n, _)| n.clone())
        .collect();

    let tokens: Vec<([u8; 32], String)> = active
        .iter()
        .map(|n| {
            let addr_str = n.link_local.to_string();
            let token = make_discovery_token(group_id, &addr_str);
            (token, addr_str)
        })
        .collect();

    (active, tokens)
}

/// Compute the discovery token for a reverse peering announcement.
///
/// The token must be verifiable by the peer using the sender's source IP.
/// Looks up the peer's NIC in `active_nics` to find OUR link-local address
/// on that NIC — the peer will verify `hash(group_id + our_source_ip)`.
///
/// Returns `None` if the NIC is not found in `active_nics`.
pub(crate) fn compute_reverse_peering_token(
    group_id: &[u8],
    peer_nic_name: &str,
    active_nics: &[AdoptedNic],
) -> Option<[u8; 32]> {
    let our_nic = active_nics.iter().find(|n| n.name == peer_nic_name)?;
    let our_addr_str = our_nic.link_local.to_string();
    Some(make_discovery_token(group_id, &our_addr_str))
}

/// Spawn the AutoInterface orchestrator as a background tokio task.
///
/// The orchestrator enumerates NICs, binds sockets, and runs the discovery
/// and data forwarding loop. Discovered peers are registered as individual
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

/// Main orchestrator loop.
///
/// Enumerates NICs, binds sockets, and runs the discovery + data loop.
/// Each discovered peer becomes a separate InterfaceHandle registered
/// via `new_iface_tx` into the main event loop.
async fn run_auto_interface(
    config: AutoInterfaceConfig,
    next_id: Arc<AtomicUsize>,
    new_iface_tx: mpsc::Sender<InterfaceHandle>,
) -> io::Result<()> {
    // Enumerate suitable NICs
    let nics = enumerate_nics(&config);
    if nics.is_empty() {
        tracing::warn!("AutoInterface: no suitable network interfaces found");
        return Ok(());
    }

    let mcast_addr = derive_multicast_address(&config.group_id, &config.discovery_scope)?;
    let unicast_port = unicast_discovery_port(config.discovery_port);

    tracing::info!(
        "AutoInterface: {} NIC(s), multicast={}, discovery_port={}, data_port={}",
        nics.len(),
        mcast_addr,
        config.discovery_port,
        config.data_port
    );

    // Bind sockets per NIC, tracking which succeeded
    let mut mcast_sockets = Vec::new();
    let mut unicast_sockets = Vec::new();
    let mut data_sockets = Vec::new();
    let mut bind_results = Vec::with_capacity(nics.len());
    for nic in &nics {
        match bind_multicast_socket(
            nic,
            &mcast_addr,
            config.discovery_port,
            &config.discovery_scope,
            config.multicast_loopback,
        ) {
            Ok(s) => {
                tracing::info!(
                    "AutoInterface: multicast socket on {} ({})",
                    nic.name,
                    nic.link_local
                );
                mcast_sockets.push(s);
            }
            Err(e) => {
                tracing::warn!(
                    "AutoInterface: failed to bind multicast on {}: {}",
                    nic.name,
                    e
                );
                bind_results.push(false);
                continue;
            }
        }

        match bind_unicast_socket(nic, unicast_port) {
            Ok(s) => unicast_sockets.push(s),
            Err(e) => {
                tracing::warn!(
                    "AutoInterface: failed to bind unicast on {}: {}",
                    nic.name,
                    e
                );
                // Remove the multicast socket we just pushed — can't function without unicast
                mcast_sockets.pop();
                bind_results.push(false);
                continue;
            }
        }

        match bind_data_socket(nic, config.data_port) {
            Ok(s) => {
                data_sockets.push(s);
            }
            Err(e) => {
                tracing::warn!("AutoInterface: failed to bind data on {}: {}", nic.name, e);
                mcast_sockets.pop();
                unicast_sockets.pop();
                bind_results.push(false);
                continue;
            }
        }
        bind_results.push(true);
    }

    if mcast_sockets.is_empty() {
        tracing::warn!("AutoInterface: no sockets could be bound, exiting");
        return Ok(());
    }

    // Shared outbound socket for peer send tasks
    let outbound = Arc::new(bind_outbound_socket()?);

    // Per-peer state: keyed by peer's IPv6 link-local address
    let mut peers: HashMap<Ipv6Addr, PeerInfo> = HashMap::new();

    // Per-NIC state for carrier detection
    let mut nic_states: HashMap<String, NicState> = nics
        .iter()
        .map(|n| {
            (
                n.name.clone(),
                NicState {
                    last_echo: None,
                    timed_out: false,
                },
            )
        })
        .collect();

    // Deduplication cache for data packets received on multiple NICs
    let mut dedup = DeduplicationCache::new();

    // Timers
    let announce_interval = Duration::from_secs_f64(ANNOUNCE_INTERVAL_SECS);
    let peer_job_interval = Duration::from_secs_f64(PEER_JOB_INTERVAL_SECS);
    let peering_timeout = Duration::from_secs_f64(PEERING_TIMEOUT_SECS);
    let echo_timeout = Duration::from_secs_f64(MCAST_ECHO_TIMEOUT_SECS);
    let reverse_peering_interval = Duration::from_secs_f64(super::reverse_peering_interval_secs());

    let mut announce_timer = tokio::time::interval(announce_interval);
    let mut peer_job_timer = tokio::time::interval(peer_job_interval);

    // Build active_nics (only NICs where all 3 sockets bound) and their tokens
    let (active_nics, our_tokens) =
        build_active_nics_and_tokens(&nics, &bind_results, &config.group_id);
    // Collect our own link-local addresses for self-echo detection
    let our_addrs: Vec<Ipv6Addr> = active_nics.iter().map(|n| n.link_local).collect();

    let mut mcast_buf = [0u8; 64];
    let mut unicast_buf = [0u8; 64];
    let mut data_buf = [0u8; MAX_DATAGRAM_SIZE];
    let mut mcast_poll = 0usize;
    let mut unicast_poll = 0usize;
    let mut data_poll = 0usize;

    loop {
        tokio::select! {
            // ── Multicast discovery recv ──────────────────────────────
            result = recv_from_any(&mcast_sockets, &mut mcast_buf, &mut mcast_poll) => {
                let recv = match result {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("AutoInterface: multicast recv error: {}", e);
                        continue;
                    }
                };
                let token = &mcast_buf[..recv.bytes_read];
                let src_addr = *recv.source.ip();
                let nic = &active_nics[recv.socket_index];

                handle_discovery_token(
                    token,
                    src_addr,
                    nic,
                    &config,
                    &our_addrs,
                    &mut nic_states,
                    &mut peers,
                    &next_id,
                    &new_iface_tx,
                    &outbound,
                );
            }

            // ── Unicast discovery recv ────────────────────────────────
            result = recv_from_any(&unicast_sockets, &mut unicast_buf, &mut unicast_poll) => {
                let recv = match result {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("AutoInterface: unicast recv error: {}", e);
                        continue;
                    }
                };
                let token = &unicast_buf[..recv.bytes_read];
                let src_addr = *recv.source.ip();
                let nic = &active_nics[recv.socket_index];

                handle_discovery_token(
                    token,
                    src_addr,
                    nic,
                    &config,
                    &our_addrs,
                    &mut nic_states,
                    &mut peers,
                    &next_id,
                    &new_iface_tx,
                    &outbound,
                );
            }

            // ── Data recv + demux ─────────────────────────────────────
            result = recv_from_any(&data_sockets, &mut data_buf, &mut data_poll) => {
                let recv = match result {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("AutoInterface: data recv error: {}", e);
                        continue;
                    }
                };

                let data = &data_buf[..recv.bytes_read];
                if data.is_empty() {
                    continue;
                }

                // Dedup (same packet from multiple NICs)
                if dedup.is_duplicate(data) {
                    continue;
                }

                let src_addr = *recv.source.ip();

                // Look up peer
                if let Some(peer) = peers.get_mut(&src_addr) {
                    peer.last_heard = Instant::now();
                    // Forward to event loop via incoming channel
                    match peer.incoming_tx.try_send(IncomingPacket {
                        data: data.to_vec(),
                    }) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            tracing::debug!(
                                "AutoInterface: incoming channel full for {}, dropping packet",
                                src_addr
                            );
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            tracing::warn!(
                                "AutoInterface: incoming channel closed for {}",
                                src_addr
                            );
                        }
                    }
                } else {
                    tracing::debug!(
                        "AutoInterface: data from unknown peer {}, dropping (no discovery yet)",
                        src_addr
                    );
                }
            }

            // ── Announce timer (send multicast token) ─────────────────
            _ = announce_timer.tick() => {
                for (nic_idx, sock) in mcast_sockets.iter().enumerate() {
                    let nic = &active_nics[nic_idx];
                    let (ref token, _) = our_tokens[nic_idx];
                    let dest = SocketAddrV6::new(mcast_addr, config.discovery_port, 0, nic.index);
                    if let Err(e) = sock.send_to(token, dest).await {
                        tracing::debug!(
                            "AutoInterface: multicast send on {} failed: {}",
                            nic.name,
                            e
                        );
                    }
                }
            }

            // ── Peer job timer (timeout + reverse peering + carrier) ──
            _ = peer_job_timer.tick() => {
                let now = Instant::now();

                // Check peer timeouts
                let timed_out: Vec<Ipv6Addr> = peers
                    .iter()
                    .filter(|(_, p)| now.duration_since(p.last_heard) > peering_timeout)
                    .map(|(addr, _)| *addr)
                    .collect();

                for addr in timed_out {
                    if let Some(peer) = peers.remove(&addr) {
                        tracing::info!(
                            "AutoInterface: peer {} on {} timed out",
                            addr,
                            peer.nic_name,
                        );
                        // Dropping incoming_tx triggers the cascade:
                        // event loop detects Disconnected → handle_interface_down → cleanup
                    }
                }

                // Send reverse peering tokens to peers that haven't been poked recently
                for (addr, peer) in &mut peers {
                    if now.duration_since(peer.last_reverse_peering) > reverse_peering_interval {
                        peer.last_reverse_peering = now;
                        // Token must be verifiable by the peer using OUR source IP
                        let token = match compute_reverse_peering_token(
                            &config.group_id,
                            &peer.nic_name,
                            &active_nics,
                        ) {
                            Some(t) => t,
                            None => continue,
                        };
                        // Find the multicast socket for this peer's NIC
                        if let Some(nic_idx) = active_nics.iter().position(|n| n.name == peer.nic_name) {
                            let dest = SocketAddrV6::new(
                                *addr,
                                unicast_port,
                                0,
                                peer.scope_id,
                            );
                            // Use the NIC's multicast socket for sending (it's already
                            // bound to the right interface)
                            if nic_idx < mcast_sockets.len() {
                                if let Err(e) = mcast_sockets[nic_idx].send_to(&token, dest).await {
                                    tracing::debug!(
                                        "AutoInterface: reverse peering send to {} failed: {}",
                                        addr,
                                        e
                                    );
                                }
                            }
                        }
                    }
                }

                // Check multicast echo timeouts (carrier detection)
                for (nic_name, state) in &mut nic_states {
                    let echo_timed_out = match state.last_echo {
                        Some(last) => now.duration_since(last) > echo_timeout,
                        None => true, // Never received an echo
                    };

                    if echo_timed_out && !state.timed_out {
                        state.timed_out = true;
                        tracing::warn!(
                            "AutoInterface: multicast echo timeout on {}. Carrier lost.",
                            nic_name
                        );
                    } else if !echo_timed_out && state.timed_out {
                        state.timed_out = false;
                        tracing::warn!(
                            "AutoInterface: carrier recovered on {}",
                            nic_name
                        );
                    }
                }
            }

            // ── Event loop shut down ──────────────────────────────────
            _ = new_iface_tx.closed() => {
                tracing::info!("AutoInterface: event loop shut down, exiting");
                break;
            }
        }
    }

    Ok(())
}

/// Process a discovery token received via multicast or unicast.
///
/// If the token is from ourselves (self-echo), update carrier detection.
/// If from a new peer, create channels and register the interface.
/// If from a known peer, refresh the last_heard timestamp.
#[allow(clippy::too_many_arguments)]
fn handle_discovery_token(
    token: &[u8],
    src_addr: Ipv6Addr,
    nic: &AdoptedNic,
    config: &AutoInterfaceConfig,
    our_addrs: &[Ipv6Addr],
    nic_states: &mut HashMap<String, NicState>,
    peers: &mut HashMap<Ipv6Addr, PeerInfo>,
    next_id: &Arc<AtomicUsize>,
    new_iface_tx: &mpsc::Sender<InterfaceHandle>,
    outbound: &Arc<UdpSocket>,
) {
    // Verify token
    let src_str = src_addr.to_string();
    if !verify_discovery_token(token, &config.group_id, &src_str) {
        tracing::debug!(
            "AutoInterface: invalid discovery token from {} on {}",
            src_addr,
            nic.name
        );
        return;
    }

    // Self-echo detection: if the source is one of our own addresses
    if our_addrs.contains(&src_addr) {
        // Update multicast echo timestamp for carrier detection
        if let Some(state) = nic_states.get_mut(&nic.name) {
            state.last_echo = Some(Instant::now());
        }
        return;
    }

    // Known peer — refresh
    if let Some(peer) = peers.get_mut(&src_addr) {
        peer.last_heard = Instant::now();
        return;
    }

    // New peer — register
    let id = InterfaceId(next_id.fetch_add(1, Ordering::Relaxed));
    let (incoming_tx, incoming_rx) = mpsc::channel(PEER_CHANNEL_BUFFER);
    let (outgoing_tx, outgoing_rx) = mpsc::channel(PEER_CHANNEL_BUFFER);

    let peer_sockaddr = SocketAddrV6::new(src_addr, config.data_port, 0, nic.index);

    // Spawn per-peer send task
    let send_socket = outbound.clone();
    tokio::spawn(async move {
        peer_send_task(outgoing_rx, send_socket, peer_sockaddr).await;
    });

    // Format short address for interface name (last 4 octets as 8 hex chars)
    let o = src_addr.octets();
    let addr_short = format!("{:02x}{:02x}{:02x}{:02x}", o[12], o[13], o[14], o[15]);
    let iface_name = format!("auto/{}/{}", nic.name, addr_short);

    let handle = InterfaceHandle {
        info: InterfaceInfo {
            id,
            name: iface_name.clone(),
            hw_mtu: Some(AUTO_HW_MTU),
        },
        incoming: incoming_rx,
        outgoing: outgoing_tx,
    };

    let now = Instant::now();
    peers.insert(
        src_addr,
        PeerInfo {
            nic_name: nic.name.clone(),
            scope_id: nic.index,
            last_heard: now,
            last_reverse_peering: now,
            incoming_tx,
        },
    );

    match new_iface_tx.try_send(handle) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            tracing::warn!(
                "AutoInterface: new-interface channel full, cannot register peer {}",
                src_addr
            );
            peers.remove(&src_addr);
            return;
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            tracing::warn!("AutoInterface: event loop gone, cannot register peer");
            peers.remove(&src_addr);
            return;
        }
    }

    tracing::info!(
        "AutoInterface: new peer {} on {} (id={}, name={})",
        src_addr,
        nic.name,
        id,
        iface_name
    );
}

/// Per-peer send task: reads outgoing packets from the event loop and
/// sends them to the peer's address via the shared outbound socket.
///
/// Exits when `outgoing_rx` is closed (event loop dropped the sender,
/// which happens when the InterfaceHandle is removed from the registry).
async fn peer_send_task(
    mut outgoing_rx: mpsc::Receiver<OutgoingPacket>,
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddrV6,
) {
    while let Some(pkt) = outgoing_rx.recv().await {
        if let Err(e) = socket.send_to(&pkt.data, peer_addr).await {
            tracing::debug!("AutoInterface: send to {} failed: {}", peer_addr.ip(), e);
            // Don't break — send errors are transient for UDP
        }
    }
    tracing::debug!("AutoInterface: send task for {} exiting", peer_addr.ip());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_active_nics_skip_failed_binds() {
        let nics = vec![
            AdoptedNic {
                name: "eth0".into(),
                link_local: "fe80::1".parse().unwrap(),
                index: 1,
            },
            AdoptedNic {
                name: "eth1".into(),
                link_local: "fe80::2".parse().unwrap(),
                index: 2,
            },
            AdoptedNic {
                name: "eth2".into(),
                link_local: "fe80::3".parse().unwrap(),
                index: 3,
            },
        ];
        // eth0 failed to bind, eth1 and eth2 succeeded
        let bind_results = vec![false, true, true];

        let (active, tokens) = build_active_nics_and_tokens(&nics, &bind_results, b"reticulum");

        // active_nics[0] must be eth1, NOT eth0
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].name, "eth1");
        assert_eq!(active[1].name, "eth2");

        // Token at index 0 must be for eth1's address (fe80::2)
        let expected = make_discovery_token(b"reticulum", "fe80::2");
        assert_eq!(tokens[0].0, expected, "token[0] must match eth1, not eth0");
    }

    #[test]
    fn test_active_nics_all_succeed() {
        let nics = vec![
            AdoptedNic {
                name: "eth0".into(),
                link_local: "fe80::1".parse().unwrap(),
                index: 1,
            },
            AdoptedNic {
                name: "eth1".into(),
                link_local: "fe80::2".parse().unwrap(),
                index: 2,
            },
        ];
        let bind_results = vec![true, true];

        let (active, tokens) = build_active_nics_and_tokens(&nics, &bind_results, b"reticulum");

        assert_eq!(active.len(), 2);
        assert_eq!(active[0].name, "eth0");
        assert_eq!(active[1].name, "eth1");
        assert_eq!(tokens.len(), 2);
    }

    #[test]
    fn test_reverse_peering_token_verifiable_by_peer() {
        let group_id = b"reticulum";
        let our_nic = AdoptedNic {
            name: "eth0".into(),
            link_local: "fe80::1".parse().unwrap(),
            index: 1,
        };
        let active_nics = vec![our_nic];
        // Peer's address is different from ours
        let _peer_addr: Ipv6Addr = "fe80::99".parse().unwrap();

        let token =
            compute_reverse_peering_token(group_id, "eth0", &active_nics).expect("should find NIC");

        // Peer receives this token and verifies against our source IP (fe80::1)
        assert!(
            verify_discovery_token(&token, group_id, "fe80::1"),
            "token must verify against sender's source IP, not peer's address"
        );
        // Must NOT verify against the peer's address
        assert!(
            !verify_discovery_token(&token, group_id, "fe80::99"),
            "token must NOT verify against peer's own address"
        );
    }

    #[test]
    fn test_reverse_peering_token_unknown_nic() {
        let active_nics = vec![AdoptedNic {
            name: "eth0".into(),
            link_local: "fe80::1".parse().unwrap(),
            index: 1,
        }];

        let result = compute_reverse_peering_token(b"reticulum", "wlan0", &active_nics);
        assert!(result.is_none(), "unknown NIC should return None");
    }

    #[test]
    fn test_active_nics_all_fail() {
        let nics = vec![AdoptedNic {
            name: "eth0".into(),
            link_local: "fe80::1".parse().unwrap(),
            index: 1,
        }];
        let bind_results = vec![false];

        let (active, tokens) = build_active_nics_and_tokens(&nics, &bind_results, b"reticulum");

        assert!(active.is_empty());
        assert!(tokens.is_empty());
    }

    #[test]
    fn test_peer_info_fields() {
        // Basic construction test — verifies the struct layout compiles
        let (tx, _rx) = mpsc::channel(1);
        let _peer = PeerInfo {
            nic_name: "eth0".to_string(),
            scope_id: 2,
            last_heard: Instant::now(),
            last_reverse_peering: Instant::now(),
            incoming_tx: tx,
        };
    }

    #[tokio::test]
    async fn test_peer_send_task_exits_on_channel_close() {
        let (outgoing_tx, outgoing_rx) = mpsc::channel(8);
        let socket = Arc::new(bind_outbound_socket().unwrap());
        // Use a dummy address — we won't actually receive
        let peer_addr = SocketAddrV6::new("::1".parse().unwrap(), 9999, 0, 0);

        let handle = tokio::spawn(async move {
            peer_send_task(outgoing_rx, socket, peer_addr).await;
        });

        // Drop the sender — task should exit
        drop(outgoing_tx);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("peer_send_task should exit within 2s")
            .expect("task should not panic");
    }

    #[tokio::test]
    async fn test_peer_send_task_forwards_data() {
        let (outgoing_tx, outgoing_rx) = mpsc::channel(8);
        let socket = Arc::new(bind_outbound_socket().unwrap());

        // Bind a receiver socket to verify the send arrives
        let recv_socket = bind_outbound_socket().unwrap();
        let recv_addr = recv_socket.local_addr().unwrap();
        let recv_v6 = match recv_addr {
            std::net::SocketAddr::V6(v6) => v6,
            _ => panic!("expected v6"),
        };

        // Rewrite to use loopback with correct port
        let peer_addr = SocketAddrV6::new("::1".parse().unwrap(), recv_v6.port(), 0, 0);

        tokio::spawn(async move {
            peer_send_task(outgoing_rx, socket, peer_addr).await;
        });

        // Send a packet
        outgoing_tx
            .send(OutgoingPacket {
                data: b"test data".to_vec(),
            })
            .await
            .unwrap();

        let mut buf = [0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), recv_socket.recv_from(&mut buf))
            .await
            .expect("timeout")
            .expect("recv error");
        assert_eq!(&buf[..n], b"test data");
    }

    #[tokio::test]
    async fn test_self_echo_not_added_as_peer() {
        let config = AutoInterfaceConfig::default();
        let nic = AdoptedNic {
            name: "eth0".to_string(),
            link_local: "fe80::1".parse().unwrap(),
            index: 1,
        };
        let our_addrs = vec![nic.link_local];
        let mut nic_states = HashMap::new();
        nic_states.insert(
            "eth0".to_string(),
            NicState {
                last_echo: None,
                timed_out: true,
            },
        );
        let mut peers = HashMap::new();
        let next_id = Arc::new(AtomicUsize::new(0));
        let (new_iface_tx, _new_iface_rx) = mpsc::channel(8);
        let outbound = Arc::new(bind_outbound_socket().unwrap());

        // Create a valid token for our own address
        let token = make_discovery_token(&config.group_id, "fe80::1");

        handle_discovery_token(
            &token,
            "fe80::1".parse().unwrap(),
            &nic,
            &config,
            &our_addrs,
            &mut nic_states,
            &mut peers,
            &next_id,
            &new_iface_tx,
            &outbound,
        );

        // Should NOT create a peer (self-echo)
        assert!(peers.is_empty(), "self-echo should not create a peer");
        // Should update echo timestamp
        assert!(
            nic_states["eth0"].last_echo.is_some(),
            "self-echo should update echo timestamp"
        );
    }

    #[tokio::test]
    async fn test_new_peer_registered() {
        let config = AutoInterfaceConfig::default();
        let nic = AdoptedNic {
            name: "eth0".to_string(),
            link_local: "fe80::1".parse().unwrap(),
            index: 1,
        };
        let our_addrs = vec![nic.link_local];
        let mut nic_states = HashMap::new();
        nic_states.insert(
            "eth0".to_string(),
            NicState {
                last_echo: None,
                timed_out: false,
            },
        );
        let mut peers = HashMap::new();
        let next_id = Arc::new(AtomicUsize::new(100));
        let (new_iface_tx, mut new_iface_rx) = mpsc::channel(8);
        let outbound = Arc::new(bind_outbound_socket().unwrap());

        // Create a token for a remote peer
        let peer_addr: Ipv6Addr = "fe80::2".parse().unwrap();
        let token = make_discovery_token(&config.group_id, &peer_addr.to_string());

        handle_discovery_token(
            &token,
            peer_addr,
            &nic,
            &config,
            &our_addrs,
            &mut nic_states,
            &mut peers,
            &next_id,
            &new_iface_tx,
            &outbound,
        );

        assert_eq!(peers.len(), 1, "should have one peer");
        assert!(peers.contains_key(&peer_addr));

        // Should have sent an InterfaceHandle to the event loop
        let handle = new_iface_rx.try_recv().expect("should receive handle");
        assert_eq!(handle.info.id, InterfaceId(100));
        assert!(handle.info.name.starts_with("auto/eth0/"));
        assert_eq!(handle.info.hw_mtu, Some(AUTO_HW_MTU));
    }

    #[tokio::test]
    async fn test_known_peer_refreshed() {
        let config = AutoInterfaceConfig::default();
        let nic = AdoptedNic {
            name: "eth0".to_string(),
            link_local: "fe80::1".parse().unwrap(),
            index: 1,
        };
        let our_addrs = vec![nic.link_local];
        let mut nic_states = HashMap::new();
        nic_states.insert(
            "eth0".to_string(),
            NicState {
                last_echo: None,
                timed_out: false,
            },
        );
        let mut peers = HashMap::new();
        let next_id = Arc::new(AtomicUsize::new(100));
        let (new_iface_tx, _new_iface_rx) = mpsc::channel(8);
        let outbound = Arc::new(bind_outbound_socket().unwrap());

        let peer_addr: Ipv6Addr = "fe80::2".parse().unwrap();
        let token = make_discovery_token(&config.group_id, &peer_addr.to_string());

        // First discovery
        handle_discovery_token(
            &token,
            peer_addr,
            &nic,
            &config,
            &our_addrs,
            &mut nic_states,
            &mut peers,
            &next_id,
            &new_iface_tx,
            &outbound,
        );

        let first_heard = peers[&peer_addr].last_heard;

        // Brief delay
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Second discovery — should refresh, not add new
        handle_discovery_token(
            &token,
            peer_addr,
            &nic,
            &config,
            &our_addrs,
            &mut nic_states,
            &mut peers,
            &next_id,
            &new_iface_tx,
            &outbound,
        );

        assert_eq!(peers.len(), 1, "should still have one peer");
        assert!(
            peers[&peer_addr].last_heard > first_heard,
            "last_heard should be refreshed"
        );
    }

    #[tokio::test]
    async fn test_invalid_token_rejected() {
        let config = AutoInterfaceConfig::default();
        let nic = AdoptedNic {
            name: "eth0".to_string(),
            link_local: "fe80::1".parse().unwrap(),
            index: 1,
        };
        let our_addrs = vec![nic.link_local];
        let mut nic_states = HashMap::new();
        nic_states.insert(
            "eth0".to_string(),
            NicState {
                last_echo: None,
                timed_out: false,
            },
        );
        let mut peers = HashMap::new();
        let next_id = Arc::new(AtomicUsize::new(100));
        let (new_iface_tx, _) = mpsc::channel(8);
        let outbound = Arc::new(bind_outbound_socket().unwrap());

        // Send a bogus token
        handle_discovery_token(
            &[0u8; 32],
            "fe80::2".parse().unwrap(),
            &nic,
            &config,
            &our_addrs,
            &mut nic_states,
            &mut peers,
            &next_id,
            &new_iface_tx,
            &outbound,
        );

        assert!(peers.is_empty(), "invalid token should not create a peer");
    }
}
