//! `lrns selftest` — real-network integration self-test
//!
//! Two ephemeral nodes in one process, both connected to a public relay,
//! establishing a link through it and exchanging messages bidirectionally.
//! After the link phase, a single-packet (fire-and-forget) exchange is run
//! to exercise the destination-addressed code path.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use sha2::{Digest, Sha256};
use tokio::sync::Notify;

use reticulum_core::link::LinkId;
use reticulum_core::node::NodeEvent;
use reticulum_core::{Destination, DestinationHash, DestinationType, Direction, Identity};
use reticulum_std::driver::{ConnectionStream, PacketEndpoint, ReticulumNodeBuilder};

// ─── Message Format ──────────────────────────────────────────────────────────

fn build_message(dir: &str, seq: u64, now_ms: u64) -> Vec<u8> {
    let payload = format!("{dir}:{seq}:{now_ms}");
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    let hash = hasher.finalize();
    let checksum = &crate::hex_encode(&hash[..4]);
    format!("{payload}:{checksum}").into_bytes()
}

struct ParsedMessage {
    dir: String,
    seq: u64,
    timestamp_ms: u64,
}

fn parse_message(data: &[u8]) -> Option<ParsedMessage> {
    let s = std::str::from_utf8(data).ok()?;
    let parts: Vec<&str> = s.splitn(4, ':').collect();
    if parts.len() != 4 {
        return None;
    }
    let dir = parts[0].to_string();
    let seq: u64 = parts[1].parse().ok()?;
    let timestamp_ms: u64 = parts[2].parse().ok()?;
    let checksum = parts[3];

    // Verify checksum
    let payload = format!("{dir}:{seq}:{timestamp_ms}");
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    let hash = hasher.finalize();
    let expected = crate::hex_encode(&hash[..4]);
    if checksum != expected {
        return None;
    }

    Some(ParsedMessage {
        dir,
        seq,
        timestamp_ms,
    })
}

// ─── Stats ───────────────────────────────────────────────────────────────────

struct SelftestStats {
    // Link phase
    sent_a: u64,
    sent_b: u64,
    recv_a: u64,
    recv_b: u64,
    confirmed_a: u64,
    confirmed_b: u64,
    send_fails_a: u64,
    send_fails_b: u64,
    corrupt: u64,
    last_seq_recv_a: u64,
    last_seq_recv_b: u64,
    out_of_order: u64,
    duplicates: u64,
    seen_seqs_a: BTreeSet<u64>,
    seen_seqs_b: BTreeSet<u64>,
    rtt_samples: Vec<u64>,
    stale_count: u64,
    recovered_count: u64,

    // Single-packet phase
    sp_sent_a: u64,
    sp_sent_b: u64,
    sp_recv_a: u64,
    sp_recv_b: u64,
    sp_send_fails_a: u64,
    sp_send_fails_b: u64,
    sp_corrupt: u64,
    sp_last_seq_recv_a: u64,
    sp_last_seq_recv_b: u64,
    sp_out_of_order: u64,
    sp_duplicates: u64,
    sp_seen_seqs_a: BTreeSet<u64>,
    sp_seen_seqs_b: BTreeSet<u64>,
    sp_rtt_samples: Vec<u64>,
}

impl SelftestStats {
    fn new() -> Self {
        Self {
            sent_a: 0,
            sent_b: 0,
            recv_a: 0,
            recv_b: 0,
            confirmed_a: 0,
            confirmed_b: 0,
            send_fails_a: 0,
            send_fails_b: 0,
            corrupt: 0,
            last_seq_recv_a: 0,
            last_seq_recv_b: 0,
            out_of_order: 0,
            duplicates: 0,
            seen_seqs_a: BTreeSet::new(),
            seen_seqs_b: BTreeSet::new(),
            rtt_samples: Vec::new(),
            stale_count: 0,
            recovered_count: 0,

            sp_sent_a: 0,
            sp_sent_b: 0,
            sp_recv_a: 0,
            sp_recv_b: 0,
            sp_send_fails_a: 0,
            sp_send_fails_b: 0,
            sp_corrupt: 0,
            sp_last_seq_recv_a: 0,
            sp_last_seq_recv_b: 0,
            sp_out_of_order: 0,
            sp_duplicates: 0,
            sp_seen_seqs_a: BTreeSet::new(),
            sp_seen_seqs_b: BTreeSet::new(),
            sp_rtt_samples: Vec::new(),
        }
    }
}

// ─── Shared State ────────────────────────────────────────────────────────────

struct SharedState {
    stats: Mutex<SelftestStats>,
    // Discovery
    b_signing_key: Mutex<Option<[u8; 32]>>,
    a_signing_key: Mutex<Option<[u8; 32]>>,
    a_discovered_b: Notify,
    b_discovered_a: Notify,
    // Link
    pending_link_b: Mutex<Option<LinkId>>,
    link_request_b: Notify,
    link_established_a: Notify,
    link_established_b: Notify,
    // Phase flag: true during single-packet phase
    single_packet_phase: AtomicBool,
}

impl SharedState {
    fn new() -> Self {
        Self {
            stats: Mutex::new(SelftestStats::new()),
            b_signing_key: Mutex::new(None),
            a_signing_key: Mutex::new(None),
            a_discovered_b: Notify::new(),
            b_discovered_a: Notify::new(),
            pending_link_b: Mutex::new(None),
            link_request_b: Notify::new(),
            link_established_a: Notify::new(),
            link_established_b: Notify::new(),
            single_packet_phase: AtomicBool::new(false),
        }
    }
}

// ─── Received message recording ──────────────────────────────────────────────

/// Record a received message into the stats, handling dedup, ordering, and RTT.
/// `is_a` = true means node A received (expects dir "ba"), false means node B (expects "ab").
fn record_received_message(
    st: &mut SelftestStats,
    data: &[u8],
    now_ms: u64,
    is_a: bool,
    is_sp: bool,
) {
    let expected_dir = if is_a { "ba" } else { "ab" };
    match parse_message(data) {
        Some(msg) if msg.dir == expected_dir => {
            if is_sp {
                // Single-packet phase counters
                if st.sp_seen_seqs_a.contains(&msg.seq) && is_a
                    || st.sp_seen_seqs_b.contains(&msg.seq) && !is_a
                {
                    st.sp_duplicates += 1;
                } else {
                    let (seen, last_seq, recv, rtt) = if is_a {
                        (
                            &mut st.sp_seen_seqs_a,
                            &mut st.sp_last_seq_recv_a,
                            &mut st.sp_recv_a,
                            &mut st.sp_rtt_samples,
                        )
                    } else {
                        (
                            &mut st.sp_seen_seqs_b,
                            &mut st.sp_last_seq_recv_b,
                            &mut st.sp_recv_b,
                            &mut st.sp_rtt_samples,
                        )
                    };
                    seen.insert(msg.seq);
                    if msg.seq < *last_seq && *recv > 0 {
                        st.sp_out_of_order += 1;
                    }
                    *last_seq = msg.seq;
                    *recv += 1;
                    rtt.push(now_ms.saturating_sub(msg.timestamp_ms));
                }
            } else {
                // Link phase counters
                let (seen, last_seq, recv, rtt) = if is_a {
                    (
                        &mut st.seen_seqs_a,
                        &mut st.last_seq_recv_a,
                        &mut st.recv_a,
                        &mut st.rtt_samples,
                    )
                } else {
                    (
                        &mut st.seen_seqs_b,
                        &mut st.last_seq_recv_b,
                        &mut st.recv_b,
                        &mut st.rtt_samples,
                    )
                };
                if seen.contains(&msg.seq) {
                    st.duplicates += 1;
                } else {
                    seen.insert(msg.seq);
                    if msg.seq < *last_seq && *recv > 0 {
                        st.out_of_order += 1;
                    }
                    *last_seq = msg.seq;
                    *recv += 1;
                    rtt.push(now_ms.saturating_sub(msg.timestamp_ms));
                }
            }
        }
        Some(_) => {} // Message from wrong direction
        None => {
            if is_sp {
                st.sp_corrupt += 1;
            } else {
                st.corrupt += 1;
            }
        }
    }
}

// ─── Verdict ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Verdict {
    Pass,
    Warn,
    Fail,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Pass => write!(f, "PASS"),
            Verdict::Warn => write!(f, "WARN"),
            Verdict::Fail => write!(f, "FAIL"),
        }
    }
}

fn compute_link_verdict(stats: &SelftestStats, warnings: &[String]) -> Verdict {
    let total_sent = stats.sent_a + stats.sent_b;
    let total_recv = stats.recv_a + stats.recv_b;
    let total_confirmed = stats.confirmed_a + stats.confirmed_b;

    // FAIL conditions
    if total_sent > 0 && total_recv == 0 {
        return Verdict::Fail;
    }
    if total_sent > 0 {
        let recv_pct = (total_recv as f64 / total_sent as f64) * 100.0;
        if recv_pct < 70.0 {
            return Verdict::Fail;
        }
        let conf_pct = (total_confirmed as f64 / total_sent as f64) * 100.0;
        if conf_pct < 50.0 {
            return Verdict::Fail;
        }
    }

    if !warnings.is_empty() {
        return Verdict::Warn;
    }

    Verdict::Pass
}

fn compute_sp_verdict(stats: &SelftestStats, warnings: &[String]) -> Verdict {
    let total_sent = stats.sp_sent_a + stats.sp_sent_b;
    let total_recv = stats.sp_recv_a + stats.sp_recv_b;

    // FAIL conditions — relaxed for unreliable single packets
    if total_sent > 0 && total_recv == 0 {
        return Verdict::Fail;
    }
    if total_sent > 0 {
        let recv_pct = (total_recv as f64 / total_sent as f64) * 100.0;
        if recv_pct < 50.0 {
            return Verdict::Fail;
        }
    }

    if !warnings.is_empty() {
        return Verdict::Warn;
    }

    Verdict::Pass
}

// ─── Event Tasks ─────────────────────────────────────────────────────────────

async fn event_task_a(
    mut event_rx: tokio::sync::mpsc::Receiver<NodeEvent>,
    state: Arc<SharedState>,
    dest_hash_b: DestinationHash,
    link_id_a: Arc<Mutex<Option<LinkId>>>,
    start_time: Instant,
) {
    while let Some(event) = event_rx.recv().await {
        match event {
            NodeEvent::AnnounceReceived { announce, .. } => {
                if *announce.destination_hash() == dest_hash_b {
                    let pk = announce.public_key();
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&pk[32..64]);
                    *state.b_signing_key.lock().unwrap() = Some(key);
                    state.a_discovered_b.notify_one();
                }
            }
            NodeEvent::ConnectionEstablished { link_id, .. } => {
                *link_id_a.lock().unwrap() = Some(link_id);
                state.link_established_a.notify_one();
            }
            NodeEvent::MessageReceived { data, .. } => {
                let now_ms = start_time.elapsed().as_millis() as u64;
                let is_sp = state.single_packet_phase.load(Ordering::Relaxed);
                let mut st = state.stats.lock().unwrap();
                record_received_message(&mut st, &data, now_ms, true, is_sp);
            }
            NodeEvent::PacketReceived { data, .. } => {
                let now_ms = start_time.elapsed().as_millis() as u64;
                let is_sp = state.single_packet_phase.load(Ordering::Relaxed);
                let mut st = state.stats.lock().unwrap();
                record_received_message(&mut st, &data, now_ms, true, is_sp);
            }
            NodeEvent::LinkDeliveryConfirmed { .. } => {
                state.stats.lock().unwrap().confirmed_a += 1;
            }
            NodeEvent::ConnectionStale { .. } => {
                state.stats.lock().unwrap().stale_count += 1;
            }
            NodeEvent::ConnectionRecovered { .. } => {
                state.stats.lock().unwrap().recovered_count += 1;
            }
            _ => {}
        }
    }
}

async fn event_task_b(
    mut event_rx: tokio::sync::mpsc::Receiver<NodeEvent>,
    state: Arc<SharedState>,
    dest_hash_a: DestinationHash,
    start_time: Instant,
) {
    while let Some(event) = event_rx.recv().await {
        match event {
            NodeEvent::AnnounceReceived { announce, .. } => {
                if *announce.destination_hash() == dest_hash_a {
                    let pk = announce.public_key();
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&pk[32..64]);
                    *state.a_signing_key.lock().unwrap() = Some(key);
                    state.b_discovered_a.notify_one();
                }
            }
            NodeEvent::ConnectionRequest { link_id, .. } => {
                *state.pending_link_b.lock().unwrap() = Some(link_id);
                state.link_request_b.notify_one();
            }
            NodeEvent::ConnectionEstablished { .. } => {
                state.link_established_b.notify_one();
            }
            NodeEvent::MessageReceived { data, .. } => {
                let now_ms = start_time.elapsed().as_millis() as u64;
                let is_sp = state.single_packet_phase.load(Ordering::Relaxed);
                let mut st = state.stats.lock().unwrap();
                record_received_message(&mut st, &data, now_ms, false, is_sp);
            }
            NodeEvent::PacketReceived { data, .. } => {
                let now_ms = start_time.elapsed().as_millis() as u64;
                let is_sp = state.single_packet_phase.load(Ordering::Relaxed);
                let mut st = state.stats.lock().unwrap();
                record_received_message(&mut st, &data, now_ms, false, is_sp);
            }
            NodeEvent::LinkDeliveryConfirmed { .. } => {
                state.stats.lock().unwrap().confirmed_b += 1;
            }
            NodeEvent::ConnectionStale { .. } => {
                state.stats.lock().unwrap().stale_count += 1;
            }
            NodeEvent::ConnectionRecovered { .. } => {
                state.stats.lock().unwrap().recovered_count += 1;
            }
            _ => {}
        }
    }
}

// ─── Send helpers ────────────────────────────────────────────────────────────

async fn send_msg(
    stream: &ConnectionStream,
    dir: &str,
    seq: u64,
    start_time: Instant,
    state: &SharedState,
    is_a: bool,
) {
    let now_ms = start_time.elapsed().as_millis() as u64;
    let msg = build_message(dir, seq, now_ms);
    match stream.send(&msg).await {
        Ok(()) => {
            let mut st = state.stats.lock().unwrap();
            if is_a {
                st.sent_a += 1;
            } else {
                st.sent_b += 1;
            }
        }
        Err(_) => {
            let mut st = state.stats.lock().unwrap();
            if is_a {
                st.send_fails_a += 1;
            } else {
                st.send_fails_b += 1;
            }
        }
    }
}

async fn send_single_msg(
    endpoint: &PacketEndpoint,
    dir: &str,
    seq: u64,
    start_time: Instant,
    state: &SharedState,
    is_a: bool,
) {
    let now_ms = start_time.elapsed().as_millis() as u64;
    let msg = build_message(dir, seq, now_ms);
    match endpoint.send(&msg).await {
        Ok(_hash) => {
            let mut st = state.stats.lock().unwrap();
            if is_a {
                st.sp_sent_a += 1;
            } else {
                st.sp_sent_b += 1;
            }
        }
        Err(_) => {
            let mut st = state.stats.lock().unwrap();
            if is_a {
                st.sp_send_fails_a += 1;
            } else {
                st.sp_send_fails_b += 1;
            }
        }
    }
}

// ─── Main Entry Point ────────────────────────────────────────────────────────

pub async fn run_selftest(
    addr: String,
    duration: u64,
    rate: f64,
    mode: &str,
    corrupt_every: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let run_link = mode == "all" || mode == "link";
    let run_packet = mode == "all" || mode == "packet";

    if !run_link && !run_packet {
        return Err(format!("invalid --mode '{mode}': expected all, link, or packet").into());
    }

    let socket_addr: SocketAddr = addr.parse().map_err(|e| format!("invalid address: {e}"))?;

    // ── Phase 1: Setup ──────────────────────────────────────────────────
    println!("[selftest] Connecting to {socket_addr} (mode: {mode})");
    if let Some(n) = corrupt_every {
        println!("[selftest] Fault injection: --corrupt-every {n}");
    }

    // TCP pre-check
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(socket_addr),
    )
    .await
    .map_err(|_| "TCP connect timeout (10s)")?
    .map_err(|e| format!("cannot connect to {socket_addr}: {e}"))?;

    // Two ephemeral identities — need two instances each (Identity is not Clone)
    use rand_core::OsRng;
    let id_a = Identity::generate(&mut OsRng);
    let pk_a = id_a.private_key_bytes().map_err(|e| e.to_string())?;
    let id_a2 = Identity::from_private_key_bytes(&pk_a).map_err(|e| e.to_string())?;

    let id_b = Identity::generate(&mut OsRng);
    let pk_b = id_b.private_key_bytes().map_err(|e| e.to_string())?;
    let id_b2 = Identity::from_private_key_bytes(&pk_b).map_err(|e| e.to_string())?;

    // Build and start nodes
    let mut node_a = ReticulumNodeBuilder::new()
        .identity(id_a)
        .enable_transport(false)
        .add_tcp_client(socket_addr)
        .corrupt_every(corrupt_every)
        .build()
        .await?;
    node_a.start().await?;

    let mut node_b = ReticulumNodeBuilder::new()
        .identity(id_b)
        .enable_transport(false)
        .add_tcp_client(socket_addr)
        .corrupt_every(corrupt_every)
        .build()
        .await?;
    node_b.start().await?;

    // Register destinations with different app paths
    let mut dest_a = Destination::new(
        Some(id_a2),
        Direction::In,
        DestinationType::Single,
        "selftest",
        &["a"],
    )
    .map_err(|e| format!("destination error: {e}"))?;
    dest_a.set_accepts_links(true);
    let dest_hash_a = *dest_a.hash();
    node_a.register_destination(dest_a);

    let mut dest_b = Destination::new(
        Some(id_b2),
        Direction::In,
        DestinationType::Single,
        "selftest",
        &["b"],
    )
    .map_err(|e| format!("destination error: {e}"))?;
    dest_b.set_accepts_links(true);
    let dest_hash_b = *dest_b.hash();
    node_b.register_destination(dest_b);

    println!(
        "[selftest] Phase 1: OK — A={} B={}",
        crate::hex_encode(&dest_hash_a.as_bytes()[..8]),
        crate::hex_encode(&dest_hash_b.as_bytes()[..8]),
    );

    let start_time = Instant::now();
    let state = Arc::new(SharedState::new());
    let link_id_a: Arc<Mutex<Option<LinkId>>> = Arc::new(Mutex::new(None));

    // ── Phase 2: Discovery ──────────────────────────────────────────────
    let event_rx_a = node_a.take_event_receiver().ok_or("event rx A")?;
    let event_rx_b = node_b.take_event_receiver().ok_or("event rx B")?;

    // Announce both
    node_a
        .announce_destination(&dest_hash_a, Some(b"selftest-a"))
        .map_err(|e| format!("announce A: {e}"))?;
    node_b
        .announce_destination(&dest_hash_b, Some(b"selftest-b"))
        .map_err(|e| format!("announce B: {e}"))?;

    // Spawn event tasks (run for entire test duration)
    let ev_state_a = Arc::clone(&state);
    let ev_link_a = Arc::clone(&link_id_a);
    let ev_task_a = tokio::spawn(event_task_a(
        event_rx_a,
        ev_state_a,
        dest_hash_b,
        ev_link_a,
        start_time,
    ));

    let ev_state_b = Arc::clone(&state);
    let ev_task_b = tokio::spawn(event_task_b(
        event_rx_b,
        ev_state_b,
        dest_hash_a,
        start_time,
    ));

    let discovery_start = Instant::now();

    // Wait for mutual discovery
    let discovery = async {
        tokio::join!(
            state.a_discovered_b.notified(),
            state.b_discovered_a.notified()
        );
    };
    tokio::time::timeout(std::time::Duration::from_secs(60), discovery)
        .await
        .map_err(|_| "Phase 2 timeout: discovery took >60s")?;

    let discovery_time = discovery_start.elapsed();
    let hops = node_a.hops_to(&dest_hash_b).unwrap_or(0);
    println!(
        "[selftest] Phase 2: OK — path found in {:.1}s ({} hops)",
        discovery_time.as_secs_f64(),
        hops,
    );

    let interval_ms = if rate > 0.0 {
        (1000.0 / rate) as u64
    } else {
        1000
    };

    // Variables used by the report — assigned by the link phases or defaulted
    let mut link_warnings: Vec<String> = Vec::new();
    let mut final_win = 0usize;
    let mut final_win_max = 0usize;

    if run_link {
        // ── Phase 3: Link ───────────────────────────────────────────────
        let link_start = Instant::now();

        let signing_key_b = state
            .b_signing_key
            .lock()
            .unwrap()
            .ok_or("no signing key for B")?;

        let stream_a = node_a.connect(&dest_hash_b, &signing_key_b).await?;

        // Wait for link request on B
        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            state.link_request_b.notified(),
        )
        .await
        .map_err(|_| "Phase 3 timeout: link request not received by B")?;

        let pending_id = state
            .pending_link_b
            .lock()
            .unwrap()
            .ok_or("no pending link on B")?;
        let stream_b = node_b.accept_connection(&pending_id).await?;

        // Wait for both sides established
        let establish = async {
            tokio::join!(
                state.link_established_a.notified(),
                state.link_established_b.notified()
            );
        };
        tokio::time::timeout(std::time::Duration::from_secs(60), establish)
            .await
            .map_err(|_| "Phase 3 timeout: link establishment >60s")?;

        println!(
            "[selftest] Phase 3: OK — link established in {:.1}s",
            link_start.elapsed().as_secs_f64(),
        );

        // ── Phase 4: Warmup ─────────────────────────────────────────────
        let warmup_start = Instant::now();
        let warmup_msgs = 10u64;

        for seq in 0..warmup_msgs {
            send_msg(&stream_a, "ab", seq, start_time, &state, true).await;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        // Wait for at least 5 confirmations (up to 30s)
        let warmup_deadline = Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let confirmed = state.stats.lock().unwrap().confirmed_a;
            if confirmed >= 5 {
                break;
            }
            if Instant::now() > warmup_deadline {
                if confirmed == 0 {
                    println!(
                        "[selftest] Phase 4: FAIL — 0 confirmations after 30s (proofs not arriving)"
                    );
                    cleanup(&mut node_a, &mut node_b, &ev_task_a, &ev_task_b).await;
                    std::process::exit(1);
                }
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        // Check window
        let link_id = link_id_a.lock().unwrap().ok_or("no link_id on A")?;
        let window = node_a
            .connection_stats(&link_id)
            .map(|s| s.window)
            .unwrap_or(0);

        if window <= 2 && Instant::now() > warmup_deadline {
            println!(
                "[selftest] Phase 4: FAIL — window still {} after warmup",
                window
            );
            cleanup(&mut node_a, &mut node_b, &ev_task_a, &ev_task_b).await;
            std::process::exit(1);
        }

        println!(
            "[selftest] Phase 4: OK — warmup {}/{}, window={} ({:.1}s)",
            state.stats.lock().unwrap().confirmed_a,
            warmup_msgs,
            window,
            warmup_start.elapsed().as_secs_f64(),
        );

        // ── Phase 5: Sustained exchange ─────────────────────────────────
        println!("[selftest] Phase 5: Sustained link exchange ({duration}s)");

        let mut seq_a = warmup_msgs;
        let mut seq_b = 0u64;
        let mut last_recv_a = 0u64;
        let mut last_recv_b = 0u64;
        let mut zero_recv_streak = 0u32;

        let phase5_start = Instant::now();
        let phase5_end = phase5_start + std::time::Duration::from_secs(duration);
        let mut next_send = tokio::time::Instant::now();
        let mut next_health = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut elapsed_checks = 0u64;

        loop {
            let now = Instant::now();
            if now >= phase5_end {
                break;
            }

            let send_due = tokio::time::Instant::now() >= next_send;
            let health_due = tokio::time::Instant::now() >= next_health;

            if send_due {
                send_msg(&stream_a, "ab", seq_a, start_time, &state, true).await;
                seq_a += 1;
                send_msg(&stream_b, "ba", seq_b, start_time, &state, false).await;
                seq_b += 1;
                next_send =
                    tokio::time::Instant::now() + std::time::Duration::from_millis(interval_ms);
            }

            if health_due {
                elapsed_checks += 15;
                next_health = tokio::time::Instant::now() + std::time::Duration::from_secs(15);

                let st = state.stats.lock().unwrap();
                let recv_a = st.recv_a;
                let recv_b = st.recv_b;
                let conf_a = st.confirmed_a;
                let conf_b = st.confirmed_b;
                let fails = st.send_fails_a + st.send_fails_b;
                let corrupt = st.corrupt;
                let oo = st.out_of_order;
                let dupes = st.duplicates;
                let total_sent = st.sent_a + st.sent_b;
                drop(st);

                let win = node_a
                    .connection_stats(&link_id)
                    .map(|s| s.window)
                    .unwrap_or(0);

                let recv_progress = recv_a > last_recv_a || recv_b > last_recv_b;

                let mut status = "OK";
                if !recv_progress && total_sent > 0 {
                    zero_recv_streak += 1;
                    if zero_recv_streak >= 2 {
                        status = "WARN";
                        link_warnings.push(format!("+{}s: no recv in 30s", elapsed_checks));
                    }
                } else {
                    zero_recv_streak = 0;
                }

                if corrupt > 0 || oo > 0 || dupes > 0 {
                    status = "WARN";
                }

                println!(
                    "[selftest]   +{elapsed_checks}s:  sent={total_sent}  recv={}  ack={}  fails={fails}  win={win} — {status}",
                    recv_a + recv_b,
                    conf_a + conf_b,
                );

                last_recv_a = recv_a;
                last_recv_b = recv_b;
            }

            if !send_due && !health_due {
                let sleep_until = next_send.min(next_health);
                tokio::time::sleep_until(sleep_until).await;
            }
        }

        // Brief drain period for in-flight messages
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        // ── Phase 6: Burst ──────────────────────────────────────────────
        // Send 10 messages as fast as possible, retrying on WindowFull.
        // This exercises the channel under load — a well-functioning link
        // should be able to absorb the burst within a few seconds.
        let mut burst_ok = 0u64;
        let mut burst_retries = 0u64;
        let burst_timeout = Instant::now() + std::time::Duration::from_secs(10);
        for seq in 0..10u64 {
            let msg = build_message("ab", 10000 + seq, start_time.elapsed().as_millis() as u64);
            loop {
                match stream_a.send(&msg).await {
                    Ok(()) => {
                        state.stats.lock().unwrap().sent_a += 1;
                        burst_ok += 1;
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        burst_retries += 1;
                        if Instant::now() > burst_timeout {
                            state.stats.lock().unwrap().send_fails_a += 1;
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                    Err(_) => {
                        state.stats.lock().unwrap().send_fails_a += 1;
                        break;
                    }
                }
            }
        }

        if burst_ok < 10 {
            println!(
                "[selftest] Phase 6: Burst {burst_ok}/10 — WARN ({} not sent, {burst_retries} retries)",
                10 - burst_ok
            );
            link_warnings.push(format!("burst: {}/10 not sent", 10 - burst_ok));
        } else if burst_retries > 0 {
            println!("[selftest] Phase 6: Burst 10/10 — OK ({burst_retries} retries)");
        } else {
            println!("[selftest] Phase 6: Burst 10/10 — OK");
        }

        // ── Phase 7: Close link ─────────────────────────────────────────
        // Drain until all sent messages are confirmed (or timeout)
        let drain_start = Instant::now();
        let drain_timeout = std::time::Duration::from_secs(15);
        loop {
            let all_confirmed = {
                let st = state.stats.lock().unwrap();
                st.confirmed_a >= st.sent_a && st.confirmed_b >= st.sent_b
            };
            if all_confirmed {
                println!("[selftest] Phase 7: All messages confirmed — closing");
                break;
            }
            if drain_start.elapsed() > drain_timeout {
                let st = state.stats.lock().unwrap();
                println!(
                    "[selftest] Phase 7: Drain timeout — confirmed {}/{} (a) {}/{} (b)",
                    st.confirmed_a, st.sent_a, st.confirmed_b, st.sent_b
                );
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        final_win = node_a
            .connection_stats(&link_id)
            .map(|s| s.window)
            .unwrap_or(0);
        final_win_max = node_a
            .connection_stats(&link_id)
            .map(|s| s.window_max)
            .unwrap_or(0);

        // Close from B side
        if let Err(e) = node_b.close_connection(stream_b.link_id()).await {
            eprintln!("[selftest] close B: {e}");
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        println!("[selftest] Phase 7: Close link — OK");
    }

    let mut sp_warnings: Vec<String> = Vec::new();

    if run_packet {
        // ── Phase 8: Single-packet sustained exchange ───────────────────
        println!("[selftest] Phase 8: Single-packet exchange ({duration}s)");
        state.single_packet_phase.store(true, Ordering::Relaxed);

        let ep_a = node_a.packet_endpoint(&dest_hash_b);
        let ep_b = node_b.packet_endpoint(&dest_hash_a);

        let mut sp_seq_a = 0u64;
        let mut sp_seq_b = 0u64;
        let mut sp_last_recv_a = 0u64;
        let mut sp_last_recv_b = 0u64;
        let mut sp_zero_recv_streak = 0u32;

        let phase8_start = Instant::now();
        let phase8_end = phase8_start + std::time::Duration::from_secs(duration);
        let mut next_send = tokio::time::Instant::now();
        let mut next_health = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut sp_elapsed_checks = 0u64;

        loop {
            let now = Instant::now();
            if now >= phase8_end {
                break;
            }

            let send_due = tokio::time::Instant::now() >= next_send;
            let health_due = tokio::time::Instant::now() >= next_health;

            if send_due {
                send_single_msg(&ep_a, "ab", sp_seq_a, start_time, &state, true).await;
                sp_seq_a += 1;
                send_single_msg(&ep_b, "ba", sp_seq_b, start_time, &state, false).await;
                sp_seq_b += 1;
                next_send =
                    tokio::time::Instant::now() + std::time::Duration::from_millis(interval_ms);
            }

            if health_due {
                sp_elapsed_checks += 15;
                next_health = tokio::time::Instant::now() + std::time::Duration::from_secs(15);

                let st = state.stats.lock().unwrap();
                let recv_a = st.sp_recv_a;
                let recv_b = st.sp_recv_b;
                let fails = st.sp_send_fails_a + st.sp_send_fails_b;
                let total_sent = st.sp_sent_a + st.sp_sent_b;
                drop(st);

                let recv_progress = recv_a > sp_last_recv_a || recv_b > sp_last_recv_b;

                let mut status = "OK";
                if !recv_progress && total_sent > 0 {
                    sp_zero_recv_streak += 1;
                    if sp_zero_recv_streak >= 2 {
                        status = "WARN";
                        sp_warnings.push(format!("+{}s: no recv in 30s", sp_elapsed_checks));
                    }
                } else {
                    sp_zero_recv_streak = 0;
                }

                println!(
                    "[selftest]   +{sp_elapsed_checks}s:  sent={total_sent}  recv={}  fails={fails} — {status}",
                    recv_a + recv_b,
                );

                sp_last_recv_a = recv_a;
                sp_last_recv_b = recv_b;
            }

            if !send_due && !health_due {
                let sleep_until = next_send.min(next_health);
                tokio::time::sleep_until(sleep_until).await;
            }
        }

        // Brief drain period
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }

    // ── Report ──────────────────────────────────────────────────────────
    let total_time = start_time.elapsed();
    let mut verdicts: Vec<Verdict> = Vec::new();

    println!("[selftest] ══════════════════════════════════════════════════");
    println!(
        "[selftest]  Duration:      {:.1}s",
        total_time.as_secs_f64()
    );
    if let Some(n) = corrupt_every {
        println!("[selftest]  Fault inject:  ~1 byte per {n} bytes");
    }

    if run_link {
        let st = state.stats.lock().unwrap();
        let total_sent = st.sent_a + st.sent_b;
        let total_recv = st.recv_a + st.recv_b;
        let total_confirmed = st.confirmed_a + st.confirmed_b;
        let total_fails = st.send_fails_a + st.send_fails_b;

        let recv_pct = if total_sent > 0 {
            (total_recv as f64 / total_sent as f64) * 100.0
        } else {
            0.0
        };
        let conf_pct = if total_sent > 0 {
            (total_confirmed as f64 / total_sent as f64) * 100.0
        } else {
            0.0
        };

        let stale_count = st.stale_count;
        let recovered_count = st.recovered_count;
        let corrupt = st.corrupt;
        let oo = st.out_of_order;
        let dupes = st.duplicates;

        let fail_rate = if total_sent > 0 {
            total_fails as f64 / total_sent as f64
        } else {
            0.0
        };
        drop(st);

        if fail_rate > 0.05 {
            link_warnings.push(format!("send fail rate {:.1}%", fail_rate * 100.0));
        }
        if stale_count > 0 && recovered_count < stale_count {
            link_warnings.push(format!("stale={stale_count} recovered={recovered_count}"));
        }
        if corrupt > 0 {
            link_warnings.push(format!("corrupt={corrupt}"));
        }
        if dupes > 0 {
            link_warnings.push(format!("duplicates={dupes}"));
        }
        if oo > 0 {
            link_warnings.push(format!("out_of_order={oo}"));
        }

        let link_verdict = {
            let st = state.stats.lock().unwrap();
            compute_link_verdict(&st, &link_warnings)
        };
        verdicts.push(link_verdict);

        println!("[selftest] ──────────────────────────────────────────────────");
        println!("[selftest]  RESULTS — Link Phase");
        println!(
            "[selftest]  Messages:      sent={total_sent} recv={total_recv} ({recv_pct:.1}%) ack={total_confirmed} ({conf_pct:.1}%)"
        );
        println!(
            "[selftest]  Integrity:     corrupt={corrupt} out_of_order={oo} duplicates={dupes}"
        );
        println!("[selftest]  Send fails:    {total_fails} WindowFull");
        println!("[selftest]  Window:        final={final_win} (max={final_win_max})");
        println!("[selftest]  Link events:   stale={stale_count} recovered={recovered_count}");
        if !link_warnings.is_empty() {
            for w in &link_warnings {
                println!("[selftest]  Warning:       {w}");
            }
        }
        println!("[selftest]  Verdict:       {link_verdict}");
    }

    if run_packet {
        let st = state.stats.lock().unwrap();
        let total_sent = st.sp_sent_a + st.sp_sent_b;
        let total_recv = st.sp_recv_a + st.sp_recv_b;
        let total_fails = st.sp_send_fails_a + st.sp_send_fails_b;

        let recv_pct = if total_sent > 0 {
            (total_recv as f64 / total_sent as f64) * 100.0
        } else {
            0.0
        };

        let corrupt = st.sp_corrupt;
        let oo = st.sp_out_of_order;
        let dupes = st.sp_duplicates;
        drop(st);

        if corrupt > 0 {
            sp_warnings.push(format!("corrupt={corrupt}"));
        }
        if dupes > 0 {
            sp_warnings.push(format!("duplicates={dupes}"));
        }
        if oo > 0 {
            sp_warnings.push(format!("out_of_order={oo}"));
        }

        let sp_verdict = {
            let st = state.stats.lock().unwrap();
            compute_sp_verdict(&st, &sp_warnings)
        };
        verdicts.push(sp_verdict);

        println!("[selftest] ──────────────────────────────────────────────────");
        println!("[selftest]  RESULTS — Single-Packet Phase");
        println!("[selftest]  Messages:      sent={total_sent} recv={total_recv} ({recv_pct:.1}%)");
        println!(
            "[selftest]  Integrity:     corrupt={corrupt} out_of_order={oo} duplicates={dupes}"
        );
        println!("[selftest]  Send fails:    {total_fails} NoPath");
        if !sp_warnings.is_empty() {
            for w in &sp_warnings {
                println!("[selftest]  Warning:       {w}");
            }
        }
        println!("[selftest]  Verdict:       {sp_verdict}");
    }

    println!("[selftest] ══════════════════════════════════════════════════");

    // Cleanup
    ev_task_a.abort();
    ev_task_b.abort();
    node_a.stop().await?;
    node_b.stop().await?;

    // Exit with worst verdict
    let final_verdict = verdicts.into_iter().max().unwrap_or(Verdict::Pass);
    if final_verdict == Verdict::Fail {
        std::process::exit(1);
    }

    Ok(())
}

async fn cleanup(
    node_a: &mut reticulum_std::driver::ReticulumNode,
    node_b: &mut reticulum_std::driver::ReticulumNode,
    ev_task_a: &tokio::task::JoinHandle<()>,
    ev_task_b: &tokio::task::JoinHandle<()>,
) {
    ev_task_a.abort();
    ev_task_b.abort();
    let _ = node_a.stop().await;
    let _ = node_b.stop().await;
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_parse_roundtrip() {
        let msg = build_message("ab", 42, 1000);
        let parsed = parse_message(&msg).expect("should parse");
        assert_eq!(parsed.dir, "ab");
        assert_eq!(parsed.seq, 42);
        assert_eq!(parsed.timestamp_ms, 1000);
    }

    #[test]
    fn test_parse_bad_checksum() {
        let mut msg = build_message("ab", 1, 1000);
        // Corrupt the last byte
        let len = msg.len();
        msg[len - 1] = b'X';
        assert!(parse_message(&msg).is_none());
    }

    #[test]
    fn test_parse_bad_format() {
        assert!(parse_message(b"not:a:valid").is_none());
        assert!(parse_message(b"").is_none());
        assert!(parse_message(b"ab:notnum:1000:deadbeef").is_none());
    }

    #[test]
    fn test_link_verdict_pass() {
        let mut stats = SelftestStats::new();
        stats.sent_a = 100;
        stats.sent_b = 100;
        stats.recv_a = 190;
        stats.recv_b = 190;
        stats.confirmed_a = 150;
        stats.confirmed_b = 150;
        let warnings = vec![];
        assert_eq!(compute_link_verdict(&stats, &warnings), Verdict::Pass);
    }

    #[test]
    fn test_link_verdict_warn() {
        let mut stats = SelftestStats::new();
        stats.sent_a = 100;
        stats.sent_b = 100;
        stats.recv_a = 190;
        stats.recv_b = 190;
        stats.confirmed_a = 150;
        stats.confirmed_b = 150;
        let warnings = vec!["something".to_string()];
        assert_eq!(compute_link_verdict(&stats, &warnings), Verdict::Warn);
    }

    #[test]
    fn test_link_verdict_fail_low_recv() {
        let mut stats = SelftestStats::new();
        stats.sent_a = 100;
        stats.sent_b = 100;
        stats.recv_a = 50;
        stats.recv_b = 50;
        stats.confirmed_a = 100;
        stats.confirmed_b = 100;
        let warnings = vec![];
        assert_eq!(compute_link_verdict(&stats, &warnings), Verdict::Fail);
    }

    #[test]
    fn test_link_verdict_fail_low_confirmed() {
        let mut stats = SelftestStats::new();
        stats.sent_a = 100;
        stats.sent_b = 100;
        stats.recv_a = 190;
        stats.recv_b = 190;
        stats.confirmed_a = 10;
        stats.confirmed_b = 10;
        let warnings = vec![];
        assert_eq!(compute_link_verdict(&stats, &warnings), Verdict::Fail);
    }

    #[test]
    fn test_link_verdict_fail_zero_recv() {
        let mut stats = SelftestStats::new();
        stats.sent_a = 100;
        stats.sent_b = 100;
        let warnings = vec![];
        assert_eq!(compute_link_verdict(&stats, &warnings), Verdict::Fail);
    }

    #[test]
    fn test_sp_verdict_pass() {
        let mut stats = SelftestStats::new();
        stats.sp_sent_a = 100;
        stats.sp_sent_b = 100;
        stats.sp_recv_a = 90;
        stats.sp_recv_b = 90;
        let warnings = vec![];
        assert_eq!(compute_sp_verdict(&stats, &warnings), Verdict::Pass);
    }

    #[test]
    fn test_sp_verdict_fail_low_recv() {
        let mut stats = SelftestStats::new();
        stats.sp_sent_a = 100;
        stats.sp_sent_b = 100;
        stats.sp_recv_a = 20;
        stats.sp_recv_b = 20;
        let warnings = vec![];
        assert_eq!(compute_sp_verdict(&stats, &warnings), Verdict::Fail);
    }

    #[test]
    fn test_sp_verdict_fail_zero_recv() {
        let mut stats = SelftestStats::new();
        stats.sp_sent_a = 100;
        stats.sp_sent_b = 100;
        let warnings = vec![];
        assert_eq!(compute_sp_verdict(&stats, &warnings), Verdict::Fail);
    }

    #[test]
    fn test_record_received_link_phase() {
        let mut stats = SelftestStats::new();
        let msg = build_message("ba", 0, 100);
        record_received_message(&mut stats, &msg, 200, true, false);
        assert_eq!(stats.recv_a, 1);
        assert_eq!(stats.sp_recv_a, 0);
    }

    #[test]
    fn test_record_received_sp_phase() {
        let mut stats = SelftestStats::new();
        let msg = build_message("ba", 0, 100);
        record_received_message(&mut stats, &msg, 200, true, true);
        assert_eq!(stats.recv_a, 0);
        assert_eq!(stats.sp_recv_a, 1);
    }

    #[test]
    fn test_record_received_wrong_dir() {
        let mut stats = SelftestStats::new();
        let msg = build_message("ab", 0, 100);
        // Node A expects "ba", so "ab" should be ignored
        record_received_message(&mut stats, &msg, 200, true, false);
        assert_eq!(stats.recv_a, 0);
        assert_eq!(stats.corrupt, 0);
    }

    #[test]
    fn test_record_received_corrupt() {
        let mut stats = SelftestStats::new();
        record_received_message(&mut stats, b"garbage", 200, true, false);
        assert_eq!(stats.corrupt, 1);
    }

    #[test]
    fn test_verdict_ordering() {
        assert!(Verdict::Pass < Verdict::Warn);
        assert!(Verdict::Warn < Verdict::Fail);
        assert_eq!(Verdict::Pass.max(Verdict::Fail), Verdict::Fail);
        assert_eq!(Verdict::Warn.max(Verdict::Pass), Verdict::Warn);
    }
}
