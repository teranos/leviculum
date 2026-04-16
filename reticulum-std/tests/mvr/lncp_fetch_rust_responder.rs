//! mvr for Bug #26 — Rust-responder `lncp` fetch timeout.
//!
//! Isolates the "`lncp -F -n` responder returns data that the `lncp -f`
//! initiator never surfaces" failure from the full LoRa scenario
//! `lora_lncp_fetch`. The topology here is two `lnsd` processes on
//! `127.0.0.1` connected by TCP (not LoRa, not proxy, not Docker), with an
//! `lncp -l -F -n` listener on node B and a `lncp -f` fetcher on node A.
//! Fetching a 1 KiB file through this pair exercises the same request /
//! response / resource code path as the full-scenario test; if the bug
//! reproduces here, we have isolation.
//!
//! Per CLAUDE.md §Protocol debugging discipline, this test is self-
//! contained (no LoRa, no Docker), runs in under 30 s, and emits a
//! structured event log on failure so the next iteration can correlate
//! daemon-side delivery against client-side fetch-result surfacing
//! without grepping through thousand-line logs.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

/// Port band starts above Linux's `ip_local_port_range` ceiling (60999 on
/// the host) so our explicit binds cannot collide with OS-assigned
/// ephemeral ports elsewhere in the test suite. Same design as the
/// `harness.rs` counter in `rnsd_interop/`.
static PORT_COUNTER: AtomicU16 = AtomicU16::new(61500);

fn next_port() -> u16 {
    loop {
        let candidate = PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
        if candidate >= 65000 {
            PORT_COUNTER.store(61500, Ordering::Relaxed);
            continue;
        }
        if std::net::TcpListener::bind(("127.0.0.1", candidate)).is_ok() {
            return candidate;
        }
    }
}

/// Resolve the release binary that the integ runner and this mvr share.
/// Honours `CARGO_TARGET_DIR` so a `just build-integ-bins` under the
/// nightly's CI cache dir is picked up the same way the runner's
/// `reticulum-integ::paths` helper resolves it.
fn release_bin(name: &str) -> PathBuf {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.join("target"));
    target_dir.join("release").join(name)
}

/// Write a minimal lnsd INI config for the mvr.
///
/// The Reticulum config format is documented in
/// `reticulum-integ/src/topology.rs::render_config`; this helper emits the
/// subset we need: one TCP interface, no LoRa, no shared-instance extras,
/// and `ingress_control = false` to keep the first-announce path clean
/// the same way the integ-test scenarios do.
fn write_config(dir: &Path, instance_name: &str, interface_ini: &str) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::create_dir_all(dir.join("storage"))?;
    // `instance_name` must differ per daemon: lnsd's shared-instance server
    // binds the abstract Unix socket `\0rns/<instance_name>`, and two
    // daemons on one host would otherwise collide on `rns/default`.
    let cfg = format!(
        "[reticulum]\n  \
         enable_transport = yes\n  \
         share_instance = yes\n  \
         instance_name = {instance_name}\n  \
         respond_to_probes = yes\n\n\
         [logging]\n  loglevel = 5\n\n\
         [interfaces]\n{interface_ini}\n"
    );
    let mut f = fs::File::create(dir.join("config"))?;
    f.write_all(cfg.as_bytes())?;
    Ok(())
}

/// Spawn `lnsd -v --config <dir>` in the background. Stdout/stderr captured
/// to files under `dir/` so a failure run can be forensically examined
/// without re-running the test.
fn spawn_lnsd(dir: &Path, label: &str) -> std::io::Result<Child> {
    let lnsd = release_bin("lnsd");
    if !lnsd.exists() {
        panic!(
            "{} not found - run `cargo build --release --bin lnsd --bin lncp` first \
             (or `just build-integ-bins`)",
            lnsd.display()
        );
    }
    let stdout_path = dir.join(format!("{label}-stdout.log"));
    let stderr_path = dir.join(format!("{label}-stderr.log"));
    Command::new(&lnsd)
        .arg("-v")
        .arg("--config")
        .arg(dir)
        .stdout(Stdio::from(fs::File::create(stdout_path)?))
        .stderr(Stdio::from(fs::File::create(stderr_path)?))
        .spawn()
}

/// Wait for a line matching `pred` on `stderr_path`, up to `timeout`.
/// Returns the matching line, or None if the timeout hit first.
fn wait_for_stderr_line(
    stderr_path: &Path,
    pred: impl Fn(&str) -> bool,
    timeout: Duration,
) -> Option<String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(text) = fs::read_to_string(stderr_path) {
            for line in text.lines() {
                if pred(line) {
                    return Some(line.to_string());
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

struct SpawnedLncp {
    child: Child,
    stderr_path: PathBuf,
    stdout_path: PathBuf,
}

impl SpawnedLncp {
    fn kill_and_collect(mut self) -> (String, String) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let stdout = fs::read_to_string(&self.stdout_path).unwrap_or_default();
        let stderr = fs::read_to_string(&self.stderr_path).unwrap_or_default();
        (stdout, stderr)
    }
}

/// Spawn `lncp` with shared-instance IPC to the lnsd at `config_dir`.
/// `args` are appended after the common config flag. stdout / stderr are
/// captured to files so the test can read them after exit.
fn spawn_lncp(config_dir: &Path, label: &str, args: &[&str]) -> std::io::Result<SpawnedLncp> {
    let lncp = release_bin("lncp");
    if !lncp.exists() {
        panic!(
            "{} not found - run `cargo build --release --bin lncp` first \
             (or `just build-integ-bins`)",
            lncp.display()
        );
    }
    let stdout_path = config_dir.join(format!("{label}-stdout.log"));
    let stderr_path = config_dir.join(format!("{label}-stderr.log"));
    let child = Command::new(&lncp)
        .arg("-v")
        .arg("--config")
        .arg(config_dir)
        .args(args)
        .stdout(Stdio::from(fs::File::create(&stdout_path)?))
        .stderr(Stdio::from(fs::File::create(&stderr_path)?))
        .spawn()?;
    Ok(SpawnedLncp {
        child,
        stderr_path,
        stdout_path,
    })
}

/// Parse the dest-hash hex string out of a `lncp listening on <HEX>` line.
fn parse_listening_hash(line: &str) -> Option<String> {
    line.split_whitespace()
        .next_back()
        .map(String::from)
        .and_then(|s| {
            if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
                Some(s)
            } else {
                None
            }
        })
}

fn structured_event<K: AsRef<str>>(name: &str, t0: Instant, pairs: &[(K, String)]) -> String {
    let t_ms = t0.elapsed().as_millis();
    let body = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k.as_ref(), v))
        .collect::<Vec<_>>()
        .join(" ");
    format!("{name} {body} t={t_ms}")
}

fn scan_file(path: &Path, pattern: &str) -> Vec<String> {
    match fs::read_to_string(path) {
        Ok(text) => text
            .lines()
            .filter(|l| l.contains(pattern))
            .map(String::from)
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// The mvr test. Spawns lnsd + lnsd + lncp + lncp, fetches a 1 KiB file,
/// asserts it arrives within 30 s. On failure emits a structured event
/// log (events from both daemons and both clients) to stdout so the
/// iteration can correlate responder delivery against initiator surfacing.
#[test]
fn lncp_fetch_rust_responder_over_tcp() {
    let t0 = Instant::now();
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path();
    let dir_a = base.join("A");
    let dir_b = base.join("B");

    let tcp_port = next_port();

    // Node A reaches Node B by initiating a TCP client connection to the
    // fixed listening port. Keep the two configs directional so there is no
    // ambiguity about which side is the server.
    let instance_a = format!("mvr-fetch-a-{tcp_port}");
    let instance_b = format!("mvr-fetch-b-{tcp_port}");
    write_config(
        &dir_a,
        &instance_a,
        &format!(
            "  [[Peer]]\n    type = TCPClientInterface\n    enabled = yes\n    \
             target_host = 127.0.0.1\n    target_port = {tcp_port}\n    \
             ingress_control = false\n"
        ),
    )
    .unwrap();
    write_config(
        &dir_b,
        &instance_b,
        &format!(
            "  [[Peer]]\n    type = TCPServerInterface\n    enabled = yes\n    \
             listen_ip = 127.0.0.1\n    listen_port = {tcp_port}\n    \
             ingress_control = false\n"
        ),
    )
    .unwrap();

    // Test payload. 1 KiB deterministic content so mismatches are obvious.
    let fetch_jail = dir_b.join("files");
    fs::create_dir_all(&fetch_jail).unwrap();
    let payload: Vec<u8> = (0..1024u32).map(|i| (i & 0xff) as u8).collect();
    let file_b = fetch_jail.join("test_transfer.bin");
    fs::write(&file_b, &payload).unwrap();

    let mut lnsd_a = spawn_lnsd(&dir_a, "lnsd").expect("spawn lnsd A");
    let mut lnsd_b = spawn_lnsd(&dir_b, "lnsd").expect("spawn lnsd B");

    // Give both daemons time to open their local sockets and the TCP
    // link to stabilise. 2 s is generous for host-local TCP.
    std::thread::sleep(Duration::from_secs(2));

    // Node B: lncp listener with allow-fetch + no-auth + fetch jail.
    let lncp_b = spawn_lncp(
        &dir_b,
        "lncp-listener",
        &[
            "-l",
            "-F",
            "-n",
            "-j",
            fetch_jail.to_str().unwrap(),
            "-b",
            "0",
        ],
    )
    .expect("spawn lncp B");

    // Grab B's destination hash out of the lncp listener's stderr banner.
    let listening_line = wait_for_stderr_line(
        &dir_b.join("lncp-listener-stderr.log"),
        |l| l.contains("lncp listening on"),
        Duration::from_secs(10),
    );
    let dest_hash = listening_line
        .as_deref()
        .and_then(parse_listening_hash)
        .unwrap_or_else(|| {
            let _ = lncp_b.child.id();
            let _ = lnsd_a.kill();
            let _ = lnsd_b.kill();
            panic!(
                "listener never printed its destination hash within 10 s — \
                 lnsd startup or lncp announce broken before the test proper ran"
            );
        });

    // Announce + TCP propagation for the server's destination to reach A.
    std::thread::sleep(Duration::from_secs(2));

    // Node A: fetch the file with a 30 s overall budget — above the
    // internal fetch timeout floor and enough to accommodate the first
    // LinkRequest retry, but well short of the full-scenario 120 s that
    // would just show us the same long-tail timeout.
    let save_dir = dir_a.join("fetched");
    fs::create_dir_all(&save_dir).unwrap();
    let fetch_spawn_t = t0.elapsed();
    let remote_path = file_b.to_str().unwrap().to_string();
    let lncp_a = spawn_lncp(
        &dir_a,
        "lncp-fetcher",
        &[
            "-f",
            &remote_path,
            &dest_hash,
            "-s",
            save_dir.to_str().unwrap(),
            "-w",
            "25",
        ],
    )
    .expect("spawn lncp A");

    // Poll the fetcher: either it exits cleanly within 30 s or we abort.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut exit_code: Option<i32> = None;
    let mut child = lncp_a.child;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code();
                break;
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("lncp-fetcher try_wait failed: {e}"),
        }
    }

    let lncp_a_still_alive = exit_code.is_none();
    if lncp_a_still_alive {
        let _ = child.kill();
        let _ = child.wait();
    }

    let lncp_a_stdout = fs::read_to_string(&lncp_a.stdout_path).unwrap_or_default();
    let lncp_a_stderr = fs::read_to_string(&lncp_a.stderr_path).unwrap_or_default();

    // Tear down before asserting so lingering daemons do not block the
    // next iteration's port allocation.
    let (lncp_b_stdout, lncp_b_stderr) = lncp_b.kill_and_collect();
    let _ = lnsd_a.kill();
    let _ = lnsd_a.wait();
    let _ = lnsd_b.kill();
    let _ = lnsd_b.wait();

    let fetched_path = save_dir.join("test_transfer.bin");
    let fetched_bytes = fs::read(&fetched_path).ok();
    let fetched_ok = fetched_bytes.as_deref() == Some(&payload[..]);

    if exit_code == Some(0) && fetched_ok {
        return;
    }

    let mut events: Vec<String> = Vec::new();
    events.push(structured_event(
        "MVR_START",
        t0,
        &[
            ("tcp_port", tcp_port.to_string()),
            ("dest_hash", dest_hash.clone()),
        ],
    ));
    events.push(structured_event(
        "FETCH_SPAWN",
        t0,
        &[("t_elapsed_ms", fetch_spawn_t.as_millis().to_string())],
    ));
    events.push(structured_event(
        "FETCH_EXIT",
        t0,
        &[
            (
                "exit_code",
                exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "KILLED_BY_DEADLINE".into()),
            ),
            ("fetched_bytes_match", fetched_ok.to_string()),
            (
                "fetched_len",
                fetched_bytes
                    .as_ref()
                    .map(|b| b.len().to_string())
                    .unwrap_or_else(|| "absent".into()),
            ),
        ],
    ));

    let initiator_data_rx = scan_file(&dir_a.join("lnsd-stderr.log"), "Data packet for").len();
    let initiator_proof_rx = scan_file(&dir_a.join("lnsd-stderr.log"), "LRPROOF arrived").len();
    let responder_data_tx = scan_file(&dir_b.join("lnsd-stderr.log"), "Data packet for").len();
    events.push(structured_event(
        "DAEMON_TRAFFIC",
        t0,
        &[
            ("A_data_rx", initiator_data_rx.to_string()),
            ("A_proof_rx", initiator_proof_rx.to_string()),
            ("B_data_tx", responder_data_tx.to_string()),
        ],
    ));

    events.push(structured_event(
        "FETCHER_STDERR_TAIL",
        t0,
        &[(
            "last3",
            lncp_a_stderr
                .lines()
                .rev()
                .take(3)
                .collect::<Vec<_>>()
                .join(" / "),
        )],
    ));
    events.push(structured_event(
        "LISTENER_STDERR_TAIL",
        t0,
        &[(
            "last3",
            lncp_b_stderr
                .lines()
                .rev()
                .take(3)
                .collect::<Vec<_>>()
                .join(" / "),
        )],
    ));

    let preserved = PathBuf::from("/tmp/mvr-fetch-last-failure");
    let _ = fs::remove_dir_all(&preserved);
    if let Err(e) = copy_dir(base, &preserved) {
        events.push(structured_event(
            "LOG_PRESERVE_FAILED",
            t0,
            &[("err", e.to_string())],
        ));
    } else {
        events.push(structured_event(
            "LOGS_PRESERVED_AT",
            t0,
            &[("path", preserved.display().to_string())],
        ));
    }

    panic!(
        "mvr fetch failed\n\n\
         Structured event log:\n{events}\n\n\
         Fetcher stdout:\n{a_stdout}\n\n\
         Listener stdout:\n{b_stdout}\n",
        events = events.join("\n"),
        a_stdout = lncp_a_stdout,
        b_stdout = lncp_b_stdout,
    );
}

fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let target = dst.join(entry.file_name());
        if path.is_dir() {
            copy_dir(&path, &target)?;
        } else {
            fs::copy(&path, &target)?;
        }
    }
    Ok(())
}
