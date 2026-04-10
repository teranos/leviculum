use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Child, Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use crate::compose::generate_compose;
use crate::topology::{apply_radio_overrides, generate_node_configs, TestScenario};

/// Monotonic counter for generating unique run IDs within a process.
static RUN_COUNTER: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum RunnerError {
    Compose { action: String, stderr: String },
    ReadinessTimeout { node: String, timeout_secs: u64 },
    Io(io::Error),
    BinaryNotFound(PathBuf),
    ConfigGeneration(String),
    ProxyError(String),
    InsufficientRNodes(String),
}

impl fmt::Display for RunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunnerError::Compose { action, stderr } => {
                write!(f, "docker compose {action} failed: {stderr}")
            }
            RunnerError::ReadinessTimeout { node, timeout_secs } => {
                write!(f, "node '{node}' not ready after {timeout_secs}s")
            }
            RunnerError::Io(e) => write!(f, "I/O error: {e}"),
            RunnerError::BinaryNotFound(path) => {
                write!(
                    f,
                    "lnsd binary not found at {}: run `cargo build --release --bin lnsd`",
                    path.display()
                )
            }
            RunnerError::ConfigGeneration(msg) => {
                write!(f, "config generation failed: {msg}")
            }
            RunnerError::ProxyError(msg) => {
                write!(f, "proxy error: {msg}")
            }
            RunnerError::InsufficientRNodes(msg) => {
                write!(f, "{msg}")
            }
        }
    }
}

impl std::error::Error for RunnerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RunnerError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for RunnerError {
    fn from(e: io::Error) -> Self {
        RunnerError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Free helpers (testable without Docker)
// ---------------------------------------------------------------------------

/// Format a container name: `integ-{test_name}-{run_id}-{node_name}`.
///
/// The `run_id` ensures parallel test runs using the same TOML scenario
/// do not collide on container names.
pub fn format_container_name(test_name: &str, run_id: u32, node_name: &str) -> String {
    format!("integ-{test_name}-{run_id}-{node_name}")
}

/// Format a compose project name: `integ-{test_name}-{run_id}`.
pub fn format_project_name(test_name: &str, run_id: u32) -> String {
    format!("integ-{test_name}-{run_id}")
}

// ---------------------------------------------------------------------------
// TestRunner
// ---------------------------------------------------------------------------

pub struct TestRunner {
    scenario: TestScenario,
    run_id: u32,
    _tempdir: TempDir,
    compose_file: PathBuf,
    project_name: String,
    is_up: bool,
    /// lora-proxy child processes (killed on drop).
    proxy_processes: Vec<Child>,
    /// Node name -> control socket path for proxy commands.
    proxy_sockets: BTreeMap<String, PathBuf>,
    /// Background `dmesg --follow` process for capturing USB/kernel events.
    /// Started in `up()`, killed in `down()`.
    dmesg_process: Option<Child>,
    /// Number of active debug capture threads (informational only, threads stop on port close).
    #[allow(dead_code)]
    debug_capture_count: usize,
}

impl TestRunner {
    /// Create a new test runner for the given scenario.
    ///
    /// Resolves repo root from `CARGO_MANIFEST_DIR`, checks that lnsd exists,
    /// creates a tempdir, generates node configs and the compose file.
    /// If any node has `rnode_proxy = true`, spawns lora-proxy processes and
    /// waits for their PTYs to appear.
    pub fn new(mut scenario: TestScenario) -> Result<Self, RunnerError> {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .expect("CARGO_MANIFEST_DIR has no parent")
            .to_path_buf();

        let lnsd_path = repo_root.join("target/release/lnsd");
        if !lnsd_path.exists() {
            return Err(RunnerError::BinaryNotFound(lnsd_path));
        }

        let lns_path = repo_root.join("target/release/lns");
        if !lns_path.exists() {
            return Err(RunnerError::BinaryNotFound(lns_path));
        }

        let has_proxy = scenario.nodes.values().any(|n| n.rnode_proxy);
        if has_proxy {
            let proxy_path = repo_root.join("target/release/lora-proxy");
            if !proxy_path.exists() {
                return Err(RunnerError::BinaryNotFound(proxy_path));
            }
        }

        // Apply env-var overrides (LORA_BANDWIDTH, LORA_SF, etc.) before
        // generating configs, so the same TOML can be run with different
        // radio settings.
        apply_radio_overrides(&mut scenario);

        // Resolve RNode device paths (env var overrides) and probe each
        // with CMD_DETECT. Skips test if devices are missing.
        resolve_and_probe_rnodes(&mut scenario)?;

        let tempdir = TempDir::new()?;
        let base_dir = tempdir.path().join("nodes");
        let run_id = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);

        // Spawn proxy processes before generating configs/compose.
        let (proxy_processes, proxy_sockets, proxy_devices) =
            spawn_proxies(&scenario, run_id, &repo_root)?;

        generate_node_configs(&scenario, &base_dir)
            .map_err(|e| RunnerError::ConfigGeneration(e.to_string()))?;

        let yaml = generate_compose(&scenario, run_id, &base_dir, &repo_root, &proxy_devices);
        let compose_file = tempdir.path().join("docker-compose.yml");
        fs::write(&compose_file, &yaml)?;

        let project_name = format_project_name(&scenario.test.name, run_id);

        Ok(TestRunner {
            scenario,
            run_id,
            _tempdir: tempdir,
            compose_file,
            project_name,
            is_up: false,
            proxy_processes,
            proxy_sockets,
            dmesg_process: None,
            debug_capture_count: 0,
        })
    }

    /// Return the container name for a node.
    pub fn container_name(&self, node: &str) -> String {
        format_container_name(&self.scenario.test.name, self.run_id, node)
    }

    /// Return a reference to the scenario.
    pub fn scenario(&self) -> &TestScenario {
        &self.scenario
    }

    /// Build a base `docker compose` command with project file and name.
    fn compose_cmd(&self) -> Command {
        let mut cmd = Command::new("docker");
        cmd.args([
            "compose",
            "-f",
            self.compose_file.to_str().expect("compose path not UTF-8"),
            "-p",
            &self.project_name,
        ]);
        cmd
    }

    /// Bring up containers in detached mode, building images first.
    pub fn up(&mut self) -> Result<(), RunnerError> {
        // Start debug serial captures BEFORE containers start.
        // The T114 debug port blocks on write_packet if no reader is
        // present, so we must have a reader ready before lnsd connects
        // to the transport port and triggers T114 activity.
        self.start_debug_captures();

        let output = self.compose_cmd().args(["up", "-d", "--build"]).output()?;

        if !output.status.success() {
            return Err(RunnerError::Compose {
                action: "up -d --build".into(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }

        self.is_up = true;
        self.start_dmesg_logger();
        Ok(())
    }

    /// Poll each node until `rnstatus` exits successfully, or timeout.
    ///
    /// Polls every 500ms. On timeout, collects logs and returns
    /// `ReadinessTimeout`.
    pub fn wait_ready(&self, timeout_secs: u64) -> Result<(), RunnerError> {
        for name in self.scenario.nodes.keys() {
            self.wait_ready_single(name, timeout_secs)?;
        }
        Ok(())
    }

    /// Poll a single node until it is ready, or timeout.
    ///
    /// Probes the abstract Unix socket `\0rns/default` that both lnsd
    /// (Rust) and rnsd (Python) listen on. Using a raw socket connect
    /// instead of `rnstatus` avoids a race condition where rnstatus
    /// accidentally becomes the shared-instance server before rnsd starts.
    ///
    /// Polls every 500ms. On timeout, collects logs and returns
    /// `ReadinessTimeout`.
    pub fn wait_ready_single(&self, node: &str, timeout_secs: u64) -> Result<(), RunnerError> {
        let container = self.container_name(node);
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);

        loop {
            let output = Command::new("docker")
                .args([
                    "exec",
                    &container,
                    "python3",
                    "-c",
                    "import socket; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(b'\\x00rns/default'); s.close()",
                ])
                .output()?;

            if output.status.success() {
                return Ok(());
            }

            if Instant::now() >= deadline {
                let _ = self.collect_logs();
                return Err(RunnerError::ReadinessTimeout {
                    node: node.to_string(),
                    timeout_secs,
                });
            }

            thread::sleep(Duration::from_millis(500));
        }
    }

    /// Return the path to the shared logs directory.
    fn logs_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("logs")
    }

    /// UTC timestamp formatted for filenames: `2026-03-20T03-12-00`.
    fn utc_timestamp() -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs();
        let days = secs / 86400;
        let day_secs = secs % 86400;
        let h = day_secs / 3600;
        let m = (day_secs % 3600) / 60;
        let s = day_secs % 60;
        let mut y = 1970i64;
        let mut rem = days as i64;
        loop {
            let ydays = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
                366
            } else {
                365
            };
            if rem < ydays {
                break;
            }
            rem -= ydays;
            y += 1;
        }
        let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
        let mdays = [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        let mut mo = 0usize;
        for md in &mdays {
            if rem < *md as i64 {
                break;
            }
            rem -= *md as i64;
            mo += 1;
        }
        format!(
            "{:04}-{:02}-{:02}T{:02}-{:02}-{:02}",
            y,
            mo + 1,
            rem + 1,
            h,
            m,
            s
        )
    }

    /// Collect container logs to a timestamped file under `reticulum-integ/logs/`.
    ///
    /// Filename: `{test_name}_{timestamp}.log` — never overwrites.
    pub fn collect_logs(&self) -> Result<PathBuf, RunnerError> {
        let logs_dir = Self::logs_dir();
        fs::create_dir_all(&logs_dir)?;

        let output = self
            .compose_cmd()
            .args(["logs", "--no-color", "--timestamps"])
            .output()?;

        let ts = Self::utc_timestamp();
        let log_file = logs_dir.join(format!("{}_{}.log", self.scenario.test.name, ts));
        fs::write(&log_file, &output.stdout)?;
        Ok(log_file)
    }

    /// Return the last `n` lines of a single container's log.
    pub fn container_logs_tail(&self, node: &str, n: usize) -> Result<String, RunnerError> {
        let container = self.container_name(node);
        let output = Command::new("docker")
            .args(["logs", "--tail", &n.to_string(), &container])
            .output()?;
        // docker logs writes to both stdout and stderr; combine them.
        let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            combined.push_str(&stderr);
        }
        Ok(combined)
    }

    /// Return the proxy control socket path for a node, if it has one.
    pub fn proxy_socket(&self, node: &str) -> Option<&PathBuf> {
        self.proxy_sockets.get(node)
    }

    /// Return ordered node names from the scenario.
    pub fn node_names(&self) -> Vec<&str> {
        self.scenario.nodes.keys().map(|s| s.as_str()).collect()
    }

    /// Bring down containers with a 10-second timeout. No-op if not up.
    /// Always saves container logs before teardown.
    pub fn down(&mut self) -> Result<(), RunnerError> {
        if !self.is_up {
            self.kill_proxies();
            return Ok(());
        }

        // Save logs BEFORE tearing down containers
        match self.collect_logs() {
            Ok(path) => eprintln!("Logs saved to: {}", path.display()),
            Err(e) => eprintln!("Failed to save logs: {e}"),
        }

        let output = self
            .compose_cmd()
            .args(["down", "--timeout", "10"])
            .output()?;

        self.is_up = false;
        self.kill_proxies();
        self.stop_dmesg_logger();

        if !output.status.success() {
            check_stale_resources(&self.scenario);
            return Err(RunnerError::Compose {
                action: "down --timeout 10".into(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }

        check_stale_resources(&self.scenario);
        Ok(())
    }

    /// Kill all proxy child processes and collect stderr output.
    fn kill_proxies(&mut self) {
        for mut child in self.proxy_processes.drain(..) {
            // Send SIGTERM so the proxy can flush its buffers.
            let _ = Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status();
            // Wait up to 2s for graceful shutdown, then force kill.
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    _ if Instant::now() >= deadline => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    _ => thread::sleep(Duration::from_millis(50)),
                }
            }
            // Collect stderr for debugging.
            if let Some(mut stderr) = child.stderr.take() {
                let mut buf = String::new();
                use std::io::Read;
                let _ = stderr.read_to_string(&mut buf);
                if !buf.is_empty() {
                    let proxy_lines: Vec<&str> = buf
                        .lines()
                        .filter(|l| l.contains("AToB") || l.contains("BToA"))
                        .collect();
                    println!("--- proxy: {} frame lines ---", proxy_lines.len());
                    for line in &proxy_lines {
                        println!("  {line}");
                    }
                    println!("--- end proxy ---");
                }
            }
        }
        for sock_path in self.proxy_sockets.values() {
            let _ = fs::remove_file(sock_path);
        }
        self.proxy_sockets.clear();
    }

    /// Start a background `dmesg --follow` process to capture USB/kernel events.
    ///
    /// Output goes to `reticulum-integ/logs/{test_name}_dmesg_{timestamp}.log`.
    /// Non-fatal if dmesg is unavailable (e.g., no permissions).
    fn start_dmesg_logger(&mut self) {
        let logs_dir = Self::logs_dir();
        let _ = fs::create_dir_all(&logs_dir);
        let ts = Self::utc_timestamp();
        let log_path = logs_dir.join(format!("{}_{}_dmesg.log", self.scenario.test.name, ts));

        match fs::File::create(&log_path) {
            Ok(file) => {
                match Command::new("dmesg")
                    .args(["--follow", "--time-format", "iso"])
                    .stdout(file)
                    .stderr(std::process::Stdio::null())
                    .spawn()
                {
                    Ok(child) => {
                        self.dmesg_process = Some(child);
                    }
                    Err(e) => {
                        eprintln!("dmesg --follow unavailable: {e}");
                    }
                }
            }
            Err(e) => {
                eprintln!("Cannot create dmesg log {}: {e}", log_path.display());
            }
        }
    }

    /// Start background serial debug capture for nodes with `debug_serial`.
    /// Uses serialport crate for reliable reading (not `cat` which exits on device reset).
    fn start_debug_captures(&mut self) {
        let logs_dir = Self::logs_dir();
        let _ = fs::create_dir_all(&logs_dir);
        let ts = Self::utc_timestamp();

        for (name, node) in &self.scenario.nodes {
            if let Some(ref port) = node.debug_serial {
                let log_path = logs_dir.join(format!(
                    "{}_{}_debug_{}.log",
                    self.scenario.test.name, name, ts
                ));
                let port = port.clone();

                match fs::File::create(&log_path) {
                    Ok(mut file) => {
                        // Open port with serialport to assert DTR (CDC-ACM
                        // only sends when DTR is asserted), then hand off to
                        // a background reader thread.
                        match serialport::new(&port, 115_200)
                            .timeout(Duration::from_secs(2))
                            .open()
                        {
                            Ok(mut serial) => {
                                let _ = serial.write_data_terminal_ready(true);
                                let _ = serial.write_request_to_send(true);
                                eprintln!("[debug-capture] {port} → {}", log_path.display());
                                // Spawn reader thread with reconnection
                                let port_path = port.clone();
                                let _ = thread::spawn(move || {
                                    use std::io::{Read, Write};
                                    let mut buf = [0u8; 1024];
                                    loop {
                                        match serial.read(&mut buf) {
                                            Ok(n) if n > 0 => {
                                                let _ = file.write_all(&buf[..n]);
                                                let _ = file.flush();
                                            }
                                            Ok(_) => {}
                                            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => continue,
                                            Err(_) => {
                                                // Port lost — try to reconnect
                                                thread::sleep(Duration::from_secs(1));
                                                match serialport::new(&port_path, 115_200)
                                                    .timeout(Duration::from_secs(2))
                                                    .open()
                                                {
                                                    Ok(mut new_serial) => {
                                                        let _ = new_serial.write_data_terminal_ready(true);
                                                        serial = new_serial;
                                                    }
                                                    Err(_) => break,
                                                }
                                            }
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                eprintln!("[debug-capture] FAILED to open {port}: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[debug-capture] cannot create {}: {e}", log_path.display());
                    }
                }
            }
        }
    }

    // Debug capture threads stop automatically when the serial port closes.

    /// Stop the background dmesg logger (if running).
    fn stop_dmesg_logger(&mut self) {
        if let Some(mut child) = self.dmesg_process.take() {
            let _ = Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status();
            let _ = child.wait();
        }
    }

    /// Save exec step stdout/stderr to a timestamped file under `reticulum-integ/logs/`.
    ///
    /// Filename: `{test_name}_{label}_{timestamp}.log` — never overwrites.
    pub fn save_exec_output(
        &self,
        step_label: &str,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Result<PathBuf, RunnerError> {
        let logs_dir = Self::logs_dir();
        fs::create_dir_all(&logs_dir)?;
        let ts = Self::utc_timestamp();
        let log_file = logs_dir.join(format!(
            "{}_{}_{}.log",
            self.scenario.test.name, step_label, ts
        ));
        let mut content = Vec::new();
        content.extend_from_slice(b"=== STDOUT ===\n");
        content.extend_from_slice(stdout);
        content.extend_from_slice(b"\n=== STDERR ===\n");
        content.extend_from_slice(stderr);
        fs::write(&log_file, &content)?;
        Ok(log_file)
    }

    /// Execute a command inside a node's container.
    ///
    /// Returns raw `Output` — the caller interprets success/failure.
    pub fn docker_exec(&self, node: &str, args: &[&str]) -> Result<Output, RunnerError> {
        let container = self.container_name(node);
        let mut cmd = Command::new("docker");
        cmd.arg("exec").arg(&container);
        cmd.args(args);
        let output = cmd.output()?;
        Ok(output)
    }

    /// Execute a command inside a node's container with extra environment variables.
    ///
    /// Returns raw `Output` — the caller interprets success/failure.
    pub fn docker_exec_with_env(
        &self,
        node: &str,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> Result<Output, RunnerError> {
        let container = self.container_name(node);
        let mut cmd = Command::new("docker");
        cmd.arg("exec");
        for (k, v) in env {
            cmd.arg("-e").arg(format!("{k}={v}"));
        }
        cmd.arg(&container);
        cmd.args(args);
        let output = cmd.output()?;
        Ok(output)
    }
}

// ---------------------------------------------------------------------------
// RNode discovery and probing
// ---------------------------------------------------------------------------

/// Probe a serial device for RNode CMD_DETECT response.
/// Returns Ok(()) if detected, Err(reason) if not.
fn probe_rnode(path: &str) -> Result<(), String> {
    if !std::path::Path::new(path).exists() {
        return Err("device does not exist".into());
    }
    // Three attempts with increasing settle times
    for settle_ms in [0, 500, 1500] {
        match probe_rnode_once(path, settle_ms) {
            Ok(true) => return Ok(()),
            Ok(false) => continue, // no detect response, try again
            Err(e) => return Err(e), // can't open — don't retry
        }
    }
    Err("no CMD_DETECT response after 3 attempts".into())
}

/// Returns Ok(true) if RNode detected, Ok(false) if no response, Err if can't open.
fn probe_rnode_once(path: &str, settle_ms: u64) -> Result<bool, String> {
    use std::io::{Read, Write};

    const FEND: u8 = 0xC0;
    const CMD_DETECT: u8 = 0x08;
    const DETECT_REQ: u8 = 0x73;
    const DETECT_RESP: u8 = 0x46;

    let mut port = match serialport::new(path, 115_200)
        .timeout(Duration::from_secs(1))
        .open()
    {
        Ok(p) => p,
        Err(e) => return Err(format!("cannot open: {e}")),
    };

    if settle_ms > 0 {
        thread::sleep(Duration::from_millis(settle_ms));
    }

    // Drain any pending data from the RNode (status frames, etc.)
    let _ = port.clear(serialport::ClearBuffer::Input);

    let query = [FEND, CMD_DETECT, DETECT_REQ, FEND];
    if port.write_all(&query).is_err() {
        return Ok(false);
    }

    let mut buf = [0u8; 128];
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        match port.read(&mut buf) {
            Ok(n) if buf[..n].contains(&DETECT_RESP) => return Ok(true),
            Ok(_) => continue,
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(_) => return Ok(false),
        }
    }
    Ok(false)
}

/// Check that a device file exists, can be opened, and is not held by another process.
/// Returns Ok(()) if accessible, Err(reason) if not.
fn check_device_accessible(path: &str) -> Result<(), String> {
    if !std::path::Path::new(path).exists() {
        return Err("does not exist".into());
    }
    // Try to open it briefly to check it's not busy
    match serialport::new(path, 115_200)
        .timeout(Duration::from_millis(100))
        .open()
    {
        Ok(_port) => Ok(()), // opened successfully, drop closes it
        Err(e) => {
            // Check if another process holds it
            let lsof = Command::new("lsof")
                .arg(path)
                .output()
                .ok()
                .and_then(|o| {
                    if o.status.success() {
                        String::from_utf8(o.stdout).ok()
                    } else {
                        None
                    }
                });
            let holder = lsof
                .as_deref()
                .and_then(|s| s.lines().nth(1)) // skip header
                .unwrap_or("unknown");
            Err(format!("cannot open ({e}), held by: {holder}"))
        }
    }
}

/// Check for stale Docker containers or processes holding test devices.
/// Called after test teardown. Prints warnings but doesn't fail.
fn check_stale_resources(scenario: &TestScenario) {
    // Check for stale Docker containers
    if let Ok(output) = Command::new("docker")
        .args(["ps", "-a", "--filter", "name=integ-", "--format", "{{.Names}} {{.Status}}"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if !line.is_empty() {
                eprintln!("[WARN] stale container: {line}");
            }
        }
    }

    // Check all device ports are released
    let mut ports: Vec<&str> = Vec::new();
    for node in scenario.nodes.values() {
        if let Some(ref p) = node.rnode { ports.push(p); }
        if let Some(ref p) = node.serial { ports.push(p); }
        if let Some(ref p) = node.debug_serial { ports.push(p); }
        if let Some(ref ifaces) = node.rnode_interfaces {
            for iface in ifaces { ports.push(&iface.rnode); }
        }
    }
    for port in ports {
        if let Ok(output) = Command::new("lsof").arg(port).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            if text.lines().count() > 1 {
                // lsof header + at least one process
                eprintln!("[WARN] device {port} still held after teardown:");
                for line in text.lines().skip(1) {
                    eprintln!("  {line}");
                }
            }
        }
    }
}

/// Extract numeric suffix from `/dev/ttyACMN` paths.
fn extract_acm_index(path: &str) -> Option<u32> {
    let stripped = path.strip_prefix("/dev/ttyACM")?;
    stripped.parse::<u32>().ok()
}

/// Resolve RNode device paths via env var overrides and probe for availability.
///
/// For each unique rnode path in the scenario:
/// 1. Extract numeric suffix N from /dev/ttyACMN
/// 2. Check LEVICULUM_RNODE_N env var — if set, use that path instead
/// 3. Probe the resolved path with CMD_DETECT
///
/// Mutates scenario paths in-place. Returns error if any device is unreachable.
fn resolve_and_probe_rnodes(scenario: &mut TestScenario) -> Result<(), RunnerError> {
    // Collect all rnode paths that need resolution
    let mut paths_to_resolve: Vec<String> = Vec::new();

    for node in scenario.nodes.values() {
        if let Some(ref path) = node.rnode {
            if !paths_to_resolve.contains(path) {
                paths_to_resolve.push(path.clone());
            }
        }
        if let Some(ref interfaces) = node.rnode_interfaces {
            for iface in interfaces {
                if !paths_to_resolve.contains(&iface.rnode) {
                    paths_to_resolve.push(iface.rnode.clone());
                }
            }
        }
    }

    // Collect serial device paths (LNode devices, not RNodes)
    let mut serial_paths: Vec<String> = Vec::new();
    for node in scenario.nodes.values() {
        if let Some(ref path) = node.serial {
            if !serial_paths.contains(path) {
                serial_paths.push(path.clone());
            }
        }
    }

    if paths_to_resolve.is_empty() && serial_paths.is_empty() {
        return Ok(());
    }

    // Build resolution map for RNodes: original_path -> resolved_path
    let mut resolution: BTreeMap<String, String> = BTreeMap::new();
    for path in &paths_to_resolve {
        if let Some(idx) = extract_acm_index(path) {
            let env_key = format!("LEVICULUM_RNODE_{idx}");
            if let Ok(override_path) = std::env::var(&env_key) {
                resolution.insert(path.clone(), override_path);
                continue;
            }
        }
        resolution.insert(path.clone(), path.clone());
    }

    // Build resolution map for serial devices: LEVICULUM_SERIAL_N overrides
    let mut serial_resolution: BTreeMap<String, String> = BTreeMap::new();
    for path in &serial_paths {
        if let Some(idx) = extract_acm_index(path) {
            let env_key = format!("LEVICULUM_SERIAL_{idx}");
            if let Ok(override_path) = std::env::var(&env_key) {
                serial_resolution.insert(path.clone(), override_path);
                continue;
            }
        }
        serial_resolution.insert(path.clone(), path.clone());
    }

    // Apply resolution to scenario
    for node in scenario.nodes.values_mut() {
        if let Some(ref mut path) = node.rnode {
            if let Some(resolved) = resolution.get(path.as_str()) {
                *path = resolved.clone();
            }
        }
        if let Some(ref mut interfaces) = node.rnode_interfaces {
            for iface in interfaces.iter_mut() {
                if let Some(resolved) = resolution.get(&iface.rnode) {
                    iface.rnode = resolved.clone();
                }
            }
        }
        if let Some(ref mut path) = node.serial {
            if let Some(resolved) = serial_resolution.get(path.as_str()) {
                *path = resolved.clone();
            }
        }
    }

    // Probe each unique resolved RNode path (CMD_DETECT)
    let unique_resolved: Vec<String> = {
        let mut v: Vec<String> = resolution.values().cloned().collect();
        v.sort();
        v.dedup();
        v
    };

    let mut available = Vec::new();
    let mut failures: Vec<(String, String)> = Vec::new();
    for path in &unique_resolved {
        match probe_rnode(path) {
            Ok(()) => available.push(path.clone()),
            Err(reason) => failures.push((path.clone(), reason)),
        }
    }

    if !failures.is_empty() {
        let needed = unique_resolved.len();
        let found = available.len();
        let details: Vec<String> = failures.iter()
            .map(|(p, r)| format!("{p}: {r}"))
            .collect();
        let env_hints: Vec<String> = paths_to_resolve
            .iter()
            .filter_map(|p| extract_acm_index(p).map(|n| format!("LEVICULUM_RNODE_{n}")))
            .collect();
        let hint = if env_hints.is_empty() {
            String::new()
        } else {
            format!(" (set {})", env_hints.join(", "))
        };
        return Err(RunnerError::InsufficientRNodes(format!(
            "Skipping: needs {needed} RNodes, found {found}{hint}\n  {}",
            details.join("\n  ")
        )));
    }

    // Check serial devices: must exist AND be openable (not held by another process)
    for (orig, resolved) in &serial_resolution {
        match check_device_accessible(resolved) {
            Ok(()) => {}
            Err(reason) => {
                let env_hint = extract_acm_index(orig)
                    .map(|n| format!(" (set LEVICULUM_SERIAL_{n})"))
                    .unwrap_or_default();
                return Err(RunnerError::InsufficientRNodes(format!(
                    "Serial device {resolved}: {reason}{env_hint}"
                )));
            }
        }
    }

    // Check debug_serial devices: must exist and be openable
    for node in scenario.nodes.values() {
        if let Some(ref port) = node.debug_serial {
            match check_device_accessible(port) {
                Ok(()) => {}
                Err(reason) => {
                    return Err(RunnerError::InsufficientRNodes(format!(
                        "Debug serial device {port}: {reason}"
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Spawn lora-proxy processes for all nodes with `rnode_proxy = true`.
///
/// Returns:
/// - Vec of child process handles
/// - BTreeMap of node name -> control socket path
/// - BTreeMap of node name -> PTY slave device path (for compose device mapping)
type ProxySpawnResult = (
    Vec<Child>,
    BTreeMap<String, PathBuf>,
    BTreeMap<String, PathBuf>,
);

fn spawn_proxies(
    scenario: &TestScenario,
    run_id: u32,
    repo_root: &std::path::Path,
) -> Result<ProxySpawnResult, RunnerError> {
    let proxy_bin = repo_root.join("target/release/lora-proxy");
    let mut children = Vec::new();
    let mut sockets = BTreeMap::new();
    let mut devices = BTreeMap::new();

    for (name, node) in &scenario.nodes {
        if !node.rnode_proxy {
            continue;
        }
        let device = node.rnode.as_ref().ok_or_else(|| {
            RunnerError::ProxyError(format!("node '{name}': rnode_proxy requires rnode"))
        })?;

        let pty_path = PathBuf::from(format!(
            "/tmp/proxy-{}-{run_id}-{name}.pty",
            scenario.test.name
        ));
        let sock_path = PathBuf::from(format!(
            "/tmp/proxy-{}-{run_id}-{name}.sock",
            scenario.test.name
        ));

        // Clean up stale files from previous runs.
        let _ = fs::remove_file(&pty_path);
        let _ = fs::remove_file(&sock_path);

        let child = Command::new(&proxy_bin)
            .args([
                "hardware",
                "--device",
                device,
                "--pty-out",
                pty_path.to_str().expect("pty path not UTF-8"),
                "--control",
                sock_path.to_str().expect("sock path not UTF-8"),
            ])
            .env("RUST_LOG", "debug")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                RunnerError::ProxyError(format!("failed to spawn lora-proxy for {name}: {e}"))
            })?;

        children.push(child);
        sockets.insert(name.clone(), sock_path);

        // Wait for the PTY symlink to appear (proxy creates it on startup).
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if pty_path.exists() {
                break;
            }
            if Instant::now() >= deadline {
                // Kill all proxies we've started so far.
                for mut c in children {
                    let _ = c.kill();
                    let _ = c.wait();
                }
                return Err(RunnerError::ProxyError(format!(
                    "proxy for node '{name}' did not create PTY at {} within 5s",
                    pty_path.display()
                )));
            }
            thread::sleep(Duration::from_millis(50));
        }

        // Resolve the PTY symlink to get the actual /dev/pts/N path.
        let real_pty = fs::read_link(&pty_path).map_err(|e| {
            RunnerError::ProxyError(format!(
                "cannot read PTY symlink {}: {e}",
                pty_path.display()
            ))
        })?;
        devices.insert(name.clone(), real_pty);
    }

    Ok((children, sockets, devices))
}

impl Drop for TestRunner {
    fn drop(&mut self) {
        if self.is_up {
            // Best-effort teardown on panic or early return.
            let _ = self.down();
        }
        // Ensure proxies are killed even if down() wasn't called.
        self.kill_proxies();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::parse_scenario;

    #[test]
    fn container_name_format() {
        assert_eq!(
            format_container_name("basic_probe", 42, "alice"),
            "integ-basic_probe-42-alice"
        );
    }

    #[test]
    fn project_name_format() {
        assert_eq!(
            format_project_name("basic_probe", 42),
            "integ-basic_probe-42"
        );
    }

    #[test]
    fn lnsd_not_found_error_message() {
        let err = RunnerError::BinaryNotFound(PathBuf::from("/some/path/lnsd"));
        let msg = err.to_string();
        assert!(msg.contains("/some/path/lnsd"), "should contain path");
        assert!(
            msg.contains("cargo build --release --bin lnsd"),
            "should contain build hint"
        );
    }

    #[test]
    fn compose_error_display() {
        let err = RunnerError::Compose {
            action: "up -d".into(),
            stderr: "no such image".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("up -d"), "should contain action");
        assert!(msg.contains("no such image"), "should contain stderr");
    }

    #[test]
    fn readiness_timeout_display() {
        let err = RunnerError::ReadinessTimeout {
            node: "alice".into(),
            timeout_secs: 30,
        };
        let msg = err.to_string();
        assert!(msg.contains("alice"), "should contain node name");
        assert!(msg.contains("30"), "should contain timeout seconds");
    }

    #[test]
    fn basic_probe_lifecycle() {
        let toml_str = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/basic_probe.toml"
        ))
        .expect("basic_probe.toml not found");
        let scenario = parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        // Verify compose file was generated.
        assert!(runner.compose_file.exists(), "compose file should exist");

        runner.up().expect("up failed");
        runner.wait_ready(30).expect("wait_ready failed");

        // Verify rnstatus works on both nodes.
        for node in ["alice", "bob"] {
            let output = runner
                .docker_exec(node, &["rnstatus", "--config", "/root/.reticulum"])
                .expect("docker_exec failed");
            assert!(
                output.status.success(),
                "rnstatus on {node} should succeed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        runner.down().expect("down failed");
    }
}
