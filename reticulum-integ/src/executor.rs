use std::collections::BTreeMap;
use std::fmt;
use std::io::{BufRead, Write};
use std::thread;
use std::time::Duration;

use crate::runner::{RunnerError, TestRunner};
use crate::topology::{scale_timeout, timeout_scale, Step};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum StepError {
    /// Could not resolve "node.aspect" to a hex destination hash.
    DestinationResolve { destination: String, detail: String },
    /// A step's assertion failed (wrong exit code, missing output, wrong hops).
    StepFailed {
        step_index: usize,
        action: String,
        detail: String,
    },
    /// Underlying runner/docker error.
    Runner(RunnerError),
}

impl fmt::Display for StepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StepError::DestinationResolve {
                destination,
                detail,
            } => {
                write!(f, "cannot resolve destination '{destination}': {detail}")
            }
            StepError::StepFailed {
                step_index,
                action,
                detail,
            } => {
                write!(f, "step {step_index} ({action}) failed: {detail}")
            }
            StepError::Runner(e) => write!(f, "runner error: {e}"),
        }
    }
}

impl std::error::Error for StepError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StepError::Runner(e) => Some(e),
            _ => None,
        }
    }
}

impl From<RunnerError> for StepError {
    fn from(e: RunnerError) -> Self {
        StepError::Runner(e)
    }
}

// ---------------------------------------------------------------------------
// Destination resolution
// ---------------------------------------------------------------------------

/// Parse "bob.probe" into (node_name, aspect).
fn parse_dest_spec(spec: &str) -> Result<(&str, &str), StepError> {
    match spec.find('.') {
        Some(pos) if pos > 0 && pos < spec.len() - 1 => Ok((&spec[..pos], &spec[pos + 1..])),
        _ => Err(StepError::DestinationResolve {
            destination: spec.to_string(),
            detail: "expected format 'node.aspect' (e.g. 'bob.probe')".into(),
        }),
    }
}

/// Extract probe responder hash from rnstatus output.
///
/// Looks for: `Probe responder at <HEX32>` and returns the 32-char hex hash.
fn extract_probe_hash(rnstatus_output: &str) -> Option<&str> {
    let marker = "Probe responder at <";
    let start = rnstatus_output.find(marker)? + marker.len();
    let rest = &rnstatus_output[start..];
    let end = rest.find('>')?;
    let hash = &rest[..end];
    // Validate: must be exactly 32 hex chars.
    if hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hash)
    } else {
        None
    }
}

/// Resolve "bob.probe" to a 32-char hex destination hash by running rnstatus
/// on the target node. Caches results in `cache` to avoid repeated docker execs.
fn resolve_destination(
    runner: &TestRunner,
    spec: &str,
    cache: &mut BTreeMap<String, String>,
) -> Result<String, StepError> {
    if let Some(cached) = cache.get(spec) {
        return Ok(cached.clone());
    }

    let (node_name, aspect) = parse_dest_spec(spec)?;

    let output = runner.docker_exec(node_name, &["rnstatus", "--config", "/root/.reticulum"])?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let hash = match aspect {
        "probe" => extract_probe_hash(&stdout).ok_or_else(|| StepError::DestinationResolve {
            destination: spec.to_string(),
            detail: format!(
                "no 'Probe responder at <hash>' found in rnstatus output on '{node_name}'"
            ),
        })?,
        other => {
            return Err(StepError::DestinationResolve {
                destination: spec.to_string(),
                detail: format!("unsupported aspect '{other}', only 'probe' is implemented"),
            });
        }
    };

    cache.insert(spec.to_string(), hash.to_string());
    Ok(hash.to_string())
}

// ---------------------------------------------------------------------------
// Command timeout scaling
// ---------------------------------------------------------------------------

/// Scale `--discovery-timeout` and `--duration` values in a command string
/// by the `LORA_TIMEOUT_SCALE` factor. Only active when the scale != 1.0.
fn scale_command_timeouts(command: &str) -> String {
    let scale = timeout_scale();
    if (scale - 1.0).abs() < f64::EPSILON {
        return command.to_string();
    }
    let mut result = command.to_string();
    for flag in &["--discovery-timeout", "--duration"] {
        if let Some(pos) = result.find(flag) {
            let after_flag = pos + flag.len();
            let rest = &result[after_flag..];
            // Skip whitespace between flag and value
            let trimmed = rest.trim_start();
            let ws_len = rest.len() - trimmed.len();
            // Parse the numeric value
            let num_end = trimmed
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(trimmed.len());
            if num_end > 0 {
                if let Ok(val) = trimmed[..num_end].parse::<u64>() {
                    let scaled = (val as f64 * scale).ceil() as u64;
                    let value_start = after_flag + ws_len;
                    let value_end = value_start + num_end;
                    result = format!(
                        "{}{}{}",
                        &result[..value_start],
                        scaled,
                        &result[value_end..]
                    );
                }
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Step execution
// ---------------------------------------------------------------------------

/// Execute all steps from the scenario against running containers.
pub fn execute_steps(runner: &TestRunner) -> Result<(), StepError> {
    let steps = runner.scenario().steps.clone();
    let total = steps.len();
    let mut cache = BTreeMap::new();

    for (i, step) in steps.iter().enumerate() {
        let step_num = i + 1;
        if let Err(e) = execute_step(runner, i, step, &mut cache, step_num, total) {
            report_failure(runner, step_num, total, step, &e);
            return Err(e);
        }
    }

    // Always collect container logs — useful for post-mortem even on success.
    let _ = runner.collect_logs();

    Ok(())
}

/// Print formatted failure report with log collection.
fn report_failure(
    runner: &TestRunner,
    step_num: usize,
    total: usize,
    step: &Step,
    error: &StepError,
) {
    let sep = "══════════════════════════════════════════════════";
    let thin = "──────────────────────────────────────────────────";

    eprintln!("\n{sep}");
    eprintln!("STEP FAILED: [{step_num}/{total}] {step:?}");
    eprintln!("{}", error);
    eprintln!("{sep}");

    match runner.collect_logs() {
        Ok(log_path) => eprintln!("Logs saved to: {}", log_path.display()),
        Err(e) => eprintln!("Failed to collect logs: {e}"),
    }
    eprintln!("{thin}");

    for name in runner.node_names() {
        match runner.container_logs_tail(name, 50) {
            Ok(tail) => {
                eprintln!("Last 50 lines from {name}:");
                for line in tail.lines() {
                    eprintln!("  {line}");
                }
            }
            Err(e) => eprintln!("Failed to get logs for {name}: {e}"),
        }
        eprintln!("{thin}");
    }

    eprintln!("{sep}\n");
}

fn execute_step(
    runner: &TestRunner,
    index: usize,
    step: &Step,
    cache: &mut BTreeMap<String, String>,
    step_num: usize,
    total: usize,
) -> Result<(), StepError> {
    match step {
        Step::WaitForPath {
            on,
            destination,
            timeout_secs,
            expect_result,
        } => {
            println!("[{step_num}/{total}] wait_for_path on {on} for {destination}...");
            execute_wait_for_path(
                runner,
                index,
                on,
                destination,
                scale_timeout(*timeout_secs),
                expect_result,
                cache,
            )
        }
        Step::RnProbe {
            from,
            to,
            expect_hops,
            expect_result,
            timeout_secs,
        } => {
            println!("[{step_num}/{total}] rnprobe from {from} to {to}...");
            execute_rnprobe(
                runner,
                index,
                from,
                to,
                expect_hops.as_ref().copied(),
                expect_result,
                scale_timeout(*timeout_secs),
                cache,
            )
        }
        Step::Sleep { duration_secs } => {
            let scaled = scale_timeout(*duration_secs);
            println!("[{step_num}/{total}] sleep {scaled}s...");
            thread::sleep(Duration::from_secs(scaled));
            Ok(())
        }
        Step::RnPath { .. } => {
            unimplemented!("step type 'rnpath' — see ROADMAP")
        }
        Step::RnStatus { .. } => {
            unimplemented!("step type 'rnstatus' — see ROADMAP")
        }
        Step::Exec {
            on,
            command,
            expect_exit_code,
            expect_stdout_contains,
            env,
        } => {
            // Scale --discovery-timeout and --duration values in command strings
            // when LORA_TIMEOUT_SCALE is set (for running tests at different bitrates).
            let scaled_command = scale_command_timeouts(command);
            println!("[{step_num}/{total}] exec on {on}: {scaled_command}...");
            let args: Vec<&str> = scaled_command.split_whitespace().collect();
            let env_pairs: Vec<(&str, &str)> =
                env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let output = if env_pairs.is_empty() {
                runner.docker_exec(on, &args)?
            } else {
                runner.docker_exec_with_env(on, &args, &env_pairs)?
            };

            // Always persist exec output for post-mortem analysis.
            let label = format!("exec_{on}_{step_num}");
            let _ = runner.save_exec_output(&label, &output.stdout, &output.stderr);

            let stdout = String::from_utf8_lossy(&output.stdout);
            let code = output.status.code().unwrap_or(-1);

            if let Some(expected) = expect_exit_code {
                if code != *expected {
                    return Err(StepError::StepFailed {
                        step_index: index,
                        action: format!("exec on {on}"),
                        detail: format!(
                            "exit code {code}, expected {expected}\nstdout: {stdout}\nstderr: {}",
                            String::from_utf8_lossy(&output.stderr)
                        ),
                    });
                }
            }

            if let Some(needle) = expect_stdout_contains {
                if !stdout.contains(needle.as_str()) {
                    return Err(StepError::StepFailed {
                        step_index: index,
                        action: format!("exec on {on}"),
                        detail: format!("stdout does not contain '{needle}'\nstdout: {stdout}"),
                    });
                }
            }

            println!("  exec ok (exit code {code})");
            Ok(())
        }
        Step::Restart { node } => {
            println!("[{step_num}/{total}] restart {node}...");
            let container = runner.container_name(node);
            let output = std::process::Command::new("docker")
                .args(["restart", &container])
                .output()
                .map_err(|e| StepError::Runner(RunnerError::Io(e)))?;
            if !output.status.success() {
                return Err(StepError::StepFailed {
                    step_index: index,
                    action: "restart".into(),
                    detail: format!(
                        "docker restart {container} failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    ),
                });
            }
            runner.wait_ready_single(node, 30)?;
            println!("  {node} restarted and ready");
            Ok(())
        }
        Step::BlockLink { from, to } => {
            println!("[{step_num}/{total}] block_link {from} -> {to}...");
            execute_iptables_rule(runner, index, from, to, "-A")
        }
        Step::RestoreLink { from, to } => {
            println!("[{step_num}/{total}] restore_link {from} -> {to}...");
            execute_iptables_rule(runner, index, from, to, "-D")
        }
        Step::ProxyRule { node, rule } => {
            println!("[{step_num}/{total}] proxy_rule on {node}: {rule}...");
            execute_proxy_cmd(runner, index, node, &format!("rule add {rule}"))
        }
        Step::ProxyRuleClear { node, id } => {
            println!("[{step_num}/{total}] proxy_rule_clear on {node}: {id}...");
            execute_proxy_cmd(runner, index, node, &format!("rule clear {id}"))
        }
        Step::ProxyStats {
            node,
            expect_dropped,
            expect_forwarded,
        } => {
            println!("[{step_num}/{total}] proxy_stats on {node}...");
            execute_proxy_stats(runner, index, node, *expect_dropped, *expect_forwarded)
        }
    }
}

/// Add or delete iptables DROP rules to block/restore traffic between containers.
///
/// `action` is `-A` (append/block) or `-D` (delete/restore).
/// Resolves the target container's IP via `getent hosts` since iptables
/// requires numeric IPs, not hostnames.
fn execute_iptables_rule(
    runner: &TestRunner,
    step_index: usize,
    from: &str,
    to: &str,
    action: &str,
) -> Result<(), StepError> {
    let cmd = format!(
        "iptables {action} INPUT -s $(getent hosts {to} | awk '{{print $1}}') -j DROP && \
         iptables {action} OUTPUT -d $(getent hosts {to} | awk '{{print $1}}') -j DROP"
    );
    let output = runner.docker_exec(from, &["sh", "-c", &cmd])?;
    if !output.status.success() {
        return Err(StepError::StepFailed {
            step_index,
            action: format!("iptables {action} on {from} targeting {to}"),
            detail: format!(
                "exit code {}, stderr: {}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr)
            ),
        });
    }
    let verb = if action == "-A" {
        "blocked"
    } else {
        "restored"
    };
    println!("  {verb} {from} <-> {to}");
    Ok(())
}

fn execute_wait_for_path(
    runner: &TestRunner,
    index: usize,
    on: &str,
    destination: &str,
    timeout_secs: u64,
    expect_result: &str,
    cache: &mut BTreeMap<String, String>,
) -> Result<(), StepError> {
    let hash = resolve_destination(runner, destination, cache)?;
    let timeout_str = timeout_secs.to_string();

    let output = runner.docker_exec(
        on,
        &[
            "rnpath",
            &hash,
            "--config",
            "/root/.reticulum",
            "-w",
            &timeout_str,
        ],
    )?;

    match (expect_result, output.status.success()) {
        ("success", true) => {
            println!("  path resolved: {hash}");
            Ok(())
        }
        ("success", false) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            Err(StepError::StepFailed {
                step_index: index,
                action: "wait_for_path".into(),
                detail: format!("rnpath exited {}: {stdout} {stderr}", output.status),
            })
        }
        ("no_path", false) => {
            println!("  no path (expected): {hash}");
            Ok(())
        }
        ("no_path", true) => Err(StepError::StepFailed {
            step_index: index,
            action: "wait_for_path".into(),
            detail: format!("expected no_path but path was resolved for {hash}"),
        }),
        _ => Err(StepError::StepFailed {
            step_index: index,
            action: "wait_for_path".into(),
            detail: format!("unknown expect_result '{expect_result}', use 'success' or 'no_path'"),
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_rnprobe(
    runner: &TestRunner,
    index: usize,
    from: &str,
    to: &str,
    expect_hops: Option<u32>,
    expect_result: &str,
    timeout_secs: u64,
    cache: &mut BTreeMap<String, String>,
) -> Result<(), StepError> {
    let hash = resolve_destination(runner, to, cache)?;
    let timeout_str = timeout_secs.to_string();
    let expect_fail = expect_result == "failure" || expect_result == "fail";

    // For expected-success probes: retry up to 3 times with 2s delay.
    // LoRa probes are fire-and-forget (no transport-level retry), so a
    // single lost packet due to half-duplex collision causes failure.
    let max_attempts = if expect_fail { 1 } else { 3 };

    let mut last_stdout = String::new();
    let mut last_stderr = String::new();
    let mut last_status = None;

    for attempt in 1..=max_attempts {
        if attempt > 1 {
            println!("  probe attempt {attempt}/{max_attempts}...");
            thread::sleep(Duration::from_secs(2));
        }

        let output = runner.docker_exec(
            from,
            &[
                "rnprobe",
                "rnstransport.probe",
                &hash,
                "--config",
                "/root/.reticulum",
                "-t",
                &timeout_str,
            ],
        )?;

        last_stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        last_stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        last_status = output.status.code();

        if output.status.success() {
            // Success — check hops and return
            return check_probe_hops(index, expect_hops, &last_stdout, &hash);
        }

        if attempt < max_attempts {
            println!("  probe attempt {attempt}/{max_attempts} failed, retrying...");
        }
    }

    // All attempts exhausted (or single attempt for expect_fail)
    if expect_fail {
        if last_status != Some(0) {
            println!("  probe failed (expected): {hash}");
            return Ok(());
        }
        return Err(StepError::StepFailed {
            step_index: index,
            action: "rnprobe".into(),
            detail: "expected failure but rnprobe exited successfully".into(),
        });
    }

    Err(StepError::StepFailed {
        step_index: index,
        action: "rnprobe".into(),
        detail: format!(
            "expected success but rnprobe failed after {max_attempts} attempts: {last_stdout} {last_stderr}",
        ),
    })
}

fn check_probe_hops(
    index: usize,
    expect_hops: Option<u32>,
    stdout: &str,
    hash: &str,
) -> Result<(), StepError> {
    if let Some(expected) = expect_hops {
        let actual = parse_hops_from_output(stdout);
        match actual {
            Some(hops) if hops == expected => {
                println!("  probe ok: {hops} hop(s) to {hash}");
            }
            Some(hops) => {
                return Err(StepError::StepFailed {
                    step_index: index,
                    action: "rnprobe".into(),
                    detail: format!("expected {expected} hop(s) but got {hops}"),
                });
            }
            None => {
                return Err(StepError::StepFailed {
                    step_index: index,
                    action: "rnprobe".into(),
                    detail: format!("could not parse hop count from output: {stdout}"),
                });
            }
        }
    } else {
        println!("  probe ok: {hash}");
    }
    Ok(())
}

/// Send a command to a node's lora-proxy control socket and return the response.
fn proxy_control_cmd(runner: &TestRunner, node: &str, cmd: &str) -> Result<String, StepError> {
    let sock_path = runner
        .proxy_socket(node)
        .ok_or_else(|| StepError::StepFailed {
            step_index: 0,
            action: "proxy_cmd".into(),
            detail: format!("node '{node}' has no proxy control socket"),
        })?;

    let stream = std::os::unix::net::UnixStream::connect(sock_path).map_err(|e| {
        StepError::Runner(RunnerError::ProxyError(format!(
            "connect to proxy socket for '{node}': {e}"
        )))
    })?;

    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| StepError::Runner(RunnerError::Io(e)))?;

    let mut writer = std::io::BufWriter::new(&stream);
    writer
        .write_all(format!("{cmd}\n").as_bytes())
        .map_err(|e| StepError::Runner(RunnerError::Io(e)))?;
    writer
        .flush()
        .map_err(|e| StepError::Runner(RunnerError::Io(e)))?;
    // Shut down write half so the proxy knows we're done sending.
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| StepError::Runner(RunnerError::Io(e)))?;

    let mut reader = std::io::BufReader::new(&stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| StepError::Runner(RunnerError::Io(e)))?;
    Ok(line.trim().to_string())
}

/// Execute a proxy command and verify the response starts with "OK".
fn execute_proxy_cmd(
    runner: &TestRunner,
    step_index: usize,
    node: &str,
    cmd: &str,
) -> Result<(), StepError> {
    let resp = proxy_control_cmd(runner, node, cmd)?;
    if resp.starts_with("OK") {
        println!("  proxy: {resp}");
        Ok(())
    } else {
        Err(StepError::StepFailed {
            step_index,
            action: format!("proxy cmd on {node}"),
            detail: format!("expected OK, got: {resp}"),
        })
    }
}

/// Query proxy stats and optionally assert on dropped/forwarded counters.
fn execute_proxy_stats(
    runner: &TestRunner,
    step_index: usize,
    node: &str,
    expect_dropped: Option<u64>,
    expect_forwarded: Option<u64>,
) -> Result<(), StepError> {
    let resp = proxy_control_cmd(runner, node, "stats")?;
    if !resp.starts_with("OK ") {
        return Err(StepError::StepFailed {
            step_index,
            action: format!("proxy stats on {node}"),
            detail: format!("expected OK {{...}}, got: {resp}"),
        });
    }
    let json = &resp[3..]; // strip "OK "
    println!("  proxy stats: {json}");

    if let Some(expected) = expect_dropped {
        let actual = parse_json_u64(json, "dropped");
        if actual != Some(expected) {
            return Err(StepError::StepFailed {
                step_index,
                action: format!("proxy stats on {node}"),
                detail: format!("expected dropped={expected}, got {:?} in {json}", actual),
            });
        }
    }

    if let Some(expected) = expect_forwarded {
        let actual = parse_json_u64(json, "forwarded");
        if actual != Some(expected) {
            return Err(StepError::StepFailed {
                step_index,
                action: format!("proxy stats on {node}"),
                detail: format!("expected forwarded={expected}, got {:?} in {json}", actual),
            });
        }
    }

    Ok(())
}

/// Simple JSON number extraction: find `"key":N` and parse N.
fn parse_json_u64(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{}\":", key);
    let pos = json.find(&needle)? + needle.len();
    let rest = &json[pos..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Parse hop count from rnprobe output. Looks for `over N hop` pattern.
fn parse_hops_from_output(output: &str) -> Option<u32> {
    // rnprobe output: "Probe reply received ... over 1 hops"
    let marker = "over ";
    let start = output.find(marker)? + marker.len();
    let rest = &output[start..];
    // Take digits until non-digit.
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let digits = &rest[..end];
    digits.parse().ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Acquire an exclusive file lock to prevent parallel LoRa test execution.
    ///
    /// `serial_test`'s `#[serial]` only works within a single cargo-test process
    /// and may not serialize `#[ignore]` tests reliably. This file lock works
    /// across processes and threads: any second test trying to acquire it will
    /// block until the first one finishes.
    ///
    /// The returned `File` holds the lock — it is released when dropped at test end.
    fn acquire_lora_lock() -> std::fs::File {
        use std::os::unix::io::AsRawFd;

        let lock_path = "/tmp/leviculum-lora-test.lock";
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(lock_path)
            .unwrap_or_else(|e| panic!("cannot open lock file {lock_path}: {e}"));

        // LOCK_EX = exclusive lock, blocks until acquired
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            panic!(
                "flock({lock_path}) failed: {}",
                std::io::Error::last_os_error()
            );
        }
        eprintln!("[lora-lock] acquired exclusive lock on {lock_path}");
        file
    }

    #[test]
    fn parse_dest_spec_valid() {
        let (node, aspect) = parse_dest_spec("bob.probe").unwrap();
        assert_eq!(node, "bob");
        assert_eq!(aspect, "probe");
    }

    #[test]
    fn parse_dest_spec_multi_part() {
        let (node, aspect) = parse_dest_spec("alice.custom_aspect").unwrap();
        assert_eq!(node, "alice");
        assert_eq!(aspect, "custom_aspect");
    }

    #[test]
    fn parse_dest_spec_no_dot() {
        let result = parse_dest_spec("bob");
        assert!(result.is_err());
        match result.unwrap_err() {
            StepError::DestinationResolve { destination, .. } => {
                assert_eq!(destination, "bob");
            }
            other => panic!("expected DestinationResolve, got: {other:?}"),
        }
    }

    #[test]
    fn parse_dest_spec_trailing_dot() {
        let result = parse_dest_spec("bob.");
        assert!(result.is_err());
    }

    #[test]
    fn parse_dest_spec_leading_dot() {
        let result = parse_dest_spec(".probe");
        assert!(result.is_err());
    }

    #[test]
    fn extract_probe_hash_from_rnstatus() {
        let output = r#"
Reticulum Transport Instance running
  Uptime is 42 seconds
  Transport Identity is <abcdef0123456789abcdef0123456789>
  1 path table entry
  Probe responder at <c46bbee6a9437963a27ad5d18ce4a87c> active
"#;
        let hash = extract_probe_hash(output).unwrap();
        assert_eq!(hash, "c46bbee6a9437963a27ad5d18ce4a87c");
    }

    #[test]
    fn extract_probe_hash_not_present() {
        let output = "Reticulum running, no probe responder\n";
        assert!(extract_probe_hash(output).is_none());
    }

    #[test]
    fn extract_probe_hash_invalid_hex() {
        let output = "Probe responder at <not_a_valid_hex_string_here_!> active\n";
        assert!(extract_probe_hash(output).is_none());
    }

    #[test]
    fn extract_probe_hash_wrong_length() {
        let output = "Probe responder at <c46bbee6> active\n";
        assert!(extract_probe_hash(output).is_none());
    }

    #[test]
    fn parse_hops_single() {
        assert_eq!(parse_hops_from_output("Probe reply over 1 hops"), Some(1));
    }

    #[test]
    fn parse_hops_multi() {
        assert_eq!(
            parse_hops_from_output("Probe reply received over 3 hops in 234ms"),
            Some(3)
        );
    }

    #[test]
    fn parse_hops_none() {
        assert_eq!(parse_hops_from_output("Probe timed out"), None);
    }

    #[test]
    fn step_error_display_destination_resolve() {
        let err = StepError::DestinationResolve {
            destination: "bob.probe".into(),
            detail: "not found".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("bob.probe"));
        assert!(msg.contains("not found"));
    }

    #[test]
    fn step_error_display_step_failed() {
        let err = StepError::StepFailed {
            step_index: 2,
            action: "rnprobe".into(),
            detail: "expected 1 hop(s) but got 3".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("step 2"));
        assert!(msg.contains("rnprobe"));
        assert!(msg.contains("expected 1 hop(s) but got 3"));
    }

    #[test]
    fn step_error_display_runner() {
        let runner_err = RunnerError::Compose {
            action: "up".into(),
            stderr: "fail".into(),
        };
        let err = StepError::Runner(runner_err);
        let msg = err.to_string();
        assert!(msg.contains("runner error"));
        assert!(msg.contains("up"));
    }

    // -----------------------------------------------------------------------
    // Integration test (requires Docker)
    // -----------------------------------------------------------------------

    #[test]
    #[serial(docker)]
    fn basic_probe_end_to_end() {
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/basic_probe.toml"
        ))
        .expect("basic_probe.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(30).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[serial(docker)]
    fn probe_through_relay() {
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/probe_through_relay.toml"
        ))
        .expect("probe_through_relay.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[serial(docker)]
    fn path_self_healing() {
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/path_self_healing.toml"
        ))
        .expect("path_self_healing.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[serial(docker)]
    fn node_restart_path_recovery() {
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/node_restart_path_recovery.toml"
        ))
        .expect("node_restart_path_recovery.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[serial(docker)]
    fn announce_replacement() {
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/announce_replacement.toml"
        ))
        .expect("announce_replacement.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[serial(docker)]
    fn four_node_chain() {
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/four_node_chain.toml"
        ))
        .expect("four_node_chain.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[serial(docker)]
    fn rust_relay_python_endpoints() {
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/rust_relay_python_endpoints.toml"
        ))
        .expect("rust_relay_python_endpoints.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[serial(docker)]
    fn double_restart_identity_persistence() {
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/double_restart_identity_persistence.toml"
        ))
        .expect("double_restart_identity_persistence.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[serial(docker)]
    fn rnstatus_transport_info() {
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/rnstatus_transport_info.toml"
        ))
        .expect("rnstatus_transport_info.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[serial(docker)]
    fn rust_probe_through_python_relay() {
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/rust_probe_through_python_relay.toml"
        ))
        .expect("rust_probe_through_python_relay.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[serial(docker)]
    fn five_node_mesh() {
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/five_node_mesh.toml"
        ))
        .expect("five_node_mesh.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[serial(docker)]
    fn link_failure_recovery() {
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/link_failure_recovery.toml"
        ))
        .expect("link_failure_recovery.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[serial(docker)]
    fn non_transport_no_relay() {
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/non_transport_no_relay.toml"
        ))
        .expect("non_transport_no_relay.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[serial(docker)]
    fn selftest_ratchet_direct() {
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/selftest_ratchet_direct.toml"
        ))
        .expect("selftest_ratchet_direct.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[serial(docker)]
    fn selftest_ratchet_chain() {
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/selftest_ratchet_chain.toml"
        ))
        .expect("selftest_ratchet_chain.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[serial(docker)]
    fn selftest_ratchet_mixed() {
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/selftest_ratchet_mixed.toml"
        ))
        .expect("selftest_ratchet_mixed.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[ignore]
    // Requires RNode hardware at /dev/ttyACM0 and /dev/ttyACM1.
    // Build lrnsd with: cargo build --release --bin lrnsd --features serial
    // NOTE: If wait_for_path times out, check container logs for
    // "configured" or "configuration failed" — wait_ready() succeeds
    // even if the RNode device is not detected (reconnect runs in background).
    #[serial(lora)]
    fn lora_direct_rust() {
        let _lock = acquire_lora_lock();
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/lora_direct_rust.toml"
        ))
        .expect("lora_direct_rust.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[ignore]
    // Requires RNode hardware at /dev/ttyACM0 and /dev/ttyACM1.
    // Build lrnsd with: cargo build --release --bin lrnsd --features serial
    // Docker image must have pyserial installed for Python RNodeInterface.
    // NOTE: If wait_for_path times out, check container logs for
    // "configured"/"configuration failed" (Rust) or RNodeInterface errors (Python).
    #[serial(lora)]
    fn lora_interop_rust_python() {
        let _lock = acquire_lora_lock();
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/lora_interop_rust_python.toml"
        ))
        .expect("lora_interop_rust_python.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[ignore]
    // Requires RNode hardware at /dev/ttyACM0 and /dev/ttyACM1.
    // Build lrnsd with: cargo build --release --bin lrnsd --features serial
    // Build lrns with: cargo build --release --bin lrns
    #[serial(lora)]
    fn lora_link_rust() {
        let _lock = acquire_lora_lock();
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/lora_link_rust.toml"
        ))
        .expect("lora_link_rust.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[ignore]
    // Requires RNode hardware at /dev/ttyACM0 and /dev/ttyACM1.
    // Build lrnsd with: cargo build --release --bin lrnsd --features serial
    // Build lrns with: cargo build --release --bin lrns
    #[serial(lora)]
    fn lora_link_interop() {
        let _lock = acquire_lora_lock();
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/lora_link_interop.toml"
        ))
        .expect("lora_link_interop.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[ignore] // Requires RNode hardware
    #[serial(lora)]
    fn lora_tcp_bridge_rust_relay() {
        let _lock = acquire_lora_lock();
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/lora_tcp_bridge_rust_relay.toml"
        ))
        .expect("lora_tcp_bridge_rust_relay.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[ignore] // Requires RNode hardware
    #[serial(lora)]
    fn lora_tcp_bridge_python_relay() {
        let _lock = acquire_lora_lock();
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/lora_tcp_bridge_python_relay.toml"
        ))
        .expect("lora_tcp_bridge_python_relay.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[ignore] // Requires RNode hardware
    #[serial(lora)]
    fn lora_tcp_bridge_python_selftest() {
        let _lock = acquire_lora_lock();
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/lora_tcp_bridge_python_selftest.toml"
        ))
        .expect("lora_tcp_bridge_python_selftest.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[ignore] // Requires RNode hardware
    #[serial(lora)]
    fn lora_late_announce_2node() {
        let _lock = acquire_lora_lock();
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/lora_late_announce_2node.toml"
        ))
        .expect("lora_late_announce_2node.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[ignore] // Requires RNode hardware
    #[serial(lora)]
    fn lora_late_announce_4node() {
        let _lock = acquire_lora_lock();
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/lora_late_announce_4node.toml"
        ))
        .expect("lora_late_announce_4node.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[ignore] // Requires RNode hardware
    #[serial(lora)]
    fn lora_late_announce_6node() {
        let _lock = acquire_lora_lock();
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/lora_late_announce_6node.toml"
        ))
        .expect("lora_late_announce_6node.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[ignore] // Requires RNode hardware
    #[serial(lora)]
    fn lora_late_announce_8node() {
        let _lock = acquire_lora_lock();
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/lora_late_announce_8node.toml"
        ))
        .expect("lora_late_announce_8node.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[ignore] // Requires RNode hardware
    #[serial(lora)]
    fn lora_late_announce_10node() {
        let _lock = acquire_lora_lock();
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/lora_late_announce_10node.toml"
        ))
        .expect("lora_late_announce_10node.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(120).expect("wait_ready failed");

        let result = execute_steps(&runner);
        // Collect logs before teardown (even on success) for LoRa analysis
        let _ = runner.collect_logs();
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[ignore] // Requires RNode hardware
    #[serial(lora)]
    fn lora_rpc_after_selftest() {
        let _lock = acquire_lora_lock();
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/lora_rpc_after_selftest.toml"
        ))
        .expect("lora_rpc_after_selftest.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[ignore] // Requires RNode hardware
    #[serial(lora)]
    fn lora_dual_cluster_rust() {
        let _lock = acquire_lora_lock();
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/lora_dual_cluster_rust.toml"
        ))
        .expect("lora_dual_cluster_rust.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(120).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[ignore] // Requires RNode hardware
    #[serial(lora)]
    fn lora_dual_cluster_mixed() {
        let _lock = acquire_lora_lock();
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/lora_dual_cluster_mixed.toml"
        ))
        .expect("lora_dual_cluster_mixed.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(120).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[ignore] // Requires RNode hardware + lora-proxy binary
    #[serial(lora)]
    fn lora_proxy_loss() {
        let _lock = acquire_lora_lock();
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/lora_proxy_loss.toml"
        ))
        .expect("lora_proxy_loss.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }

    #[test]
    #[serial(docker)]
    fn selftest_bulk() {
        let toml_str = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/selftest_bulk.toml"
        ))
        .expect("selftest_bulk.toml not found");
        let scenario = crate::topology::parse_scenario(&toml_str).expect("parse failed");

        let mut runner = TestRunner::new(scenario).expect("TestRunner::new failed");

        runner.up().expect("up failed");
        runner.wait_ready(60).expect("wait_ready failed");

        let result = execute_steps(&runner);
        runner.down().expect("down failed");
        result.expect("execute_steps should succeed");
    }
}
