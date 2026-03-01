use std::collections::BTreeMap;
use std::fmt;
use std::thread;
use std::time::Duration;

use crate::runner::{RunnerError, TestRunner};
use crate::topology::Step;

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
                *timeout_secs,
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
                *timeout_secs,
                cache,
            )
        }
        Step::Sleep { duration_secs } => {
            println!("[{step_num}/{total}] sleep {duration_secs}s...");
            thread::sleep(Duration::from_secs(*duration_secs));
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
        } => {
            println!("[{step_num}/{total}] exec on {on}: {command}...");
            let args: Vec<&str> = command.split_whitespace().collect();
            let output = runner.docker_exec(on, &args)?;
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

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Check expected result.
    let expect_fail = expect_result == "failure" || expect_result == "fail";
    if expect_result == "success" && !output.status.success() {
        return Err(StepError::StepFailed {
            step_index: index,
            action: "rnprobe".into(),
            detail: format!(
                "expected success but rnprobe exited {}: {stdout} {stderr}",
                output.status
            ),
        });
    }
    if expect_fail && output.status.success() {
        return Err(StepError::StepFailed {
            step_index: index,
            action: "rnprobe".into(),
            detail: "expected failure but rnprobe exited successfully".into(),
        });
    }
    if expect_fail && !output.status.success() {
        println!("  probe failed (expected): {hash}");
        return Ok(());
    }

    // Check expected hops.
    if let Some(expected) = expect_hops {
        let actual = parse_hops_from_output(&stdout);
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
