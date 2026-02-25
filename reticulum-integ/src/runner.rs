use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use crate::compose::generate_compose;
use crate::topology::{generate_node_configs, parse_scenario, TestScenario};

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
    LrnsdNotFound(PathBuf),
    ConfigGeneration(String),
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
            RunnerError::LrnsdNotFound(path) => {
                write!(
                    f,
                    "lrnsd binary not found at {}: run `cargo build --release --bin lrnsd`",
                    path.display()
                )
            }
            RunnerError::ConfigGeneration(msg) => {
                write!(f, "config generation failed: {msg}")
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
}

impl TestRunner {
    /// Create a new test runner for the given scenario.
    ///
    /// Resolves repo root from `CARGO_MANIFEST_DIR`, checks that lrnsd exists,
    /// creates a tempdir, generates node configs and the compose file.
    pub fn new(scenario: TestScenario) -> Result<Self, RunnerError> {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .expect("CARGO_MANIFEST_DIR has no parent")
            .to_path_buf();

        let lrnsd_path = repo_root.join("target/release/lrnsd");
        if !lrnsd_path.exists() {
            return Err(RunnerError::LrnsdNotFound(lrnsd_path));
        }

        let tempdir = TempDir::new()?;
        let base_dir = tempdir.path().join("nodes");

        generate_node_configs(&scenario, &base_dir)
            .map_err(|e| RunnerError::ConfigGeneration(e.to_string()))?;

        let run_id = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);

        let yaml = generate_compose(&scenario, run_id, &base_dir, &repo_root);
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
        let output = self
            .compose_cmd()
            .args(["up", "-d", "--build"])
            .output()?;

        if !output.status.success() {
            return Err(RunnerError::Compose {
                action: "up -d --build".into(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }

        self.is_up = true;
        Ok(())
    }

    /// Poll each node until `rnstatus` exits successfully, or timeout.
    ///
    /// Polls every 500ms. On timeout, collects logs and returns
    /// `ReadinessTimeout`.
    pub fn wait_ready(&self, timeout_secs: u64) -> Result<(), RunnerError> {
        for (name, _node) in &self.scenario.nodes {
            let container = self.container_name(name);
            let deadline = Instant::now() + Duration::from_secs(timeout_secs);

            loop {
                let output = Command::new("docker")
                    .args([
                        "exec",
                        &container,
                        "rnstatus",
                        "--config",
                        "/root/.reticulum",
                    ])
                    .output()?;

                if output.status.success() {
                    break;
                }

                if Instant::now() >= deadline {
                    // Best-effort log collection before returning error.
                    let _ = self.collect_logs();
                    return Err(RunnerError::ReadinessTimeout {
                        node: name.clone(),
                        timeout_secs,
                    });
                }

                thread::sleep(Duration::from_millis(500));
            }
        }

        Ok(())
    }

    /// Collect container logs and write to `{test_name}_failure.log` in cwd.
    pub fn collect_logs(&self) -> Result<PathBuf, RunnerError> {
        let output = self
            .compose_cmd()
            .args(["logs", "--no-color"])
            .output()?;

        let log_file = PathBuf::from(format!("{}_failure.log", self.scenario.test.name));
        fs::write(&log_file, &output.stdout)?;
        Ok(log_file)
    }

    /// Bring down containers with a 10-second timeout. No-op if not up.
    pub fn down(&mut self) -> Result<(), RunnerError> {
        if !self.is_up {
            return Ok(());
        }

        let output = self
            .compose_cmd()
            .args(["down", "--timeout", "10"])
            .output()?;

        self.is_up = false;

        if !output.status.success() {
            return Err(RunnerError::Compose {
                action: "down --timeout 10".into(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }

        Ok(())
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
}

impl Drop for TestRunner {
    fn drop(&mut self) {
        if self.is_up {
            // Best-effort teardown on panic or early return.
            let _ = self.down();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
    fn lrnsd_not_found_error_message() {
        let err = RunnerError::LrnsdNotFound(PathBuf::from("/some/path/lrnsd"));
        let msg = err.to_string();
        assert!(msg.contains("/some/path/lrnsd"), "should contain path");
        assert!(
            msg.contains("cargo build --release --bin lrnsd"),
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
        let toml_str =
            fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/basic_probe.toml"))
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
