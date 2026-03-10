use rand::RngCore;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io;
use std::path::Path;

// ---------------------------------------------------------------------------
// TOML data model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct TestScenario {
    pub test: TestMeta,
    pub nodes: BTreeMap<String, NodeDef>,
    #[serde(default)]
    pub links: BTreeMap<String, String>,
    #[serde(default)]
    pub radio: Option<RadioConfig>,
    #[serde(default)]
    pub steps: Vec<Step>,
}

// Fields populated by serde deserialization appear unused to the compiler.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct TestMeta {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// RUST_LOG filter for daemon containers. Defaults to "debug" if unset.
    #[serde(default)]
    pub rust_log: Option<String>,
}

fn default_timeout() -> u64 {
    60
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeDef {
    #[serde(rename = "type")]
    pub node_type: String,
    #[serde(default)]
    pub respond_to_probes: bool,
    #[serde(default = "default_true")]
    pub enable_transport: bool,
    /// Host device path for RNode serial (e.g., "/dev/ttyACM0").
    #[serde(default)]
    pub rnode: Option<String>,
    /// When true, a lora-proxy process sits between the host device and the
    /// container, enabling fault-injection steps (proxy_rule, proxy_stats).
    #[serde(default)]
    pub rnode_proxy: bool,
    /// TCP server port for local tool access (e.g., selftest).
    /// Generates a standalone TCPServerInterface, independent of [links].
    #[serde(default)]
    pub listen_port: Option<u16>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RadioConfig {
    pub frequency: u64,
    pub bandwidth: u32,
    #[serde(alias = "sf")]
    pub spreading_factor: u8,
    #[serde(alias = "cr")]
    pub coding_rate: u8,
    #[serde(alias = "txpower")]
    pub tx_power: u8,
}

fn default_true() -> bool {
    true
}

// Fields on unimplemented step variants are populated by serde but not yet
// read by the executor (see unimplemented!() arms in executor.rs).
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "action")]
pub enum Step {
    #[serde(rename = "wait_for_path")]
    WaitForPath {
        on: String,
        destination: String,
        #[serde(default = "default_step_timeout")]
        timeout_secs: u64,
        #[serde(default = "default_expect_success")]
        expect_result: String,
    },
    #[serde(rename = "rnprobe")]
    RnProbe {
        from: String,
        to: String,
        #[serde(default)]
        expect_hops: Option<u32>,
        #[serde(default = "default_expect_success")]
        expect_result: String,
        #[serde(default = "default_step_timeout")]
        timeout_secs: u64,
    },
    #[serde(rename = "rnpath")]
    RnPath {
        on: String,
        destination: String,
        #[serde(default)]
        expect_min_hops: Option<u32>,
        #[serde(default)]
        expect_max_hops: Option<u32>,
    },
    #[serde(rename = "rnstatus")]
    RnStatus {
        on: String,
        #[serde(default)]
        expect_transport: Option<bool>,
    },
    #[serde(rename = "exec")]
    Exec {
        on: String,
        command: String,
        #[serde(default)]
        expect_exit_code: Option<i32>,
        #[serde(default)]
        expect_stdout_contains: Option<String>,
        /// Extra environment variables passed to `docker exec -e`.
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
    #[serde(rename = "sleep")]
    Sleep { duration_secs: u64 },
    #[serde(rename = "restart")]
    Restart { node: String },
    /// Block traffic between two containers using iptables DROP rules.
    /// Must be applied on both sides for a clean bidirectional block.
    #[serde(rename = "block_link")]
    BlockLink { from: String, to: String },
    /// Restore traffic between two containers by removing iptables DROP rules.
    #[serde(rename = "restore_link")]
    RestoreLink { from: String, to: String },
    /// Add a fault-injection rule to a node's lora-proxy.
    #[serde(rename = "proxy_rule")]
    ProxyRule { node: String, rule: String },
    /// Clear proxy rules: `id` can be a numeric rule ID or "all".
    #[serde(rename = "proxy_rule_clear")]
    ProxyRuleClear { node: String, id: String },
    /// Query proxy stats and optionally assert on counters.
    #[serde(rename = "proxy_stats")]
    ProxyStats {
        node: String,
        #[serde(default)]
        expect_dropped: Option<u64>,
        #[serde(default)]
        expect_forwarded: Option<u64>,
    },
}

fn default_step_timeout() -> u64 {
    30
}

fn default_expect_success() -> String {
    "success".into()
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

pub fn parse_scenario(toml_str: &str) -> Result<TestScenario, toml::de::Error> {
    toml::from_str(toml_str)
}

// ---------------------------------------------------------------------------
// Environment-variable radio overrides
// ---------------------------------------------------------------------------

/// Return the timeout scale factor from `LORA_TIMEOUT_SCALE` env var (default 1.0).
///
/// When running tests at slower bitrates, all step timeouts and sleep durations
/// need to be scaled proportionally. Set `LORA_TIMEOUT_SCALE=3` for ~3x slower
/// radio settings (e.g., SF10 vs SF7).
pub fn timeout_scale() -> f64 {
    std::env::var("LORA_TIMEOUT_SCALE")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(1.0)
}

/// Scale a timeout value by the `LORA_TIMEOUT_SCALE` factor.
pub fn scale_timeout(secs: u64) -> u64 {
    let scaled = secs as f64 * timeout_scale();
    scaled.ceil() as u64
}

/// Override radio parameters from environment variables.
///
/// If the scenario has a `[radio]` section, any of these env vars override
/// the corresponding field:
///   - `LORA_FREQUENCY` (u64, Hz)
///   - `LORA_BANDWIDTH` (u32, Hz)
///   - `LORA_SF` (u8, spreading factor)
///   - `LORA_CR` (u8, coding rate)
///   - `LORA_TXPOWER` (u8, dBm)
///
/// This allows running the same TOML test files with different radio settings
/// without modifying them.
pub fn apply_radio_overrides(scenario: &mut TestScenario) {
    let radio = match scenario.radio.as_mut() {
        Some(r) => r,
        None => return,
    };

    if let Ok(val) = std::env::var("LORA_FREQUENCY") {
        if let Ok(v) = val.parse::<u64>() {
            radio.frequency = v;
        }
    }
    if let Ok(val) = std::env::var("LORA_BANDWIDTH") {
        if let Ok(v) = val.parse::<u32>() {
            radio.bandwidth = v;
        }
    }
    if let Ok(val) = std::env::var("LORA_SF") {
        if let Ok(v) = val.parse::<u8>() {
            radio.spreading_factor = v;
        }
    }
    if let Ok(val) = std::env::var("LORA_CR") {
        if let Ok(v) = val.parse::<u8>() {
            radio.coding_rate = v;
        }
    }
    if let Ok(val) = std::env::var("LORA_TXPOWER") {
        if let Ok(v) = val.parse::<u8>() {
            radio.tx_power = v;
        }
    }
}

// ---------------------------------------------------------------------------
// Interface assignment from links
// ---------------------------------------------------------------------------

/// A single interface entry for a node's config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceEntry {
    TcpServer {
        peer: String,
        port: u16,
    },
    TcpClient {
        peer: String,
        target_host: String,
        port: u16,
    },
}

/// Parse all links and return a map: node_name -> Vec<InterfaceEntry>.
///
/// Convention: for link key "X-Y" (with X < Y alphabetically), X gets the
/// server role and Y gets the client role. Each server node gets a unique port
/// starting from 4242, incrementing per additional link.
pub fn assign_interfaces(
    links: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, Vec<InterfaceEntry>>, String> {
    let mut interfaces: BTreeMap<String, Vec<InterfaceEntry>> = BTreeMap::new();
    // Track next port per server node.
    let mut server_ports: BTreeMap<String, u16> = BTreeMap::new();

    for (link_key, link_type) in links {
        if link_type != "tcp" {
            return Err(format!("unsupported link type: {link_type}"));
        }

        let parts: Vec<&str> = link_key.split('-').collect();
        if parts.len() != 2 {
            return Err(format!("link key must be 'nodeA-nodeB', got: {link_key}"));
        }

        // Alphabetically first = server, second = client.
        let (server, client) = if parts[0] <= parts[1] {
            (parts[0].to_string(), parts[1].to_string())
        } else {
            (parts[1].to_string(), parts[0].to_string())
        };

        let port = server_ports.entry(server.clone()).or_insert(4242);
        let current_port = *port;
        *port += 1;

        interfaces
            .entry(server.clone())
            .or_default()
            .push(InterfaceEntry::TcpServer {
                peer: client.clone(),
                port: current_port,
            });

        interfaces
            .entry(client.clone())
            .or_default()
            .push(InterfaceEntry::TcpClient {
                peer: server.clone(),
                target_host: server.clone(),
                port: current_port,
            });
    }

    Ok(interfaces)
}

// ---------------------------------------------------------------------------
// Config generation
// ---------------------------------------------------------------------------

/// Generate the Reticulum INI config string for a node.
pub fn render_config(
    node: &NodeDef,
    ifaces: &[InterfaceEntry],
    radio: Option<&RadioConfig>,
) -> String {
    let mut out = String::new();

    let enabled = if node.enable_transport { "yes" } else { "no" };
    let probes = if node.respond_to_probes { "yes" } else { "no" };

    writeln!(out, "[reticulum]").ok();
    writeln!(out, "  enable_transport = {enabled}").ok();
    writeln!(out, "  share_instance = yes").ok();
    writeln!(out, "  respond_to_probes = {probes}").ok();
    writeln!(out).ok();
    writeln!(out, "[logging]").ok();
    writeln!(out, "  loglevel = 5").ok();
    writeln!(out).ok();
    writeln!(out, "[interfaces]").ok();

    for iface in ifaces {
        match iface {
            InterfaceEntry::TcpServer { peer, port } => {
                writeln!(out, "  [[TCPServerInterface-{peer}]]").ok();
                writeln!(out, "    type = TCPServerInterface").ok();
                writeln!(out, "    enabled = yes").ok();
                writeln!(out, "    listen_ip = 0.0.0.0").ok();
                writeln!(out, "    listen_port = {port}").ok();
                // Disable ingress control in integration tests to avoid
                // non-deterministic announce suppression during rapid startup.
                writeln!(out, "    ingress_control = false").ok();
            }
            InterfaceEntry::TcpClient {
                peer,
                target_host,
                port,
            } => {
                writeln!(out, "  [[TCPClientInterface-{peer}]]").ok();
                writeln!(out, "    type = TCPClientInterface").ok();
                writeln!(out, "    enabled = yes").ok();
                writeln!(out, "    target_host = {target_host}").ok();
                writeln!(out, "    target_port = {port}").ok();
                writeln!(out, "    ingress_control = false").ok();
            }
        }
    }

    if let (Some(port), Some(radio)) = (&node.rnode, radio) {
        writeln!(out, "  [[RNode Interface]]").ok();
        writeln!(out, "    type = RNodeInterface").ok();
        writeln!(out, "    enabled = yes").ok();
        writeln!(out, "    port = {port}").ok();
        writeln!(out, "    frequency = {}", radio.frequency).ok();
        writeln!(out, "    bandwidth = {}", radio.bandwidth).ok();
        writeln!(out, "    spreadingfactor = {}", radio.spreading_factor).ok();
        writeln!(out, "    codingrate = {}", radio.coding_rate).ok();
        writeln!(out, "    txpower = {}", radio.tx_power).ok();
        writeln!(out, "    ingress_control = false").ok();
    }

    if let Some(port) = node.listen_port {
        writeln!(out, "  [[Selftest TCP Server]]").ok();
        writeln!(out, "    type = TCPServerInterface").ok();
        writeln!(out, "    enabled = yes").ok();
        writeln!(out, "    listen_ip = 0.0.0.0").ok();
        writeln!(out, "    listen_port = {port}").ok();
        writeln!(out, "    ingress_control = false").ok();
    }

    out
}

/// Generate node config files and identity files into `base_dir`.
///
/// Creates for each node:
///   - `{base_dir}/{node_name}/storage/transport_identity` (64 random bytes)
///   - `{base_dir}/{node_name}/config` (Reticulum INI format)
pub fn generate_node_configs(scenario: &TestScenario, base_dir: &Path) -> io::Result<()> {
    let interfaces = assign_interfaces(&scenario.links)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Validate: if any node has rnode set, [radio] must be present.
    let has_rnode = scenario.nodes.values().any(|n| n.rnode.is_some());
    if has_rnode && scenario.radio.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "nodes with rnode require a [radio] section",
        ));
    }

    // Validate: rnode_proxy requires rnode.
    for (name, node) in &scenario.nodes {
        if node.rnode_proxy && node.rnode.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("node '{name}': rnode_proxy requires rnode"),
            ));
        }
    }

    // Validate: listen_port must not collide with link-based TCP server ports.
    for (name, node) in &scenario.nodes {
        if let Some(listen_port) = node.listen_port {
            if let Some(ifaces) = interfaces.get(name.as_str()) {
                for iface in ifaces {
                    if let InterfaceEntry::TcpServer { port, .. } = iface {
                        if *port == listen_port {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "node '{name}': listen_port {listen_port} conflicts with \
                                     link-based TCP server on the same port"
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }

    let mut rng = rand::thread_rng();

    for (name, node) in &scenario.nodes {
        let node_dir = base_dir.join(name);
        let storage_dir = node_dir.join("storage");
        fs::create_dir_all(&storage_dir)?;

        // Generate 64-byte identity file.
        let mut identity = [0u8; 64];
        rng.fill_bytes(&mut identity);
        fs::write(storage_dir.join("transport_identity"), identity)?;

        // Render and write config.
        let ifaces = interfaces.get(name.as_str()).cloned().unwrap_or_default();
        let config = render_config(node, &ifaces, scenario.radio.as_ref());
        fs::write(node_dir.join("config"), config)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn load_basic_probe() -> TestScenario {
        let toml_str = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/basic_probe.toml"
        ))
        .expect("basic_probe.toml not found");
        parse_scenario(&toml_str).expect("parse failed")
    }

    #[test]
    fn parse_basic_probe() {
        let scenario = load_basic_probe();
        assert_eq!(scenario.test.name, "basic_probe");
        assert_eq!(scenario.test.timeout_secs, 60);
        assert_eq!(scenario.nodes.len(), 2);
        assert!(scenario.nodes.contains_key("alice"));
        assert!(scenario.nodes.contains_key("bob"));
        assert_eq!(scenario.nodes["alice"].node_type, "rust");
        assert_eq!(scenario.nodes["bob"].node_type, "python");
        assert!(scenario.nodes["alice"].respond_to_probes);
        assert!(scenario.nodes["bob"].respond_to_probes);
        assert!(scenario.nodes["alice"].enable_transport);
        assert_eq!(scenario.links.len(), 1);
        assert_eq!(scenario.links["alice-bob"], "tcp");
        assert_eq!(scenario.steps.len(), 2);
    }

    #[test]
    fn parse_steps_variants() {
        let scenario = load_basic_probe();

        match &scenario.steps[0] {
            Step::WaitForPath {
                on,
                destination,
                timeout_secs,
                expect_result,
            } => {
                assert_eq!(on, "alice");
                assert_eq!(destination, "bob.probe");
                assert_eq!(*timeout_secs, 30);
                assert_eq!(expect_result, "success");
            }
            other => panic!("expected WaitForPath, got: {other:?}"),
        }

        match &scenario.steps[1] {
            Step::RnProbe {
                from,
                to,
                expect_hops,
                expect_result,
                ..
            } => {
                assert_eq!(from, "alice");
                assert_eq!(to, "bob.probe");
                assert_eq!(*expect_hops, Some(1));
                assert_eq!(expect_result, "success");
            }
            other => panic!("expected RnProbe, got: {other:?}"),
        }
    }

    #[test]
    fn generate_configs_creates_correct_structure() {
        let scenario = load_basic_probe();
        let tmp = TempDir::new().unwrap();

        generate_node_configs(&scenario, tmp.path()).unwrap();

        // Check directory structure.
        assert!(tmp.path().join("alice/storage/transport_identity").exists());
        assert!(tmp.path().join("alice/config").exists());
        assert!(tmp.path().join("bob/storage/transport_identity").exists());
        assert!(tmp.path().join("bob/config").exists());
    }

    #[test]
    fn identity_files_are_64_bytes() {
        let scenario = load_basic_probe();
        let tmp = TempDir::new().unwrap();

        generate_node_configs(&scenario, tmp.path()).unwrap();

        let alice_id = fs::read(tmp.path().join("alice/storage/transport_identity")).unwrap();
        let bob_id = fs::read(tmp.path().join("bob/storage/transport_identity")).unwrap();
        assert_eq!(alice_id.len(), 64);
        assert_eq!(bob_id.len(), 64);
        // Identities should differ (random).
        assert_ne!(alice_id, bob_id);
    }

    #[test]
    fn alice_config_has_tcp_server() {
        let scenario = load_basic_probe();
        let tmp = TempDir::new().unwrap();

        generate_node_configs(&scenario, tmp.path()).unwrap();

        let config = fs::read_to_string(tmp.path().join("alice/config")).unwrap();
        assert!(
            config.contains("TCPServerInterface"),
            "alice should have TCPServerInterface"
        );
        assert!(config.contains("listen_port = 4242"));
        assert!(config.contains("listen_ip = 0.0.0.0"));
        assert!(
            !config.contains("TCPClientInterface"),
            "alice should NOT have TCPClientInterface"
        );
    }

    #[test]
    fn bob_config_has_tcp_client() {
        let scenario = load_basic_probe();
        let tmp = TempDir::new().unwrap();

        generate_node_configs(&scenario, tmp.path()).unwrap();

        let config = fs::read_to_string(tmp.path().join("bob/config")).unwrap();
        assert!(
            config.contains("TCPClientInterface"),
            "bob should have TCPClientInterface"
        );
        assert!(config.contains("target_host = alice"));
        assert!(config.contains("target_port = 4242"));
        assert!(
            !config.contains("TCPServerInterface"),
            "bob should NOT have TCPServerInterface"
        );
    }

    #[test]
    fn config_contains_transport_and_probe_settings() {
        let scenario = load_basic_probe();
        let tmp = TempDir::new().unwrap();

        generate_node_configs(&scenario, tmp.path()).unwrap();

        for node_name in ["alice", "bob"] {
            let config =
                fs::read_to_string(tmp.path().join(format!("{node_name}/config"))).unwrap();
            assert!(
                config.contains("enable_transport = yes"),
                "{node_name}: missing enable_transport"
            );
            assert!(
                config.contains("share_instance = yes"),
                "{node_name}: missing share_instance"
            );
            assert!(
                config.contains("respond_to_probes = yes"),
                "{node_name}: missing respond_to_probes"
            );
            assert!(
                config.contains("loglevel = 5"),
                "{node_name}: missing loglevel"
            );
        }
    }

    #[test]
    fn relay_topology_three_nodes() {
        let toml_str = r#"
[test]
name = "relay_test"
description = "A through R to B"
timeout_secs = 90

[nodes.alice]
type = "rust"
respond_to_probes = true

[nodes.relay]
type = "python"
respond_to_probes = false

[nodes.bob]
type = "rust"
respond_to_probes = true

[links]
alice-relay = "tcp"
bob-relay = "tcp"

[[steps]]
action = "sleep"
duration_secs = 5
"#;
        let scenario = parse_scenario(toml_str).unwrap();
        let tmp = TempDir::new().unwrap();

        generate_node_configs(&scenario, tmp.path()).unwrap();

        // alice-relay: alice < relay alphabetically → alice=server, relay=client
        let alice_cfg = fs::read_to_string(tmp.path().join("alice/config")).unwrap();
        assert!(alice_cfg.contains("TCPServerInterface-relay"));
        assert!(alice_cfg.contains("listen_port = 4242"));

        // bob-relay: bob < relay alphabetically → bob=server, relay=client
        let bob_cfg = fs::read_to_string(tmp.path().join("bob/config")).unwrap();
        assert!(bob_cfg.contains("TCPServerInterface-relay"));
        assert!(bob_cfg.contains("listen_port = 4242"));

        // relay should have two TCPClientInterfaces
        let relay_cfg = fs::read_to_string(tmp.path().join("relay/config")).unwrap();
        assert!(relay_cfg.contains("TCPClientInterface-alice"));
        assert!(relay_cfg.contains("target_host = alice"));
        assert!(relay_cfg.contains("TCPClientInterface-bob"));
        assert!(relay_cfg.contains("target_host = bob"));
        assert!(relay_cfg.contains("respond_to_probes = no"));
        assert!(!relay_cfg.contains("TCPServerInterface"));
    }

    #[test]
    fn multiple_links_same_server_increments_port() {
        let toml_str = r#"
[test]
name = "hub_spoke"

[nodes.hub]
type = "rust"
respond_to_probes = true

[nodes.spoke1]
type = "python"
respond_to_probes = true

[nodes.spoke2]
type = "python"
respond_to_probes = true

[links]
hub-spoke1 = "tcp"
hub-spoke2 = "tcp"
"#;
        let scenario = parse_scenario(toml_str).unwrap();
        let interfaces = assign_interfaces(&scenario.links).unwrap();

        // hub is alphabetically first in both links → hub is server for both
        let hub_ifaces = &interfaces["hub"];
        assert_eq!(hub_ifaces.len(), 2);

        let ports: Vec<u16> = hub_ifaces
            .iter()
            .map(|i| match i {
                InterfaceEntry::TcpServer { port, .. } => *port,
                other => panic!("expected TcpServer, got: {other:?}"),
            })
            .collect();

        assert!(ports.contains(&4242));
        assert!(ports.contains(&4243));
    }

    #[test]
    fn unsupported_link_type_errors() {
        let mut links = BTreeMap::new();
        links.insert("alice-bob".to_string(), "udp".to_string());
        let result = assign_interfaces(&links);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsupported link type"));
    }

    #[test]
    fn malformed_link_key_errors() {
        let mut links = BTreeMap::new();
        links.insert("alice".to_string(), "tcp".to_string());
        let result = assign_interfaces(&links);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("nodeA-nodeB"));
    }

    #[test]
    fn parse_radio_config() {
        let toml_str = r#"
[test]
name = "radio_test"

[radio]
frequency = 868000000
bandwidth = 125000
sf = 7
cr = 5
txpower = 17

[nodes.alpha]
type = "rust"
respond_to_probes = true
rnode = "/dev/ttyACM0"
"#;
        let scenario = parse_scenario(toml_str).unwrap();
        let radio = scenario.radio.as_ref().expect("radio should be present");
        assert_eq!(radio.frequency, 868000000);
        assert_eq!(radio.bandwidth, 125000);
        assert_eq!(radio.spreading_factor, 7);
        assert_eq!(radio.coding_rate, 5);
        assert_eq!(radio.tx_power, 17);
        assert_eq!(
            scenario.nodes["alpha"].rnode.as_deref(),
            Some("/dev/ttyACM0")
        );
    }

    #[test]
    fn rnode_config_generates_ini() {
        let node = NodeDef {
            node_type: "rust".into(),
            respond_to_probes: true,
            enable_transport: true,
            rnode: Some("/dev/ttyACM0".into()),
            rnode_proxy: false,
            listen_port: None,
        };
        let radio = RadioConfig {
            frequency: 868000000,
            bandwidth: 125000,
            spreading_factor: 7,
            coding_rate: 5,
            tx_power: 17,
        };
        let config = render_config(&node, &[], Some(&radio));
        assert!(
            config.contains("[[RNode Interface]]"),
            "missing RNode section"
        );
        assert!(config.contains("type = RNodeInterface"));
        assert!(config.contains("enabled = yes"));
        assert!(config.contains("port = /dev/ttyACM0"));
        assert!(config.contains("frequency = 868000000"));
        assert!(config.contains("bandwidth = 125000"));
        assert!(config.contains("spreadingfactor = 7"));
        assert!(config.contains("codingrate = 5"));
        assert!(config.contains("txpower = 17"));
        assert!(config.contains("ingress_control = false"));
    }

    #[test]
    fn rnode_without_radio_section_errors() {
        let toml_str = r#"
[test]
name = "missing_radio"

[nodes.alpha]
type = "rust"
respond_to_probes = true
rnode = "/dev/ttyACM0"
"#;
        let scenario = parse_scenario(toml_str).unwrap();
        let tmp = TempDir::new().unwrap();
        let result = generate_node_configs(&scenario, tmp.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("rnode require a [radio] section"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn existing_tcp_only_unchanged() {
        // Verify that radio: None doesn't affect existing TCP-only scenarios.
        let scenario = load_basic_probe();
        assert!(scenario.radio.is_none());
        assert!(scenario.nodes["alice"].rnode.is_none());

        let tmp = TempDir::new().unwrap();
        generate_node_configs(&scenario, tmp.path()).unwrap();

        let alice_cfg = fs::read_to_string(tmp.path().join("alice/config")).unwrap();
        assert!(alice_cfg.contains("TCPServerInterface"));
        assert!(!alice_cfg.contains("RNodeInterface"));

        let bob_cfg = fs::read_to_string(tmp.path().join("bob/config")).unwrap();
        assert!(bob_cfg.contains("TCPClientInterface"));
        assert!(!bob_cfg.contains("RNodeInterface"));
    }

    #[test]
    fn listen_port_generates_tcp_server() {
        let node = NodeDef {
            node_type: "rust".into(),
            respond_to_probes: true,
            enable_transport: true,
            rnode: None,
            rnode_proxy: false,
            listen_port: Some(4242),
        };
        let config = render_config(&node, &[], None);
        assert!(
            config.contains("[[Selftest TCP Server]]"),
            "missing Selftest TCP Server section"
        );
        assert!(config.contains("type = TCPServerInterface"));
        assert!(config.contains("listen_ip = 0.0.0.0"));
        assert!(config.contains("listen_port = 4242"));
        assert!(config.contains("enabled = yes"));
        assert!(config.contains("ingress_control = false"));
    }

    #[test]
    fn listen_port_coexists_with_rnode() {
        let node = NodeDef {
            node_type: "rust".into(),
            respond_to_probes: true,
            enable_transport: true,
            rnode: Some("/dev/ttyACM0".into()),
            rnode_proxy: false,
            listen_port: Some(4242),
        };
        let radio = RadioConfig {
            frequency: 868000000,
            bandwidth: 125000,
            spreading_factor: 7,
            coding_rate: 5,
            tx_power: 17,
        };
        let config = render_config(&node, &[], Some(&radio));
        assert!(
            config.contains("[[RNode Interface]]"),
            "missing RNode section"
        );
        assert!(
            config.contains("[[Selftest TCP Server]]"),
            "missing Selftest TCP Server section"
        );
    }

    #[test]
    fn listen_port_collides_with_link_port() {
        let toml_str = r#"
[test]
name = "port_collision"

[nodes.alpha]
type = "rust"
respond_to_probes = true
listen_port = 4242

[nodes.beta]
type = "rust"
respond_to_probes = true

[links]
alpha-beta = "tcp"
"#;
        let scenario = parse_scenario(toml_str).unwrap();
        let tmp = TempDir::new().unwrap();
        let result = generate_node_configs(&scenario, tmp.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("listen_port 4242 conflicts"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn listen_port_no_collision_different_port() {
        let toml_str = r#"
[test]
name = "no_collision"

[nodes.alpha]
type = "rust"
respond_to_probes = true
listen_port = 5555

[nodes.beta]
type = "rust"
respond_to_probes = true

[links]
alpha-beta = "tcp"
"#;
        let scenario = parse_scenario(toml_str).unwrap();
        let tmp = TempDir::new().unwrap();
        // Should succeed — listen_port 5555 != link port 4242.
        generate_node_configs(&scenario, tmp.path()).unwrap();
    }

    #[test]
    fn listen_port_none_no_section() {
        let node = NodeDef {
            node_type: "rust".into(),
            respond_to_probes: true,
            enable_transport: true,
            rnode: None,
            rnode_proxy: false,
            listen_port: None,
        };
        let config = render_config(&node, &[], None);
        assert!(
            !config.contains("Selftest TCP Server"),
            "should not have Selftest TCP Server section"
        );
    }
}
