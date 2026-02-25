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
    },
    #[serde(rename = "sleep")]
    Sleep { duration_secs: u64 },
    #[serde(rename = "restart")]
    Restart { node: String },
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
// Interface assignment from links
// ---------------------------------------------------------------------------

/// A single interface entry for a node's config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceEntry {
    TcpServer { peer: String, port: u16 },
    TcpClient { peer: String, target_host: String, port: u16 },
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
            return Err(format!(
                "link key must be 'nodeA-nodeB', got: {link_key}"
            ));
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
pub fn render_config(node: &NodeDef, ifaces: &[InterfaceEntry]) -> String {
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
            }
        }
    }

    out
}

/// Generate node config files and identity files into `base_dir`.
///
/// Creates for each node:
///   - `{base_dir}/{node_name}/storage/transport_identity` (64 random bytes)
///   - `{base_dir}/{node_name}/config` (Reticulum INI format)
pub fn generate_node_configs(
    scenario: &TestScenario,
    base_dir: &Path,
) -> io::Result<()> {
    let interfaces = assign_interfaces(&scenario.links)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut rng = rand::thread_rng();

    for (name, node) in &scenario.nodes {
        let node_dir = base_dir.join(name);
        let storage_dir = node_dir.join("storage");
        fs::create_dir_all(&storage_dir)?;

        // Generate 64-byte identity file.
        let mut identity = [0u8; 64];
        rng.fill_bytes(&mut identity);
        fs::write(storage_dir.join("transport_identity"), &identity)?;

        // Render and write config.
        let ifaces = interfaces.get(name.as_str()).cloned().unwrap_or_default();
        let config = render_config(node, &ifaces);
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
        let toml_str =
            fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/basic_probe.toml"))
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
            } => {
                assert_eq!(on, "alice");
                assert_eq!(destination, "bob.probe");
                assert_eq!(*timeout_secs, 30);
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
        assert!(config.contains("TCPServerInterface"), "alice should have TCPServerInterface");
        assert!(config.contains("listen_port = 4242"));
        assert!(config.contains("listen_ip = 0.0.0.0"));
        assert!(!config.contains("TCPClientInterface"), "alice should NOT have TCPClientInterface");
    }

    #[test]
    fn bob_config_has_tcp_client() {
        let scenario = load_basic_probe();
        let tmp = TempDir::new().unwrap();

        generate_node_configs(&scenario, tmp.path()).unwrap();

        let config = fs::read_to_string(tmp.path().join("bob/config")).unwrap();
        assert!(config.contains("TCPClientInterface"), "bob should have TCPClientInterface");
        assert!(config.contains("target_host = alice"));
        assert!(config.contains("target_port = 4242"));
        assert!(!config.contains("TCPServerInterface"), "bob should NOT have TCPServerInterface");
    }

    #[test]
    fn config_contains_transport_and_probe_settings() {
        let scenario = load_basic_probe();
        let tmp = TempDir::new().unwrap();

        generate_node_configs(&scenario, tmp.path()).unwrap();

        for node_name in ["alice", "bob"] {
            let config = fs::read_to_string(tmp.path().join(format!("{node_name}/config"))).unwrap();
            assert!(config.contains("enable_transport = yes"), "{node_name}: missing enable_transport");
            assert!(config.contains("share_instance = yes"), "{node_name}: missing share_instance");
            assert!(config.contains("respond_to_probes = yes"), "{node_name}: missing respond_to_probes");
            assert!(config.contains("loglevel = 5"), "{node_name}: missing loglevel");
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
}
