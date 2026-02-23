//! RPC command dispatch — maps requests to node state queries

use serde_pickle::value::Value;

use super::error::RpcError;
use super::pickle::*;
use crate::driver::StdNodeCore;

/// Dispatch an RPC request against node state and return the pickle-encoded response.
pub(super) fn handle_request(
    request: &RpcRequest,
    core: &StdNodeCore,
    start_time: std::time::Instant,
) -> Result<Vec<u8>, RpcError> {
    let response = match request {
        // ─── Priority 1: Full implementations (rnstatus) ──────────────
        RpcRequest::GetInterfaceStats => build_interface_stats(core, start_time),
        RpcRequest::GetLinkCount => pickle_int(core.active_link_count() as i64),

        // ─── Priority 2: Stubs (rnpath, rnprobe) ─────────────────────
        RpcRequest::GetPathTable { .. } => pickle_list(vec![]),
        RpcRequest::GetRateTable => pickle_list(vec![]),
        RpcRequest::GetNextHop { .. } => pickle_none(),
        RpcRequest::GetNextHopIfName { .. } => pickle_str("unknown"),
        RpcRequest::GetFirstHopTimeout { .. } => pickle_float(15.0),
        RpcRequest::GetPacketRssi { .. } => pickle_none(),
        RpcRequest::GetPacketSnr { .. } => pickle_none(),
        RpcRequest::GetPacketQ { .. } => pickle_none(),
        RpcRequest::GetBlackholedIdentities => pickle_dict(vec![]),
        RpcRequest::DropPath { .. } => pickle_bool(false),
        RpcRequest::DropAllVia { .. } => pickle_int(0),
        RpcRequest::DropAnnounceQueues => pickle_bool(true),
        RpcRequest::BlackholeIdentity { .. } => pickle_bool(true),
        RpcRequest::UnblackholeIdentity { .. } => pickle_bool(true),
    };

    serialize_response(&response)
}

/// Build the `interface_stats` response dict matching Python's format.
fn build_interface_stats(core: &StdNodeCore, start_time: std::time::Instant) -> Value {
    let stats = core.interface_stats();
    let identity = core.identity();
    let transport_enabled = core.transport_config().enable_transport;
    let uptime = start_time.elapsed().as_secs_f64();

    let mut iface_list = Vec::new();
    for entry in &stats {
        // Skip local client interfaces from the stats display
        // (Python also hides the LocalClientInterface from rnstatus)
        if entry.is_local_client {
            continue;
        }

        let iface_hash = compute_interface_hash(&entry.name);

        let iface_dict = pickle_dict(vec![
            (pickle_str_key("name"), pickle_str(&entry.name)),
            (
                pickle_str_key("short_name"),
                pickle_str(&short_name(&entry.name)),
            ),
            (pickle_str_key("hash"), pickle_bytes(&iface_hash)),
            (
                pickle_str_key("type"),
                pickle_str(&interface_type(&entry.name)),
            ),
            (pickle_str_key("rxb"), pickle_int(0)),
            (pickle_str_key("txb"), pickle_int(0)),
            (pickle_str_key("rxs"), pickle_int(0)),
            (pickle_str_key("txs"), pickle_int(0)),
            (pickle_str_key("status"), pickle_bool(true)),
            (pickle_str_key("mode"), pickle_int(0)),
            (pickle_str_key("bitrate"), pickle_none()),
            (pickle_str_key("clients"), pickle_none()),
            (pickle_str_key("peers"), pickle_none()),
            (
                pickle_str_key("incoming_announce_frequency"),
                pickle_float(0.0),
            ),
            (
                pickle_str_key("outgoing_announce_frequency"),
                pickle_float(0.0),
            ),
            (pickle_str_key("held_announces"), pickle_int(0)),
            (pickle_str_key("announce_queue"), pickle_none()),
            (pickle_str_key("ifac_signature"), pickle_none()),
            (pickle_str_key("ifac_size"), pickle_none()),
            (pickle_str_key("ifac_netname"), pickle_none()),
        ]);

        iface_list.push(iface_dict);
    }

    let mut entries = vec![
        (pickle_str_key("interfaces"), pickle_list(iface_list)),
        (pickle_str_key("rxb"), pickle_int(0)),
        (pickle_str_key("txb"), pickle_int(0)),
        (pickle_str_key("rxs"), pickle_float(0.0)),
        (pickle_str_key("txs"), pickle_float(0.0)),
        (pickle_str_key("rss"), pickle_none()),
    ];

    if transport_enabled {
        entries.push((
            pickle_str_key("transport_id"),
            pickle_bytes(identity.hash()),
        ));
        entries.push((pickle_str_key("transport_uptime"), pickle_float(uptime)));
        entries.push((pickle_str_key("probe_responder"), pickle_none()));
        entries.push((pickle_str_key("network_id"), pickle_none()));
    }

    pickle_dict(entries)
}

/// Compute a 16-byte interface hash from its name (matches Python Identity.full_hash).
fn compute_interface_hash(name: &str) -> [u8; 16] {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(name.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash[..16]);
    out
}

/// Extract short name from a full interface name.
/// E.g. "AutoInterface[Default Interface]" -> "Default Interface"
/// E.g. "tcp_client_0" -> "tcp_client_0"
fn short_name(name: &str) -> String {
    if let Some(start) = name.find('[') {
        if let Some(end) = name.find(']') {
            if start < end {
                return name[start + 1..end].to_string();
            }
        }
    }
    name.to_string()
}

/// Infer interface type from name.
fn interface_type(name: &str) -> String {
    if name.starts_with("AutoInterface") {
        "AutoInterface".to_string()
    } else if name.starts_with("tcp_client") || name.starts_with("TCPClient") {
        "TCPClientInterface".to_string()
    } else if name.starts_with("tcp_server") || name.starts_with("TCPServer") {
        "TCPServerInterface".to_string()
    } else if name.starts_with("udp") || name.starts_with("UDP") {
        "UDPInterface".to_string()
    } else if name.starts_with("local") || name.starts_with("Local") {
        "LocalInterface".to_string()
    } else {
        "Interface".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_name_with_brackets() {
        assert_eq!(
            short_name("AutoInterface[Default Interface]"),
            "Default Interface"
        );
    }

    #[test]
    fn test_short_name_without_brackets() {
        assert_eq!(short_name("tcp_client_0"), "tcp_client_0");
    }

    #[test]
    fn test_interface_type_auto() {
        assert_eq!(interface_type("AutoInterface[foo]"), "AutoInterface");
    }

    #[test]
    fn test_interface_type_tcp_client() {
        assert_eq!(interface_type("tcp_client_0"), "TCPClientInterface");
    }

    #[test]
    fn test_interface_type_unknown() {
        assert_eq!(interface_type("custom_iface"), "Interface");
    }

    #[test]
    fn test_interface_hash_deterministic() {
        let h1 = compute_interface_hash("test");
        let h2 = compute_interface_hash("test");
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 16]);
    }
}
