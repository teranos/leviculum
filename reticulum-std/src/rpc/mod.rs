//! RPC server for Python CLI tool compatibility
//!
//! Implements the `multiprocessing.connection` wire protocol so that Python
//! tools (`rnstatus`, `rnpath`, `rnprobe`) can query the running Rust daemon
//! as if it were a Python shared instance.
//!
//! Three layers:
//! - `connection`: Wire protocol (length-prefixed framing, HMAC handshake)
//! - `pickle`: Request parsing and response building (pickle ser/de)
//! - `handlers`: RPC command dispatch and state queries

pub(crate) mod connection;
mod error;
mod handlers;
pub(crate) mod pickle;

use std::sync::{Arc, Mutex};

use tokio::net::UnixListener;

use crate::driver::StdNodeCore;
use connection::{read_message, server_handshake, write_message};
use error::RpcError;
use handlers::handle_request;
use pickle::parse_request;

/// Spawn the RPC server on abstract Unix socket `\0rns/{instance_name}/rpc`.
///
/// Accepts connections concurrently (each in its own task).
/// Each connection: handshake -> read request -> dispatch -> write response -> close.
pub(crate) fn spawn_rpc_server(
    instance_name: &str,
    core: Arc<Mutex<StdNodeCore>>,
    authkey: [u8; 32],
    start_time: std::time::Instant,
) -> Result<(), std::io::Error> {
    let abstract_name = format!("rns/{}/rpc", instance_name);

    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(abstract_name.as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let std_listener = std::os::unix::net::UnixListener::bind_addr(&addr)?;
    std_listener.set_nonblocking(true)?;
    let listener = UnixListener::from_std(std_listener)?;

    tracing::info!(
        "RPC server listening on abstract socket \\0{}",
        abstract_name
    );

    tokio::spawn(async move {
        rpc_accept_loop(listener, core, authkey, start_time).await;
    });

    Ok(())
}

/// Accept loop: spawns a task per connection.
async fn rpc_accept_loop(
    listener: UnixListener,
    core: Arc<Mutex<StdNodeCore>>,
    authkey: [u8; 32],
    start_time: std::time::Instant,
) {
    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("RPC accept error: {}", e);
                continue;
            }
        };

        let core = Arc::clone(&core);
        tokio::spawn(async move {
            if let Err(e) = handle_rpc_connection(stream, &core, &authkey, start_time).await {
                tracing::debug!("RPC connection error: {}", e);
            }
        });
    }
}

/// Handle a single RPC connection: handshake -> read -> dispatch -> write -> close.
async fn handle_rpc_connection(
    mut stream: tokio::net::UnixStream,
    core: &Arc<Mutex<StdNodeCore>>,
    authkey: &[u8; 32],
    start_time: std::time::Instant,
) -> Result<(), RpcError> {
    server_handshake(&mut stream, authkey).await?;

    let request_bytes = read_message(&mut stream).await?;
    let request = parse_request(&request_bytes)?;

    tracing::debug!("RPC request: {:?}", request);

    let response_bytes = {
        let core = core.lock().unwrap();
        handle_request(&request, &core, start_time)?
    };

    write_message(&mut stream, &response_bytes).await?;

    Ok(())
}

// ─── Client-side functions (for integration tests) ────────────────────────

/// Connect to the RPC server, perform handshake, send request, receive response.
#[cfg(test)]
pub(crate) async fn rpc_client_call(
    abstract_name: &str,
    authkey: &[u8; 32],
    request: &serde_pickle::value::Value,
) -> Result<serde_pickle::value::Value, RpcError> {
    use std::os::linux::net::SocketAddrExt;
    use tokio::net::UnixStream;

    let addr = std::os::unix::net::SocketAddr::from_abstract_name(abstract_name.as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let std_stream = std::os::unix::net::UnixStream::connect_addr(&addr)?;
    std_stream.set_nonblocking(true)?;
    let mut stream = UnixStream::from_std(std_stream)?;

    connection::client_handshake(&mut stream, authkey).await?;

    let request_bytes = serde_pickle::value_to_vec(request, Default::default())
        .map_err(|e| RpcError::Pickle(format!("serialize request: {}", e)))?;
    write_message(&mut stream, &request_bytes).await?;

    let response_bytes = read_message(&mut stream).await?;
    let response: serde_pickle::value::Value =
        serde_pickle::value_from_slice(&response_bytes, Default::default())
            .map_err(|e| RpcError::Pickle(format!("deserialize response: {}", e)))?;

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pickle::{pickle_dict, pickle_str, pickle_str_key};
    use serde_pickle::value::{HashableValue, Value};

    /// Derive the RPC authkey from a NodeCore identity (same as driver).
    fn derive_authkey(core: &Arc<Mutex<StdNodeCore>>) -> [u8; 32] {
        let core_guard = core.lock().unwrap();
        let prv = core_guard.identity().private_key_bytes().unwrap();
        use sha2::Digest;
        let hash = sha2::Sha256::digest(&prv);
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        key
    }

    /// Create a minimal ReticulumNode and extract its inner Arc<Mutex<StdNodeCore>>.
    fn make_test_core(transport: bool) -> Arc<Mutex<StdNodeCore>> {
        let node = crate::driver::ReticulumNodeBuilder::new()
            .enable_transport(transport)
            .build_sync()
            .expect("build_sync failed");
        node.inner()
    }

    /// Spawn a minimal RPC server and test it with a Rust client.
    #[tokio::test]
    async fn test_rpc_interface_stats_round_trip() {
        let core = make_test_core(true);
        let start_time = std::time::Instant::now();
        let authkey = derive_authkey(&core);

        let instance_name = format!("rpctest_{}", std::process::id());
        let abstract_name = format!("rns/{}/rpc", instance_name);

        spawn_rpc_server(&instance_name, Arc::clone(&core), authkey, start_time).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = pickle_dict(vec![(pickle_str_key("get"), pickle_str("interface_stats"))]);
        let response = rpc_client_call(&abstract_name, &authkey, &request)
            .await
            .unwrap();

        match &response {
            Value::Dict(d) => {
                assert!(
                    d.contains_key(&HashableValue::String("transport_id".into())),
                    "response should contain transport_id"
                );
                assert!(
                    d.contains_key(&HashableValue::String("transport_uptime".into())),
                    "response should contain transport_uptime"
                );
                assert!(
                    d.contains_key(&HashableValue::String("interfaces".into())),
                    "response should contain interfaces"
                );

                if let Some(Value::F64(uptime)) =
                    d.get(&HashableValue::String("transport_uptime".into()))
                {
                    assert!(*uptime >= 0.0, "uptime should be non-negative");
                }
            }
            other => panic!("expected dict response, got: {:?}", other),
        }
    }

    /// Test that wrong authkey is rejected.
    #[tokio::test]
    async fn test_rpc_auth_failure() {
        let core = make_test_core(true);
        let start_time = std::time::Instant::now();
        let authkey = derive_authkey(&core);

        let instance_name = format!("rpctest_auth_{}", std::process::id());
        let abstract_name = format!("rns/{}/rpc", instance_name);

        spawn_rpc_server(&instance_name, Arc::clone(&core), authkey, start_time).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let wrong_key = [0xFFu8; 32];
        let request = pickle_dict(vec![(pickle_str_key("get"), pickle_str("interface_stats"))]);
        let result = rpc_client_call(&abstract_name, &wrong_key, &request).await;
        assert!(result.is_err(), "wrong authkey should cause failure");
    }

    /// Test link_count RPC.
    #[tokio::test]
    async fn test_rpc_link_count() {
        let core = make_test_core(false);
        let start_time = std::time::Instant::now();
        let authkey = derive_authkey(&core);

        let instance_name = format!("rpctest_lc_{}", std::process::id());
        let abstract_name = format!("rns/{}/rpc", instance_name);

        spawn_rpc_server(&instance_name, Arc::clone(&core), authkey, start_time).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = pickle_dict(vec![(pickle_str_key("get"), pickle_str("link_count"))]);
        let response = rpc_client_call(&abstract_name, &authkey, &request)
            .await
            .unwrap();

        match response {
            Value::I64(count) => assert_eq!(count, 0, "no links established"),
            other => panic!("expected int, got: {:?}", other),
        }
    }
}
