//! Wire protocol for CPython `multiprocessing.connection`
//!
//! Implements length-prefixed framing and bidirectional HMAC-SHA256 handshake
//! as used by Python's `multiprocessing.connection.Listener`/`Client`.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::error::RpcError;

type HmacSha256 = Hmac<Sha256>;

const CHALLENGE_PREFIX: &[u8] = b"#CHALLENGE#";
const WELCOME: &[u8] = b"#WELCOME#";
const FAILURE: &[u8] = b"#FAILURE#";
const SHA256_DIGEST_TAG: &[u8] = b"{sha256}";
const CHALLENGE_RANDOM_LEN: usize = 40;
/// Total HMAC response length: 8 bytes digest tag + 32 bytes HMAC = 40
const HMAC_RESPONSE_LEN: usize = SHA256_DIGEST_TAG.len() + 32;

/// Read a length-prefixed message from a stream.
///
/// Format: `[4-byte big-endian i32 length][payload]`
pub(crate) async fn read_message<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<Vec<u8>, RpcError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = i32::from_be_bytes(len_buf);

    if len < 0 {
        // Large message format (>= 2 GB) — not expected in RPC
        return Err(RpcError::InvalidFormat(
            "large message format not supported".into(),
        ));
    }

    let len = len as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write a length-prefixed message to a stream.
pub(crate) async fn write_message<W: AsyncWrite + Unpin>(
    stream: &mut W,
    data: &[u8],
) -> Result<(), RpcError> {
    let len = data.len();
    if len > i32::MAX as usize {
        return Err(RpcError::InvalidFormat("message too large".into()));
    }
    let len_buf = (len as i32).to_be_bytes();
    stream.write_all(&len_buf).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

/// Server-side: send challenge, verify client's HMAC response, send WELCOME/FAILURE.
pub(crate) async fn deliver_challenge<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    authkey: &[u8; 32],
) -> Result<(), RpcError> {
    // Generate challenge: #CHALLENGE#{sha256} + 40 random bytes
    let mut challenge =
        Vec::with_capacity(CHALLENGE_PREFIX.len() + SHA256_DIGEST_TAG.len() + CHALLENGE_RANDOM_LEN);
    challenge.extend_from_slice(CHALLENGE_PREFIX);
    challenge.extend_from_slice(SHA256_DIGEST_TAG);

    let mut random_bytes = [0u8; CHALLENGE_RANDOM_LEN];
    rand_core::OsRng.fill_bytes(&mut random_bytes);
    challenge.extend_from_slice(&random_bytes);

    write_message(stream, &challenge).await?;

    // Read HMAC response from client
    let response = read_message(stream).await?;
    if response.len() != HMAC_RESPONSE_LEN {
        write_message(stream, FAILURE).await?;
        return Err(RpcError::AuthFailed);
    }

    // Verify: response = {sha256} + HMAC-SHA256(authkey, {sha256} + random_bytes)
    let message = &challenge[CHALLENGE_PREFIX.len()..]; // {sha256} + random_bytes
    let mut mac = HmacSha256::new_from_slice(authkey)
        .map_err(|e| RpcError::InvalidFormat(format!("HMAC init: {}", e)))?;
    mac.update(message);

    let expected_response_hmac = &response[SHA256_DIGEST_TAG.len()..];
    if mac.verify_slice(expected_response_hmac).is_err() {
        write_message(stream, FAILURE).await?;
        return Err(RpcError::AuthFailed);
    }

    write_message(stream, WELCOME).await?;
    Ok(())
}

/// Server-side: receive client's challenge, compute HMAC, send response, read WELCOME/FAILURE.
pub(crate) async fn answer_challenge<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    authkey: &[u8; 32],
) -> Result<(), RpcError> {
    let challenge = read_message(stream).await?;

    // Parse: must start with #CHALLENGE#
    if !challenge.starts_with(CHALLENGE_PREFIX) {
        return Err(RpcError::InvalidFormat("missing #CHALLENGE# prefix".into()));
    }

    let after_prefix = &challenge[CHALLENGE_PREFIX.len()..];

    // Check digest tag
    if !after_prefix.starts_with(SHA256_DIGEST_TAG) {
        // Could be {md5} from older Python — we only support {sha256}
        let tag_end = after_prefix.iter().position(|&b| b == b'}');
        let tag = tag_end.map(|end| String::from_utf8_lossy(&after_prefix[..=end]).into_owned());
        return Err(RpcError::UnsupportedDigest(
            tag.unwrap_or_else(|| "unknown".into()),
        ));
    }

    // message = {sha256} + random_bytes (everything after #CHALLENGE#)
    let message = after_prefix;
    let mut mac = HmacSha256::new_from_slice(authkey)
        .map_err(|e| RpcError::InvalidFormat(format!("HMAC init: {}", e)))?;
    mac.update(message);
    let digest = mac.finalize().into_bytes();

    // Send response: {sha256} + HMAC digest
    let mut response = Vec::with_capacity(HMAC_RESPONSE_LEN);
    response.extend_from_slice(SHA256_DIGEST_TAG);
    response.extend_from_slice(&digest);
    write_message(stream, &response).await?;

    // Read WELCOME or FAILURE
    let reply = read_message(stream).await?;
    if reply == WELCOME {
        Ok(())
    } else {
        Err(RpcError::AuthFailed)
    }
}

/// Full server-side handshake: deliver_challenge then answer_challenge.
///
/// Matches Python's `Listener.accept()` which calls:
/// 1. `deliver_challenge(conn, authkey)` — server authenticates client
/// 2. `answer_challenge(conn, authkey)` — server answers client's challenge
pub(crate) async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    authkey: &[u8; 32],
) -> Result<(), RpcError> {
    deliver_challenge(stream, authkey).await?;
    answer_challenge(stream, authkey).await?;
    Ok(())
}

/// Full client-side handshake: answer_challenge then deliver_challenge.
///
/// Matches Python's `Client()` which calls:
/// 1. `answer_challenge(conn, authkey)` — client answers server's challenge
/// 2. `deliver_challenge(conn, authkey)` — client authenticates server
#[cfg(test)]
pub(crate) async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    authkey: &[u8; 32],
) -> Result<(), RpcError> {
    answer_challenge(stream, authkey).await?;
    deliver_challenge(stream, authkey).await?;
    Ok(())
}

use rand_core::RngCore;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_message_round_trip() {
        let (mut client, mut server) = duplex(1024);
        let data = b"hello world";

        write_message(&mut client, data).await.unwrap();
        let received = read_message(&mut server).await.unwrap();
        assert_eq!(received, data);
    }

    #[tokio::test]
    async fn test_empty_message() {
        let (mut client, mut server) = duplex(1024);
        write_message(&mut client, b"").await.unwrap();
        let received = read_message(&mut server).await.unwrap();
        assert!(received.is_empty());
    }

    #[tokio::test]
    async fn test_handshake_success() {
        let authkey = [0x42u8; 32];
        let (mut client, mut server) = duplex(4096);

        let server_task =
            tokio::spawn(async move { server_handshake(&mut server, &authkey).await });
        let client_task =
            tokio::spawn(async move { client_handshake(&mut client, &authkey).await });

        server_task.await.unwrap().unwrap();
        client_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_handshake_wrong_key() {
        let server_key = [0x42u8; 32];
        let client_key = [0x99u8; 32];
        let (mut client, mut server) = duplex(4096);

        let server_task =
            tokio::spawn(async move { server_handshake(&mut server, &server_key).await });
        let client_task =
            tokio::spawn(async move { client_handshake(&mut client, &client_key).await });

        // At least one side should fail
        let (server_result, client_result) = tokio::join!(server_task, client_task);
        let server_err = server_result.unwrap().is_err();
        let client_err = client_result.unwrap().is_err();
        assert!(
            server_err || client_err,
            "mismatched keys must cause auth failure"
        );
    }

    #[tokio::test]
    async fn test_deliver_challenge_bad_response_length() {
        let authkey = [0x42u8; 32];
        let (mut client, mut server) = duplex(4096);

        // Server sends challenge
        let server_task =
            tokio::spawn(async move { deliver_challenge(&mut server, &authkey).await });

        // Client sends wrong-length response
        let client_task = tokio::spawn(async move {
            let _challenge = read_message(&mut client).await.unwrap();
            write_message(&mut client, b"too short").await.unwrap();
            // Read the FAILURE response
            let reply = read_message(&mut client).await.unwrap();
            assert_eq!(reply, FAILURE);
        });

        let server_result = server_task.await.unwrap();
        assert!(server_result.is_err());
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_full_handshake_then_message() {
        let authkey = [0xABu8; 32];
        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            server_handshake(&mut server, &authkey).await.unwrap();
            // Read a request
            let msg = read_message(&mut server).await.unwrap();
            assert_eq!(msg, b"ping");
            // Send a response
            write_message(&mut server, b"pong").await.unwrap();
        });

        let client_task = tokio::spawn(async move {
            client_handshake(&mut client, &authkey).await.unwrap();
            // Send request
            write_message(&mut client, b"ping").await.unwrap();
            // Read response
            let resp = read_message(&mut client).await.unwrap();
            assert_eq!(resp, b"pong");
        });

        server_task.await.unwrap();
        client_task.await.unwrap();
    }
}
