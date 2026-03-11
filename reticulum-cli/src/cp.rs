//! rncp-compatible file transfer over Reticulum
//!
//! Shared module used by both `lrns cp` (standalone node) and `lrncp`
//! (shared instance client).

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use reticulum_std::driver::ReticulumNode;
use reticulum_std::{
    Destination, DestinationHash, DestinationType, Direction, Identity, NodeEvent,
};

fn err(msg: impl std::fmt::Display) -> Box<dyn std::error::Error> {
    msg.to_string().into()
}

/// Load an identity from disk, or generate a new one and save it.
pub fn load_or_generate_identity(path: &Path) -> Result<Identity, Box<dyn std::error::Error>> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        Identity::from_private_key_bytes(&bytes).map_err(|e| err(format!("bad identity file: {e}")))
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        use rand_core::OsRng;
        let id = Identity::generate(&mut OsRng);
        let pk = id
            .private_key_bytes()
            .map_err(|e| err(format!("identity error: {e}")))?;
        std::fs::write(path, pk)?;
        Ok(id)
    }
}

pub async fn run_send(
    node: &ReticulumNode,
    events: &mut mpsc::Receiver<NodeEvent>,
    file_path: &str,
    destination: &str,
    timeout_secs: f64,
    verbose: u8,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = verbose; // reserved for future use

    // Parse destination hash
    let dest_bytes_vec = crate::hex_decode(destination).map_err(err)?;
    if dest_bytes_vec.len() != 16 {
        return Err(err(format!(
            "destination must be 32 hex characters (16 bytes), got {}",
            dest_bytes_vec.len()
        )));
    }
    let mut dest_bytes = [0u8; 16];
    dest_bytes.copy_from_slice(&dest_bytes_vec);

    // Read file
    let file_path = PathBuf::from(file_path);
    if !file_path.exists() {
        return Err(err(format!("file not found: {}", file_path.display())));
    }
    let data = std::fs::read(&file_path)?;
    let filename = file_path
        .file_name()
        .ok_or_else(|| err("cannot extract filename"))?
        .to_string_lossy();

    // Encode metadata matching Python's umsgpack.packb({"name": b"..."})
    let metadata_bytes = encode_metadata(filename.as_bytes());

    // Wait for path
    let dest_hash = DestinationHash::new(dest_bytes);
    let deadline = Instant::now() + Duration::from_secs_f64(timeout_secs);
    if !node.has_path(&dest_hash) {
        if !quiet {
            eprintln!("Path to {} requested", destination);
        }
        node.request_path(&dest_hash).await?;
        while !node.has_path(&dest_hash) {
            if Instant::now() > deadline {
                return Err(err(format!("Could not find a path to {}", destination)));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    // Get signing key from identity
    let identity = node.get_identity(&dest_hash).ok_or_else(|| {
        err(format!(
            "Identity for {} not found (no announce received)",
            destination
        ))
    })?;
    let pk = identity.public_key_bytes();
    let mut signing_key = [0u8; 32];
    signing_key.copy_from_slice(&pk[32..64]);

    // Connect and wait for LinkEstablished
    if !quiet {
        eprintln!("Establishing link with {}...", destination);
    }
    let _stream = node.connect(&dest_hash, &signing_key).await?;
    let link_id = loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Some(NodeEvent::LinkEstablished { link_id, .. }) => break link_id,
                    Some(NodeEvent::LinkClosed { .. }) => {
                        return Err(err(format!(
                            "Could not establish link to {}", destination)));
                    }
                    None => {
                        return Err(err("Event channel closed"));
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep_until(
                tokio::time::Instant::from_std(deadline)) => {
                return Err(err(format!(
                    "Could not establish link to {}", destination)));
            }
        }
    };

    // Send resource
    if !quiet {
        eprintln!("Sending {} ({} bytes)...", file_path.display(), data.len());
    }
    node.send_resource(&link_id, &data, Some(&metadata_bytes))
        .await?;

    // Wait for completion
    let transfer_deadline = Instant::now() + Duration::from_secs(300);
    loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Some(NodeEvent::ResourceCompleted { is_sender: true, .. }) => {
                        if !quiet {
                            eprintln!("{} copied to {}",
                                file_path.display(), destination);
                        }
                        break;
                    }
                    Some(NodeEvent::ResourceFailed {
                        is_sender: true, error, ..
                    }) => {
                        return Err(err(format!(
                            "The transfer failed: {:?}", error)));
                    }
                    Some(NodeEvent::LinkClosed { .. }) => {
                        return Err(err("The transfer failed (link closed)"));
                    }
                    None => return Err(err("Event channel closed")),
                    _ => {}
                }
            }
            _ = tokio::time::sleep_until(
                tokio::time::Instant::from_std(transfer_deadline)) => {
                return Err(err("The transfer timed out"));
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_listen(
    node: &ReticulumNode,
    events: &mut mpsc::Receiver<NodeEvent>,
    identity: Identity,
    save_dir: Option<PathBuf>,
    overwrite: bool,
    no_auth: bool,
    announce_interval: i64,
    verbose: u8,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Register destination and announce
    let mut dest = Destination::new(
        Some(identity),
        Direction::In,
        DestinationType::Single,
        "rncp",
        &["receive"],
    )
    .map_err(|e| err(format!("destination error: {e}")))?;
    dest.set_accepts_links(true);
    let dest_hash = *dest.hash();
    node.register_destination(dest);

    eprintln!(
        "lrncp listening on {}",
        crate::hex_encode(dest_hash.as_bytes())
    );
    if !no_auth {
        eprintln!("Warning: --no-auth is required (link.identify() not yet implemented)");
    }

    if announce_interval >= 0 {
        node.announce_destination(&dest_hash, None).await?;
    }

    // Announce timer for periodic re-announce
    let mut announce_timer = if announce_interval > 0 {
        let mut interval = tokio::time::interval(Duration::from_secs(announce_interval as u64));
        interval.tick().await; // consume the immediate first tick
        Some(interval)
    } else {
        None
    };

    // Multi-segment accumulation buffer
    let mut segment_buffer: Vec<u8> = Vec::new();
    let mut segment_metadata: Option<Vec<u8>> = None;

    // Event loop
    loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Some(NodeEvent::LinkRequest { link_id, .. }) => {
                        node.accept_link(&link_id).await?;
                        if verbose > 0 {
                            eprintln!("Incoming link request accepted");
                        }
                    }
                    Some(NodeEvent::LinkEstablished {
                        link_id, is_initiator: false, ..
                    }) => {
                        node.set_resource_strategy(
                            &link_id,
                            reticulum_core::resource::ResourceStrategy::AcceptAll,
                        )?;
                        if verbose > 0 {
                            eprintln!("Link established");
                        }
                    }
                    Some(NodeEvent::ResourceCompleted {
                        data, metadata, is_sender: false,
                        segment_index, total_segments, ..
                    }) => {
                        // Accumulate segment data
                        segment_buffer.extend_from_slice(&data);
                        if metadata.is_some() {
                            segment_metadata = metadata;
                        }

                        if segment_index == total_segments {
                            // Last segment — save the complete file
                            if let Err(e) = save_received_file(
                                &segment_buffer,
                                segment_metadata.as_deref(),
                                save_dir.as_deref(),
                                overwrite,
                                quiet,
                            ) {
                                eprintln!("Error saving file: {e}");
                            }
                            segment_buffer.clear();
                            segment_metadata = None;
                        } else if verbose > 0 {
                            eprintln!(
                                "Segment {}/{} received ({} bytes)",
                                segment_index, total_segments, data.len()
                            );
                        }
                    }
                    Some(NodeEvent::ResourceFailed { error, .. }) => {
                        if verbose > 0 {
                            eprintln!("Transfer failed: {:?}", error);
                        }
                    }
                    Some(NodeEvent::LinkClosed { .. }) => {
                        if verbose > 0 {
                            eprintln!("Link closed");
                        }
                    }
                    None => break,
                    _ => {}
                }
            }
            _ = async { announce_timer.as_mut().unwrap().tick().await },
                if announce_timer.is_some() => {
                let _ = node.announce_destination(&dest_hash, None).await;
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("Shutting down");
                break;
            }
        }
    }

    Ok(())
}

fn save_received_file(
    data: &[u8],
    metadata: Option<&[u8]>,
    save_dir: Option<&Path>,
    overwrite: bool,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let filename = metadata
        .and_then(extract_filename_from_metadata)
        .unwrap_or_else(|| "received_file".to_string());

    let base_dir = save_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let mut full_path = base_dir.join(&filename);
    if !overwrite {
        let mut counter = 0u32;
        while full_path.exists() {
            counter += 1;
            full_path = base_dir.join(format!("{}.{}", filename, counter));
        }
    }

    std::fs::write(&full_path, data)?;
    if !quiet {
        eprintln!("Received: {} ({} bytes)", full_path.display(), data.len());
    }
    Ok(())
}

/// Encode metadata as msgpack: {"name": bin(filename_bytes)}
///
/// Matches Python's `umsgpack.packb({"name": filename.encode("utf-8")})`.
fn encode_metadata(filename: &[u8]) -> Vec<u8> {
    let metadata_value = rmpv::Value::Map(vec![(
        rmpv::Value::String("name".into()),
        rmpv::Value::Binary(filename.to_vec()),
    )]);
    let mut metadata_bytes = Vec::new();
    rmpv::encode::write_value(&mut metadata_bytes, &metadata_value)
        .expect("msgpack encoding to Vec cannot fail");
    metadata_bytes
}

/// Extract filename from msgpack metadata: {"name": bin(filename_bytes)}
fn extract_filename_from_metadata(metadata_bytes: &[u8]) -> Option<String> {
    let mut cursor = Cursor::new(metadata_bytes);
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    let map = match value {
        rmpv::Value::Map(map) => map,
        _ => return None,
    };
    for (key, val) in &map {
        let key_str = match key {
            rmpv::Value::String(s) => s.as_str()?,
            _ => continue,
        };
        if key_str == "name" {
            let name_bytes = match val {
                rmpv::Value::Binary(b) => b,
                _ => continue,
            };
            let s = String::from_utf8(name_bytes.clone()).ok()?;
            // Path traversal protection: basename only
            let basename = Path::new(&s).file_name()?.to_string_lossy().into_owned();
            if basename.is_empty() {
                return None;
            }
            return Some(basename);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_encoding() {
        let encoded = encode_metadata(b"myfile.txt");
        // fixmap(1)=0x81, fixstr(4)=0xa4, "name", bin8(10)=0xc4 0x0a, "myfile.txt"
        let expected: Vec<u8> = vec![
            0x81, // fixmap, 1 entry
            0xa4, // fixstr, length 4
            b'n', b'a', b'm', b'e', // "name"
            0xc4, 0x0a, // bin8, length 10
            b'm', b'y', b'f', b'i', b'l', b'e', b'.', b't', b'x', b't', // "myfile.txt"
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_filename_extraction() {
        let encoded = encode_metadata(b"hello.txt");
        let name = extract_filename_from_metadata(&encoded);
        assert_eq!(name, Some("hello.txt".to_string()));
    }

    #[test]
    fn test_filename_extraction_path_traversal() {
        let encoded = encode_metadata(b"../../etc/passwd");
        let name = extract_filename_from_metadata(&encoded);
        assert_eq!(name, Some("passwd".to_string()));
    }

    #[test]
    fn test_filename_fallback_empty() {
        assert_eq!(extract_filename_from_metadata(&[]), None);
    }

    #[test]
    fn test_filename_fallback_corrupt() {
        assert_eq!(extract_filename_from_metadata(&[0xff, 0xfe]), None);
    }

    #[test]
    fn test_filename_fallback_wrong_key() {
        // {"foo": bin("bar")}
        let value = rmpv::Value::Map(vec![(
            rmpv::Value::String("foo".into()),
            rmpv::Value::Binary(b"bar".to_vec()),
        )]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &value).unwrap();
        assert_eq!(extract_filename_from_metadata(&buf), None);
    }

    #[test]
    fn test_filename_fallback_wrong_type() {
        // {"name": "string_not_binary"}
        let value = rmpv::Value::Map(vec![(
            rmpv::Value::String("name".into()),
            rmpv::Value::String("string_not_binary".into()),
        )]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &value).unwrap();
        assert_eq!(extract_filename_from_metadata(&buf), None);
    }
}
