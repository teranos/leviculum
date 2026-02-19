//! Python-compatible packet_hashlist persistence
//!
//! Both Python and Rust use full 32-byte SHA-256 hashes for packet
//! deduplication. Files are fully compatible in both directions.
//!
//! Python ref: Transport.py:196-203 (load), Transport.py:2955-2977 (save)
//! Format: msgpack array of 32-byte binary values.

use std::collections::BTreeSet;

use crate::error::{Error, Result};
use crate::storage::Storage;

const PACKET_HASHLIST_FILE: &str = "packet_hashlist";

/// Load packet_hashlist from storage.
///
/// Returns a set of 32-byte packet hashes for deduplication.
pub(crate) fn load_packet_hashlist(storage: &Storage) -> BTreeSet<[u8; 32]> {
    let bytes = match storage.read_root(PACKET_HASHLIST_FILE) {
        Ok(b) => b,
        Err(_) => {
            tracing::debug!("No packet_hashlist file found");
            return BTreeSet::new();
        }
    };

    match decode_packet_hashlist(&bytes) {
        Ok(entries) => {
            tracing::info!("Loaded {} packet hashes from storage", entries.len());
            entries
        }
        Err(e) => {
            tracing::warn!("Failed to decode packet_hashlist: {e}");
            BTreeSet::new()
        }
    }
}

/// Save packet_hashlist to storage.
///
/// Writes the 32-byte hashes as a msgpack array, matching the Python format.
pub(crate) fn save_packet_hashlist<'a>(
    storage: &Storage,
    hashes: impl Iterator<Item = &'a [u8; 32]>,
) -> Result<()> {
    let (encoded, count) = encode_packet_hashlist(hashes)?;
    storage.write_root(PACKET_HASHLIST_FILE, &encoded)?;
    tracing::debug!("Saved {count} packet hashes to storage");
    Ok(())
}

/// Decode a packet_hashlist msgpack blob.
fn decode_packet_hashlist(data: &[u8]) -> Result<BTreeSet<[u8; 32]>> {
    let value: rmpv::Value = rmpv::decode::read_value(&mut &data[..])
        .map_err(|e| Error::Serialization(format!("msgpack decode error: {e}")))?;

    let arr = value
        .as_array()
        .ok_or_else(|| Error::Serialization("packet_hashlist: expected array".into()))?;

    let mut entries = BTreeSet::new();
    for item in arr {
        if let Some(bytes) = item.as_slice() {
            if bytes.len() == 32 {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(bytes);
                entries.insert(hash);
            }
        }
    }

    Ok(entries)
}

/// Encode packet hashes as msgpack array of 32-byte binary values.
fn encode_packet_hashlist<'a>(
    hashes: impl Iterator<Item = &'a [u8; 32]>,
) -> Result<(Vec<u8>, usize)> {
    use rmpv::Value;

    let items: Vec<Value> = hashes.map(|h| Value::Binary(h.to_vec())).collect();
    let count = items.len();
    let array = Value::Array(items);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &array)
        .map_err(|e| Error::Serialization(format!("msgpack encode error: {e}")))?;
    Ok((buf, count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_round_trip() {
        let mut cache = BTreeSet::new();
        cache.insert([0xAA; 32]);
        cache.insert([0xBB; 32]);
        cache.insert([0xCC; 32]);

        let (encoded, count) = encode_packet_hashlist(cache.iter()).unwrap();
        assert_eq!(count, 3);
        let decoded = decode_packet_hashlist(&encoded).unwrap();

        assert_eq!(decoded.len(), 3);
        assert!(decoded.contains(&[0xAA; 32]));
        assert!(decoded.contains(&[0xBB; 32]));
        assert!(decoded.contains(&[0xCC; 32]));
    }

    #[test]
    fn test_empty_cache() {
        let cache: BTreeSet<[u8; 32]> = BTreeSet::new();
        let (encoded, count) = encode_packet_hashlist(cache.iter()).unwrap();
        assert_eq!(count, 0);
        let decoded = decode_packet_hashlist(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_save_and_load_via_storage() {
        let path =
            std::env::temp_dir().join(format!("reticulum_test_hashlist_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let storage = Storage::new(&path).unwrap();

        let mut cache = BTreeSet::new();
        cache.insert([0x11; 32]);
        cache.insert([0x22; 32]);

        save_packet_hashlist(&storage, cache.iter()).unwrap();
        let loaded = load_packet_hashlist(&storage);
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains(&[0x11; 32]));

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_python_packet_hashlist_compat() {
        // Read the actual Python rnsd packet_hashlist file if present
        let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
        let Some(home) = home else { return };
        let path = home.join(".reticulum/storage/packet_hashlist");
        if !path.exists() {
            return;
        }

        let bytes = std::fs::read(&path).unwrap();
        let entries = decode_packet_hashlist(&bytes).unwrap();
        assert!(
            !entries.is_empty(),
            "Python packet_hashlist should have entries"
        );

        // Verify all entries are 32-byte hashes
        for hash in &entries {
            assert_eq!(hash.len(), 32);
        }

        // Re-encode and decode to verify round-trip preserves count
        let (re_encoded, _) = encode_packet_hashlist(entries.iter()).unwrap();
        let re_decoded = decode_packet_hashlist(&re_encoded).unwrap();
        assert_eq!(entries.len(), re_decoded.len());
    }

    #[test]
    fn test_skip_non_32byte_entries() {
        // Construct a msgpack array with mixed-length entries
        use rmpv::Value;
        let items = vec![
            Value::Binary(vec![0xAA; 32]), // valid
            Value::Binary(vec![0xBB; 16]), // invalid (too short)
            Value::Binary(vec![0xCC; 32]), // valid
            Value::Integer(42.into()),     // invalid (wrong type)
        ];
        let array = Value::Array(items);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &array).unwrap();

        let decoded = decode_packet_hashlist(&buf).unwrap();
        assert_eq!(decoded.len(), 2, "should skip non-32-byte entries");
    }
}
