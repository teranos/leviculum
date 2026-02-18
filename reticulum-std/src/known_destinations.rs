//! Python-compatible known_destinations persistence
//!
//! Format: msgpack map {dest_hash(16 bytes) → [timestamp(f64), packet_hash(32 bytes),
//! public_key(64 bytes), app_data(bytes or nil)]}
//!
//! Python ref: Identity.py:93-103 (remember), Identity.py:163-216 (save),
//! Identity.py:220-236 (load)

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use reticulum_core::DestinationHash;
use reticulum_core::Identity;

use crate::error::{Error, Result};
use crate::storage::Storage;

const KNOWN_DESTINATIONS_FILE: &str = "known_destinations";
const DEST_HASH_LEN: usize = 16;
const PUBLIC_KEY_LEN: usize = 64;
const PACKET_HASH_LEN: usize = 32;

/// A single entry in the known_destinations store.
///
/// Mirrors Python: `[timestamp, packet_hash, public_key, app_data]`
struct KnownDestEntry {
    /// Seconds since epoch (Python `time.time()`)
    timestamp: f64,
    /// Original announce packet hash (32 bytes)
    packet_hash: Vec<u8>,
    /// Combined public key: X25519(32) | Ed25519(32) = 64 bytes
    public_key: [u8; PUBLIC_KEY_LEN],
    /// Optional application data from the announce
    app_data: Option<Vec<u8>>,
}

/// Python-compatible known_destinations persistence store.
///
/// Maintains the full Python format in memory so round-tripping the file
/// preserves all fields (timestamp, packet_hash, app_data) even though
/// NodeCore only needs the Identity (public_key) part.
pub(crate) struct KnownDestinationsStore {
    entries: BTreeMap<[u8; DEST_HASH_LEN], KnownDestEntry>,
}

impl KnownDestinationsStore {
    /// Load known_destinations from storage, or return an empty store on error.
    pub(crate) fn load(storage: &Storage) -> Self {
        let entries = match storage.read_root(KNOWN_DESTINATIONS_FILE) {
            Ok(bytes) => match decode_known_destinations(&bytes) {
                Ok(entries) => {
                    tracing::info!("Loaded {} known destinations from storage", entries.len());
                    entries
                }
                Err(e) => {
                    tracing::warn!("Failed to decode known_destinations: {e}");
                    BTreeMap::new()
                }
            },
            Err(_) => {
                tracing::debug!("No known_destinations file found, starting empty");
                BTreeMap::new()
            }
        };
        Self { entries }
    }

    /// Save to storage (atomic write). Merges with on-disk data first
    /// (preserving entries added by other processes, matching Python behavior).
    pub(crate) fn save(&self, storage: &Storage) -> Result<()> {
        // Merge: load existing file, add any entries not in our in-memory store
        let mut merged = self.entries.clone();
        if let Ok(bytes) = storage.read_root(KNOWN_DESTINATIONS_FILE) {
            if let Ok(disk_entries) = decode_known_destinations(&bytes) {
                for (hash, entry) in disk_entries {
                    merged.entry(hash).or_insert(entry);
                }
            }
        }

        let encoded = encode_known_destinations(&merged)?;
        storage.write_root(KNOWN_DESTINATIONS_FILE, &encoded)?;
        tracing::debug!("Saved {} known destinations to storage", merged.len());
        Ok(())
    }

    /// Iterate identities extracted from the store.
    ///
    /// Yields `(DestinationHash, Identity)` for each entry whose public key
    /// is valid. Invalid entries are silently skipped.
    pub(crate) fn identities(&self) -> impl Iterator<Item = (DestinationHash, Identity)> + '_ {
        self.entries.iter().filter_map(|(hash, entry)| {
            let identity = Identity::from_public_key_bytes(&entry.public_key).ok()?;
            Some((DestinationHash::new(*hash), identity))
        })
    }

    /// Number of entries in the store.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Update or insert an entry from an announce.
    pub(crate) fn update_from_announce(
        &mut self,
        dest_hash: &[u8; DEST_HASH_LEN],
        public_key: &[u8; PUBLIC_KEY_LEN],
        app_data: &[u8],
    ) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        self.entries.insert(
            *dest_hash,
            KnownDestEntry {
                timestamp,
                // We don't have the original packet hash in the event path;
                // store zeros (Python only uses this for display/debugging)
                packet_hash: vec![0u8; PACKET_HASH_LEN],
                public_key: *public_key,
                app_data: if app_data.is_empty() {
                    None
                } else {
                    Some(app_data.to_vec())
                },
            },
        );
    }

    /// Merge identities from NodeCore's in-memory cache into the store.
    ///
    /// Adds entries for identities that aren't already tracked. This captures
    /// identities learned at runtime that weren't loaded from disk.
    pub(crate) fn merge_from_core<'a>(
        &mut self,
        iter: impl Iterator<Item = (&'a DestinationHash, &'a Identity)>,
    ) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        for (dest_hash, identity) in iter {
            let key = dest_hash.into_bytes();
            self.entries.entry(key).or_insert_with(|| KnownDestEntry {
                timestamp,
                packet_hash: vec![0u8; PACKET_HASH_LEN],
                public_key: identity.public_key_bytes(),
                app_data: None,
            });
        }
    }
}

impl Clone for KnownDestEntry {
    fn clone(&self) -> Self {
        Self {
            timestamp: self.timestamp,
            packet_hash: self.packet_hash.clone(),
            public_key: self.public_key,
            app_data: self.app_data.clone(),
        }
    }
}

/// Decode a known_destinations msgpack blob into entries.
///
/// Python format: msgpack map where keys are 16-byte binary (dest hashes)
/// and values are arrays: [f64, bin32, bin64, bin_or_nil].
fn decode_known_destinations(data: &[u8]) -> Result<BTreeMap<[u8; DEST_HASH_LEN], KnownDestEntry>> {
    let value: rmpv::Value = rmpv::decode::read_value(&mut &data[..])
        .map_err(|e| Error::Serialization(format!("msgpack decode error: {e}")))?;

    let map = value
        .as_map()
        .ok_or_else(|| Error::Serialization("known_destinations: expected map".into()))?;

    let mut entries = BTreeMap::new();
    for (key, val) in map {
        // Key: 16-byte binary
        let key_bytes = match key.as_slice() {
            Some(b) if b.len() == DEST_HASH_LEN => {
                let mut arr = [0u8; DEST_HASH_LEN];
                arr.copy_from_slice(b);
                arr
            }
            _ => continue, // Skip invalid keys (Python does the same length check)
        };

        // Value: array of 4 elements
        let arr = match val.as_array() {
            Some(a) if a.len() == 4 => a,
            _ => continue,
        };

        // [0] timestamp: f64
        let timestamp = match &arr[0] {
            rmpv::Value::F64(f) => *f,
            rmpv::Value::F32(f) => *f as f64,
            rmpv::Value::Integer(i) => i.as_f64().unwrap_or(0.0),
            _ => continue,
        };

        // [1] packet_hash: binary (typically 32 bytes)
        let packet_hash = match arr[1].as_slice() {
            Some(b) => b.to_vec(),
            None => vec![0u8; PACKET_HASH_LEN],
        };

        // [2] public_key: binary (64 bytes)
        let public_key = match arr[2].as_slice() {
            Some(b) if b.len() == PUBLIC_KEY_LEN => {
                let mut arr = [0u8; PUBLIC_KEY_LEN];
                arr.copy_from_slice(b);
                arr
            }
            _ => continue,
        };

        // [3] app_data: binary or nil
        let app_data = match &arr[3] {
            rmpv::Value::Nil => None,
            rmpv::Value::Binary(b) => {
                if b.is_empty() {
                    None
                } else {
                    Some(b.clone())
                }
            }
            _ => None,
        };

        entries.insert(
            key_bytes,
            KnownDestEntry {
                timestamp,
                packet_hash,
                public_key,
                app_data,
            },
        );
    }

    Ok(entries)
}

/// Encode entries into Python-compatible msgpack format.
fn encode_known_destinations(
    entries: &BTreeMap<[u8; DEST_HASH_LEN], KnownDestEntry>,
) -> Result<Vec<u8>> {
    use rmpv::Value;

    // Build a msgpack map: Vec<(Value, Value)>
    let pairs: Vec<(Value, Value)> = entries
        .iter()
        .map(|(hash, entry)| {
            let key = Value::Binary(hash.to_vec());
            let val = Value::Array(vec![
                Value::F64(entry.timestamp),
                Value::Binary(entry.packet_hash.clone()),
                Value::Binary(entry.public_key.to_vec()),
                match &entry.app_data {
                    Some(data) => Value::Binary(data.clone()),
                    None => Value::Nil,
                },
            ]);
            (key, val)
        })
        .collect();

    let map = Value::Map(pairs);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &map)
        .map_err(|e| Error::Serialization(format!("msgpack encode error: {e}")))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_store() {
        let store = KnownDestinationsStore {
            entries: BTreeMap::new(),
        };
        assert_eq!(store.len(), 0);
        assert_eq!(store.identities().count(), 0);
    }

    #[test]
    fn test_encode_decode_round_trip() {
        let mut entries = BTreeMap::new();
        let hash = [0xAA; DEST_HASH_LEN];
        let identity = Identity::generate(&mut rand_core::OsRng);
        entries.insert(
            hash,
            KnownDestEntry {
                timestamp: 1708300000.0,
                packet_hash: vec![0xBB; PACKET_HASH_LEN],
                public_key: identity.public_key_bytes(),
                app_data: Some(b"test_app".to_vec()),
            },
        );

        let encoded = encode_known_destinations(&entries).unwrap();
        let decoded = decode_known_destinations(&encoded).unwrap();

        assert_eq!(decoded.len(), 1);
        let entry = &decoded[&hash];
        assert!((entry.timestamp - 1708300000.0).abs() < f64::EPSILON);
        assert_eq!(entry.packet_hash, vec![0xBB; PACKET_HASH_LEN]);
        assert_eq!(entry.public_key, identity.public_key_bytes());
        assert_eq!(entry.app_data, Some(b"test_app".to_vec()));
    }

    #[test]
    fn test_encode_decode_nil_app_data() {
        let mut entries = BTreeMap::new();
        let hash = [0xCC; DEST_HASH_LEN];
        let identity = Identity::generate(&mut rand_core::OsRng);
        entries.insert(
            hash,
            KnownDestEntry {
                timestamp: 1708300000.0,
                packet_hash: vec![0; PACKET_HASH_LEN],
                public_key: identity.public_key_bytes(),
                app_data: None,
            },
        );

        let encoded = encode_known_destinations(&entries).unwrap();
        let decoded = decode_known_destinations(&encoded).unwrap();
        assert_eq!(decoded[&hash].app_data, None);
    }

    #[test]
    fn test_extract_identities() {
        let mut entries = BTreeMap::new();
        let id1 = Identity::generate(&mut rand_core::OsRng);
        let id2 = Identity::generate(&mut rand_core::OsRng);
        let hash1 = [0x01; DEST_HASH_LEN];
        let hash2 = [0x02; DEST_HASH_LEN];

        entries.insert(
            hash1,
            KnownDestEntry {
                timestamp: 0.0,
                packet_hash: vec![0; PACKET_HASH_LEN],
                public_key: id1.public_key_bytes(),
                app_data: None,
            },
        );
        entries.insert(
            hash2,
            KnownDestEntry {
                timestamp: 0.0,
                packet_hash: vec![0; PACKET_HASH_LEN],
                public_key: id2.public_key_bytes(),
                app_data: None,
            },
        );

        let store = KnownDestinationsStore { entries };
        let identities: Vec<_> = store.identities().collect();
        assert_eq!(identities.len(), 2);
    }

    #[test]
    fn test_update_from_announce() {
        let mut store = KnownDestinationsStore {
            entries: BTreeMap::new(),
        };
        let id = Identity::generate(&mut rand_core::OsRng);
        let hash = [0xDD; DEST_HASH_LEN];
        let pubkey = id.public_key_bytes();

        store.update_from_announce(&hash, &pubkey, b"my_app");
        assert_eq!(store.len(), 1);
        assert!(store.entries[&hash].timestamp > 0.0);
        assert_eq!(store.entries[&hash].app_data, Some(b"my_app".to_vec()));
    }

    #[test]
    fn test_merge_from_core() {
        let mut store = KnownDestinationsStore {
            entries: BTreeMap::new(),
        };

        // Pre-existing entry
        let existing_id = Identity::generate(&mut rand_core::OsRng);
        let existing_hash = [0x01; DEST_HASH_LEN];
        store.update_from_announce(&existing_hash, &existing_id.public_key_bytes(), b"");

        // New identity from core
        let new_id = Identity::generate(&mut rand_core::OsRng);
        let new_hash = DestinationHash::new([0x02; DEST_HASH_LEN]);
        let core_identities: Vec<(DestinationHash, Identity)> = vec![(new_hash, new_id)];
        let refs: Vec<(&DestinationHash, &Identity)> =
            core_identities.iter().map(|(h, i)| (h, i)).collect();

        store.merge_from_core(refs.into_iter());
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_merge_from_core_no_overwrite() {
        let mut store = KnownDestinationsStore {
            entries: BTreeMap::new(),
        };

        let id = Identity::generate(&mut rand_core::OsRng);
        let hash = [0x01; DEST_HASH_LEN];
        store.update_from_announce(&hash, &id.public_key_bytes(), b"original_app");

        // Merge with the same hash from core — should NOT overwrite
        let dest_hash = DestinationHash::new(hash);
        let core_entries = vec![(dest_hash, id)];
        let refs: Vec<(&DestinationHash, &Identity)> =
            core_entries.iter().map(|(h, i)| (h, i)).collect();

        store.merge_from_core(refs.into_iter());
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.entries[&hash].app_data,
            Some(b"original_app".to_vec()),
            "merge should not overwrite existing entries"
        );
    }

    #[test]
    fn test_python_known_destinations_compat() {
        // Read the actual Python rnsd known_destinations file if present
        let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
        let Some(home) = home else { return };
        let path = home.join(".reticulum/storage/known_destinations");
        if !path.exists() {
            return;
        }

        let bytes = std::fs::read(&path).unwrap();
        let entries = decode_known_destinations(&bytes).unwrap();
        assert!(
            !entries.is_empty(),
            "Python known_destinations should have entries"
        );

        // Verify all entries have valid structure
        for (hash, entry) in &entries {
            assert_eq!(hash.len(), DEST_HASH_LEN);
            assert_eq!(entry.public_key.len(), PUBLIC_KEY_LEN);
            assert!(entry.timestamp > 0.0);
        }

        // Verify we can extract at least some valid identities
        let store = KnownDestinationsStore { entries };
        let identities: Vec<_> = store.identities().collect();
        assert!(
            !identities.is_empty(),
            "should extract at least one valid identity from Python file"
        );

        // Re-encode and decode to verify round-trip
        let re_encoded = encode_known_destinations(&store.entries).unwrap();
        let re_decoded = decode_known_destinations(&re_encoded).unwrap();
        assert_eq!(
            store.entries.len(),
            re_decoded.len(),
            "round-trip should preserve entry count"
        );
    }

    #[test]
    fn test_save_and_load_via_storage() {
        let path = std::env::temp_dir().join(format!("reticulum_test_kd_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let storage = Storage::new(&path).unwrap();

        let mut store = KnownDestinationsStore {
            entries: BTreeMap::new(),
        };
        let id = Identity::generate(&mut rand_core::OsRng);
        let hash = [0xEE; DEST_HASH_LEN];
        store.update_from_announce(&hash, &id.public_key_bytes(), b"test");
        store.save(&storage).unwrap();

        let loaded = KnownDestinationsStore::load(&storage);
        assert_eq!(loaded.len(), 1);
        let identities: Vec<_> = loaded.identities().collect();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].0.into_bytes(), hash);

        let _ = std::fs::remove_dir_all(&path);
    }
}
