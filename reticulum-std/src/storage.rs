//! File-based storage with in-memory runtime state
//!
//! Wraps `MemoryStorage` for all runtime collections (paths, reverses, links,
//! announces, etc.) and adds disk persistence for two Python-compatible
//! collections:
//! - `known_destinations` — msgpack map of identity data
//! - `packet_hashlist` — msgpack array of 32-byte dedup hashes
//!
//! All non-persistent collections live in the inner `MemoryStorage` and are
//! lost on process exit. Persistent data is written by [`Storage::flush()`]
//! (called at shutdown from the driver).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use reticulum_core::constants::TRUNCATED_HASHBYTES;
use reticulum_core::memory_storage::MemoryStorage;
use reticulum_core::traits::Storage as CoreStorage;
use reticulum_core::Identity;

use crate::error::{Error, Result};
use crate::known_destinations::{
    decode_known_destinations, encode_known_destinations, KnownDestEntry, KNOWN_DESTINATIONS_FILE,
    PACKET_HASH_LEN,
};
use crate::packet_hashlist::{
    decode_packet_hashlist, encode_packet_hashlist, PACKET_HASHLIST_FILE,
};

/// Storage manager with in-memory runtime state and file-based persistence.
///
/// All runtime collections (paths, reverse entries, links, announces, receipts,
/// etc.) are delegated to the inner `MemoryStorage`. Two collections are
/// additionally persisted to disk in Python-compatible formats:
/// - known_destinations (identities)
/// - packet_hashlist (dedup hashes)
///
/// The legacy generic API (`load/store/delete/list_keys`) provides raw
/// file-based key-value storage for ratchets.
pub(crate) struct Storage {
    /// Base directory for all storage
    base_path: PathBuf,
    /// In-memory storage for all runtime collections
    inner: MemoryStorage,
    /// Python-compat persistence format for known_destinations.
    /// Loaded from disk at construction, merged with runtime identities
    /// and saved to disk by flush().
    known_dest_entries: BTreeMap<[u8; TRUNCATED_HASHBYTES], KnownDestEntry>,
}

impl Storage {
    /// Create a new storage manager, loading persistent data from disk.
    ///
    /// Loads known_destinations and packet_hashlist from the given path
    /// and feeds them into the inner MemoryStorage for runtime use.
    pub(crate) fn new<P: AsRef<Path>>(base_path: P) -> Result<Self> {
        let base_path = base_path.as_ref().to_path_buf();

        // Create directories if they don't exist
        std::fs::create_dir_all(&base_path)
            .map_err(|e| Error::Storage(format!("Failed to create storage dir: {e}")))?;

        let mut inner = MemoryStorage::with_defaults();

        // Load known_destinations from disk
        let known_dest_entries = match std::fs::read(base_path.join(KNOWN_DESTINATIONS_FILE)) {
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

        // Feed identities into runtime storage
        for (hash, entry) in &known_dest_entries {
            if let Ok(identity) = Identity::from_public_key_bytes(&entry.public_key) {
                CoreStorage::set_identity(&mut inner, *hash, identity);
            }
        }

        // Load packet_hashlist from disk
        match std::fs::read(base_path.join(PACKET_HASHLIST_FILE)) {
            Ok(bytes) => match decode_packet_hashlist(&bytes) {
                Ok(hashes) => {
                    tracing::info!("Loaded {} packet hashes from storage", hashes.len());
                    for hash in hashes {
                        CoreStorage::add_packet_hash(&mut inner, hash);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to decode packet_hashlist: {e}");
                }
            },
            Err(_) => {
                tracing::debug!("No packet_hashlist file found");
            }
        }

        Ok(Self {
            base_path,
            inner,
            known_dest_entries,
        })
    }

    /// Get path for a specific storage category
    pub(crate) fn category_path(&self, category: &str) -> PathBuf {
        self.base_path.join(category)
    }

    /// Ensure a category directory exists
    pub(crate) fn ensure_category(&self, category: &str) -> Result<PathBuf> {
        let path = self.category_path(category);
        std::fs::create_dir_all(&path)
            .map_err(|e| Error::Storage(format!("Failed to create category dir: {e}")))?;
        Ok(path)
    }

    /// Read raw bytes from the storage root (no category subdirectory)
    pub(crate) fn read_root(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.base_path.join(name);
        std::fs::read(&path)
            .map_err(|e| Error::Storage(format!("Failed to read {}: {e}", path.display())))
    }

    /// Write raw bytes to the storage root (atomic via .tmp + rename)
    pub(crate) fn write_root(&self, name: &str, data: &[u8]) -> Result<()> {
        let path = self.base_path.join(name);
        let temp_path = path.with_extension("tmp");
        std::fs::write(&temp_path, data)
            .map_err(|e| Error::Storage(format!("Failed to write temp file: {e}")))?;
        std::fs::rename(&temp_path, &path)
            .map_err(|e| Error::Storage(format!("Failed to rename temp file: {e}")))?;
        Ok(())
    }

    /// Read raw bytes from storage
    pub(crate) fn read_raw(&self, category: &str, name: &str) -> Result<Vec<u8>> {
        let path = self.category_path(category).join(name);
        std::fs::read(&path)
            .map_err(|e| Error::Storage(format!("Failed to read {}: {e}", path.display())))
    }

    /// Write raw bytes to storage
    pub(crate) fn write_raw(&self, category: &str, name: &str, data: &[u8]) -> Result<()> {
        let category_path = self.ensure_category(category)?;
        let path = category_path.join(name);

        // Write to temp file first, then rename (atomic on most systems)
        let temp_path = path.with_extension("tmp");
        std::fs::write(&temp_path, data)
            .map_err(|e| Error::Storage(format!("Failed to write temp file: {e}")))?;
        std::fs::rename(&temp_path, &path)
            .map_err(|e| Error::Storage(format!("Failed to rename temp file: {e}")))?;

        Ok(())
    }

    /// Read msgpack-serialized data
    #[cfg(test)]
    pub(crate) fn read<T: serde::de::DeserializeOwned>(
        &self,
        category: &str,
        name: &str,
    ) -> Result<T> {
        let data = self.read_raw(category, name)?;
        rmp_serde::from_slice(&data)
            .map_err(|e| Error::Serialization(format!("Failed to deserialize: {e}")))
    }

    /// Write msgpack-serialized data
    #[cfg(test)]
    pub(crate) fn write<T: serde::Serialize>(
        &self,
        category: &str,
        name: &str,
        value: &T,
    ) -> Result<()> {
        let data = rmp_serde::to_vec(value)
            .map_err(|e| Error::Serialization(format!("Failed to serialize: {e}")))?;
        self.write_raw(category, name, &data)
    }

    /// Check if a file exists
    #[cfg(test)]
    pub(crate) fn exists(&self, category: &str, name: &str) -> bool {
        self.category_path(category).join(name).exists()
    }

    /// Delete a file
    pub(crate) fn delete(&self, category: &str, name: &str) -> Result<()> {
        let path = self.category_path(category).join(name);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| Error::Storage(format!("Failed to delete {}: {e}", path.display())))?;
        }
        Ok(())
    }

    /// List files in a category
    pub(crate) fn list(&self, category: &str) -> Result<Vec<String>> {
        let path = self.category_path(category);
        if !path.exists() {
            return Ok(Vec::new());
        }

        let entries = std::fs::read_dir(&path)
            .map_err(|e| Error::Storage(format!("Failed to read dir: {e}")))?;

        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| Error::Storage(format!("Failed to read entry: {e}")))?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }

        Ok(names)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

// ─── Storage Trait Implementation ──────────────────────────────────────────
//
// All runtime collection methods delegate to the inner MemoryStorage.
// The legacy generic API (load/store/delete/list_keys) stays file-based
// for ratchet compatibility.

impl reticulum_core::traits::Storage for Storage {
    // ─── Packet Dedup ────────────────────────────────────────────────────
    fn has_packet_hash(&self, hash: &[u8; 32]) -> bool {
        self.inner.has_packet_hash(hash)
    }
    fn add_packet_hash(&mut self, hash: [u8; 32]) {
        self.inner.add_packet_hash(hash)
    }

    // ─── Path Table ──────────────────────────────────────────────────────
    fn get_path(
        &self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&reticulum_core::storage_types::PathEntry> {
        self.inner.get_path(dest_hash)
    }
    fn set_path(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASHBYTES],
        entry: reticulum_core::storage_types::PathEntry,
    ) {
        self.inner.set_path(dest_hash, entry)
    }
    fn remove_path(
        &mut self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<reticulum_core::storage_types::PathEntry> {
        self.inner.remove_path(dest_hash)
    }
    fn path_count(&self) -> usize {
        self.inner.path_count()
    }
    fn expire_paths(&mut self, now_ms: u64) -> Vec<[u8; TRUNCATED_HASHBYTES]> {
        self.inner.expire_paths(now_ms)
    }
    fn earliest_path_expiry(&self) -> Option<u64> {
        self.inner.earliest_path_expiry()
    }

    // ─── Path State ──────────────────────────────────────────────────────
    fn get_path_state(
        &self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<reticulum_core::storage_types::PathState> {
        self.inner.get_path_state(dest_hash)
    }
    fn set_path_state(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASHBYTES],
        state: reticulum_core::storage_types::PathState,
    ) {
        self.inner.set_path_state(dest_hash, state)
    }

    // ─── Reverse Table ───────────────────────────────────────────────────
    fn get_reverse(
        &self,
        hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&reticulum_core::storage_types::ReverseEntry> {
        self.inner.get_reverse(hash)
    }
    fn set_reverse(
        &mut self,
        hash: [u8; TRUNCATED_HASHBYTES],
        entry: reticulum_core::storage_types::ReverseEntry,
    ) {
        self.inner.set_reverse(hash, entry)
    }
    fn remove_reverse(
        &mut self,
        hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<reticulum_core::storage_types::ReverseEntry> {
        self.inner.remove_reverse(hash)
    }

    // ─── Link Table ──────────────────────────────────────────────────────
    fn get_link_entry(
        &self,
        link_id: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&reticulum_core::storage_types::LinkEntry> {
        self.inner.get_link_entry(link_id)
    }
    fn get_link_entry_mut(
        &mut self,
        link_id: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&mut reticulum_core::storage_types::LinkEntry> {
        self.inner.get_link_entry_mut(link_id)
    }
    fn set_link_entry(
        &mut self,
        link_id: [u8; TRUNCATED_HASHBYTES],
        entry: reticulum_core::storage_types::LinkEntry,
    ) {
        self.inner.set_link_entry(link_id, entry)
    }
    fn remove_link_entry(
        &mut self,
        link_id: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<reticulum_core::storage_types::LinkEntry> {
        self.inner.remove_link_entry(link_id)
    }

    // ─── Announce Table ──────────────────────────────────────────────────
    fn get_announce(
        &self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&reticulum_core::storage_types::AnnounceEntry> {
        self.inner.get_announce(dest_hash)
    }
    fn get_announce_mut(
        &mut self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&mut reticulum_core::storage_types::AnnounceEntry> {
        self.inner.get_announce_mut(dest_hash)
    }
    fn set_announce(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASHBYTES],
        entry: reticulum_core::storage_types::AnnounceEntry,
    ) {
        self.inner.set_announce(dest_hash, entry)
    }
    fn remove_announce(
        &mut self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<reticulum_core::storage_types::AnnounceEntry> {
        self.inner.remove_announce(dest_hash)
    }
    fn announce_keys(&self) -> Vec<[u8; TRUNCATED_HASHBYTES]> {
        self.inner.announce_keys()
    }

    // ─── Announce Cache ──────────────────────────────────────────────────
    fn get_announce_cache(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<&Vec<u8>> {
        self.inner.get_announce_cache(dest_hash)
    }
    fn set_announce_cache(&mut self, dest_hash: [u8; TRUNCATED_HASHBYTES], raw: Vec<u8>) {
        self.inner.set_announce_cache(dest_hash, raw)
    }

    // ─── Announce Rate ───────────────────────────────────────────────────
    fn get_announce_rate(
        &self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&reticulum_core::storage_types::AnnounceRateEntry> {
        self.inner.get_announce_rate(dest_hash)
    }
    fn set_announce_rate(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASHBYTES],
        entry: reticulum_core::storage_types::AnnounceRateEntry,
    ) {
        self.inner.set_announce_rate(dest_hash, entry)
    }

    // ─── Receipts ────────────────────────────────────────────────────────
    fn get_receipt(
        &self,
        hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&reticulum_core::storage_types::PacketReceipt> {
        self.inner.get_receipt(hash)
    }
    fn set_receipt(
        &mut self,
        hash: [u8; TRUNCATED_HASHBYTES],
        receipt: reticulum_core::storage_types::PacketReceipt,
    ) {
        self.inner.set_receipt(hash, receipt)
    }
    fn remove_receipt(
        &mut self,
        hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<reticulum_core::storage_types::PacketReceipt> {
        self.inner.remove_receipt(hash)
    }

    // ─── Path Requests ───────────────────────────────────────────────────
    fn get_path_request_time(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<u64> {
        self.inner.get_path_request_time(dest_hash)
    }
    fn set_path_request_time(&mut self, dest_hash: [u8; TRUNCATED_HASHBYTES], time_ms: u64) {
        self.inner.set_path_request_time(dest_hash, time_ms)
    }
    fn check_path_request_tag(&mut self, tag: &[u8; 32]) -> bool {
        self.inner.check_path_request_tag(tag)
    }

    // ─── Known Identities ────────────────────────────────────────────────
    fn get_identity(
        &self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&reticulum_core::Identity> {
        self.inner.get_identity(dest_hash)
    }
    fn set_identity(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASHBYTES],
        identity: reticulum_core::Identity,
    ) {
        self.inner.set_identity(dest_hash, identity)
    }

    // ─── Cleanup ─────────────────────────────────────────────────────────
    fn expire_reverses(&mut self, now_ms: u64, timeout_ms: u64) -> usize {
        self.inner.expire_reverses(now_ms, timeout_ms)
    }
    fn remove_reverse_entries_for_interface(&mut self, iface_index: usize) {
        self.inner.remove_reverse_entries_for_interface(iface_index)
    }
    fn expire_receipts(
        &mut self,
        now_ms: u64,
    ) -> Vec<reticulum_core::storage_types::PacketReceipt> {
        self.inner.expire_receipts(now_ms)
    }
    fn expire_link_entries(
        &mut self,
        now_ms: u64,
        link_timeout_ms: u64,
    ) -> Vec<(
        [u8; TRUNCATED_HASHBYTES],
        reticulum_core::storage_types::LinkEntry,
    )> {
        self.inner.expire_link_entries(now_ms, link_timeout_ms)
    }
    fn clean_stale_path_metadata(&mut self) {
        self.inner.clean_stale_path_metadata()
    }
    fn remove_link_entries_for_interface(
        &mut self,
        iface_index: usize,
    ) -> Vec<(
        [u8; TRUNCATED_HASHBYTES],
        reticulum_core::storage_types::LinkEntry,
    )> {
        self.inner.remove_link_entries_for_interface(iface_index)
    }
    fn remove_paths_for_interface(&mut self, iface_index: usize) -> Vec<[u8; TRUNCATED_HASHBYTES]> {
        self.inner.remove_paths_for_interface(iface_index)
    }

    // ─── Deadlines ───────────────────────────────────────────────────────
    fn earliest_receipt_deadline(&self) -> Option<u64> {
        self.inner.earliest_receipt_deadline()
    }
    fn earliest_link_deadline(&self, link_timeout_ms: u64) -> Option<u64> {
        self.inner.earliest_link_deadline(link_timeout_ms)
    }

    // ─── Flush (persist to disk) ─────────────────────────────────────────

    fn flush(&mut self) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        // 1. Merge runtime identities into known_dest_entries.
        //    New identities (not already loaded from disk) get a minimal entry.
        for (hash, identity) in self.inner.known_identity_iter() {
            self.known_dest_entries
                .entry(*hash)
                .or_insert_with(|| KnownDestEntry {
                    timestamp,
                    packet_hash: vec![0u8; PACKET_HASH_LEN],
                    public_key: identity.public_key_bytes(),
                    app_data: None,
                });
        }

        // 2. Merge with on-disk entries (preserving entries added by other
        //    processes, matching Python behavior).
        let mut merged = self.known_dest_entries.clone();
        if let Ok(bytes) = std::fs::read(self.base_path.join(KNOWN_DESTINATIONS_FILE)) {
            if let Ok(disk_entries) = decode_known_destinations(&bytes) {
                for (hash, entry) in disk_entries {
                    merged.entry(hash).or_insert(entry);
                }
            }
        }

        // 3. Write known_destinations
        match encode_known_destinations(&merged) {
            Ok(encoded) => {
                if let Err(e) = self.write_root(KNOWN_DESTINATIONS_FILE, &encoded) {
                    tracing::warn!("Failed to save known_destinations: {e}");
                } else {
                    tracing::debug!("Saved {} known destinations to storage", merged.len());
                }
            }
            Err(e) => {
                tracing::warn!("Failed to encode known_destinations: {e}");
            }
        }

        // 4. Write packet_hashlist
        match encode_packet_hashlist(self.inner.packet_hash_iter()) {
            Ok((encoded, count)) => {
                if let Err(e) = self.write_root(PACKET_HASHLIST_FILE, &encoded) {
                    tracing::warn!("Failed to save packet_hashlist: {e}");
                } else {
                    tracing::debug!("Saved {count} packet hashes to storage");
                }
            }
            Err(e) => {
                tracing::warn!("Failed to encode packet_hashlist: {e}");
            }
        }
    }

    // ─── Legacy Generic API (for ratchets — always file-based) ───────────
    fn load(&self, category: &str, key: &[u8]) -> Option<Vec<u8>> {
        let name = hex_encode(key);
        self.read_raw(category, &name).ok()
    }

    fn store(
        &mut self,
        category: &str,
        key: &[u8],
        value: &[u8],
    ) -> std::result::Result<(), reticulum_core::traits::StorageError> {
        let name = hex_encode(key);
        self.write_raw(category, &name, value)
            .map_err(|_| reticulum_core::traits::StorageError::IoError)
    }

    fn delete(
        &mut self,
        category: &str,
        key: &[u8],
    ) -> std::result::Result<(), reticulum_core::traits::StorageError> {
        let name = hex_encode(key);
        Storage::delete(self, category, &name)
            .map_err(|_| reticulum_core::traits::StorageError::NotFound)
    }

    fn list_keys(&self, category: &str) -> Vec<Vec<u8>> {
        self.list(category)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|s| hex_decode(&s))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    fn temp_storage() -> Storage {
        let path = temp_dir().join(format!("reticulum_test_{}", std::process::id()));
        Storage::new(&path).unwrap()
    }

    #[test]
    fn test_raw_storage() {
        let storage = temp_storage();

        storage.write_raw("test", "data.bin", b"hello").unwrap();
        let data = storage.read_raw("test", "data.bin").unwrap();
        assert_eq!(data, b"hello");

        // Cleanup
        storage.delete("test", "data.bin").unwrap();
    }

    #[test]
    fn test_serialized_storage() {
        let storage = temp_storage();

        let value = vec![1u32, 2, 3, 4, 5];
        storage.write("test", "numbers.mp", &value).unwrap();

        let loaded: Vec<u32> = storage.read("test", "numbers.mp").unwrap();
        assert_eq!(loaded, value);

        // Cleanup
        storage.delete("test", "numbers.mp").unwrap();
    }

    #[test]
    fn test_exists() {
        let storage = temp_storage();

        assert!(!storage.exists("test", "nonexistent"));

        storage.write_raw("test", "exists.bin", b"data").unwrap();
        assert!(storage.exists("test", "exists.bin"));

        // Cleanup
        storage.delete("test", "exists.bin").unwrap();
    }

    #[test]
    fn test_root_storage() {
        let storage = temp_storage();

        storage.write_root("root_data.bin", b"root_hello").unwrap();
        let data = storage.read_root("root_data.bin").unwrap();
        assert_eq!(data, b"root_hello");

        // Verify file is directly in base path, not in a subdirectory
        let expected_path = storage.base_path.join("root_data.bin");
        assert!(expected_path.exists());

        // Cleanup
        std::fs::remove_file(expected_path).unwrap();
    }

    #[test]
    fn test_read_root_missing_file() {
        let storage = temp_storage();
        let result = storage.read_root("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_core_storage_legacy_trait() {
        use reticulum_core::traits::Storage as CoreStorage;

        let mut storage = temp_storage();
        let key = [0x01, 0x02, 0x03];

        // Store via legacy trait
        CoreStorage::store(&mut storage, "core_test", &key, b"trait_value").unwrap();

        // Load via legacy trait
        let data = CoreStorage::load(&storage, "core_test", &key);
        assert_eq!(data, Some(b"trait_value".to_vec()));

        // List keys via legacy trait
        let keys = CoreStorage::list_keys(&storage, "core_test");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], key.to_vec());

        // Delete via legacy trait
        CoreStorage::delete(&mut storage, "core_test", &key).unwrap();
        assert!(CoreStorage::load(&storage, "core_test", &key).is_none());
    }

    #[test]
    fn test_runtime_storage_delegates_to_inner() {
        use reticulum_core::traits::Storage as CoreStorage;

        let mut storage = temp_storage();

        // Verify packet hash dedup works (was no-op before this commit)
        let hash = [0x42u8; 32];
        assert!(!CoreStorage::has_packet_hash(&storage, &hash));
        CoreStorage::add_packet_hash(&mut storage, hash);
        assert!(CoreStorage::has_packet_hash(&storage, &hash));

        // Verify path table works
        let dest = [0x01u8; TRUNCATED_HASHBYTES];
        assert!(CoreStorage::get_path(&storage, &dest).is_none());
        CoreStorage::set_path(
            &mut storage,
            dest,
            reticulum_core::storage_types::PathEntry {
                hops: 2,
                expires_ms: 5000,
                interface_index: 0,
                random_blobs: Vec::new(),
                next_hop: None,
            },
        );
        assert_eq!(CoreStorage::get_path(&storage, &dest).unwrap().hops, 2);
        assert_eq!(CoreStorage::path_count(&storage), 1);

        // Verify identity storage works
        let id = Identity::generate(&mut rand_core::OsRng);
        let id_hash = [0x02u8; TRUNCATED_HASHBYTES];
        CoreStorage::set_identity(&mut storage, id_hash, id);
        assert!(CoreStorage::get_identity(&storage, &id_hash).is_some());
    }

    #[test]
    fn test_flush_persists_identities() {
        use reticulum_core::traits::Storage as CoreStorage;

        let path = temp_dir().join(format!("reticulum_test_flush_id_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);

        // Create storage, add identity, flush
        {
            let mut storage = Storage::new(&path).unwrap();
            let id = Identity::generate(&mut rand_core::OsRng);
            CoreStorage::set_identity(&mut storage, [0xAA; TRUNCATED_HASHBYTES], id);
            CoreStorage::flush(&mut storage);
        }

        // Re-open storage — identity should be loaded from disk
        {
            let storage = Storage::new(&path).unwrap();
            assert!(
                CoreStorage::get_identity(&storage, &[0xAA; TRUNCATED_HASHBYTES]).is_some(),
                "identity should persist across restarts"
            );
        }

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_flush_persists_packet_hashes() {
        use reticulum_core::traits::Storage as CoreStorage;

        let path = temp_dir().join(format!("reticulum_test_flush_hash_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);

        let hash = [0xBB; 32];

        // Create storage, add hash, flush
        {
            let mut storage = Storage::new(&path).unwrap();
            CoreStorage::add_packet_hash(&mut storage, hash);
            CoreStorage::flush(&mut storage);
        }

        // Re-open storage — hash should be loaded from disk
        {
            let storage = Storage::new(&path).unwrap();
            assert!(
                CoreStorage::has_packet_hash(&storage, &hash),
                "packet hash should persist across restarts"
            );
        }

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_flush_merges_with_disk() {
        use reticulum_core::traits::Storage as CoreStorage;

        let path = temp_dir().join(format!("reticulum_test_flush_merge_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);

        // Create storage with identity A, flush
        let id_a = Identity::generate(&mut rand_core::OsRng);
        {
            let mut storage = Storage::new(&path).unwrap();
            CoreStorage::set_identity(&mut storage, [0x01; TRUNCATED_HASHBYTES], id_a);
            CoreStorage::flush(&mut storage);
        }

        // Create new storage, add identity B (not A), flush
        // A should be preserved from disk
        let id_b = Identity::generate(&mut rand_core::OsRng);
        {
            let mut storage = Storage::new(&path).unwrap();
            // A was loaded from disk
            assert!(CoreStorage::get_identity(&storage, &[0x01; TRUNCATED_HASHBYTES]).is_some());
            CoreStorage::set_identity(&mut storage, [0x02; TRUNCATED_HASHBYTES], id_b);
            CoreStorage::flush(&mut storage);
        }

        // Re-open: both A and B should be present
        {
            let storage = Storage::new(&path).unwrap();
            assert!(CoreStorage::get_identity(&storage, &[0x01; TRUNCATED_HASHBYTES]).is_some());
            assert!(CoreStorage::get_identity(&storage, &[0x02; TRUNCATED_HASHBYTES]).is_some());
        }

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_new_storage_loads_persistent_data() {
        let path = temp_dir().join(format!("reticulum_test_autoload_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);

        // Manually write a known_destinations file and packet_hashlist
        std::fs::create_dir_all(&path).unwrap();

        // Write a known_destinations file with one entry
        let id = Identity::generate(&mut rand_core::OsRng);
        let mut entries = BTreeMap::new();
        entries.insert(
            [0xCC; TRUNCATED_HASHBYTES],
            KnownDestEntry {
                timestamp: 1708300000.0,
                packet_hash: vec![0; 32],
                public_key: id.public_key_bytes(),
                app_data: None,
            },
        );
        let encoded = encode_known_destinations(&entries).unwrap();
        std::fs::write(path.join(KNOWN_DESTINATIONS_FILE), &encoded).unwrap();

        // Write a packet_hashlist with one hash
        let hash = [0xDD; 32];
        let hashes = [hash];
        let (encoded, _) = encode_packet_hashlist(hashes.iter()).unwrap();
        std::fs::write(path.join(PACKET_HASHLIST_FILE), &encoded).unwrap();

        // Create storage — should load both automatically
        let storage = Storage::new(&path).unwrap();

        use reticulum_core::traits::Storage as CoreStorage;
        assert!(
            CoreStorage::get_identity(&storage, &[0xCC; TRUNCATED_HASHBYTES]).is_some(),
            "should auto-load identity from known_destinations"
        );
        assert!(
            CoreStorage::has_packet_hash(&storage, &hash),
            "should auto-load packet hash from packet_hashlist"
        );

        let _ = std::fs::remove_dir_all(&path);
    }
}
