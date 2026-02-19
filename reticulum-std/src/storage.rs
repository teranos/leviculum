//! File-based storage for persistent data

use std::path::{Path, PathBuf};

use reticulum_core::constants::TRUNCATED_HASHBYTES;

use crate::error::{Error, Result};

/// Storage manager for persistent data
pub(crate) struct Storage {
    /// Base directory for all storage
    base_path: PathBuf,
}

impl Storage {
    /// Create a new storage manager
    pub(crate) fn new<P: AsRef<Path>>(base_path: P) -> Result<Self> {
        let base_path = base_path.as_ref().to_path_buf();

        // Create directories if they don't exist
        std::fs::create_dir_all(&base_path)
            .map_err(|e| Error::Storage(format!("Failed to create storage dir: {e}")))?;

        Ok(Self { base_path })
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

impl reticulum_core::traits::Storage for Storage {
    // ─── Packet Dedup (no-op until commit 1) ────────────────────────────
    fn has_packet_hash(&self, _hash: &[u8; 32]) -> bool {
        false
    }
    fn add_packet_hash(&mut self, _hash: [u8; 32]) {}

    // ─── Path Table (no-op until commit 7) ──────────────────────────────
    fn get_path(
        &self,
        _dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&reticulum_core::storage_types::PathEntry> {
        None
    }
    fn set_path(
        &mut self,
        _dest_hash: [u8; TRUNCATED_HASHBYTES],
        _entry: reticulum_core::storage_types::PathEntry,
    ) {
    }
    fn remove_path(
        &mut self,
        _dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<reticulum_core::storage_types::PathEntry> {
        None
    }
    fn path_count(&self) -> usize {
        0
    }
    fn expire_paths(&mut self, _now_ms: u64) -> Vec<[u8; TRUNCATED_HASHBYTES]> {
        Vec::new()
    }
    fn earliest_path_expiry(&self) -> Option<u64> {
        None
    }

    // ─── Path State (no-op until commit 7) ──────────────────────────────
    fn get_path_state(
        &self,
        _dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<reticulum_core::storage_types::PathState> {
        None
    }
    fn set_path_state(
        &mut self,
        _dest_hash: [u8; TRUNCATED_HASHBYTES],
        _state: reticulum_core::storage_types::PathState,
    ) {
    }

    // ─── Reverse Table (no-op until commit 4) ───────────────────────────
    fn get_reverse(
        &self,
        _hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&reticulum_core::storage_types::ReverseEntry> {
        None
    }
    fn set_reverse(
        &mut self,
        _hash: [u8; TRUNCATED_HASHBYTES],
        _entry: reticulum_core::storage_types::ReverseEntry,
    ) {
    }
    fn remove_reverse(
        &mut self,
        _hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<reticulum_core::storage_types::ReverseEntry> {
        None
    }

    // ─── Link Table (no-op until commit 8) ──────────────────────────────
    fn get_link_entry(
        &self,
        _link_id: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&reticulum_core::storage_types::LinkEntry> {
        None
    }
    fn get_link_entry_mut(
        &mut self,
        _link_id: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&mut reticulum_core::storage_types::LinkEntry> {
        None
    }
    fn set_link_entry(
        &mut self,
        _link_id: [u8; TRUNCATED_HASHBYTES],
        _entry: reticulum_core::storage_types::LinkEntry,
    ) {
    }
    fn remove_link_entry(
        &mut self,
        _link_id: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<reticulum_core::storage_types::LinkEntry> {
        None
    }

    // ─── Announce Table (no-op until commit 9) ──────────────────────────
    fn get_announce(
        &self,
        _dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&reticulum_core::storage_types::AnnounceEntry> {
        None
    }
    fn get_announce_mut(
        &mut self,
        _dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&mut reticulum_core::storage_types::AnnounceEntry> {
        None
    }
    fn set_announce(
        &mut self,
        _dest_hash: [u8; TRUNCATED_HASHBYTES],
        _entry: reticulum_core::storage_types::AnnounceEntry,
    ) {
    }
    fn remove_announce(
        &mut self,
        _dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<reticulum_core::storage_types::AnnounceEntry> {
        None
    }
    fn announce_keys(&self) -> Vec<[u8; TRUNCATED_HASHBYTES]> {
        Vec::new()
    }

    // ─── Announce Cache (no-op until commit 6) ──────────────────────────
    fn get_announce_cache(&self, _dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<&Vec<u8>> {
        None
    }
    fn set_announce_cache(&mut self, _dest_hash: [u8; TRUNCATED_HASHBYTES], _raw: Vec<u8>) {}

    // ─── Announce Rate (no-op until commit 3) ───────────────────────────
    fn get_announce_rate(
        &self,
        _dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&reticulum_core::storage_types::AnnounceRateEntry> {
        None
    }
    fn set_announce_rate(
        &mut self,
        _dest_hash: [u8; TRUNCATED_HASHBYTES],
        _entry: reticulum_core::storage_types::AnnounceRateEntry,
    ) {
    }

    // ─── Receipts (no-op until commit 5) ────────────────────────────────
    fn get_receipt(
        &self,
        _hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&reticulum_core::storage_types::PacketReceipt> {
        None
    }
    fn set_receipt(
        &mut self,
        _hash: [u8; TRUNCATED_HASHBYTES],
        _receipt: reticulum_core::storage_types::PacketReceipt,
    ) {
    }
    fn remove_receipt(
        &mut self,
        _hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<reticulum_core::storage_types::PacketReceipt> {
        None
    }

    // ─── Path Requests (no-op until commit 2) ───────────────────────────
    fn get_path_request_time(&self, _dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<u64> {
        None
    }
    fn set_path_request_time(&mut self, _dest_hash: [u8; TRUNCATED_HASHBYTES], _time_ms: u64) {}
    fn check_path_request_tag(&mut self, _tag: &[u8; 32]) -> bool {
        false
    }

    // ─── Known Identities (no-op until commit 10) ───────────────────────
    fn get_identity(
        &self,
        _dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&reticulum_core::Identity> {
        None
    }
    fn set_identity(
        &mut self,
        _dest_hash: [u8; TRUNCATED_HASHBYTES],
        _identity: reticulum_core::Identity,
    ) {
    }

    // ─── Cleanup (no-op until respective commits) ───────────────────────
    fn expire_reverses(&mut self, _now_ms: u64, _timeout_ms: u64) -> usize {
        0
    }
    fn expire_receipts(
        &mut self,
        _now_ms: u64,
    ) -> Vec<reticulum_core::storage_types::PacketReceipt> {
        Vec::new()
    }
    fn expire_link_entries(
        &mut self,
        _now_ms: u64,
        _link_timeout_ms: u64,
    ) -> Vec<(
        [u8; TRUNCATED_HASHBYTES],
        reticulum_core::storage_types::LinkEntry,
    )> {
        Vec::new()
    }
    fn clean_stale_path_metadata(&mut self) {}
    fn remove_link_entries_for_interface(
        &mut self,
        _iface_index: usize,
    ) -> Vec<(
        [u8; TRUNCATED_HASHBYTES],
        reticulum_core::storage_types::LinkEntry,
    )> {
        Vec::new()
    }

    // ─── Deadlines (no-op until respective commits) ─────────────────────
    fn earliest_receipt_deadline(&self) -> Option<u64> {
        None
    }
    fn earliest_link_deadline(&self, _link_timeout_ms: u64) -> Option<u64> {
        None
    }

    // ─── Legacy Generic API (for ratchets — always active) ──────────────
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
}
