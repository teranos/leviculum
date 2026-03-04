//! File-based storage with in-memory runtime state
//!
//! Wraps `MemoryStorage` for all runtime collections (paths, reverses, links,
//! announces, etc.) and adds disk persistence for four Python-compatible
//! collections:
//! - `known_destinations` — msgpack map of identity data (flush-on-shutdown)
//! - `packet_hashlist` — msgpack array of 32-byte dedup hashes (flush-on-shutdown)
//! - `ratchets/{hex_hash}` — receiver-side known ratchets (write-through)
//! - `ratchetkeys/{hex_hash}` — sender-side ratchet private keys (write-through)
//!
//! All non-persistent collections live in the inner `MemoryStorage` and are
//! lost on process exit. Flush-on-shutdown data is written by [`Storage::flush()`]
//! (called at shutdown from the driver). Ratchet data uses write-through
//! persistence (written immediately on each update).

use std::collections::{BTreeMap, HashSet};
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
/// Default packet hash capacity for FileStorage (100k entries).
/// Two-generation rotation: each generation holds up to cap/2 entries.
/// At 32 bytes/entry × 1.5x HashSet overhead ≈ 4.8 MB max.
const FILE_STORAGE_PACKET_HASH_CAP: usize = 100_000;

/// Directory for receiver-side known ratchets (one file per dest hash).
const RATCHETS_DIR: &str = "ratchets";

/// Directory for sender-side ratchet private keys (one file per dest hash).
const RATCHETKEYS_DIR: &str = "ratchetkeys";

pub(crate) struct Storage {
    /// Base directory for all storage
    base_path: PathBuf,
    /// In-memory storage for all runtime collections (except packet_cache)
    inner: MemoryStorage,
    /// Python-compat persistence format for known_destinations.
    /// Loaded from disk at construction, merged with runtime identities
    /// and saved to disk by flush().
    known_dest_entries: BTreeMap<[u8; TRUNCATED_HASHBYTES], KnownDestEntry>,
    /// Current generation of packet hashes (HashSet for lower overhead than BTreeSet)
    packet_cache: HashSet<[u8; 32]>,
    /// Previous generation (rotated out when current exceeds half cap)
    packet_cache_prev: HashSet<[u8; 32]>,
    /// Maximum total entries across both generations
    packet_hash_cap: usize,
    /// True when add_packet_hash() has been called since last flush.
    packet_hashes_dirty: bool,
    /// True when set_identity() has been called since last flush.
    identities_dirty: bool,
    /// Wall-clock milliseconds at monotonic epoch (process start).
    /// Used to convert between core's monotonic `now_ms` and Python's
    /// `time.time()` (wall-clock seconds) for on-disk ratchet timestamps.
    mono_offset_ms: u64,
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

        // Load packet_hashlist from disk into own HashSet (not inner MemoryStorage).
        // All hashes load into packet_cache regardless of cap — the cap is only
        // enforced in add_packet_hash(), so an oversized list converges naturally.
        let packet_cache = match std::fs::read(base_path.join(PACKET_HASHLIST_FILE)) {
            Ok(bytes) => match decode_packet_hashlist(&bytes) {
                Ok(hashes) => {
                    tracing::info!("Loaded {} packet hashes from storage", hashes.len());
                    hashes.into_iter().collect()
                }
                Err(e) => {
                    tracing::warn!("Failed to decode packet_hashlist: {e}");
                    HashSet::new()
                }
            },
            Err(_) => {
                tracing::debug!("No packet_hashlist file found");
                HashSet::new()
            }
        };

        let mono_offset_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut storage = Self {
            base_path,
            inner,
            known_dest_entries,
            packet_cache,
            packet_cache_prev: HashSet::new(),
            packet_hash_cap: FILE_STORAGE_PACKET_HASH_CAP,
            packet_hashes_dirty: false,
            identities_dirty: false,
            mono_offset_ms,
        };

        // Load known ratchets from disk (receiver-side)
        storage.load_known_ratchets_from_disk();

        // Load dest ratchet keys from disk (sender-side)
        storage.load_dest_ratchet_keys_from_disk();

        Ok(storage)
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
        atomic_write(&self.base_path.join(name), data)
    }

    /// Read raw bytes from storage
    #[cfg(test)]
    pub(crate) fn read_raw(&self, category: &str, name: &str) -> Result<Vec<u8>> {
        let path = self.category_path(category).join(name);
        std::fs::read(&path)
            .map_err(|e| Error::Storage(format!("Failed to read {}: {e}", path.display())))
    }

    /// Write raw bytes to storage (atomic via .tmp + rename)
    pub(crate) fn write_raw(&self, category: &str, name: &str, data: &[u8]) -> Result<()> {
        let category_path = self.ensure_category(category)?;
        atomic_write(&category_path.join(name), data)
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

    // ─── Ratchet disk persistence ─────────────────────────────────────────

    /// Load receiver-side known ratchets from `{base}/ratchets/`.
    fn load_known_ratchets_from_disk(&mut self) {
        let dir = self.base_path.join(RATCHETS_DIR);
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => return, // directory doesn't exist yet
        };

        let mut loaded = 0usize;
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            // Skip temp files
            if name.ends_with(".tmp") || name.ends_with(".out") {
                continue;
            }
            let Some(hash_bytes) = hex_decode(&name) else {
                continue;
            };
            if hash_bytes.len() != TRUNCATED_HASHBYTES {
                continue;
            }
            let data = match std::fs::read(entry.path()) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("Failed to read ratchet file {name}: {e}");
                    continue;
                }
            };
            let Some((ratchet_pub, received_secs)) = decode_known_ratchet(&data) else {
                tracing::warn!("Corrupted ratchet file {name}, deleting");
                let _ = std::fs::remove_file(entry.path());
                continue;
            };

            let mut dest_hash = [0u8; TRUNCATED_HASHBYTES];
            dest_hash.copy_from_slice(&hash_bytes);
            let received_ms = wallclock_secs_to_mono_ms(received_secs, self.mono_offset_ms);
            self.inner
                .remember_known_ratchet(dest_hash, ratchet_pub, received_ms);
            loaded += 1;
        }

        if loaded > 0 {
            tracing::info!("Loaded {loaded} known ratchets from storage");
        }
    }

    /// Load sender-side ratchet keys from `{base}/ratchetkeys/`.
    fn load_dest_ratchet_keys_from_disk(&mut self) {
        let dir = self.base_path.join(RATCHETKEYS_DIR);
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        let mut loaded = 0usize;
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            if name.ends_with(".tmp") {
                continue;
            }
            let Some(hash_bytes) = hex_decode(&name) else {
                continue;
            };
            if hash_bytes.len() != TRUNCATED_HASHBYTES {
                continue;
            }
            let data = match std::fs::read(entry.path()) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("Failed to read ratchet keys file {name}: {e}");
                    continue;
                }
            };
            if data.is_empty() {
                tracing::warn!("Empty ratchet keys file {name}, deleting");
                let _ = std::fs::remove_file(entry.path());
                continue;
            }

            let mut dest_hash = [0u8; TRUNCATED_HASHBYTES];
            dest_hash.copy_from_slice(&hash_bytes);
            CoreStorage::store_dest_ratchet_keys(&mut self.inner, dest_hash, data);
            loaded += 1;
        }

        if loaded > 0 {
            tracing::info!("Loaded {loaded} dest ratchet key sets from storage");
        }
    }
}

// ─── Known ratchet file format (Python-compatible msgpack) ──────────────────
//
// Path: {storagepath}/ratchets/{hex_dest_hash}
// Format: umsgpack.packb({"ratchet": bytes(32), "received": float(seconds)})

fn encode_known_ratchet(ratchet_pub: &[u8; 32], received_secs: f64) -> Vec<u8> {
    let map = rmpv::Value::Map(vec![
        (
            rmpv::Value::String("ratchet".into()),
            rmpv::Value::Binary(ratchet_pub.to_vec()),
        ),
        (
            rmpv::Value::String("received".into()),
            rmpv::Value::F64(received_secs),
        ),
    ]);
    let mut buf = Vec::new();
    // rmpv encode only fails on I/O errors; Vec never fails
    rmpv::encode::write_value(&mut buf, &map).expect("Vec write cannot fail");
    buf
}

fn decode_known_ratchet(data: &[u8]) -> Option<([u8; 32], f64)> {
    let value = rmpv::decode::read_value(&mut &data[..]).ok()?;
    let map = value.as_map()?;

    let mut ratchet: Option<[u8; 32]> = None;
    let mut received: Option<f64> = None;

    for (k, v) in map {
        let key_str = k.as_str()?;
        match key_str {
            "ratchet" => {
                let bytes = v.as_slice()?;
                if bytes.len() != 32 {
                    return None;
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                ratchet = Some(arr);
            }
            "received" => {
                received = Some(v.as_f64()?);
            }
            _ => {} // ignore unknown keys
        }
    }

    Some((ratchet?, received?))
}

/// Convert monotonic milliseconds to wall-clock seconds (for disk storage).
fn mono_to_wallclock_secs(mono_ms: u64, mono_offset_ms: u64) -> f64 {
    mono_offset_ms.saturating_add(mono_ms) as f64 / 1000.0
}

/// Convert wall-clock seconds to monotonic milliseconds (for loading from disk).
fn wallclock_secs_to_mono_ms(secs: f64, mono_offset_ms: u64) -> u64 {
    let wallclock_ms = (secs * 1000.0) as u64;
    wallclock_ms.saturating_sub(mono_offset_ms)
}

/// Atomic write: write to .tmp then rename into place.
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let temp_path = path.with_extension("tmp");
    std::fs::write(&temp_path, data)
        .map_err(|e| Error::Storage(format!("Failed to write temp file: {e}")))?;
    std::fs::rename(&temp_path, path)
        .map_err(|e| Error::Storage(format!("Failed to rename temp file: {e}")))?;
    Ok(())
}

/// Current Unix timestamp in seconds (f64), matching Python `time.time()`.
fn unix_timestamp_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
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
    // ─── Packet Dedup (own HashSet, not inner MemoryStorage) ─────────────
    fn has_packet_hash(&self, hash: &[u8; 32]) -> bool {
        self.packet_cache.contains(hash) || self.packet_cache_prev.contains(hash)
    }
    fn add_packet_hash(&mut self, hash: [u8; 32]) {
        self.packet_cache.insert(hash);
        if self.packet_cache.len() > self.packet_hash_cap / 2 {
            std::mem::swap(&mut self.packet_cache, &mut self.packet_cache_prev);
            self.packet_cache.clear();
        }
        self.packet_hashes_dirty = true;
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
    fn path_entries(
        &self,
    ) -> Vec<(
        [u8; TRUNCATED_HASHBYTES],
        reticulum_core::storage_types::PathEntry,
    )> {
        self.inner.path_entries()
    }
    fn announce_rate_entries(
        &self,
    ) -> Vec<(
        [u8; TRUNCATED_HASHBYTES],
        reticulum_core::storage_types::AnnounceRateEntry,
    )> {
        self.inner.announce_rate_entries()
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
        self.inner.set_identity(dest_hash, identity);
        self.identities_dirty = true;
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
    fn clean_announce_cache(
        &mut self,
        local_destinations: &std::collections::BTreeSet<[u8; TRUNCATED_HASHBYTES]>,
    ) {
        self.inner.clean_announce_cache(local_destinations)
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
        if !self.identities_dirty && !self.packet_hashes_dirty {
            tracing::debug!("Flush skipped — nothing dirty");
            return;
        }

        // 1. Write known_destinations (only if identities changed)
        if self.identities_dirty {
            let timestamp = unix_timestamp_secs();

            // Merge runtime identities into known_dest_entries.
            // New identities get a minimal entry; existing entries get their
            // timestamp and public_key refreshed (the runtime version was just
            // validated from a live announce, so it takes precedence over the
            // disk version). app_data and packet_hash are preserved — they
            // come from the original announce and are not available here.
            for (hash, identity) in self.inner.known_identity_iter() {
                self.known_dest_entries
                    .entry(*hash)
                    .and_modify(|e| {
                        e.timestamp = timestamp;
                        e.public_key = identity.public_key_bytes();
                    })
                    .or_insert_with(|| KnownDestEntry {
                        timestamp,
                        packet_hash: vec![0u8; PACKET_HASH_LEN],
                        public_key: identity.public_key_bytes(),
                        app_data: None,
                    });
            }

            // Merge with on-disk entries (preserving entries added by other
            // processes, matching Python behavior).
            let mut merged = self.known_dest_entries.clone();
            if let Ok(bytes) = std::fs::read(self.base_path.join(KNOWN_DESTINATIONS_FILE)) {
                if let Ok(disk_entries) = decode_known_destinations(&bytes) {
                    for (hash, entry) in disk_entries {
                        merged.entry(hash).or_insert(entry);
                    }
                }
            }

            match encode_known_destinations(&merged) {
                Ok(encoded) => {
                    if let Err(e) = self.write_root(KNOWN_DESTINATIONS_FILE, &encoded) {
                        tracing::error!("Failed to save known_destinations: {e}");
                    } else {
                        self.identities_dirty = false;
                        tracing::debug!("Saved {} known destinations to storage", merged.len());
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to encode known_destinations: {e}");
                }
            }
        }

        // 2. Write packet_hashlist (only if hashes changed)
        if self.packet_hashes_dirty {
            match encode_packet_hashlist(
                self.packet_cache
                    .iter()
                    .chain(self.packet_cache_prev.iter()),
            ) {
                Ok((encoded, count)) => {
                    if let Err(e) = self.write_root(PACKET_HASHLIST_FILE, &encoded) {
                        tracing::error!("Failed to save packet_hashlist: {e}");
                    } else {
                        self.packet_hashes_dirty = false;
                        tracing::debug!("Saved {count} packet hashes to storage");
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to encode packet_hashlist: {e}");
                }
            }
        }
    }

    // ─── Diagnostics ──────────────────────────────────────────────────────
    fn diagnostic_dump(&self) -> (String, u64) {
        use std::fmt::Write;
        let mut s = String::new();
        let mut total = 0u64;

        // packet_cache: HashSet<[u8; 32]> — 1.5x overhead
        let n = self.packet_cache.len();
        let raw = (n * 32) as u64;
        let est = raw * 3 / 2;
        total += est;
        let _ = writeln!(
            s,
            "packet_cache: {} entries, raw {} bytes, estimated {} bytes (HashSet 1.5x)",
            n, raw, est
        );

        // packet_cache_prev: HashSet<[u8; 32]> — 1.5x
        let n = self.packet_cache_prev.len();
        let raw = (n * 32) as u64;
        let est = raw * 3 / 2;
        total += est;
        let _ = writeln!(
            s,
            "packet_cache_prev: {} entries, raw {} bytes, estimated {} bytes (HashSet 1.5x)",
            n, raw, est
        );

        // Delegate remaining collections to inner MemoryStorage
        let (s2, total2) = self.inner.diagnostic_dump_non_packet_cache();
        s.push_str(&s2);
        total += total2;

        (s, total)
    }

    // ─── Known Ratchets (write-through to disk) ────────────────────────
    fn get_known_ratchet(
        &self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<[u8; reticulum_core::constants::RATCHET_SIZE]> {
        self.inner.get_known_ratchet(dest_hash)
    }
    fn remember_known_ratchet(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASHBYTES],
        ratchet: [u8; reticulum_core::constants::RATCHET_SIZE],
        received_at_ms: u64,
    ) {
        self.inner
            .remember_known_ratchet(dest_hash, ratchet, received_at_ms);

        // Write-through to disk
        let hex_name = hex_encode(&dest_hash);
        let received_secs = mono_to_wallclock_secs(received_at_ms, self.mono_offset_ms);
        let data = encode_known_ratchet(&ratchet, received_secs);
        if let Err(e) = self.write_raw(RATCHETS_DIR, &hex_name, &data) {
            tracing::warn!("Failed to persist known ratchet for {hex_name}: {e}");
        }
    }
    fn known_ratchet_count(&self) -> usize {
        self.inner.known_ratchet_count()
    }
    fn expire_known_ratchets(&mut self, now_ms: u64, expiry_ms: u64) -> usize {
        // Collect hashes that will be expired (before memory expiry removes them)
        let expired_hashes: Vec<[u8; TRUNCATED_HASHBYTES]> = self
            .inner
            .known_ratchet_iter()
            .filter(|(_, (_, received_at))| now_ms.saturating_sub(*received_at) >= expiry_ms)
            .map(|(hash, _)| *hash)
            .collect();

        let count = self.inner.expire_known_ratchets(now_ms, expiry_ms);

        // Delete corresponding files from disk
        for hash in &expired_hashes {
            let hex_name = hex_encode(hash);
            if let Err(e) = self.delete(RATCHETS_DIR, &hex_name) {
                tracing::warn!("Failed to delete expired ratchet file {hex_name}: {e}");
            }
        }

        count
    }

    // ─── Local Client Destinations ──────────────────────────────────────
    fn add_local_client_dest(
        &mut self,
        iface_id: usize,
        dest_hash: [u8; TRUNCATED_HASHBYTES],
    ) -> bool {
        self.inner.add_local_client_dest(iface_id, dest_hash)
    }
    fn remove_local_client_dests(&mut self, iface_id: usize) {
        self.inner.remove_local_client_dests(iface_id)
    }
    fn has_local_client_dest(
        &self,
        iface_id: usize,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> bool {
        self.inner.has_local_client_dest(iface_id, dest_hash)
    }

    // ─── Local Client Known Destinations ────────────────────────────────
    fn set_local_client_known_dest(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASHBYTES],
        last_seen_ms: u64,
    ) {
        self.inner
            .set_local_client_known_dest(dest_hash, last_seen_ms)
    }
    fn has_local_client_known_dest(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> bool {
        self.inner.has_local_client_known_dest(dest_hash)
    }
    fn local_client_known_dest_hashes(&self) -> Vec<[u8; TRUNCATED_HASHBYTES]> {
        self.inner.local_client_known_dest_hashes()
    }
    fn expire_local_client_known_dests(&mut self, now_ms: u64, expiry_ms: u64) -> usize {
        self.inner
            .expire_local_client_known_dests(now_ms, expiry_ms)
    }

    // ─── Discovery Path Requests ───────────────────────────────────────
    fn set_discovery_path_request(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASHBYTES],
        requesting_interface: usize,
        timeout_ms: u64,
    ) {
        self.inner
            .set_discovery_path_request(dest_hash, requesting_interface, timeout_ms);
    }

    fn get_discovery_path_request(
        &self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<(usize, u64)> {
        self.inner.get_discovery_path_request(dest_hash)
    }

    fn remove_discovery_path_request(&mut self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) {
        self.inner.remove_discovery_path_request(dest_hash);
    }

    fn expire_discovery_path_requests(&mut self, now_ms: u64) -> usize {
        self.inner.expire_discovery_path_requests(now_ms)
    }

    fn discovery_path_request_dest_hashes(&self) -> Vec<[u8; TRUNCATED_HASHBYTES]> {
        self.inner.discovery_path_request_dest_hashes()
    }

    // ─── Sender-Side Ratchet Keys (write-through to disk) ──────────────
    fn store_dest_ratchet_keys(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASHBYTES],
        serialized: Vec<u8>,
    ) {
        // Write-through to disk first (before moving serialized into inner)
        let hex_name = hex_encode(&dest_hash);
        if let Err(e) = self.write_raw(RATCHETKEYS_DIR, &hex_name, &serialized) {
            tracing::warn!("Failed to persist ratchet keys for {hex_name}: {e}");
        }
        self.inner.store_dest_ratchet_keys(dest_hash, serialized)
    }
    fn load_dest_ratchet_keys(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<Vec<u8>> {
        self.inner.load_dest_ratchet_keys(dest_hash)
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

    #[test]
    fn test_flush_updates_timestamp_on_existing_entry() {
        use reticulum_core::traits::Storage as CoreStorage;

        let path = temp_dir().join(format!("reticulum_test_flush_ts_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);

        let dest_hash = [0xEE; TRUNCATED_HASHBYTES];
        let id = Identity::generate(&mut rand_core::OsRng);
        let app_data = Some(b"test_app_data".to_vec());

        // Create storage, seed a known_dest_entry with old timestamp and app_data,
        // add the identity to runtime, flush
        {
            let mut storage = Storage::new(&path).unwrap();

            // Manually insert an old entry with app_data (simulates a previous flush
            // or disk load)
            storage.known_dest_entries.insert(
                dest_hash,
                KnownDestEntry {
                    timestamp: 1000.0,
                    packet_hash: vec![0xAB; PACKET_HASH_LEN],
                    public_key: id.public_key_bytes(),
                    app_data: app_data.clone(),
                },
            );

            // Add the same identity to runtime storage (simulates a fresh announce)
            CoreStorage::set_identity(&mut storage, dest_hash, id);

            // Flush — should update timestamp but preserve app_data and packet_hash
            CoreStorage::flush(&mut storage);
        }

        // Re-open and verify the timestamp was updated
        {
            let storage = Storage::new(&path).unwrap();
            let entry = storage.known_dest_entries.get(&dest_hash);
            assert!(entry.is_some(), "entry should exist after flush");
            let entry = entry.unwrap();

            // Timestamp should be much larger than the old value of 1000.0
            assert!(
                entry.timestamp > 1_000_000.0,
                "timestamp should be updated to current time, got {}",
                entry.timestamp
            );

            // app_data should be preserved (not overwritten with None)
            assert_eq!(
                entry.app_data, app_data,
                "app_data should be preserved across flush"
            );

            // packet_hash should be preserved (not overwritten with zeros)
            assert_eq!(
                entry.packet_hash,
                vec![0xAB; PACKET_HASH_LEN],
                "packet_hash should be preserved across flush"
            );
        }

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_hashset_packet_cache_has_add() {
        use reticulum_core::traits::Storage as CoreStorage;

        let mut storage = temp_storage();
        let hash = [0x42u8; 32];

        assert!(!CoreStorage::has_packet_hash(&storage, &hash));
        CoreStorage::add_packet_hash(&mut storage, hash);
        assert!(CoreStorage::has_packet_hash(&storage, &hash));

        // Inner MemoryStorage's packet_cache should stay empty
        assert_eq!(storage.inner.packet_hash_count(), 0);
    }

    #[test]
    fn test_hashset_packet_cache_rotation() {
        use reticulum_core::traits::Storage as CoreStorage;

        let path = temp_dir().join(format!("reticulum_test_rotation_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);

        let mut storage = Storage::new(&path).unwrap();
        // Override cap to a small value for testing
        storage.packet_hash_cap = 10;

        // Add 6 hashes (exceeds half of 10 = 5), triggers rotation
        for i in 0..6u8 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            CoreStorage::add_packet_hash(&mut storage, hash);
        }

        // All 6 should still be findable (5 in prev, 1 in current after rotation)
        for i in 0..6u8 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            assert!(
                CoreStorage::has_packet_hash(&storage, &hash),
                "hash {i} should be found after rotation"
            );
        }

        // Current should have 1 entry (the 6th hash, after rotation cleared current)
        // Wait — 6th hash triggers rotation, then gets inserted? No:
        // add_packet_hash inserts first, then checks. So after inserting 6th:
        // current has 6, exceeds 5, rotation happens: current(6) -> prev, current cleared.
        // So current=0, prev=6. The 6th hash is in prev.
        assert_eq!(storage.packet_cache.len(), 0);
        assert_eq!(storage.packet_cache_prev.len(), 6);

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_hashset_packet_cache_persistence() {
        use reticulum_core::traits::Storage as CoreStorage;

        let path = temp_dir().join(format!(
            "reticulum_test_hash_persist_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);

        let hash_a = [0xAA; 32];
        let hash_b = [0xBB; 32];

        // Create, add hashes to both generations, flush
        {
            let mut storage = Storage::new(&path).unwrap();
            storage.packet_hash_cap = 4; // cap/2 = 2

            CoreStorage::add_packet_hash(&mut storage, hash_a);
            CoreStorage::add_packet_hash(&mut storage, hash_b);
            // After 2 inserts: current has 2, but cap/2=2, so 2 > 2 is false — no rotation yet
            // Actually: len() > cap/2 means 2 > 2 which is false, no rotation
            // Add a third to trigger rotation
            let hash_c = [0xCC; 32];
            CoreStorage::add_packet_hash(&mut storage, hash_c);
            // Now current had 3, 3 > 2, rotation: prev=[A,B,C], current=[]

            CoreStorage::flush(&mut storage);
        }

        // Re-open — all hashes should be loaded
        {
            let storage = Storage::new(&path).unwrap();
            assert!(
                CoreStorage::has_packet_hash(&storage, &hash_a),
                "hash_a should persist"
            );
            assert!(
                CoreStorage::has_packet_hash(&storage, &hash_b),
                "hash_b should persist"
            );
        }

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_hashset_diagnostic_dump() {
        use reticulum_core::traits::Storage as CoreStorage;

        let mut storage = temp_storage();
        CoreStorage::add_packet_hash(&mut storage, [0x01; 32]);
        CoreStorage::add_packet_hash(&mut storage, [0x02; 32]);

        let (dump, total) = CoreStorage::diagnostic_dump(&storage);
        assert!(
            dump.contains("HashSet 1.5x"),
            "should report HashSet overhead"
        );
        assert!(
            dump.contains("packet_cache: 2 entries"),
            "should show 2 entries in packet_cache"
        );
        assert!(total > 0);
    }

    // ─── Ratchet Persistence Tests ──────────────────────────────────────

    /// Create a temp storage with a unique per-test directory.
    fn unique_temp_storage(suffix: &str) -> (Storage, PathBuf) {
        let path = temp_dir().join(format!("reticulum_ratchet_{}_{suffix}", std::process::id()));
        // Clean up any previous run
        let _ = std::fs::remove_dir_all(&path);
        let storage = Storage::new(&path).unwrap();
        (storage, path)
    }

    #[test]
    fn test_known_ratchet_persists_to_disk() {
        let (mut storage, path) = unique_temp_storage("kr_persist");

        let hash = [0x11; TRUNCATED_HASHBYTES];
        let ratchet = [0xaa; 32];
        CoreStorage::remember_known_ratchet(&mut storage, hash, ratchet, 5000);

        // Verify file exists
        let hex = hex_encode(&hash);
        let file_path = path.join(RATCHETS_DIR).join(&hex);
        assert!(file_path.exists(), "Ratchet file should exist on disk");

        // Drop and recreate from same directory
        drop(storage);
        let storage2 = Storage::new(&path).unwrap();
        let loaded = CoreStorage::get_known_ratchet(&storage2, &hash);
        assert_eq!(loaded, Some(ratchet), "Ratchet should survive restart");

        // Cleanup
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_dest_ratchet_keys_persist_to_disk() {
        let (mut storage, path) = unique_temp_storage("drk_persist");

        let hash = [0x22; TRUNCATED_HASHBYTES];
        let data = vec![0x82, 0xa9]; // fake signed msgpack header
        CoreStorage::store_dest_ratchet_keys(&mut storage, hash, data.clone());

        // Verify file exists
        let hex = hex_encode(&hash);
        let file_path = path.join(RATCHETKEYS_DIR).join(&hex);
        assert!(file_path.exists(), "Ratchet keys file should exist on disk");

        // Drop and recreate from same directory
        drop(storage);
        let storage2 = Storage::new(&path).unwrap();
        let loaded = CoreStorage::load_dest_ratchet_keys(&storage2, &hash);
        assert_eq!(loaded, Some(data), "Ratchet keys should survive restart");

        // Cleanup
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_known_ratchet_expire_deletes_file() {
        let (mut storage, path) = unique_temp_storage("kr_expire");

        let h1 = [0x01; TRUNCATED_HASHBYTES];
        let h2 = [0x02; TRUNCATED_HASHBYTES];
        let ratchet = [0xbb; 32];

        CoreStorage::remember_known_ratchet(&mut storage, h1, ratchet, 1000);
        CoreStorage::remember_known_ratchet(&mut storage, h2, ratchet, 5000);

        // Both files should exist
        let hex1 = hex_encode(&h1);
        let hex2 = hex_encode(&h2);
        assert!(path.join(RATCHETS_DIR).join(&hex1).exists());
        assert!(path.join(RATCHETS_DIR).join(&hex2).exists());

        // Expire: h1 is 4000ms old at now=5000, threshold=3000
        let removed = CoreStorage::expire_known_ratchets(&mut storage, 5000, 3000);
        assert_eq!(removed, 1);

        // h1 file should be deleted, h2 should remain
        assert!(
            !path.join(RATCHETS_DIR).join(&hex1).exists(),
            "Expired ratchet file should be deleted"
        );
        assert!(
            path.join(RATCHETS_DIR).join(&hex2).exists(),
            "Non-expired ratchet file should remain"
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_corrupted_ratchet_file_skipped() {
        let (_, path) = unique_temp_storage("kr_corrupt");

        // Write a corrupted file manually
        let ratchets_dir = path.join(RATCHETS_DIR);
        std::fs::create_dir_all(&ratchets_dir).unwrap();
        let hex = hex_encode(&[0x33; TRUNCATED_HASHBYTES]);
        std::fs::write(ratchets_dir.join(&hex), b"garbage data").unwrap();

        // Recreate storage — should load without panic, skip corrupted file
        let storage = Storage::new(&path).unwrap();
        let loaded = CoreStorage::get_known_ratchet(&storage, &[0x33; TRUNCATED_HASHBYTES]);
        assert!(loaded.is_none(), "Corrupted ratchet should not be loaded");

        // Corrupted file should be deleted
        assert!(
            !ratchets_dir.join(&hex).exists(),
            "Corrupted file should be deleted"
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_wallclock_conversion_roundtrip() {
        let offset = 1_700_000_000_000u64; // ~2023 in ms
        let mono = 5_000u64; // 5 seconds into process

        let secs = mono_to_wallclock_secs(mono, offset);
        let back = wallclock_secs_to_mono_ms(secs, offset);

        // Should round-trip (within f64 precision)
        assert_eq!(back, mono);
    }
}
