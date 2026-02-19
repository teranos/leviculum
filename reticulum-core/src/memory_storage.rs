//! In-memory Storage implementation backed by BTreeMaps with configurable caps.
//!
//! `MemoryStorage` is the production Storage implementation for embedded targets
//! and the default test storage for core tests. It is NOT `#[cfg(test)]` — it is
//! always available.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::constants::{HASHLIST_MAXSIZE, MAX_PATH_REQUEST_TAGS, TRUNCATED_HASHBYTES};
use crate::identity::Identity;
use crate::storage_types::{
    AnnounceEntry, AnnounceRateEntry, LinkEntry, PacketReceipt, PathEntry, PathState,
    ReceiptStatus, ReverseEntry,
};
use crate::traits::{Storage, StorageError};

/// In-memory storage with configurable per-collection capacity limits.
///
/// Uses BTreeMap/BTreeSet for all collections. Not persistent — all data is
/// lost when the process exits. For persistent storage, use `FileStorage`
/// in `reticulum-std`.
pub struct MemoryStorage {
    // ─── Capacity limits ────────────────────────────────────────────────
    packet_hash_cap: usize,
    identity_cap: usize,

    // ─── Packet dedup ───────────────────────────────────────────────────
    /// Current generation of packet hashes
    packet_cache: BTreeSet<[u8; 32]>,
    /// Previous generation (rotated out when current exceeds half cap)
    packet_cache_prev: BTreeSet<[u8; 32]>,

    // ─── Path table ─────────────────────────────────────────────────────
    path_table: BTreeMap<[u8; TRUNCATED_HASHBYTES], PathEntry>,
    path_states: BTreeMap<[u8; TRUNCATED_HASHBYTES], PathState>,

    // ─── Reverse table ──────────────────────────────────────────────────
    reverse_table: BTreeMap<[u8; TRUNCATED_HASHBYTES], ReverseEntry>,

    // ─── Link table ─────────────────────────────────────────────────────
    link_table: BTreeMap<[u8; TRUNCATED_HASHBYTES], LinkEntry>,

    // ─── Announce table ─────────────────────────────────────────────────
    announce_table: BTreeMap<[u8; TRUNCATED_HASHBYTES], AnnounceEntry>,
    announce_cache: BTreeMap<[u8; TRUNCATED_HASHBYTES], Vec<u8>>,
    announce_rate_table: BTreeMap<[u8; TRUNCATED_HASHBYTES], AnnounceRateEntry>,

    // ─── Receipts ───────────────────────────────────────────────────────
    receipts: BTreeMap<[u8; TRUNCATED_HASHBYTES], PacketReceipt>,

    // ─── Path requests ──────────────────────────────────────────────────
    path_requests: BTreeMap<[u8; TRUNCATED_HASHBYTES], u64>,
    path_request_tags: VecDeque<[u8; 32]>,

    // ─── Known identities ───────────────────────────────────────────────
    known_identities: BTreeMap<[u8; TRUNCATED_HASHBYTES], Identity>,

    // ─── Legacy generic storage (for ratchets) ──────────────────────────
    generic: BTreeMap<(Vec<u8>, Vec<u8>), Vec<u8>>,
}

impl MemoryStorage {
    /// Create MemoryStorage with generous defaults (suitable for Linux/desktop)
    pub fn with_defaults() -> Self {
        Self {
            packet_hash_cap: HASHLIST_MAXSIZE,
            identity_cap: 5_000_000,
            packet_cache: BTreeSet::new(),
            packet_cache_prev: BTreeSet::new(),
            path_table: BTreeMap::new(),
            path_states: BTreeMap::new(),
            reverse_table: BTreeMap::new(),
            link_table: BTreeMap::new(),
            announce_table: BTreeMap::new(),
            announce_cache: BTreeMap::new(),
            announce_rate_table: BTreeMap::new(),
            receipts: BTreeMap::new(),
            path_requests: BTreeMap::new(),
            path_request_tags: VecDeque::new(),
            known_identities: BTreeMap::new(),
            generic: BTreeMap::new(),
        }
    }

    /// Create MemoryStorage with small caps (suitable for constrained devices)
    pub fn compact() -> Self {
        Self {
            packet_hash_cap: 10_000,
            identity_cap: 1_000,
            ..Self::with_defaults()
        }
    }

    // ─── Test convenience methods ───────────────────────────────────────

    /// Number of packet hashes in both generations
    pub fn packet_hash_count(&self) -> usize {
        self.packet_cache.len() + self.packet_cache_prev.len()
    }

    /// Number of path request tags stored
    pub fn path_request_tag_count(&self) -> usize {
        self.path_request_tags.len()
    }

    /// Clear all packet hashes (test convenience)
    pub fn clear_packet_hashes(&mut self) {
        self.packet_cache.clear();
        self.packet_cache_prev.clear();
    }

    /// Clear all state (test convenience)
    pub fn clear_all(&mut self) {
        self.packet_cache.clear();
        self.packet_cache_prev.clear();
        self.path_table.clear();
        self.path_states.clear();
        self.reverse_table.clear();
        self.link_table.clear();
        self.announce_table.clear();
        self.announce_cache.clear();
        self.announce_rate_table.clear();
        self.receipts.clear();
        self.path_requests.clear();
        self.path_request_tags.clear();
        self.known_identities.clear();
        self.generic.clear();
    }

    /// Number of entries in the announce rate table (test/stats convenience)
    pub fn announce_rate_count(&self) -> usize {
        self.announce_rate_table.len()
    }

    /// Rotate packet cache: current becomes prev, fresh empty set takes its place
    fn rotate_packet_cache(&mut self) {
        core::mem::swap(&mut self.packet_cache, &mut self.packet_cache_prev);
        self.packet_cache.clear();
    }
}

impl Storage for MemoryStorage {
    // ─── Packet Dedup ───────────────────────────────────────────────────

    fn has_packet_hash(&self, hash: &[u8; 32]) -> bool {
        self.packet_cache.contains(hash) || self.packet_cache_prev.contains(hash)
    }

    fn add_packet_hash(&mut self, hash: [u8; 32]) {
        self.packet_cache.insert(hash);
        // Two-generation rotation: when current exceeds half cap, rotate
        if self.packet_cache.len() > self.packet_hash_cap / 2 {
            self.rotate_packet_cache();
        }
    }

    // ─── Path Table ─────────────────────────────────────────────────────

    fn get_path(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<&PathEntry> {
        self.path_table.get(dest_hash)
    }

    fn set_path(&mut self, dest_hash: [u8; TRUNCATED_HASHBYTES], entry: PathEntry) {
        self.path_table.insert(dest_hash, entry);
    }

    fn remove_path(&mut self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<PathEntry> {
        self.path_table.remove(dest_hash)
    }

    fn path_count(&self) -> usize {
        self.path_table.len()
    }

    fn expire_paths(&mut self, now_ms: u64) -> Vec<[u8; TRUNCATED_HASHBYTES]> {
        let mut expired = Vec::new();
        self.path_table.retain(|hash, entry| {
            if entry.expires_ms < now_ms {
                expired.push(*hash);
                false
            } else {
                true
            }
        });
        expired
    }

    fn earliest_path_expiry(&self) -> Option<u64> {
        self.path_table.values().map(|e| e.expires_ms).min()
    }

    // ─── Path State ─────────────────────────────────────────────────────

    fn get_path_state(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<PathState> {
        self.path_states.get(dest_hash).copied()
    }

    fn set_path_state(&mut self, dest_hash: [u8; TRUNCATED_HASHBYTES], state: PathState) {
        self.path_states.insert(dest_hash, state);
    }

    // ─── Reverse Table ──────────────────────────────────────────────────

    fn get_reverse(&self, hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<&ReverseEntry> {
        self.reverse_table.get(hash)
    }

    fn set_reverse(&mut self, hash: [u8; TRUNCATED_HASHBYTES], entry: ReverseEntry) {
        self.reverse_table.insert(hash, entry);
    }

    fn remove_reverse(&mut self, hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<ReverseEntry> {
        self.reverse_table.remove(hash)
    }

    // ─── Link Table ─────────────────────────────────────────────────────

    fn get_link_entry(&self, link_id: &[u8; TRUNCATED_HASHBYTES]) -> Option<&LinkEntry> {
        self.link_table.get(link_id)
    }

    fn get_link_entry_mut(
        &mut self,
        link_id: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&mut LinkEntry> {
        self.link_table.get_mut(link_id)
    }

    fn set_link_entry(&mut self, link_id: [u8; TRUNCATED_HASHBYTES], entry: LinkEntry) {
        self.link_table.insert(link_id, entry);
    }

    fn remove_link_entry(&mut self, link_id: &[u8; TRUNCATED_HASHBYTES]) -> Option<LinkEntry> {
        self.link_table.remove(link_id)
    }

    // ─── Announce Table ─────────────────────────────────────────────────

    fn get_announce(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<&AnnounceEntry> {
        self.announce_table.get(dest_hash)
    }

    fn get_announce_mut(
        &mut self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&mut AnnounceEntry> {
        self.announce_table.get_mut(dest_hash)
    }

    fn set_announce(&mut self, dest_hash: [u8; TRUNCATED_HASHBYTES], entry: AnnounceEntry) {
        self.announce_table.insert(dest_hash, entry);
    }

    fn remove_announce(&mut self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<AnnounceEntry> {
        self.announce_table.remove(dest_hash)
    }

    fn announce_keys(&self) -> Vec<[u8; TRUNCATED_HASHBYTES]> {
        self.announce_table.keys().copied().collect()
    }

    // ─── Announce Cache ─────────────────────────────────────────────────

    fn get_announce_cache(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<&Vec<u8>> {
        self.announce_cache.get(dest_hash)
    }

    fn set_announce_cache(&mut self, dest_hash: [u8; TRUNCATED_HASHBYTES], raw: Vec<u8>) {
        self.announce_cache.insert(dest_hash, raw);
    }

    // ─── Announce Rate ──────────────────────────────────────────────────

    fn get_announce_rate(
        &self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<&AnnounceRateEntry> {
        self.announce_rate_table.get(dest_hash)
    }

    fn set_announce_rate(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASHBYTES],
        entry: AnnounceRateEntry,
    ) {
        self.announce_rate_table.insert(dest_hash, entry);
    }

    // ─── Receipts ───────────────────────────────────────────────────────

    fn get_receipt(&self, hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<&PacketReceipt> {
        self.receipts.get(hash)
    }

    fn set_receipt(&mut self, hash: [u8; TRUNCATED_HASHBYTES], receipt: PacketReceipt) {
        self.receipts.insert(hash, receipt);
    }

    fn remove_receipt(&mut self, hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<PacketReceipt> {
        self.receipts.remove(hash)
    }

    // ─── Path Requests ──────────────────────────────────────────────────

    fn get_path_request_time(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<u64> {
        self.path_requests.get(dest_hash).copied()
    }

    fn set_path_request_time(&mut self, dest_hash: [u8; TRUNCATED_HASHBYTES], time_ms: u64) {
        self.path_requests.insert(dest_hash, time_ms);
    }

    fn check_path_request_tag(&mut self, tag: &[u8; 32]) -> bool {
        if self.path_request_tags.contains(tag) {
            return true;
        }
        self.path_request_tags.push_back(*tag);
        while self.path_request_tags.len() > MAX_PATH_REQUEST_TAGS {
            self.path_request_tags.pop_front();
        }
        false
    }

    // ─── Known Identities ───────────────────────────────────────────────

    fn get_identity(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<&Identity> {
        self.known_identities.get(dest_hash)
    }

    fn set_identity(&mut self, dest_hash: [u8; TRUNCATED_HASHBYTES], identity: Identity) {
        // Evict oldest when at cap (BTreeMap has no insertion order,
        // so we just remove the first key — deterministic but arbitrary)
        if self.known_identities.len() >= self.identity_cap
            && !self.known_identities.contains_key(&dest_hash)
        {
            if let Some(&first_key) = self.known_identities.keys().next() {
                self.known_identities.remove(&first_key);
            }
        }
        self.known_identities.insert(dest_hash, identity);
    }

    // ─── Cleanup ────────────────────────────────────────────────────────

    fn expire_reverses(&mut self, now_ms: u64, timeout_ms: u64) -> usize {
        let before = self.reverse_table.len();
        self.reverse_table
            .retain(|_, entry| now_ms.saturating_sub(entry.timestamp_ms) <= timeout_ms);
        before - self.reverse_table.len()
    }

    fn remove_reverse_entries_for_interface(&mut self, iface_index: usize) {
        self.reverse_table.retain(|_, e| {
            e.receiving_interface_index != iface_index && e.outbound_interface_index != iface_index
        });
    }

    fn expire_receipts(&mut self, now_ms: u64) -> Vec<PacketReceipt> {
        let mut expired = Vec::new();
        self.receipts.retain(|_, receipt| {
            if receipt.status == ReceiptStatus::Sent && receipt.is_expired(now_ms) {
                expired.push(receipt.clone());
                false
            } else {
                true
            }
        });
        expired
    }

    fn expire_link_entries(
        &mut self,
        now_ms: u64,
        link_timeout_ms: u64,
    ) -> Vec<([u8; TRUNCATED_HASHBYTES], LinkEntry)> {
        let mut expired = Vec::new();
        self.link_table.retain(|hash, entry| {
            let is_expired = if entry.validated {
                now_ms.saturating_sub(entry.timestamp_ms) > link_timeout_ms
            } else {
                now_ms > entry.proof_timeout_ms
            };
            if is_expired {
                expired.push((*hash, entry.clone()));
                false
            } else {
                true
            }
        });
        expired
    }

    fn clean_stale_path_metadata(&mut self) {
        self.path_states
            .retain(|hash, _| self.path_table.contains_key(hash));
        self.announce_rate_table
            .retain(|hash, _| self.path_table.contains_key(hash));
    }

    fn remove_link_entries_for_interface(
        &mut self,
        iface_index: usize,
    ) -> Vec<([u8; TRUNCATED_HASHBYTES], LinkEntry)> {
        let mut removed = Vec::new();
        self.link_table.retain(|hash, entry| {
            if entry.received_interface_index == iface_index
                || entry.next_hop_interface_index == iface_index
            {
                removed.push((*hash, entry.clone()));
                false
            } else {
                true
            }
        });
        removed
    }

    fn remove_paths_for_interface(&mut self, iface_index: usize) -> Vec<[u8; TRUNCATED_HASHBYTES]> {
        let mut removed = Vec::new();
        self.path_table.retain(|hash, entry| {
            if entry.interface_index == iface_index {
                removed.push(*hash);
                false
            } else {
                true
            }
        });
        removed
    }

    // ─── Deadlines ──────────────────────────────────────────────────────

    fn earliest_receipt_deadline(&self) -> Option<u64> {
        self.receipts
            .values()
            .filter(|r| r.status == ReceiptStatus::Sent)
            .map(|r| r.sent_at_ms.saturating_add(r.timeout_ms))
            .min()
    }

    fn earliest_link_deadline(&self, link_timeout_ms: u64) -> Option<u64> {
        self.link_table
            .values()
            .map(|entry| {
                if entry.validated {
                    entry.timestamp_ms.saturating_add(link_timeout_ms)
                } else {
                    entry.proof_timeout_ms
                }
            })
            .min()
    }

    // ─── Legacy Generic API (for ratchets) ──────────────────────────────

    fn load(&self, category: &str, key: &[u8]) -> Option<Vec<u8>> {
        let k = (category.as_bytes().to_vec(), key.to_vec());
        self.generic.get(&k).cloned()
    }

    fn store(&mut self, category: &str, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let k = (category.as_bytes().to_vec(), key.to_vec());
        self.generic.insert(k, value.to_vec());
        Ok(())
    }

    fn delete(&mut self, category: &str, key: &[u8]) -> Result<(), StorageError> {
        let k = (category.as_bytes().to_vec(), key.to_vec());
        self.generic.remove(&k);
        Ok(())
    }

    fn list_keys(&self, category: &str) -> Vec<Vec<u8>> {
        let cat = category.as_bytes();
        self.generic
            .keys()
            .filter(|(c, _)| c.as_slice() == cat)
            .map(|(_, k)| k.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::DestinationHash;

    #[test]
    fn test_packet_hash_dedup() {
        let mut s = MemoryStorage::with_defaults();
        let hash = [0x42u8; 32];
        assert!(!s.has_packet_hash(&hash));
        s.add_packet_hash(hash);
        assert!(s.has_packet_hash(&hash));
    }

    #[test]
    fn test_packet_hash_rotation() {
        let mut s = MemoryStorage {
            packet_hash_cap: 10,
            ..MemoryStorage::with_defaults()
        };
        // Add 6 hashes (exceeds half of 10 = 5), triggers rotation
        for i in 0..6u8 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            s.add_packet_hash(hash);
        }
        // First 5 hashes should be in prev, hash[5] in current
        let mut hash0 = [0u8; 32];
        hash0[0] = 0;
        assert!(s.has_packet_hash(&hash0)); // in prev

        let mut hash5 = [0u8; 32];
        hash5[0] = 5;
        assert!(s.has_packet_hash(&hash5)); // in current
    }

    #[test]
    fn test_path_operations() {
        let mut s = MemoryStorage::with_defaults();
        let hash = [0x01u8; TRUNCATED_HASHBYTES];
        assert!(s.get_path(&hash).is_none());
        assert_eq!(s.path_count(), 0);

        s.set_path(
            hash,
            PathEntry {
                hops: 2,
                expires_ms: 5000,
                interface_index: 0,
                random_blobs: Vec::new(),
                next_hop: None,
            },
        );
        assert_eq!(s.path_count(), 1);
        assert_eq!(s.get_path(&hash).unwrap().hops, 2);
        assert!(s.has_path(&hash));

        let removed = s.remove_path(&hash);
        assert!(removed.is_some());
        assert_eq!(s.path_count(), 0);
    }

    #[test]
    fn test_path_expiry() {
        let mut s = MemoryStorage::with_defaults();
        let h1 = [0x01u8; TRUNCATED_HASHBYTES];
        let h2 = [0x02u8; TRUNCATED_HASHBYTES];

        s.set_path(
            h1,
            PathEntry {
                hops: 0,
                expires_ms: 1000,
                interface_index: 0,
                random_blobs: Vec::new(),
                next_hop: None,
            },
        );
        s.set_path(
            h2,
            PathEntry {
                hops: 0,
                expires_ms: 5000,
                interface_index: 0,
                random_blobs: Vec::new(),
                next_hop: None,
            },
        );
        assert_eq!(s.earliest_path_expiry(), Some(1000));

        let expired = s.expire_paths(2000);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], h1);
        assert_eq!(s.path_count(), 1);
    }

    #[test]
    fn test_reverse_table() {
        let mut s = MemoryStorage::with_defaults();
        let hash = [0x01u8; TRUNCATED_HASHBYTES];

        s.set_reverse(
            hash,
            ReverseEntry {
                timestamp_ms: 1000,
                receiving_interface_index: 0,
                outbound_interface_index: 1,
            },
        );
        assert!(s.has_reverse(&hash));
        assert_eq!(s.get_reverse(&hash).unwrap().receiving_interface_index, 0);

        let count = s.expire_reverses(2000, 500);
        assert_eq!(count, 1);
        assert!(!s.has_reverse(&hash));
    }

    #[test]
    fn test_receipt_operations() {
        let mut s = MemoryStorage::with_defaults();
        let hash = [0x01u8; TRUNCATED_HASHBYTES];
        let receipt = PacketReceipt::new([0x42u8; 32], DestinationHash::new(hash), 1000);

        s.set_receipt(hash, receipt);
        assert!(s.get_receipt(&hash).is_some());
        assert_eq!(s.earliest_receipt_deadline(), Some(1000 + 30_000));

        let expired = s.expire_receipts(50_000);
        assert_eq!(expired.len(), 1);
    }

    #[test]
    fn test_path_request_tag_dedup() {
        let mut s = MemoryStorage::with_defaults();
        let tag = [0x42u8; 32];
        assert!(!s.check_path_request_tag(&tag)); // first time: not duplicate
        assert!(s.check_path_request_tag(&tag)); // second time: duplicate
    }

    #[test]
    fn test_known_identities_cap() {
        let mut s = MemoryStorage {
            identity_cap: 2,
            ..MemoryStorage::with_defaults()
        };
        let id1 = Identity::generate(&mut rand_core::OsRng);
        let id2 = Identity::generate(&mut rand_core::OsRng);
        let id3 = Identity::generate(&mut rand_core::OsRng);

        s.set_identity([0x01; TRUNCATED_HASHBYTES], id1);
        s.set_identity([0x02; TRUNCATED_HASHBYTES], id2);
        assert_eq!(s.known_identities.len(), 2);

        // Third should evict first
        s.set_identity([0x03; TRUNCATED_HASHBYTES], id3);
        assert_eq!(s.known_identities.len(), 2);
        assert!(s.get_identity(&[0x01; TRUNCATED_HASHBYTES]).is_none());
    }

    #[test]
    fn test_legacy_generic_api() {
        let mut s = MemoryStorage::with_defaults();
        assert!(s.load("ratchets", b"key1").is_none());
        assert!(s.store("ratchets", b"key1", b"value1").is_ok());
        assert_eq!(s.load("ratchets", b"key1"), Some(b"value1".to_vec()));
        assert_eq!(s.list_keys("ratchets").len(), 1);
        assert!(s.delete("ratchets", b"key1").is_ok());
        assert!(s.load("ratchets", b"key1").is_none());
    }

    #[test]
    fn test_link_entry_expire() {
        let mut s = MemoryStorage::with_defaults();
        let h1 = [0x01u8; TRUNCATED_HASHBYTES];

        s.set_link_entry(
            h1,
            LinkEntry {
                timestamp_ms: 1000,
                next_hop_interface_index: 0,
                remaining_hops: 1,
                received_interface_index: 1,
                hops: 1,
                validated: true,
                proof_timeout_ms: 0,
                destination_hash: [0u8; TRUNCATED_HASHBYTES],
                peer_signing_key: None,
            },
        );

        // Not expired yet
        let expired = s.expire_link_entries(2000, 5000);
        assert!(expired.is_empty());

        // Expired
        let expired = s.expire_link_entries(10_000, 5000);
        assert_eq!(expired.len(), 1);
    }

    #[test]
    fn test_clean_stale_path_metadata() {
        let mut s = MemoryStorage::with_defaults();
        let h1 = [0x01u8; TRUNCATED_HASHBYTES];
        let h2 = [0x02u8; TRUNCATED_HASHBYTES];

        // h1 has a path, h2 does not
        s.set_path(
            h1,
            PathEntry {
                hops: 0,
                expires_ms: u64::MAX,
                interface_index: 0,
                random_blobs: Vec::new(),
                next_hop: None,
            },
        );

        s.set_path_state(h1, PathState::Responsive);
        s.set_path_state(h2, PathState::Unresponsive); // stale
        s.set_announce_rate(
            h2,
            AnnounceRateEntry {
                last_ms: 0,
                rate_violations: 0,
                blocked_until_ms: 0,
            },
        ); // stale

        s.clean_stale_path_metadata();
        assert!(s.get_path_state(&h1).is_some());
        assert!(s.get_path_state(&h2).is_none());
        assert!(s.get_announce_rate(&h2).is_none());
    }
}
