//! Heapless Storage implementation for embedded targets (nRF52840).
//!
//! Uses `heapless::FnvIndexMap` and `heapless::IndexSet` with compile-time
//! capacities instead of `BTreeMap`/`BTreeSet`. Eliminates allocator overhead
//! for map containers — only variable-size data fields (`Vec<u8>` in announce
//! cache and ratchet keys) still use the heap allocator.
//!
//! Local client (shared-instance) methods are no-ops — embedded nodes are the
//! daemon, not a client of a daemon.

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use heapless::FnvIndexMap;
use heapless::FnvIndexSet;

use crate::constants::{RATCHET_SIZE, TRUNCATED_HASHBYTES};
use crate::identity::Identity;
use crate::storage_types::{
    AnnounceEntry, AnnounceRateEntry, LinkEntry, PacketReceipt, PathEntry, PathState,
    ReceiptStatus, ReverseEntry,
};
use crate::traits::Storage;

/// Storage implementation using heapless collections for embedded targets.
///
/// All map capacities are compile-time constants matching the embedded sizing
/// analysis: path_table=32, announce_table=8, link_table=8, etc.
///
/// When a collection is full, insert operations evict the oldest entry
/// rather than panicking. This matches the MemoryStorage overflow behavior —
/// the protocol handles missing entries gracefully via timeouts and retransmits.
///
/// **Size note**: This struct is ~20-30 KB (heapless collections are inline).
/// On Cortex-M4, it must be placed in a `static` or `Box`, not on the stack.
pub struct EmbeddedStorage {
    // ─── Packet dedup (two-generation ring) ──────────────────────────────
    packet_cache: FnvIndexSet<[u8; 32], 256>,
    packet_cache_prev: FnvIndexSet<[u8; 32], 256>,

    // ─── Path table ──────────────────────────────────────────────────────
    path_table: FnvIndexMap<[u8; TRUNCATED_HASHBYTES], PathEntry, 32>,
    path_states: FnvIndexMap<[u8; TRUNCATED_HASHBYTES], PathState, 32>,

    // ─── Announce ────────────────────────────────────────────────────────
    announce_table: FnvIndexMap<[u8; TRUNCATED_HASHBYTES], AnnounceEntry, 16>,
    announce_cache: FnvIndexMap<[u8; TRUNCATED_HASHBYTES], Vec<u8>, 16>,
    announce_rate_table: FnvIndexMap<[u8; TRUNCATED_HASHBYTES], AnnounceRateEntry, 32>,

    // ─── Routing ─────────────────────────────────────────────────────────
    link_table: FnvIndexMap<[u8; TRUNCATED_HASHBYTES], LinkEntry, 8>,
    reverse_table: FnvIndexMap<[u8; TRUNCATED_HASHBYTES], ReverseEntry, 16>,
    discovery_path_requests: FnvIndexMap<[u8; TRUNCATED_HASHBYTES], (usize, u64), 4>,

    // ─── Path requests ───────────────────────────────────────────────────
    path_requests: FnvIndexMap<[u8; TRUNCATED_HASHBYTES], u64, 8>,
    path_request_tag_set: FnvIndexSet<[u8; 32], 32>,

    // ─── Identity / security ─────────────────────────────────────────────
    known_identities: FnvIndexMap<[u8; TRUNCATED_HASHBYTES], Identity, 16>,
    known_ratchets: FnvIndexMap<[u8; TRUNCATED_HASHBYTES], ([u8; RATCHET_SIZE], u64), 8>,
    dest_ratchet_keys: FnvIndexMap<[u8; TRUNCATED_HASHBYTES], Vec<u8>, 4>,

    // ─── Receipts ────────────────────────────────────────────────────────
    receipts: FnvIndexMap<[u8; TRUNCATED_HASHBYTES], PacketReceipt, 8>,
}

impl EmbeddedStorage {
    /// Create a new EmbeddedStorage with all collections empty.
    pub fn new() -> Self {
        Self {
            packet_cache: FnvIndexSet::new(),
            packet_cache_prev: FnvIndexSet::new(),
            path_table: FnvIndexMap::new(),
            path_states: FnvIndexMap::new(),
            announce_table: FnvIndexMap::new(),
            announce_cache: FnvIndexMap::new(),
            announce_rate_table: FnvIndexMap::new(),
            link_table: FnvIndexMap::new(),
            reverse_table: FnvIndexMap::new(),
            discovery_path_requests: FnvIndexMap::new(),
            path_requests: FnvIndexMap::new(),
            path_request_tag_set: FnvIndexSet::new(),
            known_identities: FnvIndexMap::new(),
            known_ratchets: FnvIndexMap::new(),
            dest_ratchet_keys: FnvIndexMap::new(),
            receipts: FnvIndexMap::new(),
        }
    }

    /// Rotate packet cache: current becomes prev, prev is cleared.
    fn rotate_packet_cache(&mut self) {
        core::mem::swap(&mut self.packet_cache, &mut self.packet_cache_prev);
        self.packet_cache.clear();
    }
}

impl Default for EmbeddedStorage {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helper: insert-or-evict for FnvIndexMap ──────────────────────────────
//
// heapless::FnvIndexMap::insert() returns Err((K,V)) when full and key is new.
// We evict the first (oldest-inserted) entry and retry.
fn map_set<K: Eq + core::hash::Hash + Copy, V, const N: usize>(
    map: &mut FnvIndexMap<K, V, N>,
    key: K,
    value: V,
) {
    match map.insert(key, value) {
        Ok(_) => {}
        Err((k, v)) => {
            // Full and key not already present — evict oldest entry
            if let Some(&first_key) = map.keys().next() {
                map.remove(&first_key);
            }
            let _ = map.insert(k, v);
        }
    }
}

// Retain helper: heapless FnvIndexMap doesn't have retain().
// We collect keys to remove, then remove them.
fn map_retain<K: Eq + core::hash::Hash + Copy, V, const N: usize>(
    map: &mut FnvIndexMap<K, V, N>,
    mut pred: impl FnMut(&K, &V) -> bool,
) {
    let keys_to_remove: heapless::Vec<K, N> = map
        .iter()
        .filter(|(k, v)| !pred(k, v))
        .map(|(k, _)| *k)
        .collect();
    for key in &keys_to_remove {
        map.remove(key);
    }
}

// Retain helper that also collects removed entries
fn map_retain_collect<K: Eq + core::hash::Hash + Copy, V: Clone, const N: usize>(
    map: &mut FnvIndexMap<K, V, N>,
    mut pred: impl FnMut(&K, &V) -> bool,
) -> Vec<(K, V)> {
    let mut removed = Vec::new();
    let mut keys_to_remove: heapless::Vec<K, N> = heapless::Vec::new();
    for (k, v) in map.iter() {
        if !pred(k, v) {
            removed.push((*k, v.clone()));
            let _ = keys_to_remove.push(*k);
        }
    }
    for key in &keys_to_remove {
        map.remove(key);
    }
    removed
}

impl Storage for EmbeddedStorage {
    // ─── Packet Dedup ───────────────────────────────────────────────────

    fn has_packet_hash(&self, hash: &[u8; 32]) -> bool {
        self.packet_cache.contains(hash) || self.packet_cache_prev.contains(hash)
    }

    fn add_packet_hash(&mut self, hash: [u8; 32]) {
        let _ = self.packet_cache.insert(hash);
        // Two-generation rotation: when current exceeds half capacity, rotate
        if self.packet_cache.len() > 128 {
            self.rotate_packet_cache();
        }
    }

    // ─── Path Table ─────────────────────────────────────────────────────

    fn get_path(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<&PathEntry> {
        self.path_table.get(dest_hash)
    }

    fn set_path(&mut self, dest_hash: [u8; TRUNCATED_HASHBYTES], entry: PathEntry) {
        map_set(&mut self.path_table, dest_hash, entry);
    }

    fn remove_path(&mut self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<PathEntry> {
        self.path_table.remove(dest_hash)
    }

    fn path_count(&self) -> usize {
        self.path_table.len()
    }

    fn expire_paths(&mut self, now_ms: u64) -> Vec<[u8; TRUNCATED_HASHBYTES]> {
        let mut expired = Vec::new();
        let keys: heapless::Vec<[u8; TRUNCATED_HASHBYTES], 32> = self
            .path_table
            .iter()
            .filter(|(_, entry)| entry.expires_ms < now_ms)
            .map(|(k, _)| *k)
            .collect();
        for key in &keys {
            self.path_table.remove(key);
            expired.push(*key);
        }
        expired
    }

    fn earliest_path_expiry(&self) -> Option<u64> {
        self.path_table.values().map(|e| e.expires_ms).min()
    }

    fn path_entries(&self) -> Vec<([u8; TRUNCATED_HASHBYTES], PathEntry)> {
        self.path_table
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    fn announce_rate_entries(&self) -> Vec<([u8; TRUNCATED_HASHBYTES], AnnounceRateEntry)> {
        self.announce_rate_table
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect()
    }

    // ─── Path State ─────────────────────────────────────────────────────

    fn get_path_state(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<PathState> {
        self.path_states.get(dest_hash).copied()
    }

    fn set_path_state(&mut self, dest_hash: [u8; TRUNCATED_HASHBYTES], state: PathState) {
        map_set(&mut self.path_states, dest_hash, state);
    }

    // ─── Reverse Table ──────────────────────────────────────────────────

    fn get_reverse(&self, hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<&ReverseEntry> {
        self.reverse_table.get(hash)
    }

    fn set_reverse(&mut self, hash: [u8; TRUNCATED_HASHBYTES], entry: ReverseEntry) {
        map_set(&mut self.reverse_table, hash, entry);
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
        map_set(&mut self.link_table, link_id, entry);
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
        map_set(&mut self.announce_table, dest_hash, entry);
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
        map_set(&mut self.announce_cache, dest_hash, raw);
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
        map_set(&mut self.announce_rate_table, dest_hash, entry);
    }

    // ─── Receipts ───────────────────────────────────────────────────────

    fn get_receipt(&self, hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<&PacketReceipt> {
        self.receipts.get(hash)
    }

    fn set_receipt(&mut self, hash: [u8; TRUNCATED_HASHBYTES], receipt: PacketReceipt) {
        map_set(&mut self.receipts, hash, receipt);
    }

    // ─── Path Requests ──────────────────────────────────────────────────

    fn get_path_request_time(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<u64> {
        self.path_requests.get(dest_hash).copied()
    }

    fn set_path_request_time(&mut self, dest_hash: [u8; TRUNCATED_HASHBYTES], time_ms: u64) {
        map_set(&mut self.path_requests, dest_hash, time_ms);
    }

    fn check_path_request_tag(&mut self, tag: &[u8; 32]) -> bool {
        if self.path_request_tag_set.contains(tag) {
            return true;
        }
        // If full, evict oldest (first inserted)
        if self.path_request_tag_set.len() >= self.path_request_tag_set.capacity() {
            if let Some(&oldest) = self.path_request_tag_set.iter().next() {
                self.path_request_tag_set.remove(&oldest);
            }
        }
        let _ = self.path_request_tag_set.insert(*tag);
        false
    }

    // ─── Known Identities ───────────────────────────────────────────────

    fn get_identity(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<&Identity> {
        self.known_identities.get(dest_hash)
    }

    fn set_identity(&mut self, dest_hash: [u8; TRUNCATED_HASHBYTES], identity: Identity) {
        map_set(&mut self.known_identities, dest_hash, identity);
    }

    // ─── Cleanup ────────────────────────────────────────────────────────

    fn expire_reverses(&mut self, now_ms: u64, timeout_ms: u64) -> usize {
        let before = self.reverse_table.len();
        map_retain(&mut self.reverse_table, |_, entry| {
            now_ms.saturating_sub(entry.timestamp_ms) <= timeout_ms
        });
        before - self.reverse_table.len()
    }

    fn remove_reverse_entries_for_interface(&mut self, iface_index: usize) {
        map_retain(&mut self.reverse_table, |_, e| {
            e.receiving_interface_index != iface_index && e.outbound_interface_index != iface_index
        });
    }

    fn expire_receipts(&mut self, now_ms: u64) -> Vec<PacketReceipt> {
        map_retain_collect(&mut self.receipts, |_, receipt| {
            !(receipt.status == ReceiptStatus::Sent && receipt.is_expired(now_ms))
        })
        .into_iter()
        .map(|(_, r)| r)
        .collect()
    }

    fn expire_link_entries(
        &mut self,
        now_ms: u64,
        link_timeout_ms: u64,
    ) -> Vec<([u8; TRUNCATED_HASHBYTES], LinkEntry)> {
        map_retain_collect(&mut self.link_table, |_, entry| {
            let is_expired = if entry.validated {
                now_ms.saturating_sub(entry.timestamp_ms) > link_timeout_ms
            } else {
                now_ms > entry.proof_timeout_ms
            };
            !is_expired
        })
    }

    fn clean_stale_path_metadata(&mut self) {
        // Collect keys of path_states not in path_table
        let stale_states: heapless::Vec<[u8; TRUNCATED_HASHBYTES], 32> = self
            .path_states
            .keys()
            .filter(|k| !self.path_table.contains_key(*k))
            .copied()
            .collect();
        for key in &stale_states {
            self.path_states.remove(key);
        }

        let stale_rates: heapless::Vec<[u8; TRUNCATED_HASHBYTES], 32> = self
            .announce_rate_table
            .keys()
            .filter(|k| !self.path_table.contains_key(*k))
            .copied()
            .collect();
        for key in &stale_rates {
            self.announce_rate_table.remove(key);
        }
    }

    fn clean_announce_cache(&mut self, local_destinations: &BTreeSet<[u8; TRUNCATED_HASHBYTES]>) {
        let stale: heapless::Vec<[u8; TRUNCATED_HASHBYTES], 16> = self
            .announce_cache
            .keys()
            .filter(|k| !self.path_table.contains_key(*k) && !local_destinations.contains(*k))
            .copied()
            .collect();
        for key in &stale {
            self.announce_cache.remove(key);
        }
    }

    fn remove_link_entries_for_interface(
        &mut self,
        iface_index: usize,
    ) -> Vec<([u8; TRUNCATED_HASHBYTES], LinkEntry)> {
        map_retain_collect(&mut self.link_table, |_, entry| {
            entry.received_interface_index != iface_index
                && entry.next_hop_interface_index != iface_index
        })
    }

    fn remove_paths_for_interface(&mut self, iface_index: usize) -> Vec<[u8; TRUNCATED_HASHBYTES]> {
        let mut removed = Vec::new();
        let keys: heapless::Vec<[u8; TRUNCATED_HASHBYTES], 32> = self
            .path_table
            .iter()
            .filter(|(_, entry)| entry.interface_index == iface_index)
            .map(|(k, _)| *k)
            .collect();
        for key in &keys {
            self.path_table.remove(key);
            removed.push(*key);
        }
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

    // ─── Known Ratchets ─────────────────────────────────────────────────

    fn get_known_ratchet(
        &self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<[u8; RATCHET_SIZE]> {
        self.known_ratchets.get(dest_hash).map(|(r, _)| *r)
    }

    fn remember_known_ratchet(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASHBYTES],
        ratchet: [u8; RATCHET_SIZE],
        received_at_ms: u64,
    ) {
        map_set(
            &mut self.known_ratchets,
            dest_hash,
            (ratchet, received_at_ms),
        );
    }

    fn expire_known_ratchets(&mut self, now_ms: u64, expiry_ms: u64) -> usize {
        let before = self.known_ratchets.len();
        map_retain(&mut self.known_ratchets, |_, (_, received_at)| {
            now_ms.saturating_sub(*received_at) < expiry_ms
        });
        before - self.known_ratchets.len()
    }

    // ─── Local Client Destinations (no-op on embedded) ──────────────────

    fn add_local_client_dest(
        &mut self,
        _iface_id: usize,
        _dest_hash: [u8; TRUNCATED_HASHBYTES],
    ) -> bool {
        false
    }

    fn remove_local_client_dests(&mut self, _iface_id: usize) {}

    // ─── Local Client Known Destinations (no-op on embedded) ────────────

    fn set_local_client_known_dest(
        &mut self,
        _dest_hash: [u8; TRUNCATED_HASHBYTES],
        _last_seen_ms: u64,
    ) {
    }

    fn local_client_known_dest_hashes(&self) -> Vec<[u8; TRUNCATED_HASHBYTES]> {
        Vec::new()
    }

    fn expire_local_client_known_dests(&mut self, _now_ms: u64, _expiry_ms: u64) -> usize {
        0
    }

    // ─── Discovery Path Requests ────────────────────────────────────────

    fn set_discovery_path_request(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASHBYTES],
        requesting_interface: usize,
        timeout_ms: u64,
    ) {
        // Only store first request (Python behavior)
        if !self.discovery_path_requests.contains_key(&dest_hash) {
            map_set(
                &mut self.discovery_path_requests,
                dest_hash,
                (requesting_interface, timeout_ms),
            );
        }
    }

    fn get_discovery_path_request(
        &self,
        dest_hash: &[u8; TRUNCATED_HASHBYTES],
    ) -> Option<(usize, u64)> {
        self.discovery_path_requests.get(dest_hash).copied()
    }

    fn remove_discovery_path_request(&mut self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) {
        self.discovery_path_requests.remove(dest_hash);
    }

    fn expire_discovery_path_requests(&mut self, now_ms: u64) -> usize {
        let before = self.discovery_path_requests.len();
        map_retain(&mut self.discovery_path_requests, |_, (_, timeout)| {
            *timeout > now_ms
        });
        before - self.discovery_path_requests.len()
    }

    fn discovery_path_request_dest_hashes(&self) -> Vec<[u8; TRUNCATED_HASHBYTES]> {
        self.discovery_path_requests.keys().copied().collect()
    }

    // ─── Sender-Side Ratchet Keys ───────────────────────────────────────

    fn store_dest_ratchet_keys(
        &mut self,
        dest_hash: [u8; TRUNCATED_HASHBYTES],
        serialized: Vec<u8>,
    ) {
        map_set(&mut self.dest_ratchet_keys, dest_hash, serialized);
    }

    fn load_dest_ratchet_keys(&self, dest_hash: &[u8; TRUNCATED_HASHBYTES]) -> Option<Vec<u8>> {
        self.dest_ratchet_keys.get(dest_hash).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::DestinationHash;

    #[test]
    fn test_embedded_storage_path_roundtrip() {
        let mut s = EmbeddedStorage::new();
        let hash = [0x01u8; TRUNCATED_HASHBYTES];
        let entry = PathEntry {
            hops: 2,
            expires_ms: 10000,
            interface_index: 0,
            random_blobs: Vec::new(),
            next_hop: None,
        };

        assert!(s.get_path(&hash).is_none());
        s.set_path(hash, entry.clone());
        assert_eq!(s.get_path(&hash).unwrap().hops, 2);
        assert_eq!(s.path_count(), 1);
    }

    #[test]
    fn test_embedded_storage_path_eviction() {
        let mut s = EmbeddedStorage::new();

        // Fill path_table to capacity (32)
        for i in 0u8..32 {
            let mut hash = [0u8; TRUNCATED_HASHBYTES];
            hash[0] = i;
            s.set_path(
                hash,
                PathEntry {
                    hops: 1,
                    expires_ms: 10000 + i as u64,
                    interface_index: 0,
                    random_blobs: Vec::new(),
                    next_hop: None,
                },
            );
        }
        assert_eq!(s.path_count(), 32);

        // Insert one more — should evict the first
        let mut new_hash = [0xFFu8; TRUNCATED_HASHBYTES];
        new_hash[0] = 0xFF;
        s.set_path(
            new_hash,
            PathEntry {
                hops: 3,
                expires_ms: 99999,
                interface_index: 1,
                random_blobs: Vec::new(),
                next_hop: None,
            },
        );
        assert_eq!(s.path_count(), 32);
        // New entry is present
        assert!(s.get_path(&new_hash).is_some());
        // First entry was evicted
        let first = [0u8; TRUNCATED_HASHBYTES];
        assert!(s.get_path(&first).is_none());
    }

    #[test]
    fn test_embedded_storage_packet_dedup() {
        let mut s = EmbeddedStorage::new();
        let hash = [0x42u8; 32];

        assert!(!s.has_packet_hash(&hash));
        s.add_packet_hash(hash);
        assert!(s.has_packet_hash(&hash));
    }

    #[test]
    fn test_embedded_storage_receipt_roundtrip() {
        let mut s = EmbeddedStorage::new();
        let hash = [0x01u8; TRUNCATED_HASHBYTES];
        let receipt = PacketReceipt::new([0x42u8; 32], DestinationHash::new(hash), 1000);

        s.set_receipt(hash, receipt);
        assert!(s.get_receipt(&hash).is_some());
        assert_eq!(s.earliest_receipt_deadline(), Some(1000 + 30_000));
    }

    #[test]
    fn test_embedded_storage_announce_roundtrip() {
        let mut s = EmbeddedStorage::new();
        let hash = [0x01u8; TRUNCATED_HASHBYTES];
        let entry = AnnounceEntry {
            timestamp_ms: 1000,
            hops: 1,
            retries: 0,
            retransmit_at_ms: None,
            raw_packet: alloc::vec![0xAA; 100],
            receiving_interface_index: 0,
            target_interface: None,
            local_rebroadcasts: 0,
            block_rebroadcasts: false,
        };

        s.set_announce(hash, entry);
        assert!(s.get_announce(&hash).is_some());
        assert_eq!(s.announce_keys().len(), 1);

        s.remove_announce(&hash);
        assert!(s.get_announce(&hash).is_none());
    }

    #[test]
    fn test_embedded_storage_local_client_noop() {
        let mut s = EmbeddedStorage::new();
        let hash = [0x42u8; TRUNCATED_HASHBYTES];
        assert!(!s.add_local_client_dest(0, hash));
        s.remove_local_client_dests(0);
        s.set_local_client_known_dest(hash, 1000);
        assert!(s.local_client_known_dest_hashes().is_empty());
    }
}
