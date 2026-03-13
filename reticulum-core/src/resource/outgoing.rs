//! Outgoing resource state machine (sender side).
//!
//! Sans-I/O: receives packets via methods, returns raw packet bytes to send.
//! Owned by Link (same pattern as Channel).

use alloc::vec;
use alloc::vec::Vec;

use rand_core::CryptoRngCore;

#[cfg(feature = "compression")]
use crate::constants::RESOURCE_AUTO_COMPRESS_MAX;
use crate::constants::{RESOURCE_HASHMAP_LEN, RESOURCE_WINDOW_MAX_FAST};
use crate::crypto::full_hash;
use crate::link::Link;
use crate::packet::PacketContext;
use crate::resource::hashmap::map_hash;
use crate::resource::msgpack;
use crate::resource::{
    resource_sdu, ResourceAdvertisement, ResourceError, ResourceFlags, ResourceStatus,
    COLLISION_GUARD_SIZE, HASHMAP_IS_EXHAUSTED, HASHMAP_MAX_LEN, RESOURCE_MAX_ADV_RETRIES,
    RESOURCE_MAX_RETRIES, RESOURCE_RANDOM_HASH_SIZE,
};

/// Result of polling an outgoing resource for timeout.
#[derive(Debug)]
pub(crate) enum ResourcePollResult {
    /// No action needed.
    Nothing,
    /// Re-send advertisement packet.
    RetransmitAdv(Vec<u8>),
    /// Transfer has timed out — should be failed.
    TimedOut,
}

/// Outgoing resource transfer state machine.
///
/// Fields like `flags`, `original_hash`, `random_hash`, `uncompressed_size`,
/// `total_hashmap_segments`, `request_id`, and `sdu` are stored during resource
/// creation and needed for protocol correctness (advertisement reconstruction,
/// hash verification, hashmap segment calculation). Accessors are provided and
/// exercised in tests; production callers arrive with ROADMAP v1.1 (Resource Transfer).
#[allow(dead_code)] // Protocol state fields — see ROADMAP v1.1 (Resource Transfer)
pub(crate) struct OutgoingResource {
    status: ResourceStatus,
    flags: ResourceFlags,
    resource_hash: [u8; 32],
    original_hash: [u8; 32],
    random_hash: [u8; RESOURCE_RANDOM_HASH_SIZE],
    encrypted_data: Vec<u8>,
    expected_proof: [u8; 32],
    uncompressed_size: u64,
    parts: Vec<Vec<u8>>,
    hashmap: Vec<[u8; RESOURCE_HASHMAP_LEN]>,
    num_parts: u32,
    sent_parts: usize,
    receiver_min_consecutive_height: usize,
    total_hashmap_segments: u32,
    window: usize,
    retries: usize,
    adv_retries: usize,
    last_activity_ms: u64,
    request_id: Option<Vec<u8>>,
    adv_packet: Vec<u8>,
    link_mdu: usize,
    sdu: usize,
}

impl OutgoingResource {
    /// Create a new outgoing resource for transfer over a link.
    ///
    /// # Arguments
    /// * `data` - Application data to send
    /// * `metadata` - Optional metadata (msgpack-encoded by caller)
    /// * `request_id` - Optional request ID for request/response pairing
    /// * `link` - The link to send over (must be Active)
    /// * `rng` - Random number generator
    /// * `now_ms` - Current time in milliseconds
    pub(crate) fn new(
        data: &[u8],
        metadata: Option<&[u8]>,
        request_id: Option<&[u8]>,
        link: &Link,
        auto_compress: bool,
        rng: &mut impl CryptoRngCore,
        now_ms: u64,
    ) -> Result<Self, ResourceError> {
        if !link.is_active() {
            return Err(ResourceError::LinkNotActive);
        }

        let sdu = resource_sdu(link.negotiated_mtu());
        let link_mdu = link.mdu();

        // Build combined = metadata_prefix + data
        // Python line 264: struct.pack(">I", metadata_size)[1:] + packed_metadata
        let mut combined = Vec::new();
        let has_metadata = metadata.is_some();
        if let Some(meta) = metadata {
            let meta_len = meta.len();
            // 3-byte big-endian length (high 3 bytes of u32)
            combined.push((meta_len >> 16) as u8);
            combined.push((meta_len >> 8) as u8);
            combined.push(meta_len as u8);
            combined.extend_from_slice(meta);
        }
        combined.extend_from_slice(data);

        let uncompressed_size = combined.len() as u64;

        // Compute original_hash over unencrypted combined data
        let original_hash_full = full_hash(&combined);
        let mut original_hash = [0u8; 32];
        original_hash.copy_from_slice(&original_hash_full);

        // Try compression
        #[allow(unused_mut)]
        let mut compressed = false;
        let data_to_encrypt = {
            #[cfg(feature = "compression")]
            {
                if auto_compress && combined.len() <= RESOURCE_AUTO_COMPRESS_MAX {
                    match super::compression::bz2_compress(&combined) {
                        Ok(compressed_data) if compressed_data.len() < combined.len() => {
                            compressed = true;
                            compressed_data
                        }
                        _ => combined.clone(),
                    }
                } else {
                    combined.clone()
                }
            }
            #[cfg(not(feature = "compression"))]
            {
                let _ = auto_compress;
                combined.clone()
            }
        };

        // Generate wire random (prepended, not stored)
        let mut wire_random = [0u8; RESOURCE_RANDOM_HASH_SIZE];
        rng.fill_bytes(&mut wire_random);

        // Build plaintext: wire_random + data_to_encrypt
        let mut plaintext = Vec::with_capacity(RESOURCE_RANDOM_HASH_SIZE + data_to_encrypt.len());
        plaintext.extend_from_slice(&wire_random);
        plaintext.extend_from_slice(&data_to_encrypt);

        // Encrypt via link
        let enc_size = Link::encrypted_size(plaintext.len());
        let mut encrypted = vec![0u8; enc_size];
        let written = link
            .encrypt(&plaintext, &mut encrypted, rng)
            .map_err(|_| ResourceError::CryptoError)?;
        encrypted.truncate(written);

        // Generate verification random_hash (stored, sent in ADV "r" field)
        let mut random_hash = [0u8; RESOURCE_RANDOM_HASH_SIZE];
        rng.fill_bytes(&mut random_hash);

        // resource_hash = full_hash(combined + random_hash) — uses UNENCRYPTED combined
        let mut hash_input = Vec::with_capacity(combined.len() + RESOURCE_RANDOM_HASH_SIZE);
        hash_input.extend_from_slice(&combined);
        hash_input.extend_from_slice(&random_hash);
        let resource_hash_full = full_hash(&hash_input);
        let mut resource_hash = [0u8; 32];
        resource_hash.copy_from_slice(&resource_hash_full);

        // expected_proof = full_hash(combined + resource_hash) — precomputed
        let mut proof_input = Vec::with_capacity(combined.len() + 32);
        proof_input.extend_from_slice(&combined);
        proof_input.extend_from_slice(&resource_hash);
        let expected_proof_full = full_hash(&proof_input);
        let mut expected_proof = [0u8; 32];
        expected_proof.copy_from_slice(&expected_proof_full);

        // Segment encrypted data into parts
        let num_parts = if encrypted.is_empty() {
            1
        } else {
            encrypted.len().div_ceil(sdu) as u32
        };

        let guard_size = COLLISION_GUARD_SIZE;
        let hashmap_max = HASHMAP_MAX_LEN;

        // Build parts and hashmap, retrying if hash collisions occur
        let (parts, hashmap) = loop {
            let mut parts = Vec::with_capacity(num_parts as usize);
            let mut hashmap_entries = Vec::with_capacity(num_parts as usize);
            let mut collision_guard: Vec<[u8; RESOURCE_HASHMAP_LEN]> = Vec::new();
            let mut collision_found = false;

            for i in 0..num_parts as usize {
                let start = i * sdu;
                let end = core::cmp::min(start + sdu, encrypted.len());
                let part_data = &encrypted[start..end];

                let mh = map_hash(part_data, &random_hash);

                if collision_guard.contains(&mh) {
                    // Collision — regenerate random_hash and retry
                    rng.fill_bytes(&mut random_hash);

                    // Recompute resource_hash and expected_proof with new random_hash
                    let mut hi = Vec::with_capacity(combined.len() + RESOURCE_RANDOM_HASH_SIZE);
                    hi.extend_from_slice(&combined);
                    hi.extend_from_slice(&random_hash);
                    let rh = full_hash(&hi);
                    resource_hash.copy_from_slice(&rh);

                    let mut pi = Vec::with_capacity(combined.len() + 32);
                    pi.extend_from_slice(&combined);
                    pi.extend_from_slice(&resource_hash);
                    let ep = full_hash(&pi);
                    expected_proof.copy_from_slice(&ep);

                    collision_found = true;
                    break;
                }

                collision_guard.push(mh);
                if collision_guard.len() > guard_size {
                    collision_guard.remove(0);
                }

                hashmap_entries.push(mh);
                parts.push(part_data.to_vec());
            }

            if !collision_found {
                break (parts, hashmap_entries);
            }
        };

        // Calculate hashmap segments
        let total_hashmap_segments = if hashmap_max == 0 {
            1
        } else {
            hashmap.len().div_ceil(hashmap_max) as u32
        };

        // Build first hashmap segment for advertisement
        let first_segment_end = core::cmp::min(hashmap_max, hashmap.len());
        let mut hashmap_data = Vec::with_capacity(first_segment_end * RESOURCE_HASHMAP_LEN);
        for entry in &hashmap[..first_segment_end] {
            hashmap_data.extend_from_slice(entry);
        }

        // Build flags
        let flags = ResourceFlags {
            encrypted: true,
            compressed,
            split: false,
            is_request: false,
            is_response: false,
            has_metadata,
        };

        // Build and cache advertisement
        let adv = ResourceAdvertisement {
            transfer_size: encrypted.len() as u64,
            data_size: uncompressed_size,
            num_parts,
            resource_hash,
            random_hash,
            original_hash,
            segment_index: 1,
            total_segments: 1,
            request_id: request_id.map(|r| r.to_vec()),
            flags,
            hashmap_data,
        };
        let adv_packet = adv.pack();

        Ok(Self {
            status: ResourceStatus::Advertised,
            flags,
            resource_hash,
            original_hash,
            random_hash,
            encrypted_data: encrypted,
            expected_proof,
            uncompressed_size,
            parts,
            hashmap,
            num_parts,
            sent_parts: 0,
            receiver_min_consecutive_height: 0,
            total_hashmap_segments,
            window: crate::constants::RESOURCE_WINDOW_INITIAL,
            retries: 0,
            adv_retries: 0,
            last_activity_ms: now_ms,
            request_id: request_id.map(|r| r.to_vec()),
            adv_packet,
            link_mdu,
            sdu,
        })
    }

    /// Handle a REQ packet from the receiver.
    ///
    /// Returns raw data packets to send (RESOURCE context, pre-encrypted).
    /// May also return an HMU packet if the receiver's hashmap is exhausted.
    pub(crate) fn handle_request(
        &mut self,
        req_data: &[u8],
        link: &Link,
        rng: &mut impl CryptoRngCore,
        now_ms: u64,
    ) -> Result<Vec<Vec<u8>>, ResourceError> {
        if self.status == ResourceStatus::Failed {
            return Err(ResourceError::Cancelled);
        }

        // Parse REQ wire format: [1:exhausted_flag][4?:last_map_hash][32:resource_hash][N*4:requested_hashes]
        if req_data.is_empty() {
            return Err(ResourceError::InvalidRequest);
        }

        let wants_more_hashmap = req_data[0] == HASHMAP_IS_EXHAUSTED;
        let pad = if wants_more_hashmap {
            1 + RESOURCE_HASHMAP_LEN
        } else {
            1
        };

        // resource_hash starts at offset `pad`
        if req_data.len() < pad + 32 {
            return Err(ResourceError::InvalidRequest);
        }

        let req_resource_hash = &req_data[pad..pad + 32];
        if req_resource_hash != self.resource_hash {
            return Err(ResourceError::InvalidRequest);
        }

        // Transition to transferring on first REQ
        if self.status == ResourceStatus::Advertised {
            self.status = ResourceStatus::Transferring;
        }

        self.retries = 0;
        self.last_activity_ms = now_ms;

        let mut packets = Vec::new();

        // Parse requested map hashes
        let requested_hashes_data = &req_data[pad + 32..];
        let num_requested = requested_hashes_data.len() / RESOURCE_HASHMAP_LEN;

        let mut requested_hashes = Vec::with_capacity(num_requested);
        for i in 0..num_requested {
            let start = i * RESOURCE_HASHMAP_LEN;
            let mut mh = [0u8; RESOURCE_HASHMAP_LEN];
            mh.copy_from_slice(&requested_hashes_data[start..start + RESOURCE_HASHMAP_LEN]);
            requested_hashes.push(mh);
        }

        // Search within collision guard scope for matching parts
        let search_start = self.receiver_min_consecutive_height;
        let search_end = core::cmp::min(search_start + COLLISION_GUARD_SIZE, self.parts.len());

        for i in search_start..search_end {
            if requested_hashes.contains(&self.hashmap[i]) {
                // Build raw data packet (no per-packet encryption)
                let raw_pkt = link
                    .build_raw_data_packet(&self.parts[i], PacketContext::Resource)
                    .map_err(|_| ResourceError::LinkNotActive)?;
                packets.push(raw_pkt);
                self.sent_parts += 1;
            }
        }

        // Handle hashmap exhaustion — send next HMU segment
        if wants_more_hashmap {
            let last_map_hash = &req_data[1..1 + RESOURCE_HASHMAP_LEN];
            let hashmap_max = HASHMAP_MAX_LEN;

            // Find the part index matching last_map_hash
            let mut part_index = self.receiver_min_consecutive_height;
            let scan_end = core::cmp::min(
                self.receiver_min_consecutive_height + COLLISION_GUARD_SIZE,
                self.hashmap.len(),
            );
            for i in self.receiver_min_consecutive_height..scan_end {
                part_index = i + 1;
                if self.hashmap[i] == *last_map_hash {
                    break;
                }
            }

            // Update receiver_min_consecutive_height
            self.receiver_min_consecutive_height =
                part_index.saturating_sub(1 + RESOURCE_WINDOW_MAX_FAST);

            if hashmap_max > 0 {
                let segment = part_index / hashmap_max;

                let hashmap_start = segment * hashmap_max;
                let hashmap_end = core::cmp::min((segment + 1) * hashmap_max, self.hashmap.len());

                // Build hashmap bytes for this segment
                let mut hashmap_bytes =
                    Vec::with_capacity((hashmap_end - hashmap_start) * RESOURCE_HASHMAP_LEN);
                for entry in &self.hashmap[hashmap_start..hashmap_end] {
                    hashmap_bytes.extend_from_slice(entry);
                }

                // Build HMU: resource_hash + msgpack([segment, hashmap_bytes])
                let mut hmu = Vec::with_capacity(32 + 10 + hashmap_bytes.len());
                hmu.extend_from_slice(&self.resource_hash);
                msgpack::write_fixarray_header(&mut hmu, 2);
                msgpack::write_uint(&mut hmu, segment as u64);
                msgpack::write_bin(&mut hmu, &hashmap_bytes);

                // Wrap in encrypted link packet
                let hmu_pkt = link
                    .build_data_packet_with_context(&hmu, PacketContext::ResourceHmu, rng)
                    .map_err(|_| ResourceError::LinkNotActive)?;
                packets.push(hmu_pkt);
            }
        }

        // Check if all parts sent → transition to AwaitingProof
        if self.sent_parts >= self.parts.len() {
            self.status = ResourceStatus::AwaitingProof;
            self.retries = 0;
        }

        Ok(packets)
    }

    /// Validate a proof from the receiver.
    ///
    /// Returns `Ok(ResourceStatus::Complete)` if valid.
    pub(crate) fn handle_proof(
        &mut self,
        proof_data: &[u8],
    ) -> Result<ResourceStatus, ResourceError> {
        if self.status == ResourceStatus::Failed {
            return Err(ResourceError::Cancelled);
        }

        // Proof format: [32: resource_hash] [32: proof_hash]
        if proof_data.len() != 64 {
            return Err(ResourceError::InvalidProof);
        }

        let proof_resource_hash = &proof_data[..32];
        let proof_hash = &proof_data[32..];

        if proof_resource_hash != self.resource_hash {
            return Err(ResourceError::InvalidProof);
        }

        if proof_hash != self.expected_proof {
            return Err(ResourceError::InvalidProof);
        }

        self.status = ResourceStatus::Complete;
        Ok(ResourceStatus::Complete)
    }

    /// Poll for timeout. Called periodically by the timeout handler.
    pub(crate) fn poll(&mut self, now_ms: u64, rtt_ms: u64) -> ResourcePollResult {
        let rtt_ms = core::cmp::max(rtt_ms, 1);

        match self.status {
            ResourceStatus::Advertised => {
                let timeout = rtt_ms.saturating_mul(6);
                if now_ms.saturating_sub(self.last_activity_ms) >= timeout {
                    self.adv_retries += 1;
                    if self.adv_retries < RESOURCE_MAX_ADV_RETRIES {
                        self.last_activity_ms = now_ms;
                        ResourcePollResult::RetransmitAdv(self.adv_packet.clone())
                    } else {
                        self.status = ResourceStatus::Failed;
                        ResourcePollResult::TimedOut
                    }
                } else {
                    ResourcePollResult::Nothing
                }
            }
            ResourceStatus::Transferring => {
                // timeout = max(rtt * 2.5, per_part_timeout * window * 1.125)
                let rtt_timeout = rtt_ms * 5 / 2;
                let per_part_timeout = if self.num_parts > 0 {
                    (self.encrypted_data.len() as u64).saturating_mul(1000)
                        / self.num_parts as u64
                        / core::cmp::max(rtt_ms, 1)
                } else {
                    rtt_ms
                };
                let window_timeout = per_part_timeout * self.window as u64 * 1125 / 1000;
                let timeout = core::cmp::max(rtt_timeout, window_timeout);

                if now_ms.saturating_sub(self.last_activity_ms) >= timeout {
                    self.retries += 1;
                    if self.retries >= RESOURCE_MAX_RETRIES {
                        self.status = ResourceStatus::Failed;
                        ResourcePollResult::TimedOut
                    } else {
                        // Just wait for another REQ
                        ResourcePollResult::Nothing
                    }
                } else {
                    ResourcePollResult::Nothing
                }
            }
            ResourceStatus::AwaitingProof => {
                let timeout = rtt_ms.saturating_mul(6);
                if now_ms.saturating_sub(self.last_activity_ms) >= timeout {
                    self.status = ResourceStatus::Failed;
                    ResourcePollResult::TimedOut
                } else {
                    ResourcePollResult::Nothing
                }
            }
            _ => ResourcePollResult::Nothing,
        }
    }

    /// Compute the next deadline (absolute ms) for this resource.
    pub(crate) fn next_deadline(&self, rtt_ms: u64) -> Option<u64> {
        let rtt_ms = core::cmp::max(rtt_ms, 1);
        match self.status {
            ResourceStatus::Advertised => Some(
                self.last_activity_ms
                    .saturating_add(rtt_ms.saturating_mul(6)),
            ),
            ResourceStatus::Transferring => {
                let rtt_timeout = rtt_ms * 5 / 2;
                let per_part_timeout = if self.num_parts > 0 {
                    (self.encrypted_data.len() as u64).saturating_mul(1000)
                        / self.num_parts as u64
                        / core::cmp::max(rtt_ms, 1)
                } else {
                    rtt_ms
                };
                let window_timeout = per_part_timeout * self.window as u64 * 1125 / 1000;
                let timeout = core::cmp::max(rtt_timeout, window_timeout);
                Some(self.last_activity_ms.saturating_add(timeout))
            }
            ResourceStatus::AwaitingProof => Some(
                self.last_activity_ms
                    .saturating_add(rtt_ms.saturating_mul(6)),
            ),
            _ => None,
        }
    }

    /// Mark this resource as failed/cancelled.
    #[allow(dead_code)] // Resource cancel API — see ROADMAP v1.1 (Resource Transfer)
    pub(crate) fn cancel(&mut self) {
        self.status = ResourceStatus::Failed;
    }

    // ── Accessors ──────────────────────────────────────────────────────────

    pub(crate) fn status(&self) -> ResourceStatus {
        self.status
    }

    pub(crate) fn resource_hash(&self) -> &[u8; 32] {
        &self.resource_hash
    }

    pub(crate) fn adv_packet(&self) -> &[u8] {
        &self.adv_packet
    }

    pub(crate) fn progress(&self) -> f32 {
        if self.num_parts == 0 {
            return 1.0;
        }
        self.sent_parts as f32 / self.num_parts as f32
    }

    pub(crate) fn transfer_size(&self) -> u64 {
        self.encrypted_data.len() as u64
    }

    #[allow(dead_code)] // Resource accessor API — see ROADMAP v1.1 (Resource Transfer)
    pub(crate) fn flags(&self) -> &ResourceFlags {
        &self.flags
    }

    #[allow(dead_code)] // Resource accessor API — see ROADMAP v1.1 (Resource Transfer)
    pub(crate) fn original_hash(&self) -> &[u8; 32] {
        &self.original_hash
    }

    #[allow(dead_code)] // Resource accessor API — see ROADMAP v1.1 (Resource Transfer)
    pub(crate) fn random_hash(&self) -> &[u8; RESOURCE_RANDOM_HASH_SIZE] {
        &self.random_hash
    }

    pub(crate) fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    #[allow(dead_code)] // Resource accessor API — see ROADMAP v1.1 (Resource Transfer)
    pub(crate) fn total_hashmap_segments(&self) -> u32 {
        self.total_hashmap_segments
    }

    #[allow(dead_code)] // Resource accessor API — see ROADMAP v1.1 (Resource Transfer)
    pub(crate) fn request_id(&self) -> Option<&[u8]> {
        self.request_id.as_deref()
    }

    #[allow(dead_code)] // Resource accessor API — see ROADMAP v1.1 (Resource Transfer)
    pub(crate) fn sdu(&self) -> usize {
        self.sdu
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::ResourceAdvertisement;

    /// Helper to create a test link with known keys.
    /// We use Link's test infrastructure.
    fn make_test_link() -> (Link, Link) {
        use rand_core::OsRng;
        let dest_hash = crate::destination::DestinationHash::new([0xAA; 16]);
        let mut initiator = Link::new_outgoing(dest_hash, &mut OsRng);

        // Create responder and complete handshake for testing
        let dest_hash2 = crate::destination::DestinationHash::new([0xBB; 16]);
        let responder = Link::new_outgoing(dest_hash2, &mut OsRng);

        // We need an active link for encryption — use the test helper
        // that sets link_key directly.
        let link_key = [0x42u8; 64];
        initiator.set_link_key_for_test(link_key);

        let mut resp = Link::new_outgoing(dest_hash, &mut OsRng);
        resp.set_link_key_for_test(link_key);

        // Both need to be Active
        initiator.set_state(crate::link::LinkState::Active);
        resp.set_state(crate::link::LinkState::Active);

        (initiator, resp)
    }

    #[test]
    fn test_outgoing_resource_creation() {
        let (link, _) = make_test_link();
        let mut rng = rand_core::OsRng;
        let data = b"Hello, Resource!";

        let res = OutgoingResource::new(data, None, None, &link, true, &mut rng, 1000).unwrap();

        assert_eq!(res.status(), ResourceStatus::Advertised);
        assert_eq!(res.num_parts, 1); // small data = 1 part
        assert!(!res.adv_packet().is_empty());
    }

    #[test]
    fn test_outgoing_resource_adv_roundtrip() {
        let (link, _) = make_test_link();
        let mut rng = rand_core::OsRng;
        let data = b"Test data for advertisement roundtrip";

        let res = OutgoingResource::new(data, None, None, &link, true, &mut rng, 1000).unwrap();

        // Verify the cached ADV unpacks correctly
        let adv = ResourceAdvertisement::unpack(res.adv_packet()).unwrap();
        assert_eq!(adv.resource_hash, *res.resource_hash());
        assert_eq!(adv.num_parts, res.num_parts);
        assert_eq!(adv.flags.encrypted, true);
        assert_eq!(adv.segment_index, 1);
        assert_eq!(adv.total_segments, 1);
        assert!(adv.request_id.is_none());
    }

    #[test]
    fn test_outgoing_resource_with_metadata() {
        let (link, _) = make_test_link();
        let mut rng = rand_core::OsRng;
        let data = b"data with metadata";
        let metadata = b"some metadata";

        let res =
            OutgoingResource::new(data, Some(metadata), None, &link, true, &mut rng, 1000).unwrap();

        let adv = ResourceAdvertisement::unpack(res.adv_packet()).unwrap();
        assert!(adv.flags.has_metadata);
    }

    #[test]
    fn test_outgoing_resource_proof_validation() {
        let (link, _) = make_test_link();
        let mut rng = rand_core::OsRng;
        let data = b"proof test data";

        let mut res = OutgoingResource::new(data, None, None, &link, true, &mut rng, 1000).unwrap();

        // Forge a valid proof: resource_hash + expected_proof
        let mut valid_proof = Vec::new();
        valid_proof.extend_from_slice(&res.resource_hash);
        valid_proof.extend_from_slice(&res.expected_proof);

        let result = res.handle_proof(&valid_proof).unwrap();
        assert_eq!(result, ResourceStatus::Complete);
        assert_eq!(res.status(), ResourceStatus::Complete);
    }

    #[test]
    fn test_outgoing_resource_invalid_proof() {
        let (link, _) = make_test_link();
        let mut rng = rand_core::OsRng;
        let data = b"proof test data";

        let mut res = OutgoingResource::new(data, None, None, &link, true, &mut rng, 1000).unwrap();

        // Invalid proof
        let bad_proof = [0u8; 64];
        assert_eq!(
            res.handle_proof(&bad_proof),
            Err(ResourceError::InvalidProof)
        );
    }

    #[test]
    fn test_outgoing_resource_poll_adv_timeout() {
        let (link, _) = make_test_link();
        let mut rng = rand_core::OsRng;
        let data = b"timeout test";

        let mut res = OutgoingResource::new(data, None, None, &link, true, &mut rng, 1000).unwrap();

        // Not timed out yet
        let result = res.poll(1000, 100);
        assert!(matches!(result, ResourcePollResult::Nothing));

        // Timed out (rtt_ms * 6 = 600ms)
        let result = res.poll(1601, 100);
        assert!(matches!(result, ResourcePollResult::RetransmitAdv(_)));

        // After max retries, should be TimedOut
        for _ in 0..RESOURCE_MAX_ADV_RETRIES {
            res.poll(res.last_activity_ms + 601, 100);
        }
        assert_eq!(res.status(), ResourceStatus::Failed);
    }

    #[test]
    fn test_outgoing_resource_hashmap_integrity() {
        let (link, _) = make_test_link();
        let mut rng = rand_core::OsRng;
        // Create data large enough for multiple parts
        let data = vec![0x42u8; 2000];

        let res = OutgoingResource::new(&data, None, None, &link, true, &mut rng, 1000).unwrap();

        // Verify each part's map_hash matches
        for (i, part) in res.parts.iter().enumerate() {
            let expected = map_hash(part, &res.random_hash);
            assert_eq!(res.hashmap[i], expected, "hashmap mismatch at part {i}");
        }
    }

    #[test]
    fn test_outgoing_resource_accessors() {
        let (link, _) = make_test_link();
        let mut rng = rand_core::OsRng;
        let data = b"accessor test data";
        let request_id = b"req-42";

        let mut res =
            OutgoingResource::new(data, None, Some(request_id), &link, true, &mut rng, 1000)
                .unwrap();

        // Protocol state fields accessible via accessors
        assert!(res.flags().encrypted);
        assert!(!res.flags().compressed);
        assert!(res.original_hash() != &[0u8; 32]);
        assert!(res.random_hash() != &[0u8; RESOURCE_RANDOM_HASH_SIZE]);
        assert!(res.uncompressed_size() > 0);
        assert!(res.total_hashmap_segments() >= 1);
        assert_eq!(res.request_id(), Some(request_id.as_slice()));
        assert!(res.sdu() > 0);

        // cancel() transitions to Failed
        res.cancel();
        assert_eq!(res.status(), ResourceStatus::Failed);
    }
}
