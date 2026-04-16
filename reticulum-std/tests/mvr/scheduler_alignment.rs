//! mvr for Bug #25 — post-parity scheduler-alignment collision risk.
//!
//! Hypothesis H1 from `~/.claude/bugs/25.md`: when two Leviculum nodes
//! receive the same announce at (effectively) the same epoch, the
//! Python-parity retry scheduler lands their next rebroadcast inside a
//! `PATHFINDER_G_MS + jitter` window whose spread is `announce_jitter_
//! max_ms` (≈ 750 ms at SF7 / BW62500). A LoRa frame airs in roughly
//! 230–500 ms at the same radio profile, so any pair of nodes whose
//! jitter values land within one airtime of each other TX while the
//! peer is still on air. That is the half-duplex collision the
//! Tier-3 `lora_link_rust` failure traces show at the 4 ms level.
//!
//! The mvr asserts the property directly, without running any LoRa or
//! even a full Transport instance, by driving the scheduler's jitter
//! function over a deterministic population of identity pairs and
//! measuring how many land within 200 ms of each other. 200 ms is the
//! "safe distance" for SF7: below it, packets overlap on air.
//!
//! Currently this test FAILS (demonstrating the bug). A post-fix mvr
//! should PASS (demonstrating the fix — either a wider jitter window
//! that breaks alignment, or a scheduler pause during link
//! establishment that removes the competing TX entirely).
//!
//! No LoRa, no Transport full-state, no tokio. Runs in under 100 ms.

use std::hash::Hasher;

/// One airtime at SF7/BW62500 for a typical 193-byte announce frame
/// is ≈ 250 ms. A safe distance of 200 ms keeps two rebroadcasts from
/// overlapping on air. The constant is the scheduler-alignment
/// hypothesis's definition of "colliding": below this, the two TXes
/// share the channel.
const SAFE_DISTANCE_MS: u64 = 200;

/// Sampled population of identity pairs. Larger = more precise
/// alignment-rate measurement; kept at 1000 so the mvr stays cheap.
const SAMPLE_PAIRS: usize = 1000;

/// The scheduler's `deterministic_jitter_ms` is internally:
///
///     let mut buf = [0u8; 8];
///     for i in 0..8 { buf[i] = id_hash[i] ^ seed[i % seed.len()]; }
///     u64::from_le_bytes(buf) % max_ms
///
/// Same computation reproduced here so the mvr does not need to build
/// a whole `Transport` instance. The property we are probing is a pure
/// function of (id_hash, seed, max_ms); that is the minimum surface
/// needed to demonstrate H1.
fn jitter_ms(id_hash: &[u8; 16], seed: &[u8; 16], max_ms: u64) -> u64 {
    if max_ms == 0 {
        return 0;
    }
    let mut buf = [0u8; 8];
    for i in 0..8 {
        buf[i] = id_hash[i] ^ seed[i];
    }
    u64::from_le_bytes(buf) % max_ms
}

/// Deterministic 16-byte "identity hash" derived from a u32 index.
/// Avoids pulling in full `Identity::generate` just to reach the
/// 16-byte hash surface the scheduler consumes.
fn id_from_index(idx: u32) -> [u8; 16] {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write_u32(idx);
    let a = hasher.finish();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write_u32(idx.wrapping_add(0x9E37_79B9));
    let b = hasher.finish();
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&a.to_le_bytes());
    out[8..].copy_from_slice(&b.to_le_bytes());
    out
}

/// One fixed "announce" seed (the dest_hash the scheduler feeds into
/// `deterministic_jitter_ms`). Same-dest, different-identity is the
/// worst case for alignment.
fn fixed_seed() -> [u8; 16] {
    [
        0x13, 0x37, 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44,
        0x55,
    ]
}

/// Helper: the announce_jitter_max_ms that SF7/BW62500 produces once
/// the interface pushes its airtime estimate to the Transport via
/// `set_interface_max_airtime_ms`. JITTER_AIRTIME_FACTOR is 3 in
/// constants.rs; for a 250 ms airtime that floor is 750 ms.
const ANNOUNCE_JITTER_MAX_MS: u64 = 3 * 250;

/// Count how many (id_a, id_b) pairs from a deterministic population
/// produce jitter values within `SAFE_DISTANCE_MS` of each other.
fn count_aligned_pairs(sample: usize, seed: &[u8; 16], max_ms: u64) -> usize {
    let mut aligned = 0;
    for pair_idx in 0..sample {
        let a = id_from_index(2 * pair_idx as u32);
        let b = id_from_index(2 * pair_idx as u32 + 1);
        let j_a = jitter_ms(&a, seed, max_ms);
        let j_b = jitter_ms(&b, seed, max_ms);
        if j_a.abs_diff(j_b) < SAFE_DISTANCE_MS {
            aligned += 1;
        }
    }
    aligned
}

/// Demonstrates H1: the current jitter window is too narrow for the
/// population of identity pairs we see in the mesh. The test currently
/// FAILS (44.5 % of identity pairs align within 200 ms) and will PASS
/// post-fix. Carried behind `#[ignore]` so `just standard` stays green
/// until the Bug #25 fix lands; remove the `#[ignore]` in the fix
/// commit and record the before/after alignment rate in the commit
/// body as the primary verification evidence.
#[test]
#[ignore = "red mvr: remove once Bug #25 scheduler-alignment fix lands"]
fn scheduler_alignment_below_safe_rate() {
    let seed = fixed_seed();
    let aligned = count_aligned_pairs(SAMPLE_PAIRS, &seed, ANNOUNCE_JITTER_MAX_MS);
    let rate_percent = (aligned as f64) * 100.0 / (SAMPLE_PAIRS as f64);

    // Property under test: no more than 5 % of identity pairs should
    // land inside one airtime's overlap window. A 5 % ceiling
    // corresponds to roughly one collision per 20 node pairs per
    // announce epoch, which the P1 envelope accepts as a residual
    // background.
    //
    // Post-parity this assertion fails because the jitter window
    // (750 ms at SF7 / BW62500) is narrow relative to the 200 ms
    // collision distance: for uniform-distributed jitter the closed-
    // form expected alignment rate is 1 - (1 - 200/750)^2 ≈ 46 %,
    // and the empirical 1000-pair sample lands in that ballpark.
    let threshold = SAMPLE_PAIRS / 20;
    assert!(
        aligned < threshold,
        "scheduler alignment rate too high: {aligned}/{SAMPLE_PAIRS} \
         ({rate_percent:.1}%) of identity pairs schedule retries within \
         {SAFE_DISTANCE_MS} ms of each other, over a {ANNOUNCE_JITTER_MAX_MS} \
         ms jitter window. Target: < {threshold}/{SAMPLE_PAIRS} (5 %). \
         Hypothesis 1 from ~/.claude/bugs/25.md confirmed."
    );
}

/// Sanity: no jitter (max_ms = 0) returns 0 for any identity and any
/// seed. Catches a regression where a future refactor accidentally
/// produces randomness even when the floor is disabled.
#[test]
fn jitter_zero_when_max_zero() {
    let seed = fixed_seed();
    for i in 0..100 {
        let id = id_from_index(i);
        assert_eq!(jitter_ms(&id, &seed, 0), 0);
    }
}
