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
//!
//! # H1 follow-up (2026-04-17)
//!
//! Extended with `measure_alignment_rate(...)` for parametric sweeps
//! over (jitter_max_ms, extra_random_max_ms, collision_distance_ms).
//! The `#[ignore]` test `print_h1_variant_sweep` prints the two
//! candidate-fix tables used to pick between widening the
//! deterministic window (Variant A) and adding a fresh random draw
//! on top (Variant B). Measurement-only; the sweep output is
//! informational, not threshold-asserted.

use std::hash::Hasher;

use rand_core::{OsRng, RngCore};

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

// ---------------------------------------------------------------------------
// H1 follow-up — parametric sweep helpers
// ---------------------------------------------------------------------------
//
// The original test above answers "is the current jitter window narrow
// enough that the alignment rate exceeds 5 %?". The sweep below answers
// "for each candidate parameter point, what IS the alignment rate, and
// what propagation-latency cost does it carry?". Two variants under
// consideration:
//
//   Variant A — widen the deterministic jitter window:
//     jitter_max_ms ∈ {2925, 3900, 5850, 7800, 9750} ms (3×, 4×, 6×,
//     8×, 10× worst-case airtime of 975 ms at SF7/BW62500).
//     extra_random_max_ms = 0.
//
//   Variant B — keep 2925 ms deterministic, add a fresh random draw:
//     jitter_max_ms = 2925 ms.
//     extra_random_max_ms ∈ {0, 50, 100, 250, 500, 1000} ms.
//
// Each point reports (alignment@200ms, alignment@600ms, p50, p95) so
// the reviewer can weigh alignment reduction against latency cost.

/// Sample one (deterministic + optional random) jitter value for a
/// given identity. `extra_random_max_ms == 0` reproduces the pure
/// `deterministic_jitter_ms` behaviour exactly.
fn jitter_sample_ms(
    id: &[u8; 16],
    seed: &[u8; 16],
    jitter_max_ms: u64,
    extra_random_max_ms: u64,
) -> u64 {
    let det = jitter_ms(id, seed, jitter_max_ms);
    if extra_random_max_ms == 0 {
        return det;
    }
    // rand_core::OsRng is already used elsewhere in the crate (see
    // rnode.rs jitter path). Each call pulls 8 fresh bytes from the
    // OS entropy pool, so two consecutive calls in the same test
    // row yield independent draws.
    let r = OsRng.next_u64() % extra_random_max_ms;
    det + r
}

/// Count aligned pairs and collect the full jitter distribution so we
/// can report p50 / p95. Both sides of each pair are sampled; the
/// collision check is `|j_a - j_b| < collision_distance_ms`.
fn sweep_one_point(
    sample_pairs: usize,
    seed: &[u8; 16],
    jitter_max_ms: u64,
    extra_random_max_ms: u64,
    collision_distance_ms: u64,
) -> SweepPoint {
    let mut aligned = 0usize;
    let mut all_jitters: Vec<u64> = Vec::with_capacity(sample_pairs * 2);
    for pair_idx in 0..sample_pairs {
        let a = id_from_index(2 * pair_idx as u32);
        let b = id_from_index(2 * pair_idx as u32 + 1);
        let j_a = jitter_sample_ms(&a, seed, jitter_max_ms, extra_random_max_ms);
        let j_b = jitter_sample_ms(&b, seed, jitter_max_ms, extra_random_max_ms);
        if j_a.abs_diff(j_b) < collision_distance_ms {
            aligned += 1;
        }
        all_jitters.push(j_a);
        all_jitters.push(j_b);
    }
    all_jitters.sort_unstable();
    let p50 = all_jitters[all_jitters.len() / 2];
    let p95 = all_jitters[(all_jitters.len() * 95) / 100];
    SweepPoint {
        aligned_rate: aligned as f64 / sample_pairs as f64,
        p50_ms: p50,
        p95_ms: p95,
    }
}

#[derive(Clone, Copy)]
struct SweepPoint {
    aligned_rate: f64,
    p50_ms: u64,
    p95_ms: u64,
}

/// Public measurement entry point for both variants.
///
/// `jitter_max_ms` controls the deterministic window (Variant A).
/// `extra_random_max_ms` adds an independent random draw on top
/// (Variant B). Setting `extra_random_max_ms = 0` reduces this to
/// the pure deterministic measurement. The function returns only
/// the alignment rate; the full sweep that includes p50/p95 is in
/// `sweep_one_point` above.
fn measure_alignment_rate(
    sample_pairs: usize,
    jitter_max_ms: u64,
    extra_random_max_ms: u64,
    collision_distance_ms: u64,
) -> f64 {
    let seed = fixed_seed();
    sweep_one_point(
        sample_pairs,
        &seed,
        jitter_max_ms,
        extra_random_max_ms,
        collision_distance_ms,
    )
    .aligned_rate
}

/// Sanity: the extraction preserves the original test's measurement
/// exactly when fed the original parameters. Guards against a silent
/// refactor that changes the math.
#[test]
fn measure_alignment_rate_matches_original_mvr() {
    let rate = measure_alignment_rate(SAMPLE_PAIRS, ANNOUNCE_JITTER_MAX_MS, 0, SAFE_DISTANCE_MS);
    // The original test reported ~46 %; the deterministic count is
    // exactly reproducible between runs because no randomness is
    // introduced when extra_random_max_ms = 0.
    assert!(
        (0.30..=0.60).contains(&rate),
        "alignment rate {rate} fell outside the expected 30–60 % band \
         for the characterisation-test parameters"
    );
}

/// Prints both variant tables. Not an assertion — its purpose is to
/// surface the data for the reviewer picking between Variant A and
/// Variant B. `#[ignore]` so it does not clutter `just standard`.
#[test]
#[ignore = "prints parametric sweep tables for Bug #25 H1 decision"]
fn print_h1_variant_sweep() {
    // 975 ms ≈ worst-case airtime at SF7/BW62500 for a 500-byte
    // Reticulum packet (rnode::airtime_ms formula). Keeping the
    // multiplier explicit here so readers can cross-check against
    // `transport.rs` when the fix lands.
    const WORST_AIRTIME_MS: u64 = 975;
    const SAMPLE_PAIRS_SWEEP: usize = 10_000;

    let seed = fixed_seed();

    // Variant A — widen the deterministic window only.
    println!("# Variant A — widen deterministic jitter window");
    println!("# sample_pairs = {SAMPLE_PAIRS_SWEEP}, extra_random_max_ms = 0");
    println!(
        "# {:>4} | {:>9} | {:>12} | {:>12} | {:>7} | {:>7}",
        "mult", "jitter_ms", "align@200ms", "align@600ms", "p50_ms", "p95_ms"
    );
    for mult in [3, 4, 6, 8, 10] {
        let jitter_max = (mult as u64) * WORST_AIRTIME_MS;
        let pt_200 = sweep_one_point(SAMPLE_PAIRS_SWEEP, &seed, jitter_max, 0, 200);
        let pt_600 = sweep_one_point(SAMPLE_PAIRS_SWEEP, &seed, jitter_max, 0, 600);
        // p50/p95 do not depend on the collision distance; read from
        // the first measurement.
        println!(
            "# {:>4} | {:>9} | {:>11.2}% | {:>11.2}% | {:>7} | {:>7}",
            format!("{}x", mult),
            jitter_max,
            pt_200.aligned_rate * 100.0,
            pt_600.aligned_rate * 100.0,
            pt_200.p50_ms,
            pt_200.p95_ms,
        );
        // Sanity on the two readings: the collision-count at 600 ms
        // collision distance cannot be smaller than at 200 ms (wider
        // window catches strict superset of pairs). This is a quiet
        // self-check.
        assert!(pt_600.aligned_rate >= pt_200.aligned_rate - f64::EPSILON);
    }

    println!();

    // Variant B — keep jitter at the current 3× baseline, add random.
    const BASELINE_JITTER_MS: u64 = 3 * WORST_AIRTIME_MS;
    println!("# Variant B — deterministic + extra random");
    println!(
        "# sample_pairs = {SAMPLE_PAIRS_SWEEP}, \
         jitter_max_ms = {BASELINE_JITTER_MS} (= 3x worst airtime)"
    );
    println!(
        "# {:>8} | {:>12} | {:>12} | {:>7} | {:>7}",
        "extra_ms", "align@200ms", "align@600ms", "p50_ms", "p95_ms"
    );
    for extra in [0u64, 50, 100, 250, 500, 1000] {
        let pt_200 = sweep_one_point(SAMPLE_PAIRS_SWEEP, &seed, BASELINE_JITTER_MS, extra, 200);
        let pt_600 = sweep_one_point(SAMPLE_PAIRS_SWEEP, &seed, BASELINE_JITTER_MS, extra, 600);
        println!(
            "# {:>8} | {:>11.2}% | {:>11.2}% | {:>7} | {:>7}",
            extra,
            pt_200.aligned_rate * 100.0,
            pt_600.aligned_rate * 100.0,
            pt_200.p50_ms,
            pt_200.p95_ms,
        );
    }
}

// ---------------------------------------------------------------------------
// H1 follow-up round 2 — exhaustive cross-profile sweep
// ---------------------------------------------------------------------------

use reticulum_core::rnode::airtime_ms;

/// The three radio profiles represented by the integ-test matrix.
/// `worst_airtime_ms` is the 500-byte airtime under each profile,
/// computed by `rnode::airtime_ms` so the numbers in the report track
/// the same helper the production `announce_jitter_max_ms` builds on.
#[derive(Clone, Copy)]
struct Profile {
    name: &'static str,
    sf: u8,
    bw_hz: u32,
    cr: u8,
    // Three collision distances worth reporting for each profile's
    // typical air-time regime.
    cds: [u64; 3],
}

const FAST: Profile = Profile {
    name: "Fast",
    sf: 7,
    bw_hz: 500_000,
    cr: 5,
    cds: [30, 60, 120],
};
const MEDIUM: Profile = Profile {
    name: "Medium",
    sf: 7,
    bw_hz: 62_500,
    cr: 5,
    cds: [100, 300, 600],
};
const SLOW: Profile = Profile {
    name: "Slow",
    sf: 10,
    bw_hz: 125_000,
    cr: 5,
    cds: [500, 1500, 3000],
};

fn worst_airtime(p: Profile) -> u64 {
    airtime_ms(500, p.bw_hz, p.sf, p.cr)
}

/// Derive a 16-byte seed from a u32 index. Used for seed-robustness
/// measurements so the same multiplier point can be probed against
/// many independent destination seeds.
fn seed_from_index(idx: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, chunk) in out.chunks_mut(4).enumerate() {
        let v = idx
            .wrapping_mul(0x9E37_79B9)
            .wrapping_add(i as u32)
            .to_le_bytes();
        chunk.copy_from_slice(&v);
    }
    out
}

/// Probability that at least one pair among `n` identities schedules
/// within `collision_distance_ms` of each other for the given jitter
/// parameters. Returns a rate in [0, 1].
fn n_node_alignment_rate(
    n: usize,
    sample_groups: usize,
    seed: &[u8; 16],
    jitter_max_ms: u64,
    extra_random_max_ms: u64,
    collision_distance_ms: u64,
) -> f64 {
    assert!(n >= 2);
    let mut aligned_groups = 0usize;
    let mut jitters = vec![0u64; n];
    for group_idx in 0..sample_groups {
        for k in 0..n {
            let id = id_from_index((group_idx * n + k) as u32);
            jitters[k] = jitter_sample_ms(&id, seed, jitter_max_ms, extra_random_max_ms);
        }
        jitters.sort_unstable();
        let any_pair_close = (1..n).any(|k| jitters[k] - jitters[k - 1] < collision_distance_ms);
        if any_pair_close {
            aligned_groups += 1;
        }
    }
    aligned_groups as f64 / sample_groups as f64
}

/// Matrix 1 — fine multiplier sweep, one sub-table per profile.
/// Reports alignment rate at three collision distances, plus p50 / p95
/// of the jitter distribution (these do not depend on the collision
/// distance so we sample once).
#[test]
#[ignore = "prints H1 exhaustive sweep matrix 1"]
fn print_h1_matrix1_multiplier_per_profile() {
    const SAMPLE_PAIRS: usize = 100_000;
    const MULTS: &[f64] = &[
        1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 12.0, 15.0, 20.0,
    ];
    let seed = fixed_seed();
    for profile in [FAST, MEDIUM, SLOW] {
        let airtime = worst_airtime(profile);
        println!(
            "\n# Matrix 1 — {} profile (SF{} BW{} CR4/{}, worst_airtime = {} ms)",
            profile.name, profile.sf, profile.bw_hz, profile.cr, airtime
        );
        println!("# sample_pairs = {SAMPLE_PAIRS}, extra_random_max_ms = 0");
        println!(
            "# {:>6} | {:>10} | {:>9} ms | {:>9} ms | {:>9} ms | {:>7} | {:>8}",
            "mult",
            "jitter_ms",
            format!("@{}ms", profile.cds[0]),
            format!("@{}ms", profile.cds[1]),
            format!("@{}ms", profile.cds[2]),
            "p50_ms",
            "p95_ms",
        );
        for &mult in MULTS {
            let jitter_max = (mult * airtime as f64) as u64;
            let pt0 = sweep_one_point(SAMPLE_PAIRS, &seed, jitter_max, 0, profile.cds[0]);
            let pt1 = sweep_one_point(SAMPLE_PAIRS, &seed, jitter_max, 0, profile.cds[1]);
            let pt2 = sweep_one_point(SAMPLE_PAIRS, &seed, jitter_max, 0, profile.cds[2]);
            println!(
                "# {:>6} | {:>10} | {:>8.2}%   | {:>8.2}%   | {:>8.2}%   | {:>7} | {:>8}",
                format!("{:.1}x", mult),
                jitter_max,
                pt0.aligned_rate * 100.0,
                pt1.aligned_rate * 100.0,
                pt2.aligned_rate * 100.0,
                pt0.p50_ms,
                pt0.p95_ms,
            );
        }
    }
}

/// Matrix 2 — 2D hybrid grid (multiplier × extra_random) at Medium.
/// Single collision distance 600 ms, the typical mid-announce airtime.
#[test]
#[ignore = "prints H1 exhaustive sweep matrix 2"]
fn print_h1_matrix2_hybrid_grid_medium() {
    const SAMPLE_PAIRS: usize = 50_000;
    const MULTS: &[f64] = &[3.0, 4.0, 5.0, 6.0, 8.0, 10.0];
    const EXTRAS: &[u64] = &[0, 100, 250, 500, 1000, 2000];
    const CD: u64 = 600;
    let airtime = worst_airtime(MEDIUM);
    let seed = fixed_seed();
    println!(
        "\n# Matrix 2 — 2D hybrid grid at {} profile (worst_airtime = {} ms)",
        MEDIUM.name, airtime
    );
    println!("# sample_pairs = {SAMPLE_PAIRS}, collision_distance = {CD} ms");
    println!("# Each cell: alignment rate (%). Row = mult, column = extra_random_ms.");
    print!("# {:>6}", "mult\\r");
    for &e in EXTRAS {
        print!(" | {:>8}", e);
    }
    println!();
    for &mult in MULTS {
        let jitter_max = (mult * airtime as f64) as u64;
        print!("# {:>6}", format!("{:.1}x", mult));
        for &extra in EXTRAS {
            let pt = sweep_one_point(SAMPLE_PAIRS, &seed, jitter_max, extra, CD);
            print!(" | {:>7.2}%", pt.aligned_rate * 100.0);
        }
        println!();
    }
}

/// Matrix 3 — group-wise alignment probability as a function of mesh
/// size. Shows how the pair-wise 5 % number scales up in real meshes.
#[test]
#[ignore = "prints H1 exhaustive sweep matrix 3"]
fn print_h1_matrix3_n_node_scaling() {
    const SAMPLE_GROUPS: usize = 20_000;
    const MULT: f64 = 8.0;
    const CD: u64 = 600;
    let airtime = worst_airtime(MEDIUM);
    let jitter_max = (MULT * airtime as f64) as u64;
    let seed = fixed_seed();
    println!(
        "\n# Matrix 3 — N-node scaling at {} profile, mult = {}x, jitter_max = {} ms, CD = {} ms",
        MEDIUM.name, MULT, jitter_max, CD
    );
    println!("# sample_groups = {SAMPLE_GROUPS}");
    println!("# {:>4} | {:>10} | {:>10}", "N", "any_pair_%", "expected_%");
    for n in [2usize, 3, 4, 5, 6, 8, 10, 16] {
        let rate = n_node_alignment_rate(n, SAMPLE_GROUPS, &seed, jitter_max, 0, CD);
        // Independent-uniform expectation for "at least one pair within
        // CD among N uniform draws on W": approx
        //     P(at least one) ≈ 1 - (1 - (N-1)*CD/W)  for small CD/W
        // Exact formula is complex but this gives the reviewer a quick
        // sanity column.
        let pair_p = (CD as f64) / (jitter_max as f64);
        let pair_p = pair_p.min(1.0);
        let exp = 1.0 - (1.0 - pair_p).powi(((n * (n - 1)) / 2) as i32);
        println!(
            "# {:>4} | {:>9.2}% | {:>9.2}%",
            n,
            rate * 100.0,
            exp * 100.0
        );
    }
}

/// Matrix 4 — profile-equivalent multipliers. For each profile, find
/// the multiplier from Matrix 1's grid that gets closest to 5 %
/// alignment at the middle collision distance.
#[test]
#[ignore = "prints H1 exhaustive sweep matrix 4"]
fn print_h1_matrix4_profile_equivalence() {
    const SAMPLE_PAIRS: usize = 100_000;
    const TARGET: f64 = 0.05;
    // Same fine-grained sweep Matrix 1 used, so the numbers match.
    const MULTS: &[f64] = &[
        1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 12.0, 15.0, 20.0,
    ];
    let seed = fixed_seed();
    println!("\n# Matrix 4 — multiplier per profile to reach ~5 % alignment");
    println!("# sample_pairs = {SAMPLE_PAIRS}, collision_distance = profile.cds[1] (middle value)");
    println!(
        "# {:>8} | {:>4} | {:>5} | {:>5} | {:>9} | {:>9} | {:>9}",
        "profile", "mult", "cd_ms", "rate%", "jitter_ms", "p50_ms", "p95_ms"
    );
    for profile in [FAST, MEDIUM, SLOW] {
        let airtime = worst_airtime(profile);
        let cd = profile.cds[1];
        let mut best_mult = MULTS[0];
        let mut best_point = sweep_one_point(
            SAMPLE_PAIRS,
            &seed,
            (MULTS[0] * airtime as f64) as u64,
            0,
            cd,
        );
        let mut best_delta = (best_point.aligned_rate - TARGET).abs();
        for &mult in &MULTS[1..] {
            let jitter_max = (mult * airtime as f64) as u64;
            let pt = sweep_one_point(SAMPLE_PAIRS, &seed, jitter_max, 0, cd);
            let delta = (pt.aligned_rate - TARGET).abs();
            // Prefer the point that is closest to 5 % but on the
            // "sufficient" side when there is a tie. Small nudge:
            // if the new candidate is below 5 % and the incumbent is
            // above, prefer the new one.
            let prefer_new = delta < best_delta
                || (pt.aligned_rate <= TARGET && best_point.aligned_rate > TARGET);
            if prefer_new {
                best_mult = mult;
                best_point = pt;
                best_delta = delta;
            }
        }
        let jitter_max = (best_mult * airtime as f64) as u64;
        println!(
            "# {:>8} | {:>4} | {:>5} | {:>4.2}% | {:>9} | {:>9} | {:>9}",
            profile.name,
            format!("{:.1}x", best_mult),
            cd,
            best_point.aligned_rate * 100.0,
            jitter_max,
            best_point.p50_ms,
            best_point.p95_ms,
        );
    }
}

/// Matrix 5 — seed robustness. For the "5 % alignment" multiplier
/// from Matrix 4, measure the rate across 10 independent destination
/// seeds and report mean + standard deviation.
#[test]
#[ignore = "prints H1 exhaustive sweep matrix 5"]
fn print_h1_matrix5_seed_robustness() {
    const SAMPLE_PAIRS: usize = 100_000;
    const N_SEEDS: u32 = 10;
    // Hand-picked multipliers from Matrix 1 preview (will be refined
    // once Matrix 4 output is in). If Matrix 4's picks disagree, the
    // reviewer should update these.
    let picks: [(Profile, f64); 3] = [(FAST, 8.0), (MEDIUM, 8.0), (SLOW, 8.0)];
    println!("\n# Matrix 5 — seed robustness for the 5 % multipliers");
    println!("# sample_pairs = {SAMPLE_PAIRS}, n_seeds = {N_SEEDS}");
    println!(
        "# {:>8} | {:>4} | {:>5} | {:>9} | {:>9} | {:>9}",
        "profile", "mult", "cd_ms", "mean_%", "stdev_%", "range"
    );
    for (profile, mult) in picks {
        let airtime = worst_airtime(profile);
        let cd = profile.cds[1];
        let jitter_max = (mult * airtime as f64) as u64;
        let mut rates: Vec<f64> = Vec::with_capacity(N_SEEDS as usize);
        for i in 0..N_SEEDS {
            let seed = seed_from_index(i);
            let pt = sweep_one_point(SAMPLE_PAIRS, &seed, jitter_max, 0, cd);
            rates.push(pt.aligned_rate);
        }
        let mean = rates.iter().sum::<f64>() / rates.len() as f64;
        let var = rates.iter().map(|r| (r - mean).powi(2)).sum::<f64>() / rates.len() as f64;
        let stdev = var.sqrt();
        let min = rates.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = rates.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        println!(
            "# {:>8} | {:>4} | {:>5} | {:>8.2}% | {:>8.3}% | {:>4.2}-{:.2}%",
            profile.name,
            format!("{:.1}x", mult),
            cd,
            mean * 100.0,
            stdev * 100.0,
            min * 100.0,
            max * 100.0,
        );
    }
}

/// Matrix 6 — fine collision-distance sweep at the 8× multiplier for
/// the Medium profile, showing the full alignment-vs-distance curve.
#[test]
#[ignore = "prints H1 exhaustive sweep matrix 6"]
fn print_h1_matrix6_cd_sweep_medium() {
    const SAMPLE_PAIRS: usize = 100_000;
    const MULT: f64 = 8.0;
    const CDS: &[u64] = &[50, 100, 150, 200, 300, 400, 500, 600, 800, 1000, 1500, 2000];
    let airtime = worst_airtime(MEDIUM);
    let jitter_max = (MULT * airtime as f64) as u64;
    let seed = fixed_seed();
    println!(
        "\n# Matrix 6 — CD sweep at {} profile, mult = {}x, jitter_max = {} ms",
        MEDIUM.name, MULT, jitter_max
    );
    println!("# sample_pairs = {SAMPLE_PAIRS}");
    println!("# {:>6} | {:>9}", "cd_ms", "align_%");
    for &cd in CDS {
        let pt = sweep_one_point(SAMPLE_PAIRS, &seed, jitter_max, 0, cd);
        println!("# {:>6} | {:>8.2}%", cd, pt.aligned_rate * 100.0);
    }
}
