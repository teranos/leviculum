//! mvr for Bug #25 — interface-level TX spacing (F-A Path α).
//!
//! The 2026-04-17 capture-and-compare batch named interface-layer pacing
//! (C1 in `~/.claude/report.md`) as the mechanism Python has and we don't.
//! In a failing `lora_link_rust` run the host wrote two KISS frames to the
//! RNode 65 ms apart (LinkRequest 102 B at t+26.066 s, announce retransmit
//! 193 B at t+26.131 s). The RNode's own CSMA cannot absorb that spacing
//! when it is in its "light traffic" band (`cw_min=0`), so the peer's
//! LRPROOF emitted 6 ms after LRQ arrival landed on top of alpha's
//! still-in-flight announce and was lost.
//!
//! Root cause: `rnode_io_task`'s post-TX timer (see
//! `reticulum-std/src/interfaces/rnode.rs` around the TX gate) arms a
//! fixed 50 ms `MIN_SPACING_MS` between consecutive KISS writes. That is
//! the serial-buffer floor, not a CSMA-fair airtime spacing.
//!
//! F-A Path α routes the decision through `post_tx_spacing_ms` and
//! replaces its body with `rnode::compute_spacing_ms` (airtime + DIFS +
//! MAX_CW + margin). This mvr exercises the same helper so a red → green
//! transition accompanies the F-A commit.
//!
//! Pre-fix: `post_tx_spacing_ms(102, 62500, 7, 5)` returns
//! `MIN_SPACING_MS = 50` → the airtime-ratio assertions fail.
//! Post-fix: it returns `airtime(102) + DIFS + MAX_CW + margin` ≈ 950 ms
//! at SF7/BW62500 → the assertions pass.
//!
//! Carries `#[ignore = "red mvr: remove once Bug #25 F-A lands"]` on
//! the red tests so `just standard` stays green between the mvr commit
//! and the fix commit.
//!
//! No tokio, no hardware, < 100 ms. Pure-function mvr matching the
//! pattern of `scheduler_alignment.rs`.

use reticulum_core::rnode::{airtime_ms, CSMA_DIFS_MS, CSMA_MAX_CW_MS, MIN_SPACING_MS, PACING_MARGIN_MS};
use reticulum_std::interfaces::post_tx_spacing_ms;

/// Radio profile that `lora_link_rust` uses on the integ fixture.
const BW_HZ: u32 = 62_500;
const SF: u8 = 7;
const CR: u8 = 5;

/// Representative Phase-3 payloads captured in run-01 FAIL of
/// `/tmp/bug25-captures/rust/run-01/timeline.txt`.
const PAYLOAD_LINK_REQUEST: u64 = 102;
const PAYLOAD_ANNOUNCE: u64 = 193;
const PAYLOAD_PROOF: u64 = 118;

fn expected_airtime_spacing(payload: u64) -> u64 {
    airtime_ms(payload as u32, BW_HZ, SF, CR)
        + CSMA_DIFS_MS
        + CSMA_MAX_CW_MS
        + PACING_MARGIN_MS
}

/// Core property under test: at SF7/BW62500 a 102-byte LinkRequest TX
/// must be followed by at least one airtime+DIFS+CW+margin wait before
/// the next frame leaves the host. Pre-fix returns 50 ms and fails; the
/// F-A Path α fix routes the decision through `rnode::compute_spacing_ms`
/// and pushes the return value to ~950 ms.
#[test]
#[ignore = "red mvr: remove once Bug #25 F-A Path α lands"]
fn post_tx_spacing_lr_at_sf7_bw62500_exceeds_airtime_floor() {
    let expected = expected_airtime_spacing(PAYLOAD_LINK_REQUEST);
    let got = post_tx_spacing_ms(PAYLOAD_LINK_REQUEST, BW_HZ, SF, CR);
    let epsilon_ms = 10;
    assert!(
        got + epsilon_ms >= expected,
        "post_tx_spacing_ms(102B, SF7, BW62.5k) = {got} ms, \
         expected >= {expected} ms - epsilon ({epsilon_ms} ms). \
         Pre-fix returns {MIN_SPACING_MS} (MIN_SPACING_MS) which loses \
         the half-duplex race in run-01's LinkRequest+Proof exchange."
    );
}

/// Follow-on packet on the same scheduler tick (the announce retransmit
/// captured in run-01) must also be airtime-gated, not fall through the
/// floor. 193-byte announce has ~840 ms airtime.
#[test]
#[ignore = "red mvr: remove once Bug #25 F-A Path α lands"]
fn post_tx_spacing_announce_at_sf7_bw62500_exceeds_airtime_floor() {
    let expected = expected_airtime_spacing(PAYLOAD_ANNOUNCE);
    let got = post_tx_spacing_ms(PAYLOAD_ANNOUNCE, BW_HZ, SF, CR);
    let epsilon_ms = 10;
    assert!(
        got + epsilon_ms >= expected,
        "post_tx_spacing_ms(193B, SF7, BW62.5k) = {got} ms, \
         expected >= {expected} ms - epsilon ({epsilon_ms} ms). \
         This is the packet whose 65 ms-after-LRQ write caused the \
         Bug #25 collision."
    );
}

/// Proof-frame spacing (118 bytes, the LRPROOF that collided in run-01)
/// is the third representative size. At SF7/BW62500 airtime ~480 ms.
#[test]
#[ignore = "red mvr: remove once Bug #25 F-A Path α lands"]
fn post_tx_spacing_proof_at_sf7_bw62500_exceeds_airtime_floor() {
    let expected = expected_airtime_spacing(PAYLOAD_PROOF);
    let got = post_tx_spacing_ms(PAYLOAD_PROOF, BW_HZ, SF, CR);
    let epsilon_ms = 10;
    assert!(
        got + epsilon_ms >= expected,
        "post_tx_spacing_ms(118B, SF7, BW62.5k) = {got} ms, \
         expected >= {expected} ms - epsilon ({epsilon_ms} ms)."
    );
}

/// Worst-case verification: at SF10/BW125000 (slowest radio profile
/// present in the test matrix) airtime dominates and the spacing must
/// scale with it, not stay pinned at the fast-mode floor. Hand-computed
/// airtime ~3 s for 500 B → spacing ≥ 3 s + DIFS + CW + margin.
#[test]
#[ignore = "red mvr: remove once Bug #25 F-A Path α lands"]
fn post_tx_spacing_sf10_bw125k_worst_case() {
    let expected = expected_airtime_spacing(500);
    let got = post_tx_spacing_ms(500, 125_000, 10, 5);
    let slack = 200; // 5 % of ~3 s is 150 ms; round up to 200.
    assert!(
        got + slack >= expected,
        "post_tx_spacing_ms(500B, SF10, BW125k) = {got} ms, \
         expected >= {expected} ms - slack ({slack} ms)"
    );
    // Sanity: must be substantially larger than fast-mode SF7/BW62500.
    let sf7 = post_tx_spacing_ms(500, BW_HZ, SF, CR);
    assert!(
        got > sf7,
        "SF10/BW125 spacing ({got} ms) must exceed SF7/BW62.5k spacing \
         ({sf7} ms) because airtime dominates for slow modes"
    );
}

/// Floor verification: a 1-byte packet cannot drive the spacing below
/// `MIN_SPACING_MS` — the serial-buffer floor must be respected even
/// when airtime is tiny. Passes both pre- and post-fix because
/// `compute_spacing_ms` applies `.max(MIN_SPACING_MS)` explicitly.
#[test]
fn post_tx_spacing_short_packet_respects_floor() {
    let got = post_tx_spacing_ms(1, BW_HZ, SF, CR);
    assert!(
        got >= MIN_SPACING_MS,
        "post_tx_spacing_ms(1B, SF7, BW62.5k) = {got} ms must never drop \
         below MIN_SPACING_MS = {MIN_SPACING_MS} ms (serial-buffer floor)"
    );
}
