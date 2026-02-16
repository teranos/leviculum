# leviculum — Issues Tracker

All known issues that cannot be fixed immediately go here.
When an issue is fixed, remove it from this file entirely.

## Phases

Phase numbering follows `doc/BATTLEPLAN.md`. Phases 0–6 are complete.

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Cleanup | done |
| 1 | Test infrastructure | done |
| 2 | Test coverage (TDD) | done |
| 3 | Bug fixes | done |
| 4 | The big rename (Connection → Link) | done |
| 5 | Structural refactoring (LinkManager dissolution) | done |
| 6 | Consolidation (SSOT, receipt tracking) | done |
| 7 | API polish (naming, visibility, perf) | **in progress** |

## Status Overview

| ID | P | Phase | Status | Category | Summary |
|----|---|-------|--------|----------|---------|
| E8 | H | 7 | open | Feature gap | Single-packet encryption missing |

---

## Issues

### E8: Single-packet encryption missing
- **Status:** open
- **Priority:** HIGH
- **Phase:** 7
- **Category:** Feature gap
- **Blocked-by:** —
- **Detail:** `send_single_packet()` sends plaintext. Python `Destination.SINGLE` always decrypts incoming data via X25519 (`Destination.decrypt()` → `Identity.decrypt()`). Every single packet from Rust to Python is silently dropped because decryption fails and `Destination.receive()` returns `False`. This blocks all single-packet interop including the proof round-trip test (`test_single_packet_proof_round_trip_via_node`, currently `#[ignore]`). Needs: encrypt payload using destination's public key before sending, matching Python's `Packet.encrypt()` / `Identity.encrypt()`.
- **Fix:** In `send_single_packet()`, look up the destination's public key and encrypt the payload with X25519+AES before packing. Mirror Python's `Identity.encrypt()` which uses ephemeral X25519 key exchange + Fernet token.
- **Test:** Un-ignore `test_single_packet_proof_round_trip_via_node` in `proof_tests.rs`. Add dedicated encrypt/decrypt interop test.


