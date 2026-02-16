# leviculum — Refactoring Battle Plan

Phases 0–7 complete.

---

## Phases 0–5: Complete

44 issues resolved. See git history for details.

| Phase | Issues | Description |
|-------|--------|-------------|
| 0 | 17 | Cleanup (dead code, renames, docs) |
| 1 | 5 | Test infrastructure (MockClock, helpers, constants) |
| 2 | 8 | Test coverage / TDD (red tests for known bugs) |
| 3 | 4 | Bug fixes (GC, cleanup, mark_delivered) |
| 4 | 7 | The big rename (Connection → Link) |
| 5 | 3 | Structural refactoring (LinkManager dissolution) |

---

## Phase 6: Consolidation — Complete

**All 5 issues done (E5, E1, H4+A4, E6, H1). Bugs found and fixed during H1.**

| # | Issue | What | Status |
|---|-------|------|--------|
| 1 | E5 | Verify cleanup path for unregister_destination | Verified clean (no bug) |
| 2 | E1 | Split `handle_link_data` god method | Done — 5 per-context handlers |
| 3 | H4+A4 | Consolidate receipt tracking into `ReceiptTracker` | Done — single owner for receipt state |
| 4 | E6 | Split `handle_channel_packet` into sub-methods | Done |
| 5 | H1 | Deduplicate `Transport.destinations` vs `NodeCore.destinations` | Done — `DestinationEntry` eliminated, Transport uses `BTreeSet<hash>` |

**Bugs found and fixed during H1:**

| Bug | Detail | Commit |
|-----|--------|--------|
| Proof verification identity always `None` | `register_destination_with_proof()` passed `None` for identity; proof verification used Transport's copy (always `None`) instead of NodeCore's Destination. Moved verification to NodeCore. | Step 1 |
| Proof generation Bug 1: All/App dispatch inverted | `ProofStrategy::All` emitted `NodeEvent::ProofRequested` (app callback) instead of auto-sending. `App` auto-sent instead of emitting. | 9358fad |
| Proof generation Bug 2: missing `send_proof` call | `ProofStrategy::All` branch never called `transport.send_proof()`. | 9358fad |
| Proof generation Bug 3: docstring mismatch | Docstring described correct behavior but code did the opposite. | 9358fad |

**Issues eliminated by Phase 5c (no longer needed):**

| Issue | Why eliminated |
|-------|--------------|
| A3 | `channel_hash_to_seq` already on NodeCore — no cross-layer dependency |
| A5 | `LinkEvent` no longer exists — no pass-through translations |
| A6 | Drain buffers no longer exist |
| C4 (remaining) | Pure delegation methods dissolved with LinkManager |
| G2 | Pass-through parameters naturally reduced (fewer layers) |

---

## Phase 7: API Polish

**14 issues (all done). The public face of the library.**

| # | Issue | P | What | Status |
|---|-------|---|------|--------|
| 1 | E8 | H | Single-packet encryption (blocks all single-packet interop) | **done** |
| 2 | E7 | M | Split transport.rs — won't-fix (2253 LoC production, no natural boundaries) | **closed** |
| 3 | D2 | M | `PacketEndpoint` → `PacketSender` | **done** |
| 4 | D3 | M | `send()` → `try_send()`, `send_bytes()` → `send()` | **done** |
| 5 | D5 | M | `DataReceived` → `LinkDataReceived` | **done** |
| 6 | D6 | M | `DeliveryConfirmed` → `PacketDeliveryConfirmed` | **done** |
| 7 | D7 | M | `ProofRequested` → `PacketProofRequested` | **done** |
| 8 | D12+D13 | L | `ChannelExhausted` close reason (distinct from handshake timeout) | **done** |
| 9 | E2 | M | `pub(crate)` field audit (verified clean — no violations found) | **done** |
| 10 | E3 | M | Silent send failures — `let _ =` replaced with tracing | **done** |
| 11 | E4 | L | Identity table asymmetry — dead `identity_table` removed | **done** |
| 12 | F2 | L | `connect()` returns `was_routed` flag | **done** |
| 13 | G1 | L | `next_deadline_ms` in TickOutput, double-lock eliminated | **done** |

**Naming renames complete** (D2, D3, D5, D6, D7, D12+D13). **E2 verified clean, E4 dead code removed. E7 closed (won't-fix). E8 done (single-packet encryption + decryption).**

---

## Summary

| Phase | Issues | Core Goal | Status |
|-------|--------|-----------|--------|
| 0 — Cleanup | 17 | Clear noise | **done** |
| 1 — Test Infra | 5 | Foundation for all tests | **done** |
| 2 — Test Coverage (TDD) | 8 | Red tests for known bugs | **done** |
| 3 — Bug Fixes | 4 | Tests go green | **done** |
| 4 — Rename | 7 | One concept, one name | **done** |
| 5 — Structure | 3 | 4 maps → 1, LinkManager dissolved | **done** |
| 6 — Consolidation | 5 | Single source of truth, proof bugs fixed | **done** |
| 7 — API Polish | 14 | Clean public API, encryption, split transport | **done** |
| **Total** | **63** | **Complete codebase overhaul** | **all done** |
