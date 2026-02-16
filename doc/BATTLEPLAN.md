# leviculum — Refactoring Battle Plan

17 open issues from OPEN_ISSUES_TRACKER.md, ordered for maximum efficiency.
Phases 0–5 complete. Remaining: Phase 6 (consolidation) and Phase 7 (polish).

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

## Phase 6: Consolidation

**5 issues. Down from 8 — LinkManager dissolution eliminated 5 automatically. 2 new issues added post-Phase 5c.**

| # | Issue | What | Effort | Notes |
|---|-------|------|--------|-------|
| 1 | E5 | Verify `unregister_destination()` cleans up Transport's DestinationEntry | 30 min | Potential bug — verify first, fix if broken. Prerequisite for H1. |
| 2 | E1 | Split `handle_link_data` god method (241 lines) | 1h | Extract per-message-type handlers. Pure mechanical. Prerequisite for H4 and A4. |
| 3 | H4 | Consolidate bidirectional hash/seq maps | 2h | Both maps now on NodeCore — straightforward. Easier after E1 split. |
| 4 | A4 | Formalize receipt tracking (data_receipts + channel_receipt_keys) | 1h | Receipt code lives in handle_link_data — easier after E1 split. |
| 5 | H1 | Deduplicate `Transport.destinations` vs `NodeCore.destinations` | 3-4h | Transport queries NodeCore's registry. E5 must be verified first. |

**Order:** E5 first (potential bug — quick verify/fix). E1 second (makes H4 and A4 readable). H4 third. A4 fourth (receipt code lives in the split methods). H1 last (largest, benefits from all prior cleanup).

**Issues eliminated by Phase 5c (no longer needed):**

| Issue | Why eliminated |
|-------|--------------|
| A3 | `channel_hash_to_seq` already on NodeCore — no cross-layer dependency |
| A5 | `LinkEvent` no longer exists — no pass-through translations |
| A6 | Drain buffers no longer exist |
| C4 (remaining) | Pure delegation methods dissolved with LinkManager |
| G2 | Pass-through parameters naturally reduced (fewer layers) |

**Estimated effort: ~7-9h**

---

## Phase 7: API Polish

**12 issues. The public face of the library. 3 new issues added post-Phase 5c.**

| # | Issue | What |
|---|-------|------|
| 1 | D2 | `PacketEndpoint` → `PacketSender` |
| 2 | D3 | `send()` → `try_send()`, `send_bytes()` → `send()` |
| 3 | D5 | `DataReceived` → `LinkDataReceived` |
| 4 | D6 | `DeliveryConfirmed` → `PacketDeliveryConfirmed` |
| 5 | D7 | `ProofRequested` → `PacketProofRequested` |
| 6 | D12 | Separate handshake vs active-link timeout events |
| 7 | D13 | `ChannelExhausted` close reason |
| 8 | E2 | `pub(crate)` field audit (DataReceipt confirmed, others TBD) |
| 9 | E3 | Silent send failures — audit `let _ =` on transport calls |
| 10 | E4 | Identity table asymmetry (Transport + NodeCore) |
| 11 | F2 | `connect()` broadcast fallback transparent |
| 12 | G1 | Merge lock-and-read in event loop |

**Why last:** API renames after structural refactoring — don't rename what will change again. D12 and D13 need new event variants. E2/E3 are cleanup that shouldn't block consolidation. E4 is a minor data model improvement.

**Estimated effort: ~6-8h**

---

## Summary

| Phase | Issues | Effort | Core Goal | Status |
|-------|--------|--------|-----------|--------|
| 0 — Cleanup | 17 | ~3h | Clear noise | **done** |
| 1 — Test Infra | 5 | ~3h | Foundation for all tests | **done** |
| 2 — Test Coverage (TDD) | 8 | ~12-15h | Red tests for known bugs | **done** |
| 3 — Bug Fixes | 4 | ~2h | Tests go green | **done** |
| 4 — Rename | 7 | ~4-6h | One concept, one name | **done** |
| 5 — Structure | 3 | ~12-16h | 4 maps → 1, LinkManager dissolved | **done** |
| 6 — Consolidation | 5 | ~7-9h | Single source of truth | **next** |
| 7 — API Polish | 12 | ~6-8h | Clean public API | open |
| **Total** | **61** | **~50-62h** | **Complete codebase overhaul** | |
| **Remaining** | **17** | **~13-17h** | | |

**Dependency chain (remaining):**
```
Phase 6:
  E5 (verify unregister bug)
    → H1 (deduplicate destinations)
  E1 (split god method)
    → H4 (consolidate receipt maps)
    → A4 (receipt tracking — code lives in split methods)
    → Phase 7 (API polish — all 12 issues independent of each other)
```
