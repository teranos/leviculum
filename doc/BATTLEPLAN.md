# leviculum — Refactoring Battle Plan

16 open issues from OPEN_ISSUES_TRACKER.md, ordered for maximum efficiency.
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

**4 issues remaining (E1 done). E5 verified clean (no bug).**

| # | Issue | What | Notes |
|---|-------|------|-------|
| 1 | H4 | Consolidate bidirectional hash/seq maps | Both maps now on NodeCore — straightforward. |
| 2 | E6 | Split `handle_channel_packet` (131 lines) | 4 responsibilities: decrypt, receive+drain, proof, rx_ring. Blocked by H4. |
| 3 | A4 | Formalize receipt tracking (data_receipts + channel_receipt_keys) | Receipt code lives in the split methods. |
| 4 | H1 | Deduplicate `Transport.destinations` vs `NodeCore.destinations` | Transport queries NodeCore's registry. |

**Order:** H4 first. E6 second (boundaries stable after H4). A4 third. H1 last (largest, benefits from all prior cleanup).

**Issues eliminated by Phase 5c (no longer needed):**

| Issue | Why eliminated |
|-------|--------------|
| E5 | Verified clean — `Transport::unregister_destination()` calls `self.destinations.remove()` |
| A3 | `channel_hash_to_seq` already on NodeCore — no cross-layer dependency |
| A5 | `LinkEvent` no longer exists — no pass-through translations |
| A6 | Drain buffers no longer exist |
| C4 (remaining) | Pure delegation methods dissolved with LinkManager |
| G2 | Pass-through parameters naturally reduced (fewer layers) |

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
| 6 — Consolidation | 5 (1 done) | Single source of truth | **next** |
| 7 — API Polish | 12 | Clean public API | open |
| **Total** | **62** | **Complete codebase overhaul** | |
| **Remaining** | **16** | | |

**Dependency chain (remaining):**
```
Phase 6:
  E1 ✓ (split god method — done)
    → H4 (consolidate receipt maps)
      → E6 (split channel handler — boundaries stable after H4)
    → A4 (receipt tracking — code lives in split methods)
  H1 (deduplicate destinations — independent)
    → Phase 7 (API polish — all 12 issues independent of each other)
```
