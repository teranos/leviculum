# leviculum — Refactoring Battle Plan

All 55 issues from OPEN_ISSUES_TRACKER.md, ordered for maximum efficiency.
Logic: Aufräumen → Testen → Fixen → Benennen → Umbauen → Konsolidieren → Polieren.

---

## Phase 0: Cleanup

**17 issues. No risk, no behavior changes. Clears noise before real work begins.**

| # | Issue | What | Effort |
|---|-------|------|--------|
| 1 | T15 | Delete duplicate test | 1 min |
| 2 | T14 | Rename `test_connection_new` collision | 1 min |
| 3 | T12 | Add assertions to 3 smoke tests | 10 min |
| 4 | C1 | Remove 8 dead error variants, `build()` infallible | 30 min |
| 5 | C2 | ~20 unused re-exports → `pub(crate)` | 15 min |
| 6 | C3 | Buffer types out of public exports | 5 min |
| 7 | E2 | Drain methods → `pub(crate)` | 5 min |
| 8 | H2 | Unify RTT units to ms, document distinction | 15 min |
| 9 | H5 | Deduplicate WindowFull/PacingDelay | 20 min |
| 10 | D10 | Remove `ReticulumNodeImpl` alias | 5 min |
| 11 | D14 | Document `PathRequestReceived` as informational | 5 min |
| 12 | D15 | Document `ChannelRetransmit` as observability-only | 5 min |
| 13 | D4 | `PacketReceived { from }` → `{ destination }` | 10 min |
| 14 | E1 | `transport()` → `now_ms()` accessor | 10 min |
| 15 | F3 | `IdentityNotFound` → `DestinationNotRegistered` | 5 min |
| 16 | F1 | `#[must_use]` on `TickOutput`, document dispatch | 15 min |
| 17 | E3 | Inline `Channel::send()` into `send_internal()` | 10 min |

**Why first:** Zero risk. C1 must happen before the big rename (Phase 4) — no point renaming dead code. After this phase, 17 issues closed, codebase cleaner for everything that follows.

**Estimated effort: ~3h**

---

## Phase 1: Test Infrastructure

**5 issues. Builds the foundation every subsequent test depends on.**

| # | Issue | What | Effort |
|---|-------|------|--------|
| 1 | T1 | Unify MockClock into `test_utils.rs` | 30 min |
| 2 | T2 | Transport test helper | 45 min |
| 3 | T3 | Magic numbers → named constants | 60 min |
| 4 | T4 | 5 Link tests → use `setup_active_link_pair()` | 30 min |
| 5 | T5 | 6 `#[cfg(test)]` setters, 2 new accessors | 30 min |

**Why here:** Every test written from now on benefits. Without T1/T2, Phase 2 starts with copy-paste boilerplate — creating new tech debt while fixing old.

**Estimated effort: ~3h**

---

## Phase 2: Test Coverage for Known Bugs (TDD)

**8 issues. Write tests that are RED now because the bugs still exist.**

| # | Issue | What | Effort | Covers |
|---|-------|------|--------|--------|
| 1 | T8 | FAST tier guard test | 20 min | v0.5.19 regression guard |
| 2 | T7 | LinkManager lifecycle tests (9) | 3-4h | B1, B2, B3, stale, keepalive, peer close |
| 3 | T6 | NodeCore messaging tests (13) | 4-5h | accept, send, close, full packet flow |
| 4 | T9 | Channel edge cases (5) | 1h | poll() empty, window_min |
| 5 | T10 | Link lifecycle (4) | 1h | Active→Stale→Closed, recovery |
| 6 | T11 | Transport gaps (4) | 1h | Hop limit, signature at transport layer |
| 7 | T13 | Split large tests | 1h | 4 tests → 8-10 focused tests |
| 8 | T16 | Regression tests for all ISSUES.md bugs | 2h | B1, B2, B3, F4, H4, etc. |

**Order within phase:** T8 first (20 min, protects v0.5.19). Then T7 (lifecycle infrastructure that T6 and T10 need). Then T6. Then the rest.

**Why here:** TDD. The tests for B1 (memory leak) will FAIL — they document the bug. Phase 3 fixes the bugs and the tests go green.

**Estimated effort: ~12-15h**

---

## Phase 3: Bug Fixes

**4 issues. Tests from Phase 2 verify immediately.**

| # | Issue | What | Effort | Tests go green |
|---|-------|------|--------|---------------|
| 1 | B1 | GC for Closed links | 1h | T7 cleanup test, T16 B1 regression |
| 2 | B2 | `channel_hash_to_seq` cleanup on link close | 30 min | T6 hash_to_seq test, T16 B2 regression |
| 3 | B3 | (Solved by B1) | — | T16 B3 regression |
| 4 | F4 | Handle `mark_delivered()` return value | 15 min | T16 F4 regression |

**Why here:** Bugs documented, tests exist. Each fix is small (B1 is a few lines in `poll()`, B2 is a cleanup loop in the close path). Without Phase 2 tests, we couldn't verify correctness.

**Estimated effort: ~2h**

---

## Phase 4: The Big Rename (A1)

**7 issues. Mechanically large, logically simple. One concept, one name.**

| # | Issue | What |
|---|-------|------|
| 1 | A1 | Eliminate `Connection`, use `Link` everywhere. Move 4 Connection fields into Link. |
| 2 | H3 | Eliminate `CloseReason` / `LinkCloseReason` duplicate (one enum) |
| 3 | D1 | `ConnectionStream` → `LinkHandle` |
| 4 | D8 | `initiate()` → unified verb across all layers |
| 5 | D9 | `accept_link()` / `accept_connection()` → unified |
| 6 | D11 | `Connection` struct dissolved (fields already moved to Link in step 1) |
| 7 | C4 | Inline the 2 event translations that existed for Connection→Link mapping |

**Why here and not earlier:** Phases 0-3 write and modify many tests. If A1 comes first, all new tests must use new names while old tests still use old names — merge conflicts. Better: tests first with old names, then a clean rename pass over everything.

**Why here and not later:** Phase 5 dissolves the `connections` BTreeMap entirely. The rename must happen first so that `Connection` is already gone when we consolidate maps. Otherwise Phase 5 renames AND restructures simultaneously — too much at once.

**After this phase:** `Connection` type no longer exists. `connections: BTreeMap<LinkId, Connection>` on NodeCore is eliminated — its 4 fields live on `Link`. The only LinkId-keyed map left on NodeCore is `link_manager.links`. This sets up Phase 5 perfectly.

**Estimated effort: ~4-6h**

---

## Phase 5: Structural Refactoring

**3 steps, building on each other. Culminates in LinkManager dissolution.**

### Phase 5a: Pending → Link Phase Enum

| Issue | What | Effort |
|-------|------|--------|
| A2 (part 1) | `pending_outgoing`/`pending_incoming` → phase/state enum on Link | 2h |

Eliminates 2 maps. Link now carries its own lifecycle state (Pending, Handshaking, Active, Stale, Closed).

### Phase 5b: Channel → Option\<Channel\> on Link

| Issue | What | Effort |
|-------|------|--------|
| A2 (part 2) | `channels: BTreeMap<LinkId, Channel>` → `Option<Channel>` field on Link | 4-6h |

Eliminates the third parallel map. After this, LinkManager holds only `links`, `data_receipts`, `channel_receipt_keys`, and drain buffers. The two-channel bug class is structurally impossible.

### Phase 5c: LinkManager Dissolution

| Issue | What | Effort |
|-------|------|--------|
| A2 (part 3) | Dissolve LinkManager entirely | 6-8h |

Based on the feasibility analysis:

**What happens:**
- `links`, `data_receipts`, `channel_receipt_keys` become fields on NodeCore
- 23 LinkManager methods become NodeCore methods (in `node/link_management.rs`)
- 5 methods move to `impl Link` (channel accessors)
- 1 becomes a free function (`collect_timed_out_ids`)
- 17 are eliminated (constructors, drain buffers, accepted_destinations)

**What gets eliminated:**
- `LinkEvent` enum (all 11 variants inlined at emission site)
- `PendingPacket` enum (all 5 variants — packets sent directly via `self.transport`)
- `Vec<LinkEvent>` drain buffer
- `Vec<PendingPacket>` drain buffer
- `handle_link_event()` on NodeCore (~150 lines)
- `send_pending_packets()` on NodeCore (~25 lines)
- `drain_events()`, `drain_pending_packets()`, all drain methods

**File organization:**
- `node/link_management.rs` (~949 lines) — all link-related methods as `impl NodeCore` split block
- `node/mod.rs` stays at ~1025 lines
- `link/manager.rs` deleted

**Borrow checker:** Zero methods need restructuring. All conflicts resolved by split borrows (different struct fields) or extract-to-local pattern (copy scalars before mutable borrow).

**Test migration:** ~70 interop test usages of `LinkManager` need updating. Tests either go through NodeCore or test `Link` directly for channel operations.

**Estimated effort for all of Phase 5: ~12-16h**

---

## Phase 6: Consolidation

**3 issues. Down from 8 — LinkManager dissolution eliminated 5 automatically.**

| # | Issue | What | Effort | Notes |
|---|-------|------|--------|-------|
| 1 | H4 | Consolidate bidirectional hash/seq maps | 2h | Both maps now on NodeCore — straightforward |
| 2 | A4 | Formalize receipt tracking (data_receipts + channel_receipt_keys) | 1h | Small helper struct or just documented fields |
| 3 | H1 | Deduplicate `Transport.destinations` vs `NodeCore.destinations` | 3-4h | Transport queries NodeCore's registry |

**Issues eliminated by Phase 5c (no longer needed):**

| Issue | Why eliminated |
|-------|--------------|
| A3 | `channel_hash_to_seq` already on NodeCore — no cross-layer dependency |
| A5 | `LinkEvent` no longer exists — no pass-through translations |
| A6 | Drain buffers no longer exist |
| C4 (remaining) | Pure delegation methods dissolved with LinkManager |
| G2 | Pass-through parameters naturally reduced (fewer layers) |

**Estimated effort: ~6-7h**

---

## Phase 7: API Polish

**9 issues. The public face of the library.**

| # | Issue | What |
|---|-------|------|
| 1 | D2 | `PacketEndpoint` → `PacketSender` |
| 2 | D3 | `send()` → `try_send()`, `send_bytes()` → `send()` |
| 3 | D5 | `DataReceived` → `LinkDataReceived` |
| 4 | D6 | `DeliveryConfirmed` → `PacketDeliveryConfirmed` |
| 5 | D7 | `ProofRequested` → `PacketProofRequested` |
| 6 | D12 | Separate handshake vs active-link timeout events |
| 7 | D13 | `ChannelExhausted` close reason |
| 8 | F2 | `connect()` broadcast fallback transparent |
| 9 | G1 | Merge lock-and-read in event loop |

**Why last:** API renames after structural refactoring — don't rename what will change again. D12 and D13 need new event variants, easier after the event cascade is cleaned up. G1 (lock optimization) touches the event loop which changes in Phase 5c.

**Estimated effort: ~4-6h**

---

## Summary

| Phase | Issues | Effort | Core Goal |
|-------|--------|--------|-----------|
| 0 — Cleanup | 17 | ~3h | Clear noise |
| 1 — Test Infra | 5 | ~3h | Foundation for all tests |
| 2 — Test Coverage (TDD) | 8 | ~12-15h | Red tests for known bugs |
| 3 — Bug Fixes | 4 | ~2h | Tests go green |
| 4 — Rename | 7 | ~4-6h | One concept, one name |
| 5 — Structure | 3 | ~12-16h | 4 maps → 1, LinkManager dissolved |
| 6 — Consolidation | 3 | ~6-7h | Single source of truth |
| 7 — API Polish | 9 | ~4-6h | Clean public API |
| **Total** | **55** | **~45-55h** | **Complete codebase overhaul** |

**Key improvements vs. previous plan:**
- Phase 5c (LinkManager dissolution) eliminates 5 Phase 6 issues automatically
- Total effort reduced by ~8-10h (from ~55-65h to ~45-55h)
- Phase 6 shrinks from 8 issues to 3
- Cleaner end state: no LinkEvent, no PendingPacket, no drain buffers, single `links` map

**Dependency chain:**
```
Phase 0 (independent)
  → Phase 1 (test infra)
    → Phase 2 (TDD — tests are red)
      → Phase 3 (bug fixes — tests go green)
  → Phase 4 (rename — Connection eliminated)
    → Phase 5a (pending → phase enum)
      → Phase 5b (Channel → Option<Channel> on Link)
        → Phase 5c (LinkManager dissolved)
          → Phase 6 (consolidation)
            → Phase 7 (API polish)
```

Phases 0 and 1 can run in parallel. Phase 2 needs Phase 1. Phases 3 and 4 can run in parallel (independent changes). Phase 5 needs Phase 4 completed.
