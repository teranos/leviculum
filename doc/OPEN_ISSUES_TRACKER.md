# leviculum — Issues Tracker

All known issues that cannot be fixed immediately go here.
When an issue is fixed, remove it from this file entirely.

## Phases

Phase numbering follows `doc/BATTLEPLAN.md`. Phases 0–7 are complete.

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Cleanup | done |
| 1 | Test infrastructure | done |
| 2 | Test coverage (TDD) | done |
| 3 | Bug fixes | done |
| 4 | The big rename (Connection → Link) | done |
| 5 | Structural refactoring (LinkManager dissolution) | done |
| 6 | Consolidation (SSOT, receipt tracking) | done |
| 7 | API polish (naming, visibility, perf) | done |

## Status Overview

| ID | P | Phase | Status | Category | Summary |
|----|---|-------|--------|----------|---------|
| E10 | M | post-7 | open | Feature | Interface-specific send-side jitter for shared-medium interfaces |
| E11 | L | post-7 | open | Refactor | Migrate ratchet.rs to new Storage trait methods |

---

## Issues

### E10: Interface-specific send-side jitter for shared-medium interfaces
- **Status:** open
- **Priority:** M
- **Phase:** post-7
- **Category:** Feature
- **Blocked-by:** LoRa/serial interface implementation (ROADMAP #6-#8)
- **Detail:** When LoRa/serial shared-medium interfaces are implemented, they need send-side jitter to prevent collision storms. The core stays instant (no jitter). The interface delays the actual transmission. The interface receives a Broadcast or SendPacket action from the core instantly. Shared-medium interfaces (LoRa, serial) hold the packet in a send queue and apply the jitter delay before the actual transmission. TCP and UDP interfaces send immediately. This keeps the sans-I/O core interface-agnostic.
- **Jitter points to implement per-interface (matching Python values):**
  - First announce rebroadcast: 0-500ms random delay before sending (Python Transport.py:1728, `PATHFINDER_RW = 0.5s`)
  - Announce retry: 5s + 0-500ms random delay (Python Transport.py:531, `PATHFINDER_G + PATHFINDER_RW`). Max 1 retry (`PATHFINDER_R = 1`).
- **What does NOT get jitter (same as Python):**
  - Local client announces (immediate, no jitter — Python Transport.py:1751)
  - Path request responses (deterministic grace periods only: 0ms local, 400ms normal, 1900ms roaming)
  - Bandwidth cap queue draining
  - Rate limiting
- **Fix:** Implement a send queue with configurable jitter delay in shared-medium interface implementations. The core emits actions instantly; the interface holds and delays before transmitting on the wire.
- **Test:** Unit test: verify shared-medium interface applies jitter delay between action receipt and wire transmission. Integration test: two LoRa interfaces receiving the same announce do not transmit at the same instant.

### E11: Migrate ratchet.rs to new Storage trait methods
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Refactor
- **Blocked-by:** B4 (ratchet validation integration)
- **Detail:** The Storage trait includes `load_ratchet/store_ratchet/list_ratchet_keys` methods that currently delegate to the old generic `load/store/delete/list_keys` API. When ratchet validation is integrated (B4), migrate ratchet.rs to use the new type-safe Storage trait methods directly and remove the legacy generic API from the Storage trait.
- **Fix:** Update ratchet.rs to call `storage.load_ratchet()`, `storage.store_ratchet()`, `storage.list_ratchet_keys()` instead of the generic `load/store/delete/list_keys`. Remove the legacy methods from the Storage trait once no code uses them.
- **Test:** Existing ratchet unit tests should pass unchanged after migration.
