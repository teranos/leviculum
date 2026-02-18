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
| E9 | M | post-7 | open | Feature | Persistent storage for known_identities and path_table |
| E10 | M | post-7 | open | Feature | Interface-specific send-side jitter for shared-medium interfaces |

---

## Issues

### E9: Persistent storage for known_identities and path_table
- **Status:** open
- **Priority:** M
- **Phase:** post-7
- **Category:** Feature
- **Blocked-by:** —
- **Detail:** Use the existing Storage trait to persist known_identities, path_table, and other node state across restarts. Match Python's save_known_destinations() / save_path_table(). Currently in-memory only — state is lost on restart, requiring fresh announces before single-packet communication is possible.
- **Fix:** Implement Storage-backed persistence for NodeCore.known_identities and Transport.path_table. Load on startup, save on insert/update.
- **Test:** Interop test: restart Rust node, verify previously-known destinations are still reachable without re-announce.

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
