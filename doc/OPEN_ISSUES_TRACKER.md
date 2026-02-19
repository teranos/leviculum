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
| E12 | L | post-7 | open | Feature | Periodic flush interval should be configurable (currently hardcoded 3600s) |
| E13 | L | post-7 | open | Design | Storage trait returns references — blocks disk-backed implementations |
| E14 | L | post-7 | open | Design | FileStorage wraps MemoryStorage — cannot use IndexMap for insertion-order eviction |
| E15 | L | post-7 | open | Docs | Git history has 11 commits where FileStorage was no-op — avoid git bisect in that range |
| E16 | L | post-7 | open | Perf | FileStorage writes complete files on every flush — consider delta-based persistence |

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

### E12: Periodic flush interval should be configurable
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Feature
- **Detail:** The periodic storage flush interval is hardcoded to 3600 seconds (1 hour) in `reticulum-std/src/driver/mod.rs` (`FLUSH_INTERVAL_SECS`). The periodic flush is crash protection only — normal shutdown calls `flush()` via the signal handler. This should be configurable via `ReticulumNodeBuilder` or the config file for deployments where a different trade-off between disk I/O and data loss window is desired.
- **Fix:** Add a `flush_interval_secs` field to `ReticulumNodeBuilder` and pass it through to the event loop.
- **Test:** Unit test: verify builder accepts custom flush interval.

### E13: Storage trait returns references — blocks disk-backed implementations
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Design
- **Detail:** Several `Storage` trait methods return `Option<&T>` (e.g., `get_path`, `get_identity`, `get_link_entry`). This requires the storage implementation to hold all data in memory so it can hand out references. A purely disk-backed storage (without an in-memory cache) cannot implement these methods because it would need to return references to temporary values. The current `FileStorage`-wraps-`MemoryStorage` design works around this, but it prevents future pure-disk implementations.
- **Fix:** Change affected trait methods to return owned values (`Option<T>`) or use a cow pattern. This is a breaking API change that touches all `Storage` implementors.
- **Test:** All existing Storage tests should pass after migration.

### E14: FileStorage wraps MemoryStorage — cannot use IndexMap for insertion-order eviction
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Design
- **Detail:** `FileStorage` delegates all runtime collections to `MemoryStorage` (from `reticulum-core`). Because `MemoryStorage` is `no_std`-compatible, it uses `BTreeMap` for all collections. If insertion-order eviction (LRU-style) is ever needed (e.g., for capping the packet hashlist or known_destinations), `BTreeMap` cannot provide it. An `IndexMap` or linked-list-backed map would be needed, but that requires either changing `MemoryStorage` or having `FileStorage` manage those collections directly.
- **Fix:** When eviction is needed, either add an `IndexMap` dependency to the `std` storage or implement a custom ordered map in core.
- **Test:** N/A — design issue, no immediate code change.

### E15: Git history has no-op FileStorage commits — avoid git bisect in that range
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Docs
- **Detail:** During the Storage trait refactoring (E9), commits 0a–11 (between the initial Storage trait introduction and the final FileStorage-wraps-MemoryStorage design) had a FileStorage that was partially or fully no-op for runtime collections. `git bisect` in that range may produce misleading results because storage operations silently did nothing. The affected range is roughly from "Migrate path_table to Storage trait" through "FileStorage wraps MemoryStorage for runtime collections".
- **Fix:** No code change needed. If bisecting a storage-related bug, skip this commit range.
- **Test:** N/A — informational only.

### E16: FileStorage writes complete files on every flush — consider delta-based persistence
- **Status:** open
- **Priority:** L
- **Phase:** post-7
- **Category:** Perf
- **Blocked-by:** Python msgpack format compatibility
- **Detail:** FileStorage rewrites the entire `known_destinations` and `packet_hashlist` files on every flush. On high-traffic nodes these files can reach 14 MB+. Dirty-flag tracking (added Feb 2026) avoids writes when idle, but when dirty the full file is still rewritten. On SD-card-based devices (Raspberry Pi), frequent full rewrites accelerate wear. An append-only or delta-based format would reduce write amplification, but the Python-compatible msgpack format encodes total element count in the file header, making appending impossible without breaking compatibility.
- **Fix:** Requires a new on-disk format (e.g., log-structured or one-value-per-record) with a migration path from the current msgpack format. Python compatibility would need a conversion tool or dual-format support.
- **Test:** Benchmark write amplification before and after format change.
