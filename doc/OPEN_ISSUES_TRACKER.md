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
