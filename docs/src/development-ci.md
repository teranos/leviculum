# CI Pipeline

A self-hosted CI pipeline runs entirely on the developer's machine.
Four tiers with different time budgets and triggers automate the
test discipline mandated by `CLAUDE.md` — no GitHub Actions, no
external runners.

## Tiers

| Tier | Name | Trigger | Budget | Test scope |
|------|------|---------|--------|------------|
| 0 | `fast` | pre-push hook | ~3 min | fmt + clippy + workspace lib tests |
| 1 | `standard` | post-commit (background) | ~15 min (first run: 20-40 min cold compile) | Tier 0 + core/tests + ffi + proxy + rnsd_interop |
| 2 | `extensive` | systemd timer 12:30 + 18:30 daily | ~30-90 min | Tier 1 + integ Docker tests |
| 3 | `nightly` | systemd timer 02:00 daily | ~2-6h | Tier 2 + LoRa hardware tests |

Each tier runs everything from the lower tiers as well, so a green
nightly proves the entire stack.

## Installation

One command, idempotent:

```
bash scripts/install-ci.sh
```

It installs `git` hooks (via `core.hooksPath = .githooks`), runner
scripts, systemd user units, the separate cargo target dir, and the
state dir. Re-running is safe.

## Manual operation

```
just fast        # Tier 0
just standard    # Tier 1
just extensive   # Tier 2
just nightly     # Tier 3
just status      # show recent runs across all tiers
```

## First-run expectation

Tier 1 runs in a separate `CARGO_TARGET_DIR` (`~/.cache/leviculum-ci-
target/`) so it doesn't fight your IDE's `target/` for inkremental
caches. The first run after `install-ci.sh` compiles the whole
workspace and all test binaries from scratch — **plan for 20-40
minutes**. Subsequent runs are incremental, ~5-15 minutes.

## Notifications

`notify-send` is called on every Tier 1/2/3 result. Failures use
`-u critical` (sticky until dismissed); successes use `-u low`.

**Prerequisite:** `notify-send` needs `DBUS_SESSION_BUS_ADDRESS` and
`XDG_RUNTIME_DIR` in the user systemd manager environment, which
exists only when you have a logged-in graphical session. On a
headless server, notifications are silently dropped — inspect
`~/.local/state/leviculum-ci/last-results.txt` instead.

## Stale-block on push

`pre-push` blocks the push if Tier 2 hasn't run successfully in
≥ 10 commits or ≥ 24 hours (warning at 5 commits / 8h). To override:

```
git push --no-verify
```

To clear the block normally, run `just extensive` once (or wait for
the next scheduled run).

## Logs

Location: `~/.local/state/leviculum-ci/`

| File | Contents |
|------|----------|
| `last-results.txt` | one-line tally per run (`<iso-timestamp> <tier> GREEN/RED <log-path>`) |
| `tier1-YYYYMMDD-HHMMSS.log` | full Tier 1 output |
| `tier2-YYYYMMDD-HHMMSS.log` | full Tier 2 output |
| `nightly-YYYYMMDD-HHMMSS.log` | full Tier 3 output |
| `tier1.lock` | flock for Tier 1 concurrency control |
| `tier1.dirty` | marker that Tier 1 needs to (re-)run |

Rotation: tier 1/2 logs are deleted after 14 days; nightly logs after
60 days. Done at the start of each runner script.

## Convention: `#[ignore]` is for hardware-dependent tests only

In `reticulum-integ`, the CI tier separation depends on `#[ignore]`:

- Tier 2 runs `cargo test` with default behavior (skips ignored).
- Tier 3 adds `--include-ignored` to pick up exactly the LoRa
  hardware tests.

If you mark a slow but non-hardware test as `#[ignore]`, it ends up
in nightly Tier 3 alongside the LoRa tests — wrong tier. Use a
Cargo feature (e.g. `slow-tests`) for that case instead. Currently
the invariant `#[ignore] tests == #[serial(lora)] tests` holds; keep
it that way.

## Troubleshooting

| Symptom | Action |
|---------|--------|
| post-commit looks dead | `ps -ef | grep run-tier1` and check the latest log file |
| Notification never arrived | Check `last-results.txt`. On headless boxes notifications are dropped. |
| Tier 1 spuriously red | Check log; if Docker is involved, ensure no leftover containers (`docker ps -a`) |
| Timer didn't fire | `systemctl --user list-timers`, then `journalctl --user -u leviculum-ci-tier2.timer` |
| Stale-block annoying | `git push --no-verify` (one-shot) or run `just extensive` |
| Disk filling up | Logs auto-rotate (14d/60d), but `~/.cache/leviculum-ci-target/` can grow large — clear with `cargo clean --target-dir ~/.cache/leviculum-ci-target` |
