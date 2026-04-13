# Tier 0: ~3 min, runs on every git push.
# Exclude reticulum-integ: its lib tests are Docker-based and require
# --test-threads=1 (run in Tier 2). Including them here would race-fail
# and blow the 3 min budget.
fast:
    cargo fmt --all -- --check
    cargo clippy --workspace -- -D warnings
    cargo test --workspace --lib --exclude reticulum-integ

# Tier 1: ~15 min (first run after fresh CARGO_TARGET_DIR: 20-40 min)
# Runs in background after every commit.
standard: fast
    cargo test -p reticulum-core --tests
    cargo test -p reticulum-ffi
    cargo test -p reticulum-proxy
    cargo test -p reticulum-std --test rnsd_interop

# Tier 2: ~30-90 min, scheduled or on demand.
# Default cargo test runs non-ignored tests and skips ignored ones.
# Docker tests (#[serial(docker)]) run; LoRa tests (#[ignore] #[serial(lora)])
# skip automatically. --test-threads=1 is required even though serial_test
# enforces per-group serialization, because the embedded #[serial(docker)]
# groups can still overlap resource usage with unit tests in the same
# binary on a multi-CPU harness.
extensive: standard
    cargo test -p reticulum-integ -- --test-threads=1

# Tier 3: ~2-6h, scheduled nightly. --include-ignored adds LoRa tests.
nightly: extensive
    cargo test -p reticulum-integ -- --include-ignored --test-threads=1

# Status of last runs across all tiers
status:
    @bash scripts/ci-status.sh
