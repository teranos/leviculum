#!/bin/bash
LOG_DIR=~/.local/state/leviculum-ci
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/nightly-$(date +%Y%m%d-%H%M%S).log"
RESULTS="$LOG_DIR/last-results.txt"

cd "$(dirname "$0")/.."

# Rotate logs (keep nightly logs longer: 60 days)
find "$LOG_DIR" -name 'nightly-*.log' -mtime +60 -delete 2>/dev/null || true

if CARGO_TARGET_DIR=~/.cache/leviculum-ci-target just nightly > "$LOG" 2>&1; then
    # Parse pass/skip counts for hardware-availability awareness.
    # Format may vary across cargo versions; adjust if parsing fails.
    PASSED=$(grep -oP 'test result: ok\. \K\d+' "$LOG" | awk '{s+=$1} END{print s}')
    SKIPPED=$(grep -oP 'test result: ok\..+?\K\d+(?= ignored)' "$LOG" | awk '{s+=$1} END{print s}')
    notify-send -u normal "Leviculum CI" "Nightly: GREEN (passed: ${PASSED:-?}, skipped: ${SKIPPED:-?})"
    echo "$(date -Iseconds) tier3 GREEN passed=${PASSED:-?} skipped=${SKIPPED:-?}" >> "$RESULTS"
else
    notify-send -u critical "Leviculum CI" "Nightly: RED — see $LOG"
    echo "$(date -Iseconds) tier3 RED $LOG" >> "$RESULTS"
fi
