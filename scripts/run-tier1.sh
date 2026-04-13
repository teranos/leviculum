#!/bin/bash
LOG_DIR=~/.local/state/leviculum-ci
mkdir -p "$LOG_DIR"
LOCK="$LOG_DIR/tier1.lock"
DIRTY="$LOG_DIR/tier1.dirty"
LOG="$LOG_DIR/tier1-$(date +%Y%m%d-%H%M%S).log"
RESULTS="$LOG_DIR/last-results.txt"

touch "$DIRTY"

exec 9>"$LOCK"
flock -n 9 || exit 0

cd "$(dirname "$0")/.."

# Rotate logs: keep only the last 14 days
find "$LOG_DIR" -name 'tier*.log' -mtime +14 -delete 2>/dev/null || true

while [ -f "$DIRTY" ]; do
    rm -f "$DIRTY"
    if CARGO_TARGET_DIR=~/.cache/leviculum-ci-target just standard > "$LOG" 2>&1; then
        notify-send -u low "Leviculum CI" "Tier 1 standard: GREEN"
        echo "$(date -Iseconds) tier1 GREEN" >> "$RESULTS"
    else
        notify-send -u critical "Leviculum CI" "Tier 1 standard: RED — see $LOG"
        echo "$(date -Iseconds) tier1 RED $LOG" >> "$RESULTS"
    fi
done
