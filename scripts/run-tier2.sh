#!/bin/bash
LOG_DIR=~/.local/state/leviculum-ci
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/tier2-$(date +%Y%m%d-%H%M%S).log"
RESULTS="$LOG_DIR/last-results.txt"

cd "$(dirname "$0")/.."

# Rotate logs
find "$LOG_DIR" -name 'tier*.log' -mtime +14 -delete 2>/dev/null || true

# Skip if already ran successfully today
if grep -q "$(date +%Y-%m-%d).*tier2 GREEN" "$RESULTS" 2>/dev/null; then
    exit 0
fi

# Skip if no commits today
if [ -z "$(git log --since=midnight --oneline 2>/dev/null)" ]; then
    exit 0
fi

if CARGO_TARGET_DIR=~/.cache/leviculum-ci-target just extensive > "$LOG" 2>&1; then
    notify-send -u low "Leviculum CI" "Tier 2 extensive: GREEN"
    echo "$(date -Iseconds) tier2 GREEN" >> "$RESULTS"
else
    notify-send -u critical "Leviculum CI" "Tier 2 extensive: RED — see $LOG"
    echo "$(date -Iseconds) tier2 RED $LOG" >> "$RESULTS"
fi
