#!/usr/bin/env bash
# Run a single announce propagation test with full diagnostics.
#
# 1. Ensures clean rnsd environment via test_env.sh
# 2. Records rnsd log position
# 3. Runs ONLY test_announce_propagation_between_clients with --nocapture
# 4. Dumps relevant rnsd log lines from during the test
# 5. Hard timeout of 60s to prevent hangs
#
# Usage:
#   bash scripts/test_single_propagation.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="${HOME}/.reticulum/logfile"
HARD_TIMEOUT=60

# --- Step 1: Clean environment ---

echo "=== Setting up clean rnsd environment ==="
# Source test_env.sh to get RNSD_PID and stop_rnsd function
source "$SCRIPT_DIR/test_env.sh"

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    stop_rnsd
}
trap cleanup EXIT

# --- Step 2: Record log position ---

LOG_START=0
if [ -f "$LOG_FILE" ]; then
    LOG_START=$(wc -c < "$LOG_FILE")
fi
echo ""
echo "=== rnsd log position: byte $LOG_START ==="

# --- Step 3: Run the single test ---

echo ""
echo "=== Running test_announce_propagation_between_clients ==="
echo "    (hard timeout: ${HARD_TIMEOUT}s)"
echo ""

TEST_EXIT=0
timeout "$HARD_TIMEOUT" \
    cargo test \
    --package reticulum-std \
    --test rnsd_interop \
    -- --ignored --nocapture \
    test_announce_propagation_between_clients \
    2>&1 || TEST_EXIT=$?

echo ""

if [ "$TEST_EXIT" -eq 0 ]; then
    echo "=== TEST PASSED ==="
elif [ "$TEST_EXIT" -eq 124 ]; then
    echo "=== TEST TIMED OUT (${HARD_TIMEOUT}s) ==="
else
    echo "=== TEST FAILED (exit code $TEST_EXIT) ==="
fi

# --- Step 4: Dump rnsd log from during the test ---

echo ""
echo "=== rnsd log entries during test ==="

if [ -f "$LOG_FILE" ]; then
    LOG_END=$(wc -c < "$LOG_FILE")
    BYTES_NEW=$((LOG_END - LOG_START))

    if [ "$BYTES_NEW" -gt 0 ]; then
        # Extract only the new bytes and filter for relevant lines
        tail -c +"$((LOG_START + 1))" "$LOG_FILE" | head -c "$BYTES_NEW" | while IFS= read -r line; do
            # Show all lines, but highlight important ones
            case "$line" in
                *"Error"*|*"error"*|*"Invalid"*|*"invalid"*|*"Dropped"*|*"dropped"*|*"Signature"*|*"signature"*)
                    echo "  >>> $line"
                    ;;
                *"announce"*|*"Announce"*|*"inbound"*|*"outbound"*|*"Retransmit"*|*"retransmit"*)
                    echo "  [A] $line"
                    ;;
                *"TCPClient"*|*"TCPServer"*|*"interface"*|*"Interface"*)
                    echo "  [I] $line"
                    ;;
                *)
                    echo "      $line"
                    ;;
            esac
        done
    else
        echo "  (no new log entries)"
    fi
else
    echo "  (log file not found: $LOG_FILE)"
fi

echo ""
exit "$TEST_EXIT"
