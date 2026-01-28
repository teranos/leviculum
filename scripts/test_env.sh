#!/usr/bin/env bash
# Clean environment setup for rnsd interop tests.
# Sources or runs standalone to guarantee a fresh rnsd on port 4242.
#
# Usage:
#   source scripts/test_env.sh   # sets RNSD_PID, can call stop_rnsd later
#   bash scripts/test_env.sh     # standalone: starts rnsd, prints status

set -euo pipefail

RETICULUM_SRC="/home/lew/coding/Reticulum"
RNSD_SCRIPT="${RETICULUM_SRC}/RNS/Utilities/rnsd.py"
RNSD_PORT=4242
RNSD_STARTUP_TIMEOUT=30
RNSD_OUTPUT="/tmp/rnsd_test_output.log"

export PYTHONPATH="${RETICULUM_SRC}"

# --- helpers ---

log() { echo "[test_env] $*"; }

kill_stale_processes() {
    local killed=0

    # Kill any running rnsd processes
    if pkill -f "rnsd" 2>/dev/null; then
        killed=$((killed + 1))
        log "Killed rnsd process(es)"
    fi

    # Kill any link_test_destination.py
    if pkill -f "link_test_destination.py" 2>/dev/null; then
        killed=$((killed + 1))
        log "Killed link_test_destination.py"
    fi

    # Kill any cargo test processes targeting our test
    if pkill -f "rnsd_interop" 2>/dev/null; then
        killed=$((killed + 1))
        log "Killed stale cargo test process(es)"
    fi

    if [ "$killed" -gt 0 ]; then
        # Give processes time to release the port
        sleep 1
    fi
}

wait_for_port_free() {
    local attempts=0
    while ss -tlnp 2>/dev/null | grep -q ":${RNSD_PORT} "; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 5 ]; then
            log "ERROR: Port ${RNSD_PORT} still in use after waiting"
            ss -tlnp 2>/dev/null | grep ":${RNSD_PORT} " || true
            return 1
        fi
        sleep 1
    done
}

wait_for_port_open() {
    local elapsed=0
    while [ "$elapsed" -lt "$RNSD_STARTUP_TIMEOUT" ]; do
        if (echo > /dev/tcp/127.0.0.1/${RNSD_PORT}) 2>/dev/null; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

stop_rnsd() {
    if [ -n "${RNSD_PID:-}" ] && kill -0 "$RNSD_PID" 2>/dev/null; then
        kill "$RNSD_PID" 2>/dev/null || true
        wait "$RNSD_PID" 2>/dev/null || true
        log "Stopped rnsd (PID $RNSD_PID)"
        RNSD_PID=""
    fi
}

# --- main ---

log "Step 1: Kill stale processes"
kill_stale_processes

log "Step 2: Verify port ${RNSD_PORT} is free"
if ! wait_for_port_free; then
    log "ABORT: Cannot free port ${RNSD_PORT}"
    exit 1
fi
log "Port ${RNSD_PORT} is free"

log "Step 3: Start rnsd from ${RETICULUM_SRC}"
python3 "$RNSD_SCRIPT" > "$RNSD_OUTPUT" 2>&1 &
RNSD_PID=$!
export RNSD_PID

log "Step 4: Wait for port ${RNSD_PORT} to accept connections (timeout ${RNSD_STARTUP_TIMEOUT}s)"
if ! wait_for_port_open; then
    log "ABORT: rnsd did not start within ${RNSD_STARTUP_TIMEOUT}s"
    kill "$RNSD_PID" 2>/dev/null || true
    exit 1
fi

log "rnsd ready on :${RNSD_PORT} (PID ${RNSD_PID})"
