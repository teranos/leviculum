#!/usr/bin/env bash
# Manage the 3-daemon test chain:
#   hamster_rnsd (local Python) <-> hamster_lrnsd (Rust) <-> schneckenschreck_rnsd (remote Python)
#
# Usage:
#   ./scripts/test-chain.sh start   - start all three daemons
#   ./scripts/test-chain.sh stop    - stop all three daemons
#   ./scripts/test-chain.sh restart - stop then start
#   ./scripts/test-chain.sh status  - show running state
#   ./scripts/test-chain.sh logs    - tail all three logs interleaved
#   ./scripts/test-chain.sh log <daemon> - tail one daemon's log (lrnsd|rnsd|schneck)
#   ./scripts/test-chain.sh cat <daemon> - cat full log for one daemon
#   ./scripts/test-chain.sh rncp [file]  - run rncp file transfer test (default: python3 binary)

set -euo pipefail

LOGDIR="/tmp/test-chain-logs"
PIDDIR="/tmp/test-chain-pids"
mkdir -p "$LOGDIR" "$PIDDIR"

LRNSD_LOG="$LOGDIR/lrnsd.log"
RNSD_LOG="$LOGDIR/rnsd.log"
SCHNECK_LOG="$LOGDIR/schneck.log"

LRNSD_PID="$PIDDIR/lrnsd.pid"
RNSD_PID="$PIDDIR/rnsd.pid"
SCHNECK_PID="$PIDDIR/schneck.pid"

RNCP_LISTENER_PID="$PIDDIR/rncp_listener.pid"
RNCP_LISTENER_LOG="$LOGDIR/rncp_listener.log"
RNCP_SENDER_LOG="$LOGDIR/rncp_sender.log"

LRNSD_BIN="/home/lew/coding/leviculum/target/debug/lrnsd"
LRNSD_HOME="/home/lew/retis/leviculum"
VENV_ACTIVATE="/home/lew/pythonenvironment/bin/activate"

is_running() {
    local pidfile="$1"
    if [[ -f "$pidfile" ]]; then
        local pid
        pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

kill_pid() {
    local pidfile="$1"
    local name="$2"
    if [[ -f "$pidfile" ]]; then
        local pid
        pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            # Wait up to 3 seconds for graceful shutdown
            for _ in 1 2 3 4 5 6; do
                if ! kill -0 "$pid" 2>/dev/null; then
                    break
                fi
                sleep 0.5
            done
            # Force kill if still running
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
                echo "  $name (pid $pid) force-killed"
            else
                echo "  $name (pid $pid) stopped"
            fi
        else
            echo "  $name not running (stale pidfile)"
        fi
        rm -f "$pidfile"
    else
        echo "  $name not running"
    fi
}

do_start() {
    # Check nothing is already running
    local already=0
    if is_running "$LRNSD_PID"; then
        echo "lrnsd already running (pid $(cat "$LRNSD_PID"))"
        already=1
    fi
    if is_running "$RNSD_PID"; then
        echo "rnsd already running (pid $(cat "$RNSD_PID"))"
        already=1
    fi
    if is_running "$SCHNECK_PID"; then
        echo "schneck already running (pid $(cat "$SCHNECK_PID"))"
        already=1
    fi
    if [[ $already -eq 1 ]]; then
        echo "Stop first with: $0 stop"
        exit 1
    fi

    # Clear old logs
    : > "$LRNSD_LOG"
    : > "$RNSD_LOG"
    : > "$SCHNECK_LOG"

    # 1. Start lrnsd (Rust, middle relay) — must be first since both clients connect to it
    echo "Starting lrnsd (Rust, :4243)..."
    env HOME="$LRNSD_HOME" "$LRNSD_BIN" -vv > "$LRNSD_LOG" 2>&1 &
    echo $! > "$LRNSD_PID"
    echo "  pid $(cat "$LRNSD_PID"), log: $LRNSD_LOG"

    # Wait for TCP server to be ready
    for i in $(seq 1 20); do
        if ss -tln 2>/dev/null | grep -q ':4243 '; then
            break
        fi
        if [[ $i -eq 20 ]]; then
            echo "ERROR: lrnsd did not start listening on :4243"
            do_stop
            exit 1
        fi
        sleep 0.25
    done
    echo "  lrnsd listening on :4243"

    # 2. Start local Python rnsd
    echo "Starting rnsd (Python, :4242)..."
    bash -c "source '$VENV_ACTIVATE' && PYTHONUNBUFFERED=1 exec rnsd -v" > "$RNSD_LOG" 2>&1 &
    echo $! > "$RNSD_PID"
    echo "  pid $(cat "$RNSD_PID"), log: $RNSD_LOG"

    # Wait for TCP server to be ready
    for i in $(seq 1 20); do
        if ss -tln 2>/dev/null | grep -q ':4242 '; then
            break
        fi
        if [[ $i -eq 20 ]]; then
            echo "ERROR: rnsd did not start listening on :4242"
            do_stop
            exit 1
        fi
        sleep 0.25
    done
    echo "  rnsd listening on :4242"

    # 3. Start schneckenschreck rnsd (remote Python)
    echo "Starting schneckenschreck rnsd (Python, remote)..."
    ssh -tt schneckenschreck "source $VENV_ACTIVATE && PYTHONUNBUFFERED=1 rnsd -v" > "$SCHNECK_LOG" 2>&1 &
    echo $! > "$SCHNECK_PID"
    echo "  pid $(cat "$SCHNECK_PID"), log: $SCHNECK_LOG"

    # Wait for schneckenschreck to connect (check lrnsd accepted a connection from .71)
    sleep 2
    echo ""
    echo "Chain started. Connections:"
    ss -tn | grep -E ':4243|:4242' | head -10 || echo "  (no connections yet, give it a moment)"
    echo ""
    echo "Logs:  $LOGDIR/"
    echo "Usage: $0 logs        # tail all three interleaved"
    echo "       $0 log lrnsd   # tail just lrnsd"
}

do_stop() {
    echo "Stopping daemons..."
    kill_pid "$RNCP_LISTENER_PID" "rncp-listener"
    kill_pid "$SCHNECK_PID" "schneckenschreck"
    kill_pid "$RNSD_PID" "rnsd"
    kill_pid "$LRNSD_PID" "lrnsd"
    # Clean up any orphaned ssh sessions to schneckenschreck
    pkill -f "ssh.*schneckenschreck.*rnsd" 2>/dev/null || true
    pkill -f "ssh.*schneckenschreck.*rncp" 2>/dev/null || true
    echo "All stopped."
}

do_status() {
    for pair in "lrnsd:$LRNSD_PID" "rnsd:$RNSD_PID" "schneck:$SCHNECK_PID"; do
        local name="${pair%%:*}"
        local pidfile="${pair#*:}"
        if is_running "$pidfile"; then
            echo "$name: running (pid $(cat "$pidfile"))"
        else
            echo "$name: stopped"
        fi
    done
    echo ""
    echo "TCP connections:"
    ss -tn | grep -E ':4243|:4242' | head -10 || echo "  (none)"
}

do_logs() {
    tail -f "$LRNSD_LOG" "$RNSD_LOG" "$SCHNECK_LOG"
}

do_log_one() {
    local which="$1"
    case "$which" in
        lrnsd)    tail -f "$LRNSD_LOG" ;;
        rnsd)     tail -f "$RNSD_LOG" ;;
        schneck*) tail -f "$SCHNECK_LOG" ;;
        *) echo "Unknown daemon: $which (use lrnsd|rnsd|schneck)"; exit 1 ;;
    esac
}

do_cat_one() {
    local which="$1"
    case "$which" in
        lrnsd)    cat "$LRNSD_LOG" ;;
        rnsd)     cat "$RNSD_LOG" ;;
        schneck*) cat "$SCHNECK_LOG" ;;
        *) echo "Unknown daemon: $which (use lrnsd|rnsd|schneck)"; exit 1 ;;
    esac
}

do_rncp() {
    local test_file="${1:-/home/lew/pythonenvironment/bin/python3}"
    local test_file_basename
    test_file_basename=$(basename "$test_file")
    local received_file="/tmp/test-chain-rncp-received/$test_file_basename"
    mkdir -p /tmp/test-chain-rncp-received

    # Ensure the chain is running
    if ! is_running "$LRNSD_PID" || ! is_running "$RNSD_PID" || ! is_running "$SCHNECK_PID"; then
        echo "Daemon chain not running. Starting it first..."
        do_start
    fi

    # Kill any leftover rncp listener
    kill_pid "$RNCP_LISTENER_PID" "rncp-listener" 2>/dev/null
    : > "$RNCP_LISTENER_LOG"
    : > "$RNCP_SENDER_LOG"
    rm -f "$received_file"

    # 1. Start rncp listener on hamster (receives into /tmp)
    echo "Starting rncp listener on hamster..."
    bash -c "source '$VENV_ACTIVATE' && cd /tmp/test-chain-rncp-received && PYTHONUNBUFFERED=1 exec rncp -nlv" \
        > "$RNCP_LISTENER_LOG" 2>&1 &
    echo $! > "$RNCP_LISTENER_PID"

    # Wait for listener to print its destination hash
    local dest_hash=""
    for i in $(seq 1 30); do
        if [[ -s "$RNCP_LISTENER_LOG" ]]; then
            dest_hash=$(grep -oP '<\K[0-9a-f]{32}' "$RNCP_LISTENER_LOG" | head -1)
            if [[ -n "$dest_hash" ]]; then
                break
            fi
        fi
        sleep 0.5
    done
    if [[ -z "$dest_hash" ]]; then
        echo "ERROR: rncp listener did not produce a destination hash"
        cat "$RNCP_LISTENER_LOG"
        kill_pid "$RNCP_LISTENER_PID" "rncp-listener"
        exit 1
    fi
    echo "  Listener ready: <$dest_hash>"

    # 2. Wait for the announce to propagate through lrnsd to schneckenschreck
    echo "Waiting for announce propagation..."
    local announce_seen=0
    for i in $(seq 1 30); do
        if grep -q "Rebroadcasting announce.*${dest_hash:0:16}" "$LRNSD_LOG" 2>/dev/null; then
            announce_seen=1
            break
        fi
        sleep 0.5
    done
    if [[ $announce_seen -eq 0 ]]; then
        echo "WARNING: Did not see announce rebroadcast in lrnsd log, trying anyway..."
    else
        echo "  Announce propagated through lrnsd"
        sleep 1  # extra settling time for schneckenschreck
    fi

    # 3. Verify test file exists on schneckenschreck
    if ! ssh schneckenschreck "test -f '$test_file'" 2>/dev/null; then
        echo "ERROR: Test file '$test_file' does not exist on schneckenschreck"
        kill_pid "$RNCP_LISTENER_PID" "rncp-listener"
        exit 1
    fi
    local remote_size
    remote_size=$(ssh schneckenschreck "stat -c%s '$test_file'" 2>/dev/null)
    echo "  Source file: $test_file ($remote_size bytes) on schneckenschreck"

    # 4. Run rncp sender on schneckenschreck (foreground, blocks until done)
    echo "Starting file transfer..."
    ssh -tt schneckenschreck \
        "source $VENV_ACTIVATE && PYTHONUNBUFFERED=1 rncp -v '$test_file' '$dest_hash'" \
        > "$RNCP_SENDER_LOG" 2>&1
    local sender_rc=$?

    # 5. Stop rncp listener
    sleep 1
    kill_pid "$RNCP_LISTENER_PID" "rncp-listener" > /dev/null 2>&1

    # 6. Check results
    echo ""
    if [[ $sender_rc -ne 0 ]]; then
        echo "FAIL: rncp sender exited with code $sender_rc"
        echo ""
        echo "--- Sender log ---"
        cat "$RNCP_SENDER_LOG" | tr '\r' '\n' | grep -v '^\[2K' | tail -20
        echo ""
        echo "--- Listener log ---"
        cat "$RNCP_LISTENER_LOG"
        echo ""
        echo "--- lrnsd errors ---"
        grep -iE "error|too long|failed|dropping" "$LRNSD_LOG" | tail -20 || echo "(none)"
        exit 1
    fi

    if [[ ! -f "$received_file" ]]; then
        echo "FAIL: Received file not found at $received_file"
        echo ""
        echo "--- Listener log ---"
        cat "$RNCP_LISTENER_LOG"
        exit 1
    fi

    local local_size
    local_size=$(stat -c%s "$received_file")
    if [[ "$local_size" != "$remote_size" ]]; then
        echo "FAIL: Size mismatch (remote=$remote_size, local=$local_size)"
        exit 1
    fi

    local remote_md5 local_md5
    remote_md5=$(ssh schneckenschreck "md5sum '$test_file'" 2>/dev/null | awk '{print $1}')
    local_md5=$(md5sum "$received_file" | awk '{print $1}')

    if [[ "$remote_md5" != "$local_md5" ]]; then
        echo "FAIL: Checksum mismatch (remote=$remote_md5, local=$local_md5)"
        exit 1
    fi

    # Check for errors in lrnsd log
    local lrnsd_errors
    lrnsd_errors=$(grep -ciE "error|too long|failed to process" "$LRNSD_LOG" 2>/dev/null || true)
    lrnsd_errors="${lrnsd_errors:-0}"

    echo "OK: $test_file_basename transferred successfully"
    echo "  Size:     $local_size bytes"
    echo "  Checksum: $local_md5"
    echo "  lrnsd errors: $lrnsd_errors"
    # Extract transfer speed from sender log
    grep -oP '\d+\.\d+ [MKG]bps' "$RNCP_SENDER_LOG" | tail -1 | xargs -I{} echo "  Speed:    {}" 2>/dev/null || true

    rm -f "$received_file"
}

case "${1:-help}" in
    start)   do_start ;;
    stop)    do_stop ;;
    restart) do_stop; sleep 1; do_start ;;
    status)  do_status ;;
    logs)    do_logs ;;
    log)     do_log_one "${2:?Usage: $0 log <lrnsd|rnsd|schneck>}" ;;
    cat)     do_cat_one "${2:?Usage: $0 cat <lrnsd|rnsd|schneck>}" ;;
    rncp)    do_rncp "${2:-}" ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|log <daemon>|cat <daemon>|rncp [file]}"
        echo ""
        echo "Daemons: lrnsd (Rust relay), rnsd (local Python), schneck (remote Python)"
        echo "Logs:    $LOGDIR/"
        echo ""
        echo "rncp test:"
        echo "  $0 rncp              # transfer python3 binary (default)"
        echo "  $0 rncp /path/file   # transfer a specific file from schneckenschreck"
        exit 1
        ;;
esac
