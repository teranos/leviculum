#!/bin/bash
# Smoke check: the python_link_selftest.py --responder process is alive
# after the detached launch in python_link_responder_bg.sh.
#
# `pgrep` / `ps` aren't guaranteed to be in the reticulum-test Docker
# image, so we read /proc/*/cmdline directly.
set -u
found=0
for d in /proc/[0-9]*; do
    [ -r "$d/cmdline" ] || continue
    if tr '\0' ' ' < "$d/cmdline" | grep -q 'python_link_selftest.py.*--responder'; then
        echo "RESPONDER_PROC pid=${d##*/} cmdline=$(tr '\0' ' ' < "$d/cmdline")"
        found=1
    fi
done
if [ "$found" = 0 ]; then
    echo "NO_RESPONDER_PROC"
    echo "--- recent responder log ---"
    cat /tmp/mvr-resp.log 2>/dev/null | tail -30 || echo "(no log file)"
    exit 1
fi
exit 0
