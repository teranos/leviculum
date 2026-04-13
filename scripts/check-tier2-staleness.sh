#!/bin/bash
RESULTS=~/.local/state/leviculum-ci/last-results.txt

if [ ! -f "$RESULTS" ]; then
    echo "OK"
    exit 0
fi

LAST_GREEN=$(grep "tier2 GREEN" "$RESULTS" | tail -1 | awk '{print $1}')
if [ -z "$LAST_GREEN" ]; then
    LAST_GREEN="1970-01-01T00:00:00+00:00"
fi

cd "$(dirname "$0")/.." 2>/dev/null || exit 0
COMMITS_SINCE=$(git log --since="$LAST_GREEN" --oneline 2>/dev/null | wc -l)
HOURS_SINCE=$(( ($(date +%s) - $(date -d "$LAST_GREEN" +%s)) / 3600 ))

if [ "$COMMITS_SINCE" -ge 10 ] || [ "$HOURS_SINCE" -ge 24 ]; then
    echo "STALE"
elif [ "$COMMITS_SINCE" -ge 5 ] || [ "$HOURS_SINCE" -ge 8 ]; then
    echo "WARN"
else
    echo "OK"
fi
