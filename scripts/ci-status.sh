#!/bin/bash
RESULTS=~/.local/state/leviculum-ci/last-results.txt

if [ ! -f "$RESULTS" ]; then
    echo "No CI runs yet."
    exit 0
fi

for tier in tier0 tier1 tier2 tier3; do
    LAST=$(grep " $tier " "$RESULTS" | tail -1)
    if [ -n "$LAST" ]; then
        printf "  %-6s  %s\n" "$tier" "$LAST"
    else
        printf "  %-6s  (no runs yet)\n" "$tier"
    fi
done

STALE=$(bash "$(dirname "$0")/check-tier2-staleness.sh")
echo ""
echo "Tier 2 staleness: $STALE"
