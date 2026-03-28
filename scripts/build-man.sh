#!/bin/sh
# Generate man pages from mdBook markdown sources using pandoc.
# Output goes to target/man/.
#
# Usage: sh scripts/build-man.sh

set -eu

DOCS_DIR="docs/src/man"
OUT_DIR="target/man"

mkdir -p "$OUT_DIR"

for src in "$DOCS_DIR"/*.md; do
    basename=$(basename "$src" .md)    # e.g. lnsd.1
    section="${basename##*.}"           # e.g. 1
    name="${basename%.*}"               # e.g. lnsd

    pandoc "$src" \
        --standalone \
        --to man \
        --variable header="Leviculum" \
        --variable section="$section" \
        --variable title="$name" \
        --output "$OUT_DIR/$basename"

    echo "  $basename -> $OUT_DIR/$basename"
done

echo "Man pages built in $OUT_DIR/"
